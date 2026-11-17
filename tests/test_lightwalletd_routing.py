import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import DecodeError

from src.clients.errors import LightwalletdCapabilityError
from src.clients.lightwalletd import (
    LightwalletdClient,
    _NamespacedCompactTxStreamerStub,
)
from src.clients.protocol import (
    btcz_compact_formats_pb2,
    btcz_service_pb2,
    compact_formats_pb2,
    service_pb2,
)
from src.coin_loader import load_coin_configs
from src.coin_schemas import CoinConfig, ConfigurationError
from src.manager import ClientManager

ROOT = Path(__file__).resolve().parents[1]


class _RecordingChannel:
    def __init__(self):
        self.paths = []
        self.request_bytes = []
        self.timeouts = []
        self.request_serializers = {}
        self.response_deserializers = {}

    async def channel_ready(self):
        return None

    async def close(self):
        return None

    def _bind(self, path, request_serializer, response_deserializer):
        self.paths.append(path)
        self.request_serializers[path] = request_serializer
        self.response_deserializers[path] = response_deserializer

        async def unary(request, **kwargs):
            self.request_bytes.append(request_serializer(request))
            self.timeouts.append(kwargs.get("timeout"))
            return response_deserializer(b"")

        return unary

    def unary_unary(self, path, *, request_serializer, response_deserializer):
        return self._bind(path, request_serializer, response_deserializer)

    def unary_stream(self, path, *, request_serializer, response_deserializer):
        return self._bind(path, request_serializer, response_deserializer)

    def stream_unary(self, path, *, request_serializer, response_deserializer):
        return self._bind(path, request_serializer, response_deserializer)

    def stream_stream(self, path, *, request_serializer, response_deserializer):
        return self._bind(path, request_serializer, response_deserializer)


class LightwalletdNamespaceConfigTests(unittest.TestCase):
    def test_configured_coins_select_their_service_package(self):
        networks = {
            coin_id: ClientManager().add(coin_id, protocol="lightwalletd")
            for coin_id in ("btcz", "zec")
        }
        self.assertEqual(networks["btcz"].proto_package, "cash.bitcoinz")
        self.assertEqual(networks["zec"].proto_package, "cash.z")

    def test_missing_malformed_and_coin_mismatched_packages_are_rejected(self):
        cases = (
            ("btcz", None),
            ("btcz", "cash.unsupported"),
            ("btcz", "cash.z"),
            ("zec", 7),
            ("zec", ""),
        )
        for coin_id, package in cases:
            with self.subTest(coin_id=coin_id, package=package):
                path = ROOT / "src" / "coins" / f"{coin_id}.json"
                definition = copy.deepcopy(json.loads(path.read_text()))
                lightwalletd = definition["networks"]["mainnet"]["lightwalletd"]
                if package is None:
                    lightwalletd.pop("proto_package", None)
                else:
                    lightwalletd["proto_package"] = package
                with self.assertRaisesRegex(ConfigurationError, "proto_package"):
                    CoinConfig.from_mapping(definition)

    def test_direct_client_requires_an_explicit_supported_package(self):
        for package in (None, "", "cash.unsupported"):
            with self.subTest(package=package), self.assertRaisesRegex(
                ValueError,
                "proto_package",
            ):
                LightwalletdClient("localhost", proto_package=package)


class LightwalletdNamespaceRoutingTests(unittest.IsolatedAsyncioTestCase):
    async def test_every_service_rpc_uses_the_configured_namespace(self):
        schemas = (
            ("cash.bitcoinz", btcz_service_pb2),
            ("cash.z", service_pb2),
        )
        for package, schema in schemas:
            with self.subTest(package=package):
                service = schema.DESCRIPTOR.services_by_name[
                    "CompactTxStreamer"
                ]
                channel = _RecordingChannel()
                client = LightwalletdClient(
                    "localhost",
                    proto_package=package,
                )
                with patch(
                    "src.clients.lightwalletd.grpc.aio.secure_channel",
                    return_value=channel,
                ), patch(
                    "src.clients.lightwalletd.grpc.ssl_channel_credentials",
                    return_value=object(),
                ):
                    await client.connect()
                    response = await client.get_lightd_info()

                self.assertIsInstance(response, service_pb2.LightdInfo)
                self.assertEqual(
                    set(channel.paths),
                    {
                        f"/{package}.wallet.sdk.rpc.CompactTxStreamer/"
                        f"{method.name}"
                        for method in service.methods
                    },
                )
                self.assertEqual(len(channel.paths), len(service.methods))
                if package == "cash.bitcoinz":
                    self.assertNotIn(
                        f"/{package}.wallet.sdk.rpc.CompactTxStreamer/"
                        "GetStandardFee",
                        channel.paths,
                    )
                self.assertEqual(channel.request_bytes, [b""])
                self.assertEqual(channel.timeouts, [30.0])
                await client.close()

    def test_loaded_configuration_does_not_default_unconfigured_networks(self):
        configs = load_coin_configs()
        self.assertEqual(
            configs["btcz"].get_network("mainnet").lightwalletd_proto_package,
            "cash.bitcoinz",
        )
        self.assertEqual(
            configs["zec"].get_network("mainnet").lightwalletd_proto_package,
            "cash.z",
        )
        self.assertIsNone(
            configs["zec"].get_network("testnet").lightwalletd_proto_package
        )


class LightwalletdSchemaCompatibilityTests(unittest.TestCase):
    def setUp(self):
        fixture_path = ROOT / "tests" / "fixtures" / "lightwalletd_schema_wire_vectors.json"
        self.vectors = json.loads(fixture_path.read_text())["vectors"]

    @staticmethod
    def _fields(descriptor):
        return {field.number: field for field in descriptor.fields}

    @staticmethod
    def _stub(channel, package):
        return _NamespacedCompactTxStreamerStub(channel, package)

    def test_schema_field_numbers_types_and_defaults(self):
        btc_service = btcz_service_pb2.DESCRIPTOR
        zec_service = service_pb2.DESCRIPTOR
        btc_compact = btcz_compact_formats_pb2.DESCRIPTOR
        zec_compact = compact_formats_pb2.DESCRIPTOR

        btc_info = self._fields(btc_service.message_types_by_name["LightdInfo"])
        zec_info = self._fields(zec_service.message_types_by_name["LightdInfo"])
        for number in range(1, 16):
            self.assertEqual((btc_info[number].name, btc_info[number].type),
                             (zec_info[number].name, zec_info[number].type))
        self.assertNotIn(18, btc_info)
        self.assertEqual(zec_info[18].type, FieldDescriptor.TYPE_STRING)
        self.assertFalse(zec_info[18].has_presence)
        self.assertEqual(service_pb2.LightdInfo().lightwalletProtocolVersion, "")

        btc_range = self._fields(btc_service.message_types_by_name["BlockRange"])
        zec_range = self._fields(zec_service.message_types_by_name["BlockRange"])
        self.assertEqual(set(btc_range), {1, 2})
        self.assertEqual(zec_range[3].type, FieldDescriptor.TYPE_ENUM)
        self.assertTrue(zec_range[3].is_repeated)

        btc_chain = self._fields(btc_compact.message_types_by_name["ChainMetadata"])
        zec_chain = self._fields(zec_compact.message_types_by_name["ChainMetadata"])
        self.assertEqual(set(btc_chain), {1, 2})
        self.assertNotIn(3, btc_chain)
        self.assertEqual(zec_chain[3].type, FieldDescriptor.TYPE_UINT32)

        btc_block = self._fields(btc_compact.message_types_by_name["CompactBlock"])
        zec_block = self._fields(zec_compact.message_types_by_name["CompactBlock"])
        self.assertEqual(btc_block[1].name, "protoVersion")
        self.assertEqual(btc_block[1].type, FieldDescriptor.TYPE_UINT32)
        self.assertNotIn(1, zec_block)

        btc_tx = self._fields(btc_compact.message_types_by_name["CompactTx"])
        zec_tx = self._fields(zec_compact.message_types_by_name["CompactTx"])
        self.assertEqual(
            (btc_tx[2].name, btc_tx[2].type),
            ("hash", FieldDescriptor.TYPE_BYTES),
        )
        self.assertEqual(
            (zec_tx[2].name, zec_tx[2].type),
            ("txid", FieldDescriptor.TYPE_BYTES),
        )
        self.assertEqual(set(btc_tx), {1, 2, 3, 4, 5, 6})
        self.assertEqual(set(zec_tx), {1, 2, 3, 4, 5, 6, 7, 8, 9})

        for message_name in ("CompactSaplingSpend", "CompactSaplingOutput",
                             "CompactOrchardAction"):
            btc_fields = self._fields(btc_compact.message_types_by_name[message_name])
            zec_fields = self._fields(zec_compact.message_types_by_name[message_name])
            self.assertEqual(
                [(field.number, field.name, field.type) for field in btc_fields.values()],
                [(field.number, field.name, field.type) for field in zec_fields.values()],
            )

        btc_tree = self._fields(btc_service.message_types_by_name["TreeState"])
        zec_tree = self._fields(zec_service.message_types_by_name["TreeState"])
        self.assertEqual(set(btc_tree), {1, 2, 3, 4, 5, 6})
        self.assertNotIn(7, btc_tree)
        self.assertEqual(zec_tree[7].type, FieldDescriptor.TYPE_STRING)

        btc_exclude = self._fields(btc_service.message_types_by_name["Exclude"])
        zec_mempool = self._fields(
            zec_service.message_types_by_name["GetMempoolTxRequest"]
        )
        self.assertEqual((btc_exclude[1].type, btc_exclude[1].is_repeated),
                         (zec_mempool[1].type, zec_mempool[1].is_repeated))
        self.assertEqual(btc_exclude[1].type, FieldDescriptor.TYPE_BYTES)
        self.assertNotIn(3, btc_exclude)
        self.assertEqual(zec_mempool[3].type, FieldDescriptor.TYPE_ENUM)

    def test_rpc_signatures_and_availability_are_coin_specific(self):
        btc_service = btcz_service_pb2.DESCRIPTOR.services_by_name[
            "CompactTxStreamer"
        ]
        zec_service = service_pb2.DESCRIPTOR.services_by_name[
            "CompactTxStreamer"
        ]
        btc_methods = btc_service.methods_by_name
        zec_methods = zec_service.methods_by_name
        self.assertEqual(set(btc_methods), set(zec_methods) - {"GetStandardFee"})

        for name in btc_methods:
            with self.subTest(method=name):
                btc_method = btc_methods[name]
                zec_method = zec_methods[name]
                self.assertEqual(
                    (btc_method.client_streaming, btc_method.server_streaming),
                    (zec_method.client_streaming, zec_method.server_streaming),
                )
                self.assertEqual(btc_method.output_type.name, zec_method.output_type.name)
                if name == "GetMempoolTx":
                    self.assertEqual(btc_method.input_type.name, "Exclude")
                    self.assertEqual(zec_method.input_type.name, "GetMempoolTxRequest")
                else:
                    self.assertEqual(btc_method.input_type.name, zec_method.input_type.name)

        self.assertEqual(
            btc_methods["GetTreeState"].input_type.name,
            zec_methods["GetTreeState"].input_type.name,
        )
        self.assertNotIn("GetStandardFee", btc_methods)

    def test_reference_vectors_distinguish_protocol_version_and_pool_types(self):
        protocol_version_wire = bytes.fromhex(
            self.vectors["lightd_info_field_18_protocol_version"]
        )
        zec_info = service_pb2.LightdInfo.FromString(protocol_version_wire)
        self.assertEqual(zec_info.lightwalletProtocolVersion, "0.6.0")
        self.assertNotIn(
            18,
            self._fields(btcz_service_pb2.DESCRIPTOR.message_types_by_name["LightdInfo"]),
        )

        btc_channel = _RecordingChannel()
        self._stub(btc_channel, "cash.bitcoinz")
        info_path = (
            "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetLightdInfo"
        )
        btcz_info = btc_channel.response_deserializers[info_path](
            protocol_version_wire
        )
        self.assertEqual(btcz_info.lightwalletProtocolVersion, "")
        self.assertEqual(
            btc_channel.response_deserializers[info_path](b"")
            .lightwalletProtocolVersion,
            "",
        )

        pool_types_wire = bytes.fromhex(
            self.vectors["block_range_field_3_sapling_pool_type"]
        )
        zec_range = service_pb2.BlockRange.FromString(pool_types_wire)
        self.assertEqual(list(zec_range.poolTypes), [service_pb2.SAPLING])
        btc_range = btcz_service_pb2.BlockRange.FromString(pool_types_wire)
        btc_range.DiscardUnknownFields()
        self.assertEqual(btc_range.SerializeToString(), b"")

        with self.assertRaises(DecodeError):
            btc_channel.response_deserializers[info_path](
                bytes.fromhex("92010530")
            )

    def test_btcz_sapling_range_is_explicitly_adapted_without_pool_types(self):
        btc_channel = _RecordingChannel()
        self._stub(btc_channel, "cash.bitcoinz")
        btc_client = LightwalletdClient(
            "localhost",
            proto_package="cash.bitcoinz",
        )
        request = service_pb2.BlockRange(
            start=service_pb2.BlockID(height=10),
            end=service_pb2.BlockID(height=11),
            poolTypes=[service_pb2.SAPLING],
        )
        with patch.object(btc_client, "_stream", return_value=()) as stream:
            btc_client.get_block_range(request)
        adapted = stream.call_args.args[1]
        self.assertEqual(list(request.poolTypes), [service_pb2.SAPLING])
        self.assertEqual(list(adapted.poolTypes), [])
        btc_path = (
            "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange"
        )
        serialized = btc_channel.request_serializers[btc_path](adapted)
        self.assertEqual(
            btcz_service_pb2.BlockRange.FromString(serialized).start.height,
            10,
        )
        with self.assertRaises(LightwalletdCapabilityError):
            btc_channel.request_serializers[btc_path](request)
        for unsupported in (service_pb2.TRANSPARENT, service_pb2.IRONWOOD):
            with self.subTest(pool_type=unsupported), self.assertRaises(
                LightwalletdCapabilityError
            ):
                btc_client.get_block_range(
                    service_pb2.BlockRange(poolTypes=[unsupported])
                )
        with self.assertRaises(LightwalletdCapabilityError):
            btc_client.get_address_transactions(
                service_pb2.TransparentAddressBlockFilter(
                    range=service_pb2.BlockRange(
                        poolTypes=[service_pb2.SAPLING]
                    )
                )
            )

        zec_channel = _RecordingChannel()
        self._stub(zec_channel, "cash.z")
        zec_client = LightwalletdClient("localhost", proto_package="cash.z")
        with patch.object(zec_client, "_stream", return_value=()) as stream:
            zec_client.get_block_range(request)
        zec_path = "/cash.z.wallet.sdk.rpc.CompactTxStreamer/GetBlockRange"
        zec_serialized = zec_channel.request_serializers[zec_path](
            stream.call_args.args[1]
        )
        self.assertEqual(
            list(service_pb2.BlockRange.FromString(zec_serialized).poolTypes),
            [service_pb2.SAPLING],
        )

    def test_compact_sapling_and_tree_state_fields_convert_by_wire(self):
        compact_tx = (
            b"\x08\x02"
            + bytes.fromhex(self.vectors["compact_tx_field_2_hash_or_txid"])
        )
        spend = bytes.fromhex(self.vectors["sapling_spend_field_1_nf"])
        compact_tx += b"\x22" + bytes([len(spend)]) + spend
        output = b"".join(
            bytes.fromhex(self.vectors[name])
            for name in (
                "sapling_output_field_1_cmu",
                "sapling_output_field_2_ephemeral_key",
                "sapling_output_field_3_ciphertext",
            )
        )
        compact_tx += b"\x2a" + bytes([len(output)]) + output
        compact_block = (
            bytes.fromhex(self.vectors["compact_block_field_1_proto_version"])
            + b"\x10\x2a"
            + b"\x3a"
            + bytes([len(compact_tx)])
            + compact_tx
            + b"\x42\x02\x08\x0a"
        )

        btc_channel = _RecordingChannel()
        self._stub(btc_channel, "cash.bitcoinz")
        block_path = "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetBlock"
        converted = btc_channel.response_deserializers[block_path](compact_block)
        self.assertIsInstance(converted, compact_formats_pb2.CompactBlock)
        self.assertEqual(converted.height, 42)
        self.assertEqual(converted.chainMetadata.saplingCommitmentTreeSize, 10)
        self.assertEqual(converted.vtx[0].txid, b"\xaa\xbb")
        self.assertEqual(converted.vtx[0].spends[0].nf, b"\xaa\xbb")
        self.assertEqual(converted.vtx[0].outputs[0].cmu, b"\xaa\xbb")
        self.assertEqual(converted.vtx[0].outputs[0].ephemeralKey, b"\xcc\xdd")
        self.assertEqual(converted.vtx[0].outputs[0].ciphertext, b"\xee\xff")
        self.assertNotIn(b"\x08\x01", converted.SerializeToString())

        tree_wire = btcz_service_pb2.TreeState(
            network="main",
            height=42,
            hash="block-hash",
            time=100,
            saplingTree="sapling-state",
            orchardTree="orchard-state",
        ).SerializeToString()
        tree_wire += bytes.fromhex(
            self.vectors["tree_state_field_7_ironwood_tree"]
        )
        tree_path = "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetTreeState"
        tree = btc_channel.response_deserializers[tree_path](tree_wire)
        self.assertEqual(tree.saplingTree, "sapling-state")
        self.assertEqual(tree.orchardTree, "orchard-state")
        self.assertEqual(tree.ironwoodTree, "")

        missing_metadata = btcz_compact_formats_pb2.CompactBlock(
            height=42,
            vtx=[
                btcz_compact_formats_pb2.CompactTx(
                    outputs=[
                        btcz_compact_formats_pb2.CompactSaplingOutput(
                            cmu=b"\xaa" * 32,
                            ephemeralKey=b"\xbb" * 32,
                            ciphertext=b"\xcc" * 52,
                        )
                    ]
                )
            ],
        ).SerializeToString()
        missing_block = btc_channel.response_deserializers[block_path](
            missing_metadata
        )
        self.assertFalse(missing_block.HasField("chainMetadata"))

    def test_btcz_drops_zcash_only_compact_fields_and_rejects_new_selectors(self):
        zec_block = compact_formats_pb2.CompactBlock(
            height=42,
            vtx=[
                compact_formats_pb2.CompactTx(
                    index=1,
                    txid=b"\xaa" * 32,
                    vin=[
                        compact_formats_pb2.CompactTxIn(
                            prevoutTxid=b"\xbb" * 32,
                            prevoutIndex=0,
                        )
                    ],
                    vout=[
                        compact_formats_pb2.TxOut(value=1, scriptPubKey=b"\x51")
                    ],
                    ironwoodActions=[
                        compact_formats_pb2.CompactOrchardAction()
                    ],
                )
            ],
            chainMetadata=compact_formats_pb2.ChainMetadata(
                saplingCommitmentTreeSize=1,
                ironwoodCommitmentTreeSize=1,
            ),
        ).SerializeToString()
        btc_channel = _RecordingChannel()
        self._stub(btc_channel, "cash.bitcoinz")
        block_path = "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetBlock"
        converted = btc_channel.response_deserializers[block_path](zec_block)
        self.assertEqual(converted.vtx[0].vin, [])
        self.assertEqual(converted.vtx[0].vout, [])
        self.assertEqual(converted.vtx[0].ironwoodActions, [])
        self.assertEqual(converted.chainMetadata.ironwoodCommitmentTreeSize, 0)

        pool_path = (
            "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetMempoolTx"
        )
        serializer = btc_channel.request_serializers[pool_path]
        exclude_request = service_pb2.GetMempoolTxRequest(
            exclude_txid_suffixes=[b"\xaa\xbb"]
        )
        excluded = btcz_service_pb2.Exclude.FromString(
            serializer(exclude_request)
        )
        self.assertEqual(list(excluded.txid), [b"\xaa\xbb"])
        with self.assertRaises(LightwalletdCapabilityError):
            serializer(
                service_pb2.GetMempoolTxRequest(
                    poolTypes=[service_pb2.SAPLING]
                )
            )

        subtree_path = (
            "/cash.bitcoinz.wallet.sdk.rpc.CompactTxStreamer/GetSubtreeRoots"
        )
        with self.assertRaises(LightwalletdCapabilityError):
            btc_channel.request_serializers[subtree_path](
                service_pb2.GetSubtreeRootsArg(shieldedProtocol=2)
            )

        stub = self._stub(_RecordingChannel(), "cash.bitcoinz")
        self.assertFalse(hasattr(stub, "GetStandardFee"))
