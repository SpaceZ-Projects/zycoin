import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from src.clients.lightwalletd import LightwalletdClient
from src.clients.protocol import service_pb2
from src.coin_loader import load_coin_configs
from src.coin_schemas import CoinConfig, ConfigurationError
from src.manager import ClientManager

ROOT = Path(__file__).resolve().parents[1]


class _RecordingChannel:
    def __init__(self):
        self.paths = []
        self.request_bytes = []
        self.timeouts = []

    async def channel_ready(self):
        return None

    async def close(self):
        return None

    def _bind(self, path, request_serializer, response_deserializer):
        self.paths.append(path)

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
        service = service_pb2.DESCRIPTOR.services_by_name["CompactTxStreamer"]
        for package in ("cash.bitcoinz", "cash.z"):
            with self.subTest(package=package):
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
