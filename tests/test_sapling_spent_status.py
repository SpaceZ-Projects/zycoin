import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.clients import LightwalletdClient
from src.clients.errors import LightwalletdConnectionError, LightwalletdRpcError
from src.clients.protocol import compact_formats_pb2, service_pb2
from src.coin_loader import load_coin_configs
from src.jubjub import group_hash
from src.nullifiers import SaplingNote
from src.sapling_tree import SaplingCommitmentTree
from src.scanning import (
    SaplingCompactOutput,
    SaplingPositionedOutput,
    SaplingSpentStatus,
    SaplingTreeScanResult,
    get_scan_capabilities,
    verify_sapling_note_spent_status,
)

_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_reference.json"
)


class SaplingSpentStatusTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        configs = load_coin_configs()
        self.network = configs["zec"].get_network("mainnet")
        case = json.loads(_FIXTURE.read_text(encoding="utf-8"))["cases"][0]
        diversifier_base = group_hash(
            b"Zcash_gd",
            bytes.fromhex(case["default_d"]),
        )
        self.note = SaplingNote(
            note_commitment=bytes.fromhex(case["note_cmu"]),
            diversifier_base=diversifier_base.encode(),
            transmission_key=bytes.fromhex(case["default_pk_d"]),
            value=case["note_v"],
            commitment_randomness=int.from_bytes(
                bytes.fromhex(case["note_r"]),
                "little",
            ),
            zip212_version=1,
        )
        self.nk = bytes.fromhex(case["nk"])
        self.expected_nullifier = bytes.fromhex(case["note_nf"])
        self.note_height = self.network.sapling["activation_height"] + 20
        compact_output = SaplingCompactOutput(
            txid="fixture-note",
            height=self.note_height,
            transaction_index=0,
            output_index=0,
            cmu=self.note.note_commitment,
            ephemeral_key=bytes(32),
            ciphertext_prefix=bytes(52),
        )
        self.positioned_output = SaplingPositionedOutput(
            compact_output=compact_output,
            position=case["note_pos"],
            coin_id=self.network.coin_id,
            network_id=self.network.network_id,
        )
        tree = SaplingCommitmentTree(self.network)
        tree.append(self.note.note_commitment)
        self.tree_state = SaplingTreeScanResult(
            outputs=(self.positioned_output,),
            tree=tree,
            start_height=self.network.sapling["activation_height"],
            end_height=self.note_height,
        )
        self.tip_height = self.note_height + 2
        self.predecessor_hash = b"\x10" * 32
        self.blocks = self._blocks()
        self.client = object.__new__(LightwalletdClient)
        self.requests = []

    def _blocks(self, spends_by_height=None):
        spends_by_height = spends_by_height or {}
        blocks = []
        previous_hash = self.predecessor_hash
        for offset in range(self.tip_height - self.note_height + 1):
            height = self.note_height + offset
            block_hash = bytes((0x40 + offset,)) * 32
            vtx = []
            if height in spends_by_height:
                vtx.append(
                    compact_formats_pb2.CompactTx(
                        index=0,
                        txid=b"\x55" * 32,
                        spends=[
                            compact_formats_pb2.CompactSaplingSpend(nf=nf)
                            for nf in spends_by_height[height]
                        ],
                    )
                )
            blocks.append(
                compact_formats_pb2.CompactBlock(
                    height=height,
                    hash=block_hash,
                    prevHash=previous_hash,
                    vtx=vtx,
                )
            )
            previous_hash = block_hash
        return tuple(blocks)

    async def _query(
        self,
        *,
        network=None,
        blocks=None,
        trust=False,
        info=None,
        latest=None,
        latest_error=None,
        range_error=None,
        snapshot_hash=None,
        max_blocks=10,
    ):
        network = network or self.network
        blocks = self.blocks if blocks is None else tuple(blocks)
        info = info or service_pb2.LightdInfo(
            chainName="main",
            saplingActivationHeight=network.sapling["activation_height"],
            lightwalletProtocolVersion="0.6.0",
        )
        latest = latest or service_pb2.BlockID(
            height=self.tip_height,
            hash=self.blocks[-1].hash,
        )
        self.requests.clear()

        async def get_block(_client, block_id, *, timeout=None):
            self.assertIs(_client, self.client)
            self.assertIsNone(timeout)
            if block_id.height == self.note_height - 1:
                return compact_formats_pb2.CompactBlock(
                    height=block_id.height,
                    hash=self.predecessor_hash,
                    prevHash=b"\x09" * 32,
                )
            if block_id.height == self.tip_height:
                tip_block = next(
                    (block for block in self.blocks if block.height == self.tip_height),
                    None,
                )
                if tip_block is None:
                    return compact_formats_pb2.CompactBlock(
                        height=self.tip_height,
                        hash=snapshot_hash or latest.hash,
                        prevHash=b"\x00" * 32,
                    )
                return compact_formats_pb2.CompactBlock(
                    height=self.tip_height,
                    hash=snapshot_hash or tip_block.hash,
                    prevHash=tip_block.prevHash,
                )
            raise AssertionError(f"unexpected boundary height {block_id.height}")

        async def get_block_range(_client, request, *, timeout=None):
            self.assertIs(_client, self.client)
            self.assertIsNone(timeout)
            self.requests.append(request)
            if range_error is not None:
                raise range_error
            for block in blocks:
                yield block

        latest_mock = (
            AsyncMock(side_effect=latest_error)
            if latest_error is not None
            else AsyncMock(return_value=latest)
        )
        with (
            patch.object(
                LightwalletdClient,
                "get_lightd_info",
                new=AsyncMock(return_value=info),
            ),
            patch.object(
                LightwalletdClient,
                "get_latest_block",
                new=latest_mock,
            ),
            patch.object(LightwalletdClient, "get_block", new=get_block),
            patch.object(
                LightwalletdClient,
                "get_block_range",
                new=get_block_range,
            ),
        ):
            return await verify_sapling_note_spent_status(
                self.client,
                self.note,
                self.nk,
                self.positioned_output,
                self.tree_state,
                network=network,
                trust_backend_for_unspent=trust,
                max_blocks=max_blocks,
            )

    async def test_observed_nullifier_is_spent(self):
        blocks = self._blocks(
            {self.note_height + 1: (self.expected_nullifier,)},
        )
        result = await self._query(blocks=blocks)

        self.assertEqual(result.status, SaplingSpentStatus.SPENT)
        self.assertEqual(result.nullifier, self.expected_nullifier)
        self.assertEqual(result.observed_height, self.note_height + 1)
        self.assertFalse(result.backend_trusted_for_unspent)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].start.height, self.note_height)
        self.assertEqual(self.requests[0].end.height, self.tip_height)
        self.assertEqual(list(self.requests[0].poolTypes), [])

    async def test_absence_requires_complete_coverage_and_explicit_trust(self):
        trusted = await self._query(trust=True)
        self.assertEqual(trusted.status, SaplingSpentStatus.UNSPENT)
        self.assertEqual(trusted.covered_from_height, self.note_height)
        self.assertEqual(trusted.covered_through_height, self.tip_height)
        self.assertEqual(trusted.chain_tip_hash, self.blocks[-1].hash)

        untrusted = await self._query(trust=False)
        self.assertEqual(untrusted.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("trust", untrusted.reason)
        self.assertEqual(untrusted.covered_through_height, self.tip_height)

    async def test_incomplete_coverage_never_reports_unspent_or_spent(self):
        blocks = self._blocks(
            {self.note_height: (self.expected_nullifier,)},
        )
        result = await self._query(blocks=blocks[:1], trust=True)

        self.assertEqual(result.status, SaplingSpentStatus.UNKNOWN)
        self.assertIsNone(result.covered_through_height)
        self.assertIn("returned 1 blocks", result.reason)

    async def test_chain_tip_must_be_present_consistent_and_stable(self):
        missing = await self._query(
            trust=True,
            latest_error=LightwalletdRpcError(
                "GetLatestBlock",
                None,
                "unavailable",
            ),
        )
        self.assertEqual(missing.status, SaplingSpentStatus.UNKNOWN)
        self.assertIsNone(missing.chain_tip_height)

        inconsistent = await self._query(
            trust=True,
            latest=service_pb2.BlockID(
                height=self.tip_height,
                hash=b"\x99" * 32,
            ),
        )
        self.assertEqual(inconsistent.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("does not end at", inconsistent.reason)

        changed = await self._query(
            trust=True,
            snapshot_hash=b"\x98" * 32,
        )
        self.assertEqual(changed.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("tip changed", changed.reason)

    async def test_unsupported_capability_and_protocol_return_unknown(self):
        rpcs = tuple(
            rpc
            for rpc in self.network.lightwalletd["implemented_rpcs"]
            if rpc != "GetBlockRange"
        )
        unsupported = replace(
            self.network,
            lightwalletd={
                **self.network.lightwalletd,
                "implemented_rpcs": rpcs,
            },
        )
        result = await self._query(network=unsupported, trust=True)
        self.assertEqual(result.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("not configured", result.reason)
        self.assertEqual(self.requests, [])

        old_protocol = await self._query(
            trust=True,
            info=service_pb2.LightdInfo(
                chainName="main",
                saplingActivationHeight=self.network.sapling["activation_height"],
                lightwalletProtocolVersion="0.5.0",
            ),
        )
        self.assertEqual(old_protocol.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("protocol version", old_protocol.reason)

    async def test_malformed_nullifier_response_and_backend_errors_are_unknown(self):
        malformed = self._blocks({self.note_height: (bytes(31),)})
        malformed_result = await self._query(blocks=malformed, trust=True)
        self.assertEqual(malformed_result.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("malformed Sapling nullifier", malformed_result.reason)

        backend_error = await self._query(
            trust=True,
            range_error=LightwalletdRpcError(
                "GetBlockRange",
                None,
                "service unavailable",
            ),
        )
        self.assertEqual(backend_error.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("coverage could not be established", backend_error.reason)

        unavailable = await self._query(
            trust=True,
            latest_error=LightwalletdConnectionError("offline"),
        )
        self.assertEqual(unavailable.status, SaplingSpentStatus.UNKNOWN)
        self.assertIn("offline", unavailable.reason)

    async def test_repeat_queries_are_deterministic(self):
        first = await self._query(trust=True)
        second = await self._query(trust=True)
        self.assertEqual(first, second)

    async def test_btcz_and_zcash_capabilities_are_explicitly_unverified(self):
        configs = load_coin_configs()
        for coin_id in ("zec", "btcz"):
            network = configs[coin_id].get_network("mainnet")
            with self.subTest(coin=coin_id):
                capability = get_scan_capabilities(network)
                self.assertIn("endpoint trust required", capability.sapling_nullifier_scan)
                self.assertNotIn(
                    "GetBlockRangeNullifiers",
                    network.lightwalletd["implemented_rpcs"],
                )
        btcz = configs["btcz"].get_network("mainnet")
        self.assertEqual(btcz.sapling["status"], "partial")


if __name__ == "__main__":
    unittest.main()
