"""Stateless, bounded Lightwalletd compact-block scanners."""

import inspect
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Optional, Tuple

from .clients import LightwalletdClient
from .clients.errors import LightwalletdError
from .clients.protocol import service_pb2 as pb2
from .coins import CoinNetworkConfig
from .crypto import TYPE_ADDRESS, address_to_script, get_address_from_output_script
from .note_decryption import (
    SaplingDecryptedNote as SaplingDecryptedNote,
)
from .note_decryption import (
    SaplingNoteDecryptionError,
    decrypt_sapling_compact_output,
    normalize_viewing_key,
)
from .note_decryption import (
    _require_network_capability as _require_note_decryption_capability,
)
from .nullifiers import (
    SaplingNote,
    SaplingNullifierError,
    derive_sapling_nullifier,
)
from .sapling_tree import SaplingCommitmentTree, SaplingTreeError


class ScanError(RuntimeError):
    """Raised when a Lightwalletd response cannot be scanned safely."""


class ScanCapabilityError(ScanError):
    """Raised when the coin or configured service lacks the requested capability."""


class ScanLimitError(ScanError):
    """Raised when a scan exceeds its configured bound."""


@dataclass(frozen=True)
class ScanProgress:
    backend: str
    coin_id: str
    network_id: str
    start_height: int
    end_height: int
    current_height: int
    completed_blocks: int = 0
    transactions_found: int = 0


@dataclass(frozen=True)
class ScanCapabilities:
    coin_id: str
    network_id: str
    lightwalletd: str
    transparent_scan: str
    sapling_compact_scan: str
    sapling_note_decryption: str = "Unavailable"
    sapling_nullifier_scan: str = "Unavailable"


class SaplingSpentStatus(str, Enum):
    SPENT = "SPENT"
    UNSPENT = "UNSPENT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class SaplingSpentStatusResult:
    status: SaplingSpentStatus
    nullifier: bytes
    note_height: int
    chain_tip_height: int | None = None
    chain_tip_hash: bytes | None = None
    covered_from_height: int | None = None
    covered_through_height: int | None = None
    observed_height: int | None = None
    backend_trusted_for_unspent: bool = False
    reason: str | None = None


@dataclass(frozen=True)
class TransparentInput:
    txid: str
    output_index: int
    address: Optional[str] = None
    value: Any = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TransparentOutput:
    value: int
    script_pub_key: bytes
    address: Optional[str]
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TransparentTransaction:
    txid: str
    height: int
    inputs: Tuple[TransparentInput, ...]
    outputs: Tuple[TransparentOutput, ...]
    addresses: Tuple[str, ...]
    backend: str
    raw_transaction: Optional[bytes] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SaplingCompactOutput:
    txid: str
    height: int
    transaction_index: int
    output_index: int
    cmu: bytes
    ephemeral_key: bytes
    ciphertext_prefix: bytes
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SaplingPositionedOutput:
    compact_output: SaplingCompactOutput
    position: int
    coin_id: str
    network_id: str


@dataclass(frozen=True)
class SaplingTreeScanResult:
    outputs: Tuple[SaplingPositionedOutput, ...]
    tree: SaplingCommitmentTree | None
    start_height: int
    end_height: int

    def validate_spend_anchor(self, anchor: bytes) -> bytes:
        """Require a Spend anchor to occur in this scan's retained tree history."""
        if not isinstance(self.tree, SaplingCommitmentTree):
            raise ScanError("Sapling commitment-tree state is unavailable")
        try:
            return self.tree.require_root_in_history(anchor)
        except SaplingTreeError as exc:
            raise ScanError(
                f"Sapling Spend anchor is invalid or unavailable: {exc}"
            ) from exc

    def witness_for(self, output):
        if not isinstance(output, SaplingPositionedOutput):
            raise TypeError("output must be a SaplingPositionedOutput")
        if not isinstance(self.tree, SaplingCommitmentTree):
            raise ScanError("Sapling commitment-tree state is unavailable")
        if (output.coin_id, output.network_id) != (
            self.tree.network.coin_id,
            self.tree.network.network_id,
        ):
            raise ScanError("output and commitment tree network identities do not match")
        if output not in self.outputs:
            raise ScanError("output is not part of this complete tree scan")
        try:
            witness = self.tree.witness(output.position)
        except SaplingTreeError as exc:
            raise ScanError("could not construct Sapling output witness") from exc
        self.validate_spend_anchor(witness.anchor)
        return witness


def _validate_network(client, network):
    if not isinstance(network, CoinNetworkConfig):
        raise TypeError("network must be a loaded coin network config")
    client_network = getattr(client, "coin", None)
    if client_network is not None and (
        client_network.coin_id != network.coin_id
        or client_network.network_id != network.network_id
    ):
        raise ScanCapabilityError(
            "client and scan network configurations do not match"
        )
    if not isinstance(client, LightwalletdClient):
        raise TypeError("client must be a LightwalletdClient")


def _configured_rpc(network, rpc):
    config = network.lightwalletd
    return (
        config.get("status")
        not in (None, "unsupported", "unknown", "unverified")
        and bool(config.get("endpoints"))
        and "GetLightdInfo" in config.get("implemented_rpcs", ())
        and rpc in config.get("implemented_rpcs", ())
    )


def _require_transparent_capability(network):
    if not _configured_rpc(network, "GetBlockRange"):
        raise ScanCapabilityError(
            f"Lightwalletd transparent scanning is not configured for {network.coin_id}"
        )


def _require_sapling_capability(network):
    sapling = network.sapling
    if (
        not _configured_rpc(network, "GetBlockRange")
        or sapling.get("status") not in (
            "supported_verified_parameters",
            "partial",
        )
        or sapling.get("activation_height") is None
        or sapling.get("lightwalletd_compact_block_capability")
        in (None, "not_configured", "unsupported")
    ):
        raise ScanCapabilityError(
            f"Lightwalletd Sapling compact scanning is not configured for {network.coin_id}"
        )


def get_scan_capabilities(network):
    """Report configured Lightwalletd capabilities without probing an endpoint."""
    if not isinstance(network, CoinNetworkConfig):
        raise TypeError("network must be a loaded coin network config")
    lightwalletd_status = network.lightwalletd.get("status")
    lightwalletd = (
        "Partially Verified"
        if _configured_rpc(network, "GetBlockRange")
        and lightwalletd_status == "partial"
        else "Unverified"
        if _configured_rpc(network, "GetBlockRange")
        else "Unavailable"
    )
    transparent = (
        "Unverified"
        if _configured_rpc(network, "GetBlockRange")
        else "Unavailable"
    )
    compact_capability = network.sapling.get(
        "lightwalletd_compact_block_capability"
    )
    sapling_configured = (
        network.sapling.get("status")
        in ("supported_verified_parameters", "partial")
        and compact_capability not in (None, "not_configured", "unsupported")
        and _configured_rpc(network, "GetBlockRange")
    )
    sapling = (
        "Verified"
        if sapling_configured and compact_capability == "verified"
        else "Partially Verified"
        if sapling_configured and compact_capability == "partially_verified"
        else "Unverified"
        if sapling_configured
        else "Unavailable"
    )
    note_decryption = (
        "Supported"
        if network.sapling.get("note_decryption_status")
        == "supported_verified_parameters"
        and network.sapling.get("zip212_activation_height") is not None
        else "Unavailable"
    )
    nullifier_scan = (
        "Configured; protocol support and endpoint trust required for UNSPENT"
        if _sapling_nullifier_scan_configured(network)
        else "Unavailable"
    )
    return ScanCapabilities(
        coin_id=network.coin_id,
        network_id=network.network_id,
        lightwalletd=lightwalletd,
        transparent_scan=transparent,
        sapling_compact_scan=sapling,
        sapling_note_decryption=note_decryption,
        sapling_nullifier_scan=nullifier_scan,
    )


def _sapling_nullifier_scan_configured(network):
    return (
        all(
            _configured_rpc(network, rpc)
            for rpc in ("GetBlock", "GetBlockRange", "GetLatestBlock")
        )
        and network.sapling.get("status")
        in ("supported_verified_parameters", "partial")
        and network.sapling.get("activation_height") is not None
        and network.sapling.get("lightwalletd_compact_block_capability")
        not in (None, "not_configured", "unsupported")
    )


def _validate_range(start_height, end_height, *, max_blocks):
    if (
        isinstance(start_height, bool)
        or not isinstance(start_height, int)
        or start_height < 0
    ):
        raise ValueError("start_height must be a non-negative integer")
    if (
        isinstance(end_height, bool)
        or not isinstance(end_height, int)
        or end_height < start_height
    ):
        raise ValueError("end_height must be an integer >= start_height")
    if (
        isinstance(max_blocks, bool)
        or not isinstance(max_blocks, int)
        or max_blocks < 1
    ):
        raise ValueError("max_blocks must be a positive integer")
    count = end_height - start_height + 1
    if count > max_blocks:
        raise ScanLimitError(
            f"requested {count} blocks exceeds max_blocks={max_blocks}"
        )
    return count


def _validate_lightd_info(info, network):
    if not isinstance(info, pb2.LightdInfo):
        raise ScanError("Lightwalletd returned malformed chain information")
    if not info.chainName.strip():
        raise ScanError("Lightwalletd returned an empty chain name")
    expected_chain = {
        "mainnet": {"main", "mainnet"},
        "testnet": {"test", "testnet"},
    }.get(network.network_id)
    chain_name = info.chainName.strip().lower()
    if expected_chain and chain_name and chain_name not in expected_chain:
        raise ScanCapabilityError(
            f"Lightwalletd chain '{info.chainName}' does not match "
            f"{network.coin_id} {network.network_id}"
        )


def _lightwallet_protocol_supports_shielded_ranges(info):
    version = getattr(info, "lightwalletProtocolVersion", "")
    if not isinstance(version, str):
        return False
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", version.strip())
    return bool(match) and tuple(map(int, match.groups())) >= (0, 6, 0)


def _validate_block(block, expected_height):
    if not all(
        hasattr(block, name)
        for name in ("height", "hash", "prevHash", "vtx")
    ):
        raise ScanError("Lightwalletd returned a malformed compact block")
    if type(block.height) is not int or block.height != expected_height:
        raise ScanError(
            f"Lightwalletd returned block {block.height}; expected {expected_height}"
        )
    for name in ("hash", "prevHash"):
        value = getattr(block, name)
        if not isinstance(value, bytes):
            raise ScanError(f"Lightwalletd returned a malformed block {name}")
        if value and len(value) != 32:
            raise ScanError(f"Lightwalletd returned a malformed block {name}")


async def _report_progress(callback, event):
    if callback is None:
        return
    result = callback(event)
    if inspect.isawaitable(result):
        await result


def _standard_txid(protocol_bytes):
    if len(protocol_bytes) != 32:
        raise ScanError("compact transaction ID must be exactly 32 bytes")
    return protocol_bytes[::-1].hex()


def _compact_input(value):
    prevout = bytes(value.prevoutTxid)
    if len(prevout) != 32:
        raise ScanError("Lightwalletd returned a malformed transparent prevout ID")
    return TransparentInput(
        txid=_standard_txid(prevout),
        output_index=value.prevoutIndex,
        metadata={"protocol_txid": prevout},
    )


def _compact_output(value, network):
    script = bytes(value.scriptPubKey)
    try:
        output_type, decoded = get_address_from_output_script(script, net=network)
    except (ValueError, IndexError, struct.error) as exc:
        raise ScanError(
            "Lightwalletd returned an invalid transparent output script"
        ) from exc
    address = decoded if output_type == TYPE_ADDRESS else None
    return TransparentOutput(
        value=value.value,
        script_pub_key=script,
        address=address,
        metadata={},
    )


async def scan_transparent(
    client,
    addresses,
    *,
    network,
    start_height,
    end_height,
    max_blocks=1000,
    max_transactions=5000,
    include_raw_transactions=False,
    progress: Optional[Callable[[ScanProgress], Any]] = None,
    timeout=None,
):
    """Scan transparent activity in an inclusive, bounded Lightwalletd range.

    Spend matches are limited to outputs observed inside the requested range.
    Raw transactions and complete compact protobuf messages are preserved as
    bytes; this function does not persist scan results.
    """
    _validate_network(client, network)
    _require_transparent_capability(network)
    if include_raw_transactions and not _configured_rpc(network, "GetTransaction"):
        raise ScanCapabilityError(
            f"Lightwalletd transaction retrieval is not configured for {network.coin_id}"
        )
    total = _validate_range(start_height, end_height, max_blocks=max_blocks)
    if (
        isinstance(max_transactions, bool)
        or not isinstance(max_transactions, int)
        or max_transactions < 1
    ):
        raise ValueError("max_transactions must be a positive integer")
    if isinstance(addresses, str):
        addresses = [addresses]
    try:
        addresses = tuple(dict.fromkeys(addresses))
    except TypeError as exc:
        raise ValueError("addresses must be an iterable of strings") from exc
    if not addresses or any(
        not isinstance(address, str) or not address for address in addresses
    ):
        raise ValueError("addresses must contain one or more non-empty strings")

    scripts = {}
    for address in addresses:
        try:
            script = bytes.fromhex(address_to_script(address, network))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"address is invalid for {network.coin_id} {network.network_id}"
            ) from exc
        scripts[script] = address

    info = await client.get_lightd_info(timeout=timeout)
    _validate_lightd_info(info, network)
    if not info.taddrSupport:
        raise ScanCapabilityError(
            f"Lightwalletd endpoint does not report transparent support for {network.coin_id}"
        )

    request = pb2.BlockRange(
        start=pb2.BlockID(height=start_height),
        end=pb2.BlockID(height=end_height),
        poolTypes=[pb2.TRANSPARENT],
    )
    known_outputs = {}
    found = {}
    requested_addresses = set(scripts.values())
    completed = 0
    expected_height = start_height
    async for block in client.get_block_range(request, timeout=timeout):
        _validate_block(block, expected_height)
        completed += 1
        expected_height += 1
        serialized_block = block.SerializeToString()
        for compact_tx in block.vtx:
            txid_bytes = bytes(compact_tx.txid)
            txid = _standard_txid(txid_bytes)
            inputs = []
            matched_addresses = set()
            for compact_input in compact_tx.vin:
                parsed_input = _compact_input(compact_input)
                outpoint = (
                    bytes(compact_input.prevoutTxid),
                    compact_input.prevoutIndex,
                )
                previous_address = known_outputs.get(outpoint)
                if previous_address is not None:
                    matched_addresses.add(previous_address)
                    parsed_input = TransparentInput(
                        parsed_input.txid,
                        parsed_input.output_index,
                        previous_address,
                        metadata=parsed_input.metadata,
                    )
                inputs.append(parsed_input)

            outputs = []
            for output_index, compact_output in enumerate(compact_tx.vout):
                parsed_output = _compact_output(compact_output, network)
                outputs.append(parsed_output)
                if parsed_output.address in requested_addresses:
                    matched_addresses.add(parsed_output.address)
                    known_outputs[(txid_bytes, output_index)] = parsed_output.address

            if not matched_addresses:
                continue
            if txid not in found:
                if len(found) >= max_transactions:
                    raise ScanLimitError(
                        f"scan exceeds max_transactions={max_transactions}"
                    )
                raw = None
                raw_height = None
                if include_raw_transactions:
                    raw_response = await client.get_transaction(
                        pb2.TxFilter(hash=txid_bytes),
                        timeout=timeout,
                    )
                    raw = bytes(raw_response.data)
                    raw_height = raw_response.height
                    if not raw:
                        raise ScanError(
                            f"Lightwalletd returned an empty transaction for {txid}"
                        )
                found[txid] = TransparentTransaction(
                    txid=txid,
                    height=block.height,
                    inputs=tuple(inputs),
                    outputs=tuple(outputs),
                    addresses=tuple(sorted(matched_addresses)),
                    backend="lightwalletd",
                    raw_transaction=raw,
                    metadata={
                        "transaction_index": compact_tx.index,
                        "fee": compact_tx.fee,
                        "protocol_txid": txid_bytes,
                        "block_hash": bytes(block.hash),
                        "block_time": block.time,
                        "raw_transaction_height": raw_height,
                        "compact_transaction": compact_tx.SerializeToString(),
                        "compact_block": serialized_block,
                    },
                )
            else:
                prior = found[txid]
                found[txid] = TransparentTransaction(
                    txid=prior.txid,
                    height=prior.height,
                    inputs=prior.inputs,
                    outputs=prior.outputs,
                    addresses=tuple(sorted(set(prior.addresses) | matched_addresses)),
                    backend=prior.backend,
                    raw_transaction=prior.raw_transaction,
                    metadata=prior.metadata,
                )

        await _report_progress(
            progress,
            ScanProgress(
                backend="lightwalletd",
                coin_id=network.coin_id,
                network_id=network.network_id,
                start_height=start_height,
                end_height=end_height,
                current_height=block.height,
                completed_blocks=completed,
                transactions_found=len(found),
            ),
        )
    if completed != total:
        raise ScanError(
            f"Lightwalletd returned {completed} blocks for a {total}-block request"
        )
    return tuple(found.values())


async def scan_sapling_compact_outputs(
    client,
    *,
    network,
    start_height,
    end_height,
    max_blocks=1000,
    max_outputs=5000,
    progress: Optional[Callable[[ScanProgress], Any]] = None,
    timeout=None,
):
    """Return bounded Sapling compact outputs without note decryption."""
    _validate_network(client, network)
    _require_sapling_capability(network)
    _validate_range(start_height, end_height, max_blocks=max_blocks)
    if (
        isinstance(max_outputs, bool)
        or not isinstance(max_outputs, int)
        or max_outputs < 1
    ):
        raise ValueError("max_outputs must be a positive integer")

    configured_activation = network.sapling["activation_height"]
    info = await client.get_lightd_info(timeout=timeout)
    _validate_lightd_info(info, network)
    service_activation = info.saplingActivationHeight
    if not service_activation:
        raise ScanCapabilityError(
            f"Lightwalletd endpoint does not report Sapling support for {network.coin_id}"
        )
    if service_activation != configured_activation:
        raise ScanCapabilityError(
            f"Lightwalletd Sapling activation height {service_activation} does not "
            f"match configured height {configured_activation} for {network.coin_id}"
        )
    if end_height < service_activation:
        return ()
    start_height = max(start_height, service_activation)
    total = _validate_range(start_height, end_height, max_blocks=max_blocks)
    request = pb2.BlockRange(
        start=pb2.BlockID(height=start_height),
        end=pb2.BlockID(height=end_height),
        poolTypes=[pb2.SAPLING],
    )
    results = []
    completed = 0
    expected_height = start_height
    async for block in client.get_block_range(request, timeout=timeout):
        _validate_block(block, expected_height)
        completed += 1
        expected_height += 1
        serialized_block = block.SerializeToString()
        for compact_tx in block.vtx:
            txid = _standard_txid(bytes(compact_tx.txid))
            for output_index, output in enumerate(compact_tx.outputs):
                if len(output.cmu) != 32 or len(output.ephemeralKey) != 32:
                    raise ScanError("Lightwalletd returned malformed Sapling output fields")
                if len(output.ciphertext) != 52:
                    raise ScanError(
                        "Lightwalletd compact Sapling ciphertext must be 52 bytes"
                    )
                if len(results) >= max_outputs:
                    raise ScanLimitError(f"scan exceeds max_outputs={max_outputs}")
                results.append(
                    SaplingCompactOutput(
                        txid=txid,
                        height=block.height,
                        transaction_index=compact_tx.index,
                        output_index=output_index,
                        cmu=bytes(output.cmu),
                        ephemeral_key=bytes(output.ephemeralKey),
                        ciphertext_prefix=bytes(output.ciphertext),
                        metadata={
                            "protocol_txid": bytes(compact_tx.txid),
                            "block_hash": bytes(block.hash),
                            "block_time": block.time,
                            "compact_output": output.SerializeToString(),
                            "compact_transaction": compact_tx.SerializeToString(),
                            "compact_block": serialized_block,
                        },
                    )
                )
        await _report_progress(
            progress,
            ScanProgress(
                backend="lightwalletd",
                coin_id=network.coin_id,
                network_id=network.network_id,
                start_height=start_height,
                end_height=end_height,
                current_height=block.height,
                completed_blocks=completed,
                transactions_found=len(results),
            ),
        )
    if completed != total:
        raise ScanError(
            f"Lightwalletd returned {completed} blocks for a {total}-block request"
        )
    return tuple(results)


async def scan_sapling_commitment_tree(
    client,
    *,
    network,
    start_height,
    end_height,
    max_blocks=1000,
    max_outputs=5000,
    progress: Optional[Callable[[ScanProgress], Any]] = None,
    timeout=None,
):
    """Rebuild a Sapling tree only from activation with endpoint size checks."""
    _validate_network(client, network)
    _require_sapling_capability(network)
    if not _configured_rpc(network, "GetBlock") or not _configured_rpc(
        network,
        "GetLatestBlock",
    ):
        raise ScanCapabilityError(
            "complete Sapling tree scans require configured GetBlock and "
            "GetLatestBlock RPCs"
        )
    _validate_range(start_height, end_height, max_blocks=max_blocks)
    if start_height != network.sapling["activation_height"]:
        raise ScanCapabilityError(
            "verified positions require a complete scan from Sapling activation"
        )
    if (
        isinstance(max_outputs, bool)
        or not isinstance(max_outputs, int)
        or max_outputs < 1
    ):
        raise ValueError("max_outputs must be a positive integer")

    info = await client.get_lightd_info(timeout=timeout)
    _validate_lightd_info(info, network)
    service_activation = info.saplingActivationHeight
    if service_activation != start_height:
        raise ScanCapabilityError(
            f"Lightwalletd Sapling activation height {service_activation} does not "
            f"match configured height {start_height} for {network.coin_id}"
        )
    latest = await client.get_latest_block(timeout=timeout)
    if (
        isinstance(latest.height, bool)
        or not isinstance(latest.height, int)
        or latest.height < end_height
        or len(latest.hash) != 32
    ):
        raise ScanCapabilityError(
            "Lightwalletd latest block does not cover the requested scan range"
        )
    predecessor = await client.get_block(
        pb2.BlockID(height=start_height - 1),
        timeout=timeout,
    )
    _validate_block(predecessor, start_height - 1)
    if len(predecessor.hash) != 32:
        raise ScanCapabilityError(
            "Lightwalletd did not provide the pre-activation Sapling boundary block"
        )

    total = _validate_range(start_height, end_height, max_blocks=max_blocks)
    request = pb2.BlockRange(
        start=pb2.BlockID(height=start_height),
        end=pb2.BlockID(height=end_height),
        poolTypes=[pb2.SAPLING],
    )
    tree = SaplingCommitmentTree(network)
    positioned = []
    completed = 0
    expected_height = start_height
    previous_hash = None
    first_previous_hash = None
    end_block_hash = None
    seen_block_hashes = set()
    async for block in client.get_block_range(request, timeout=timeout):
        _validate_block(block, expected_height)
        if len(block.hash) != 32 or len(block.prevHash) != 32:
            raise ScanCapabilityError(
                "Sapling position tracking requires compact block hashes"
            )
        if previous_hash is not None and bytes(block.prevHash) != previous_hash:
            raise ScanError("Lightwalletd compact blocks are not hash-contiguous")
        if first_previous_hash is None:
            first_previous_hash = bytes(block.prevHash)
            if first_previous_hash != bytes(predecessor.hash):
                raise ScanError(
                    "Sapling scan does not connect to the pre-activation boundary block"
                )
        block_hash = bytes(block.hash)
        if block_hash in seen_block_hashes:
            raise ScanError("Lightwalletd returned a duplicate compact block")
        if not block.HasField("chainMetadata"):
            raise ScanCapabilityError(
                "Lightwalletd did not provide Sapling commitment-tree sizes"
            )

        completed += 1
        expected_height += 1
        previous_hash = block_hash
        end_block_hash = block_hash
        seen_block_hashes.add(block_hash)
        prior_tx_index = -1
        seen_txids = set()
        serialized_block = block.SerializeToString()
        for compact_tx in block.vtx:
            if compact_tx.index <= prior_tx_index:
                raise ScanError(
                    "Lightwalletd compact transactions are not in block order"
                )
            prior_tx_index = compact_tx.index
            protocol_txid = bytes(compact_tx.txid)
            if len(protocol_txid) != 32 or protocol_txid in seen_txids:
                raise ScanError(
                    "Lightwalletd returned a malformed or duplicate compact transaction"
                )
            seen_txids.add(protocol_txid)
            txid = _standard_txid(protocol_txid)
            for output_index, output in enumerate(compact_tx.outputs):
                if len(output.ephemeralKey) != 32 or len(output.ciphertext) != 52:
                    raise ScanError(
                        "Lightwalletd returned malformed Sapling compact output data"
                    )
                if len(positioned) >= max_outputs:
                    raise ScanLimitError(f"scan exceeds max_outputs={max_outputs}")
                compact_output = SaplingCompactOutput(
                    txid=txid,
                    height=block.height,
                    transaction_index=compact_tx.index,
                    output_index=output_index,
                    cmu=bytes(output.cmu),
                    ephemeral_key=bytes(output.ephemeralKey),
                    ciphertext_prefix=bytes(output.ciphertext),
                    metadata={
                        "protocol_txid": bytes(compact_tx.txid),
                        "block_hash": bytes(block.hash),
                        "block_time": block.time,
                        "compact_output": output.SerializeToString(),
                        "compact_transaction": compact_tx.SerializeToString(),
                        "compact_block": serialized_block,
                    },
                )
                try:
                    position = tree.append(compact_output.cmu)
                except SaplingTreeError as exc:
                    raise ScanError(
                        "Lightwalletd returned a non-canonical Sapling commitment"
                    ) from exc
                positioned.append(
                    SaplingPositionedOutput(
                        compact_output=compact_output,
                        position=position,
                        coin_id=network.coin_id,
                        network_id=network.network_id,
                    )
                )

        if block.chainMetadata.saplingCommitmentTreeSize != tree.size:
            raise ScanError(
                "Lightwalletd Sapling tree size does not match the ordered "
                "compact commitments"
            )
        await _report_progress(
            progress,
            ScanProgress(
                backend="lightwalletd",
                coin_id=network.coin_id,
                network_id=network.network_id,
                start_height=start_height,
                end_height=end_height,
                current_height=block.height,
                completed_blocks=completed,
                transactions_found=len(positioned),
            ),
        )

    if completed != total:
        raise ScanError(
            f"Lightwalletd returned {completed} blocks for a {total}-block request"
        )
    if end_block_hash is None:
        raise ScanError("Lightwalletd returned no blocks for the requested range")
    current_end = await client.get_block(
        pb2.BlockID(height=end_height),
        timeout=timeout,
    )
    _validate_block(current_end, end_height)
    if bytes(current_end.hash) != end_block_hash:
        raise ScanError(
            "Lightwalletd chain changed while scanning the Sapling tree range"
        )
    if end_height == latest.height and end_block_hash != bytes(latest.hash):
        raise ScanError(
            "Lightwalletd tip changed while scanning the Sapling tree range"
        )
    return SaplingTreeScanResult(
        outputs=tuple(positioned),
        tree=tree,
        start_height=start_height,
        end_height=end_height,
    )


async def verify_sapling_note_spent_status(
    client,
    note,
    nk,
    positioned_output,
    tree_state,
    *,
    network,
    trust_backend_for_unspent=False,
    max_blocks=1000,
    timeout=None,
):
    """Check a validated note's nullifier through a stable reported chain tip.

    An endpoint observation can report ``SPENT``. An empty complete scan
    yields ``UNSPENT`` only when the caller explicitly trusts that endpoint;
    otherwise negative evidence remains ``UNKNOWN``.
    """
    _validate_network(client, network)
    if not isinstance(note, SaplingNote):
        raise TypeError("note must be a validated SaplingNote")
    if not isinstance(positioned_output, SaplingPositionedOutput):
        raise TypeError("positioned_output must be a SaplingPositionedOutput")
    if not isinstance(tree_state, SaplingTreeScanResult):
        raise TypeError("tree_state must be a SaplingTreeScanResult")
    if type(trust_backend_for_unspent) is not bool:
        raise TypeError("trust_backend_for_unspent must be a bool")
    if (
        isinstance(max_blocks, bool)
        or not isinstance(max_blocks, int)
        or max_blocks < 1
    ):
        raise ValueError("max_blocks must be a positive integer")

    compact_output = positioned_output.compact_output
    if not isinstance(compact_output, SaplingCompactOutput):
        raise ScanError("positioned Sapling output is malformed")
    note_height = compact_output.height
    if (
        isinstance(note_height, bool)
        or not isinstance(note_height, int)
        or note_height < 0
    ):
        raise ScanError("positioned Sapling output has an invalid height")
    try:
        nullifier = derive_sapling_nullifier(nk, note, positioned_output.position)
    except SaplingNullifierError as exc:
        raise ScanError(f"could not derive Sapling nullifier: {exc}") from exc
    if not isinstance(nullifier, bytes) or len(nullifier) != 32:
        raise ScanError("Sapling nullifier derivation returned malformed bytes")

    def unknown(
        reason,
        *,
        tip_height=None,
        tip_hash=None,
        covered_from=None,
        covered_through=None,
        observed_height=None,
    ):
        return SaplingSpentStatusResult(
            status=SaplingSpentStatus.UNKNOWN,
            nullifier=nullifier,
            note_height=note_height,
            chain_tip_height=tip_height,
            chain_tip_hash=tip_hash,
            covered_from_height=covered_from,
            covered_through_height=covered_through,
            observed_height=observed_height,
            backend_trusted_for_unspent=trust_backend_for_unspent,
            reason=reason,
        )

    tree = tree_state.tree
    activation_height = network.sapling.get("activation_height")
    if (
        not isinstance(tree, SaplingCommitmentTree)
        or tree.network.coin_id != network.coin_id
        or tree.network.network_id != network.network_id
        or type(activation_height) is not int
        or type(tree_state.start_height) is not int
        or tree_state.start_height != activation_height
        or type(tree_state.end_height) is not int
        or note_height < activation_height
        or tree_state.end_height < note_height
        or not isinstance(tree_state.outputs, tuple)
        or len(tree_state.outputs) != tree.size
        or positioned_output not in tree_state.outputs
        or (positioned_output.coin_id, positioned_output.network_id)
        != (network.coin_id, network.network_id)
    ):
        return unknown("note output or complete Sapling tree context is inconsistent")
    try:
        if (
            tree.root_at(tree.size) != tree.root
            or tree.commitment_at(positioned_output.position)
            != note.note_commitment
            or positioned_output.position >= len(tree_state.outputs)
            or tree_state.outputs[positioned_output.position] != positioned_output
        ):
            return unknown("note commitment or position does not match tree context")
    except (IndexError, SaplingTreeError):
        return unknown("note position is unavailable in the supplied tree context")

    if not _sapling_nullifier_scan_configured(network):
        return unknown(
            f"Lightwalletd Sapling nullifier scanning is not configured for "
            f"{network.coin_id}"
        )

    tip_height = None
    tip_hash = None
    try:
        info = await client.get_lightd_info(timeout=timeout)
        _validate_lightd_info(info, network)
        if not _lightwallet_protocol_supports_shielded_ranges(info):
            return unknown(
                "Lightwalletd protocol version does not establish shielded range support"
            )
        if info.saplingActivationHeight != activation_height:
            return unknown(
                "Lightwalletd Sapling activation height does not match configuration"
            )

        latest = await client.get_latest_block(timeout=timeout)
        if not isinstance(latest, pb2.BlockID):
            return unknown("Lightwalletd returned malformed chain-tip information")
        tip_height = latest.height
        if not isinstance(latest.hash, bytes):
            return unknown("Lightwalletd returned malformed chain-tip information")
        tip_hash = latest.hash
        if (
            isinstance(tip_height, bool)
            or not isinstance(tip_height, int)
            or tip_height < note_height
            or len(tip_hash) != 32
        ):
            return unknown(
                "Lightwalletd returned missing or inconsistent chain-tip information",
                tip_height=tip_height if type(tip_height) is int else None,
                tip_hash=tip_hash if len(tip_hash) == 32 else None,
            )
        if tip_height - note_height + 1 > max_blocks:
            return unknown(
                f"complete nullifier coverage exceeds max_blocks={max_blocks}",
                tip_height=tip_height,
                tip_hash=tip_hash,
            )

        predecessor_height = note_height - 1
        predecessor = await client.get_block(
            pb2.BlockID(height=predecessor_height),
            timeout=timeout,
        )
        _validate_block(predecessor, predecessor_height)
        previous_hash = bytes(predecessor.hash)
        if len(previous_hash) != 32:
            return unknown(
                "Lightwalletd did not provide the note-range predecessor block",
                tip_height=tip_height,
                tip_hash=tip_hash,
            )

        request = pb2.BlockRange(
            start=pb2.BlockID(height=note_height),
            end=pb2.BlockID(height=tip_height),
        )
        completed = 0
        expected_height = note_height
        observed_height = None
        seen_hashes = set()
        async for block in client.get_block_range(request, timeout=timeout):
            _validate_block(block, expected_height)
            block_hash = bytes(block.hash)
            block_previous_hash = bytes(block.prevHash)
            if len(block_hash) != 32 or len(block_previous_hash) != 32:
                raise ScanError(
                    "Lightwalletd returned malformed nullifier-scan block hashes"
                )
            if block_previous_hash != previous_hash:
                raise ScanError(
                    "Lightwalletd nullifier-scan blocks are not hash-contiguous"
                )
            if block_hash in seen_hashes:
                raise ScanError("Lightwalletd returned a duplicate nullifier-scan block")
            seen_hashes.add(block_hash)
            previous_hash = block_hash
            completed += 1
            expected_height += 1

            previous_tx_index = -1
            seen_txids = set()
            for compact_tx in block.vtx:
                protocol_txid = bytes(compact_tx.txid)
                if (
                    len(protocol_txid) != 32
                    or protocol_txid in seen_txids
                    or compact_tx.index <= previous_tx_index
                ):
                    raise ScanError(
                        "Lightwalletd returned malformed or unordered nullifier transactions"
                    )
                seen_txids.add(protocol_txid)
                previous_tx_index = compact_tx.index
                for spend in compact_tx.spends:
                    reported_nullifier = spend.nf
                    if (
                        not isinstance(reported_nullifier, bytes)
                        or len(reported_nullifier) != 32
                    ):
                        raise ScanError(
                            "Lightwalletd returned a malformed Sapling nullifier"
                        )
                    if (
                        observed_height is None
                        and reported_nullifier == nullifier
                    ):
                        observed_height = block.height

        total = tip_height - note_height + 1
        if completed != total:
            raise ScanError(
                f"Lightwalletd returned {completed} blocks for a {total}-block "
                "nullifier coverage range"
            )
        if previous_hash != tip_hash:
            raise ScanError(
                "Lightwalletd nullifier range does not end at the reported chain tip"
            )

        tip_snapshot = await client.get_block(
            pb2.BlockID(height=tip_height),
            timeout=timeout,
        )
        _validate_block(tip_snapshot, tip_height)
        if bytes(tip_snapshot.hash) != tip_hash:
            raise ScanError("Lightwalletd chain tip changed during nullifier scan")

        common = {
            "nullifier": nullifier,
            "note_height": note_height,
            "chain_tip_height": tip_height,
            "chain_tip_hash": tip_hash,
            "covered_from_height": note_height,
            "covered_through_height": tip_height,
            "observed_height": observed_height,
            "backend_trusted_for_unspent": trust_backend_for_unspent,
        }
        if observed_height is not None:
            return SaplingSpentStatusResult(
                status=SaplingSpentStatus.SPENT,
                reason=(
                    "nullifier was observed in the complete Lightwalletd range; "
                    "endpoint evidence is not independently authenticated"
                ),
                **common,
            )
        if not trust_backend_for_unspent:
            return SaplingSpentStatusResult(
                status=SaplingSpentStatus.UNKNOWN,
                reason=(
                    "range coverage is complete, but the caller has not established "
                    "trust in this endpoint for negative evidence"
                ),
                **common,
            )
        return SaplingSpentStatusResult(
            status=SaplingSpentStatus.UNSPENT,
            reason=(
                "nullifier was absent from complete trusted endpoint coverage "
                "through the reported chain tip"
            ),
            **common,
        )
    except (LightwalletdError, ScanError) as exc:
        return unknown(
            f"nullifier coverage could not be established: {exc}",
            tip_height=tip_height,
            tip_hash=tip_hash,
        )


async def scan_sapling_notes(
    client,
    viewing_key,
    *,
    network,
    start_height,
    end_height,
    max_blocks=1000,
    max_outputs=5000,
    progress: Optional[Callable[[ScanProgress], Any]] = None,
    timeout=None,
):
    """Scan bounded compact Sapling outputs and return commitment-checked notes."""
    _validate_network(client, network)
    try:
        _require_note_decryption_capability(network)
    except ValueError as exc:
        raise ScanCapabilityError(str(exc)) from exc
    normalized_key = normalize_viewing_key(viewing_key, network)

    compact_outputs = await scan_sapling_compact_outputs(
        client,
        network=network,
        start_height=start_height,
        end_height=end_height,
        max_blocks=max_blocks,
        max_outputs=max_outputs,
        progress=progress,
        timeout=timeout,
    )
    notes = []
    for compact_output in compact_outputs:
        try:
            note = decrypt_sapling_compact_output(
                compact_output,
                normalized_key,
                network,
            )
        except SaplingNoteDecryptionError as exc:
            raise ScanError(
                "Lightwalletd returned a malformed Sapling compact output"
            ) from exc
        if note is not None:
            notes.append(note)
    return tuple(notes)
