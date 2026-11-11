"""BitcoinZ transparent-only Sapling-v4 transaction construction and signing."""

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.der import UnexpectedDER
from ecdsa.util import sigdecode_der, sigencode_der_canonize

from .coin_loader import get_coin_network
from .coin_schemas import CoinNetworkConfig
from .crypto import (
    address_to_script,
    hash_160,
    public_key_from_private_key,
    public_key_to_p2pkh,
)


_TX_VERSION = 4
_SAPLING_VERSION_GROUP_ID = 0x892F2085
_SIGHASH_ALL = 1
_SIGHASH_NONE = 2
_SIGHASH_SINGLE = 3
_SIGHASH_ANYONECANPAY = 0x80
_ZERO_HASH = bytes(32)
_TXID_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class TransparentTransactionError(ValueError):
    """Raised when a transparent transaction is invalid or unsupported."""


@dataclass(frozen=True)
class TransparentInput:
    txid: str
    output_index: int
    value: int
    address: str
    account: int
    address_index: int
    change: int = 0
    sequence: int = 0xFFFFFFFF


@dataclass(frozen=True)
class TransparentOutput:
    address: str
    value: int


@dataclass(frozen=True)
class UnsignedTransparentTransaction:
    coin_id: str
    network_id: str
    raw: str
    inputs: Tuple[TransparentInput, ...]
    outputs: Tuple[TransparentOutput, ...]
    fee: int
    lock_time: int
    expiry_height: int
    branch_id: int


@dataclass(frozen=True)
class SignedTransparentTransaction:
    coin_id: str
    network_id: str
    raw: str
    txid: str
    fee: int


@dataclass(frozen=True)
class _ParsedInput:
    outpoint: bytes
    script_sig: bytes
    sequence: int


@dataclass(frozen=True)
class _ParsedTransaction:
    version: int
    version_group_id: int
    inputs: Tuple[_ParsedInput, ...]
    outputs: Tuple[bytes, ...]
    lock_time: int
    expiry_height: int
    value_balance: int
    shielded_spends: Tuple[bytes, ...]
    shielded_outputs: Tuple[bytes, ...]
    joinsplits: Tuple[bytes, ...]
    joinsplit_pubkey: bytes


def _uint(value: int, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise TransparentTransactionError(f"{name} must be an integer from 0 to {maximum}")
    return value


def _compact_size(value: int) -> bytes:
    if value < 0:
        raise TransparentTransactionError("compact size cannot be negative")
    if value < 253:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise TransparentTransactionError("compact size is too large")


def _read_compact_size(raw: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(raw):
        raise TransparentTransactionError("truncated compact size")
    prefix = raw[offset]
    offset += 1
    if prefix < 253:
        return prefix, offset
    width = {253: 2, 254: 4, 255: 8}[prefix]
    end = offset + width
    if end > len(raw):
        raise TransparentTransactionError("truncated compact size")
    value = int.from_bytes(raw[offset:end], "little")
    minimum = {2: 253, 4: 0x10000, 8: 0x100000000}[width]
    if value < minimum:
        raise TransparentTransactionError("non-canonical compact size")
    return value, end


def _read_vector(raw: bytes, offset: int) -> Tuple[bytes, int]:
    length, offset = _read_compact_size(raw, offset)
    end = offset + length
    if end > len(raw):
        raise TransparentTransactionError("truncated transaction vector")
    return raw[offset:end], end


def _parse_sapling_v4(raw: bytes) -> _ParsedTransaction:
    offset = 0

    def take(length: int) -> bytes:
        nonlocal offset
        end = offset + length
        if length < 0 or end > len(raw):
            raise TransparentTransactionError("truncated transaction")
        result = raw[offset:end]
        offset = end
        return result

    header = int.from_bytes(take(4), "little")
    if header != (0x80000000 | _TX_VERSION):
        raise TransparentTransactionError("only Overwintered version-4 transactions are supported")
    group_id = int.from_bytes(take(4), "little")
    if group_id != _SAPLING_VERSION_GROUP_ID:
        raise TransparentTransactionError("unsupported transaction version group")

    input_count, offset = _read_compact_size(raw, offset)
    if input_count > 100_000:
        raise TransparentTransactionError("transaction input count is too large")
    inputs = []
    for _ in range(input_count):
        outpoint = take(36)
        script_sig, offset = _read_vector(raw, offset)
        sequence = int.from_bytes(take(4), "little")
        inputs.append(_ParsedInput(outpoint, script_sig, sequence))

    output_count, offset = _read_compact_size(raw, offset)
    if output_count > 100_000:
        raise TransparentTransactionError("transaction output count is too large")
    outputs = []
    for _ in range(output_count):
        value = take(8)
        script, offset = _read_vector(raw, offset)
        outputs.append(value + _compact_size(len(script)) + script)

    lock_time = int.from_bytes(take(4), "little")
    expiry_height = int.from_bytes(take(4), "little")
    value_balance = int.from_bytes(take(8), "little", signed=True)

    spend_count, offset = _read_compact_size(raw, offset)
    if spend_count > 100_000:
        raise TransparentTransactionError("shielded spend count is too large")
    spends = tuple(take(384) for _ in range(spend_count))

    shielded_output_count, offset = _read_compact_size(raw, offset)
    if shielded_output_count > 100_000:
        raise TransparentTransactionError("shielded output count is too large")
    shielded_outputs = tuple(take(948) for _ in range(shielded_output_count))

    joinsplit_count, offset = _read_compact_size(raw, offset)
    if joinsplit_count > 100_000:
        raise TransparentTransactionError("joinsplit count is too large")
    joinsplits = tuple(take(1698) for _ in range(joinsplit_count))
    joinsplit_pubkey = b""
    if joinsplit_count:
        joinsplit_pubkey = take(32)
        take(64)
    if spend_count or shielded_output_count:
        take(64)
    if offset != len(raw):
        raise TransparentTransactionError("transaction has trailing data")

    return _ParsedTransaction(
        _TX_VERSION,
        group_id,
        tuple(inputs),
        tuple(outputs),
        lock_time,
        expiry_height,
        value_balance,
        spends,
        shielded_outputs,
        joinsplits,
        joinsplit_pubkey,
    )


def zip243_signature_hash(
    transaction: bytes,
    script_code: bytes,
    transparent_input_index: Optional[int],
    hash_type: int,
    amount: int,
    consensus_branch_id: int,
) -> bytes:
    """Compute a ZIP-243 signature digest for an Overwintered Sapling-v4 transaction."""
    parsed = _parse_sapling_v4(transaction)
    if not isinstance(script_code, bytes):
        raise TypeError("script_code must be bytes")
    if isinstance(hash_type, bool) or not isinstance(hash_type, int):
        raise TypeError("hash_type must be an integer")
    base_type = hash_type & 0x1F
    if base_type not in (_SIGHASH_ALL, _SIGHASH_NONE, _SIGHASH_SINGLE):
        raise TransparentTransactionError("unsupported ZIP-243 signature hash type")
    if hash_type & ~(_SIGHASH_ANYONECANPAY | 0x1F):
        raise TransparentTransactionError("unsupported ZIP-243 signature hash flags")
    amount = _uint(amount, "amount", (1 << 63) - 1)
    consensus_branch_id = _uint(consensus_branch_id, "consensus_branch_id", 0xFFFFFFFF)
    if transparent_input_index is not None:
        transparent_input_index = _uint(
            transparent_input_index,
            "transparent_input_index",
            0xFFFFFFFF,
        )
        if transparent_input_index >= len(parsed.inputs):
            raise TransparentTransactionError("transparent input index is out of range")

    anyone_can_pay = bool(hash_type & _SIGHASH_ANYONECANPAY)
    hash_prevouts = _ZERO_HASH
    if not anyone_can_pay:
        hash_prevouts = hashlib.blake2b(
            b"".join(txin.outpoint for txin in parsed.inputs),
            digest_size=32,
            person=b"ZcashPrevoutHash",
        ).digest()

    hash_sequence = _ZERO_HASH
    if not anyone_can_pay and base_type not in (_SIGHASH_NONE, _SIGHASH_SINGLE):
        hash_sequence = hashlib.blake2b(
            b"".join(struct.pack("<I", txin.sequence) for txin in parsed.inputs),
            digest_size=32,
            person=b"ZcashSequencHash",
        ).digest()

    hash_outputs = _ZERO_HASH
    if base_type == _SIGHASH_ALL:
        hash_outputs = hashlib.blake2b(
            b"".join(parsed.outputs),
            digest_size=32,
            person=b"ZcashOutputsHash",
        ).digest()
    elif (
        base_type == _SIGHASH_SINGLE
        and transparent_input_index is not None
        and transparent_input_index < len(parsed.outputs)
    ):
        hash_outputs = hashlib.blake2b(
            parsed.outputs[transparent_input_index],
            digest_size=32,
            person=b"ZcashOutputsHash",
        ).digest()

    hash_joinsplits = _ZERO_HASH
    if parsed.joinsplits:
        hash_joinsplits = hashlib.blake2b(
            b"".join(parsed.joinsplits) + parsed.joinsplit_pubkey,
            digest_size=32,
            person=b"ZcashJSplitsHash",
        ).digest()

    hash_shielded_spends = _ZERO_HASH
    if parsed.shielded_spends:
        hash_shielded_spends = hashlib.blake2b(
            b"".join(spend[:-64] for spend in parsed.shielded_spends),
            digest_size=32,
            person=b"ZcashSSpendsHash",
        ).digest()

    hash_shielded_outputs = _ZERO_HASH
    if parsed.shielded_outputs:
        hash_shielded_outputs = hashlib.blake2b(
            b"".join(parsed.shielded_outputs),
            digest_size=32,
            person=b"ZcashSOutputHash",
        ).digest()

    preimage = (
        struct.pack("<II", 0x80000000 | parsed.version, parsed.version_group_id)
        + hash_prevouts
        + hash_sequence
        + hash_outputs
        + hash_joinsplits
        + hash_shielded_spends
        + hash_shielded_outputs
        + struct.pack("<IIqI", parsed.lock_time, parsed.expiry_height, parsed.value_balance, hash_type)
    )
    if transparent_input_index is not None:
        txin = parsed.inputs[transparent_input_index]
        preimage += (
            txin.outpoint
            + _compact_size(len(script_code))
            + script_code
            + struct.pack("<Q", amount)
            + struct.pack("<I", txin.sequence)
        )

    return hashlib.blake2b(
        preimage,
        digest_size=32,
        person=b"ZcashSigHash" + struct.pack("<I", consensus_branch_id),
    ).digest()


def _configured_signing_parameters(network: CoinNetworkConfig) -> dict:
    signing = network.transparent_signing
    if signing.get("status") != "supported_verified_parameters":
        raise TransparentTransactionError(
            f"transparent signing is not verified for "
            f"{network.coin_id}/{network.network_id}"
        )
    if network.address_verification != "verified":
        raise TransparentTransactionError(
            f"address parameters are not verified for "
            f"{network.coin_id}/{network.network_id}"
        )
    if network.transparent_derivation.get("status") != "supported_verified_parameters":
        raise TransparentTransactionError(
            f"BIP44 derivation is not verified for "
            f"{network.coin_id}/{network.network_id}"
        )
    return signing


def create_unsigned_transaction(
    coin: str,
    inputs: Sequence[TransparentInput],
    outputs: Sequence[TransparentOutput],
    *,
    fee: int,
    network: str = "mainnet",
    lock_time: int = 0,
    expiry_height: int = 0,
) -> UnsignedTransparentTransaction:
    """Create an unsigned v4 P2PKH transaction; the caller sets outputs and fee."""
    network_config = get_coin_network(coin, network)
    signing = _configured_signing_parameters(network_config)
    if signing["format"] != "zip243-sapling-v4":
        raise TransparentTransactionError("unsupported transparent transaction format")
    input_items = tuple(inputs)
    output_items = tuple(outputs)
    if not input_items or not output_items:
        raise TransparentTransactionError("at least one input and output are required")
    if any(not isinstance(item, TransparentInput) for item in input_items):
        raise TypeError("inputs must contain TransparentInput values")
    if any(not isinstance(item, TransparentOutput) for item in output_items):
        raise TypeError("outputs must contain TransparentOutput values")
    fee = _uint(fee, "fee", signing["max_money"])
    lock_time = _uint(lock_time, "lock_time", 0xFFFFFFFF)
    expiry_height = _uint(expiry_height, "expiry_height", 0xFFFFFFFF)
    branch_id = int(signing["consensus_branch_id_hex"], 16)

    seen_outpoints = set()
    input_total = 0
    serialized_inputs = []
    for txin in input_items:
        if not isinstance(txin.txid, str) or not _TXID_PATTERN.fullmatch(txin.txid):
            raise TransparentTransactionError("input txid must be 32-byte hexadecimal")
        output_index = _uint(txin.output_index, "output_index", 0xFFFFFFFF)
        value = _uint(txin.value, "input value", signing["max_money"])
        if value == 0:
            raise TransparentTransactionError("input value must be positive")
        _uint(txin.account, "account", 0x7FFFFFFF)
        _uint(txin.address_index, "address_index", 0x7FFFFFFF)
        _uint(txin.change, "change", 1)
        sequence = _uint(txin.sequence, "sequence", 0xFFFFFFFF)
        outpoint_id = (txin.txid.lower(), output_index)
        if outpoint_id in seen_outpoints:
            raise TransparentTransactionError("duplicate transaction input")
        seen_outpoints.add(outpoint_id)
        input_total += value
        if input_total > signing["max_money"]:
            raise TransparentTransactionError("total input value exceeds the configured money limit")
        script = _p2pkh_script(txin.address, network_config)
        outpoint = bytes.fromhex(txin.txid)[::-1] + struct.pack("<I", output_index)
        serialized_inputs.append(
            outpoint + b"\x00" + struct.pack("<I", sequence)
        )

    output_total = 0
    serialized_outputs = []
    for txout in output_items:
        value = _uint(txout.value, "output value", signing["max_money"])
        if value == 0:
            raise TransparentTransactionError("output value must be positive")
        output_total += value
        if output_total > signing["max_money"]:
            raise TransparentTransactionError("total output value exceeds the configured money limit")
        script = _p2pkh_script(txout.address, network_config)
        serialized_outputs.append(
            struct.pack("<q", value) + _compact_size(len(script)) + script
        )
    if output_total > input_total or input_total - output_total != fee:
        raise TransparentTransactionError(
            "input value minus output value must equal the explicit fee"
        )

    raw = (
        struct.pack("<II", 0x80000000 | _TX_VERSION, _SAPLING_VERSION_GROUP_ID)
        + _compact_size(len(input_items))
        + b"".join(serialized_inputs)
        + _compact_size(len(output_items))
        + b"".join(serialized_outputs)
        + struct.pack("<IIq", lock_time, expiry_height, 0)
        + b"\x00\x00\x00"
    )
    _parse_sapling_v4(raw)
    return UnsignedTransparentTransaction(
        network_config.coin_id,
        network_config.network_id,
        raw.hex(),
        input_items,
        output_items,
        fee,
        lock_time,
        expiry_height,
        branch_id,
    )


def _p2pkh_script(address: str, network: CoinNetworkConfig) -> bytes:
    if not isinstance(address, str) or not address:
        raise TransparentTransactionError("address must be a non-empty string")
    try:
        script = bytes.fromhex(address_to_script(address, network))
    except (TypeError, ValueError) as exc:
        raise TransparentTransactionError("address is invalid for the selected network") from exc
    if len(script) != 25 or not script.startswith(b"\x76\xa9\x14") or not script.endswith(b"\x88\xac"):
        raise TransparentTransactionError("only P2PKH addresses are supported")
    return script


def _push_data(value: bytes) -> bytes:
    length = len(value)
    if length < 0x4C:
        return bytes((length,)) + value
    if length <= 0xFF:
        return b"\x4c" + bytes((length,)) + value
    if length <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", length) + value
    raise TransparentTransactionError("script data push is too large")


def sign_transaction(
    transaction: UnsignedTransparentTransaction,
    recovery_phrase: str,
    *,
    passphrase: str = "",
) -> SignedTransparentTransaction:
    """Sign configured P2PKH inputs using verified BIP44 keys and ZIP-243 SIGHASH_ALL."""
    if not isinstance(transaction, UnsignedTransparentTransaction):
        raise TypeError("transaction must be an UnsignedTransparentTransaction")
    network = get_coin_network(transaction.coin_id, transaction.network_id)
    signing = _configured_signing_parameters(network)
    if _uint(transaction.branch_id, "branch_id", 0xFFFFFFFF) != int(
        signing["consensus_branch_id_hex"],
        16,
    ):
        raise TransparentTransactionError("transaction consensus branch id is not configured")
    if bytes.fromhex(transaction.raw).hex() != transaction.raw.lower():
        raise TransparentTransactionError("unsigned transaction hex is malformed")
    canonical = create_unsigned_transaction(
        transaction.coin_id,
        transaction.inputs,
        transaction.outputs,
        fee=transaction.fee,
        network=transaction.network_id,
        lock_time=transaction.lock_time,
        expiry_height=transaction.expiry_height,
    )
    if canonical.raw != transaction.raw.lower():
        raise TransparentTransactionError(
            "unsigned transaction bytes do not match the transaction metadata"
        )

    wallets = {}
    raw = bytearray.fromhex(transaction.raw)
    parsed = _parse_sapling_v4(bytes(raw))
    if len(parsed.inputs) != len(transaction.inputs):
        raise TransparentTransactionError("transaction inputs do not match metadata")

    for index, txin in enumerate(transaction.inputs):
        wallet = wallets.get(txin.account)
        if wallet is None:
            from .wallet import TransparentWallet

            wallet = TransparentWallet.from_mnemonic(
                recovery_phrase,
                transaction.coin_id,
                network=transaction.network_id,
                passphrase=passphrase,
                account=txin.account,
            )
            wallets[txin.account] = wallet

        private_bytes = wallet.derive_private_key(
            index=txin.address_index,
            change=txin.change,
        )
        compressed = True
        private_key_bytes = bytearray(private_bytes)
        try:
            if not compressed:
                raise TransparentTransactionError("only compressed P2PKH keys are supported")
            public_key = bytes.fromhex(
                public_key_from_private_key(bytes(private_key_bytes), True)
            )
            if public_key_to_p2pkh(public_key, network) != txin.address:
                raise TransparentTransactionError(
                    f"derived key does not match input {index} address"
                )
            script_code = _p2pkh_script(txin.address, network)
            digest = zip243_signature_hash(
                bytes(raw),
                script_code,
                index,
                _SIGHASH_ALL,
                txin.value,
                transaction.branch_id,
            )
            signer = ecdsa.SigningKey.from_string(
                bytes(private_key_bytes),
                curve=SECP256k1,
            )
            signature = signer.sign_digest_deterministic(
                digest,
                hashfunc=hashlib.sha256,
                sigencode=sigencode_der_canonize,
            )
            if not signer.get_verifying_key().verify_digest(
                signature,
                digest,
                sigdecode=sigdecode_der,
            ):
                raise TransparentTransactionError("generated signature failed verification")
            script_sig = _push_data(signature + bytes((_SIGHASH_ALL,))) + _push_data(public_key)
            raw = _replace_input_script(bytes(raw), index, script_sig)
        finally:
            for byte_index in range(len(private_key_bytes)):
                private_key_bytes[byte_index] = 0
            del private_bytes

    signed_hex = bytes(raw).hex()
    if not verify_transaction_signatures(transaction, signed_hex):
        raise TransparentTransactionError("signed transaction failed independent verification")
    txid = hashlib.sha256(hashlib.sha256(bytes(raw)).digest()).digest()[::-1].hex()
    wallets.clear()
    return SignedTransparentTransaction(
        transaction.coin_id,
        transaction.network_id,
        signed_hex,
        txid,
        transaction.fee,
    )


def _replace_input_script(raw: bytes, input_index: int, script_sig: bytes) -> bytearray:
    parsed = _parse_sapling_v4(raw)
    if not 0 <= input_index < len(parsed.inputs):
        raise TransparentTransactionError("input index is out of range")
    offset = 8
    count, offset = _read_compact_size(raw, offset)
    if count != len(parsed.inputs):
        raise TransparentTransactionError("invalid transaction input count")
    result = bytearray(raw[:offset])
    for index, txin in enumerate(parsed.inputs):
        start = offset
        offset += 36
        _, offset = _read_compact_size(raw, offset)
        script_start = offset
        offset += len(txin.script_sig)
        offset += 4
        if index == input_index:
            result.extend(raw[start:start + 36])
            result.extend(_compact_size(len(script_sig)))
            result.extend(script_sig)
            result.extend(raw[script_start + len(txin.script_sig):offset])
        else:
            result.extend(raw[start:offset])
    result.extend(raw[offset:])
    return result


def _read_pushes(script: bytes) -> Tuple[bytes, ...]:
    pushes = []
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        if opcode <= 75:
            length = opcode
        elif opcode == 0x4C:
            if offset >= len(script):
                raise TransparentTransactionError("truncated script push")
            length = script[offset]
            offset += 1
            if length < 76:
                raise TransparentTransactionError("non-canonical script push")
        elif opcode == 0x4D:
            if offset + 2 > len(script):
                raise TransparentTransactionError("truncated script push")
            length = int.from_bytes(script[offset:offset + 2], "little")
            offset += 2
            if length <= 0xFF:
                raise TransparentTransactionError("non-canonical script push")
        else:
            raise TransparentTransactionError("input script contains a non-push opcode")
        end = offset + length
        if end > len(script):
            raise TransparentTransactionError("truncated script data")
        pushes.append(script[offset:end])
        offset = end
    return tuple(pushes)


def verify_transaction_signatures(
    transaction: UnsignedTransparentTransaction,
    signed_hex: str,
) -> bool:
    """Verify all P2PKH signatures, input commitments, outputs, and transaction metadata."""
    if not isinstance(transaction, UnsignedTransparentTransaction):
        raise TypeError("transaction must be an UnsignedTransparentTransaction")
    if not isinstance(signed_hex, str) or len(signed_hex) % 2:
        return False
    try:
        raw = bytes.fromhex(signed_hex)
        network = get_coin_network(transaction.coin_id, transaction.network_id)
        canonical = create_unsigned_transaction(
            transaction.coin_id,
            transaction.inputs,
            transaction.outputs,
            fee=transaction.fee,
            network=transaction.network_id,
            lock_time=transaction.lock_time,
            expiry_height=transaction.expiry_height,
        )
        if canonical.raw != transaction.raw.lower():
            return False
        parsed = _parse_sapling_v4(raw)
        unsigned = _parse_sapling_v4(bytes.fromhex(transaction.raw))
        if (
            parsed.version_group_id != unsigned.version_group_id
            or parsed.lock_time != transaction.lock_time
            or parsed.expiry_height != transaction.expiry_height
            or parsed.value_balance != 0
            or parsed.outputs != unsigned.outputs
            or len(parsed.inputs) != len(transaction.inputs)
            or parsed.shielded_spends
            or parsed.shielded_outputs
            or parsed.joinsplits
        ):
            return False
        for index, (parsed_input, input_data) in enumerate(
            zip(parsed.inputs, transaction.inputs)
        ):
            expected_outpoint = (
                bytes.fromhex(input_data.txid)[::-1]
                + struct.pack("<I", input_data.output_index)
            )
            if (
                parsed_input.outpoint != expected_outpoint
                or parsed_input.sequence != unsigned.inputs[index].sequence
            ):
                return False
            pushes = _read_pushes(parsed_input.script_sig)
            if len(pushes) != 2 or not pushes[0] or pushes[0][-1] != _SIGHASH_ALL:
                return False
            signature = pushes[0][:-1]
            public_key = pushes[1]
            if (
                len(public_key) != 33
                or public_key[0] not in (2, 3)
                or parsed_input.script_sig
                != _push_data(pushes[0]) + _push_data(public_key)
            ):
                return False
            script_code = _p2pkh_script(input_data.address, network)
            if script_code[3:23] != hash_160(public_key):
                return False
            digest = zip243_signature_hash(
                raw,
                script_code,
                index,
                _SIGHASH_ALL,
                input_data.value,
                transaction.branch_id,
            )
            verifier = ecdsa.VerifyingKey.from_string(
                public_key,
                curve=SECP256k1,
                hashfunc=hashlib.sha256,
            )
            r, s = sigdecode_der(signature, SECP256k1.order)
            if s > SECP256k1.order // 2:
                return False
            verifier.verify_digest(
                signature,
                digest,
                sigdecode=sigdecode_der,
            )
        return True
    except (
        ValueError,
        TypeError,
        struct.error,
        ecdsa.BadSignatureError,
        UnexpectedDER,
    ):
        return False


def _parse_transaction_for_test(transaction: bytes) -> _ParsedTransaction:
    return _parse_sapling_v4(transaction)


__all__ = [
    "SignedTransparentTransaction",
    "TransparentInput",
    "TransparentOutput",
    "TransparentTransactionError",
    "UnsignedTransparentTransaction",
    "create_unsigned_transaction",
    "sign_transaction",
    "verify_transaction_signatures",
    "zip243_signature_hash",
]
