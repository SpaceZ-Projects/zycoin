"""Pure-Python Sapling compact-output trial decryption and validation."""

from dataclasses import dataclass, field
from functools import lru_cache
from hashlib import blake2b
from typing import Any, Mapping, Optional

from .coins import CoinNetworkConfig
from .derivation import ExtendedFullViewingKey, _prf_expand, _to_scalar
from .jubjub import (
    FIELD_MODULUS,
    IDENTITY,
    SCALAR_MODULUS,
    Point,
    find_group_hash,
    group_hash,
)
from .serialization import bech32_decode

ZIP212_GRACE_PERIOD_BLOCKS = 32256
_CHACHA_CONSTANTS = b"expand 32-byte k"


class SaplingNoteDecryptionError(ValueError):
    """Raised when a compact Sapling output or viewing key is malformed."""


@dataclass(frozen=True)
class SaplingDecryptedNote:
    txid: Optional[str]
    height: int
    transaction_index: Optional[int]
    output_index: Optional[int]
    value: int
    diversifier: bytes
    note_commitment: bytes
    plaintext_prefix: bytes
    zip212_version: int
    memo: Optional[bytes] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


def _require_network_capability(network):
    if not isinstance(network, CoinNetworkConfig):
        raise TypeError("network must be a loaded coin network config")
    sapling = network.sapling
    if sapling.get("note_decryption_status") != "supported_verified_parameters":
        raise ValueError(
            f"Sapling note decryption is not verified for "
            f"{network.coin_id} {network.network_id}"
        )
    activation = sapling.get("zip212_activation_height")
    if (
        isinstance(activation, bool)
        or not isinstance(activation, int)
        or activation < 0
    ):
        raise ValueError(
            f"ZIP-212 activation height is unavailable for "
            f"{network.coin_id} {network.network_id}"
        )
    grace_period = sapling.get("zip212_grace_period_blocks")
    if (
        isinstance(grace_period, bool)
        or not isinstance(grace_period, int)
        or grace_period < 1
    ):
        raise ValueError(
            f"ZIP-212 grace period is unavailable for "
            f"{network.coin_id} {network.network_id}"
        )
    if sapling.get("activation_height") is None:
        raise ValueError(
            f"Sapling activation height is unavailable for "
            f"{network.coin_id} {network.network_id}"
        )
    return sapling


def normalize_viewing_key(viewing_key, network):
    """Return a canonical IVK integer from raw or network-encoded IVK/FVK data."""
    _require_network_capability(network)

    def decode_full_viewing_key(data):
        try:
            return ExtendedFullViewingKey.deserialize(data).incoming_viewing_key
        except (TypeError, ValueError) as exc:
            raise SaplingNoteDecryptionError(
                "invalid serialized Sapling full viewing key"
            ) from exc

    if isinstance(viewing_key, ExtendedFullViewingKey):
        try:
            ivk = viewing_key.incoming_viewing_key
        except ValueError as exc:
            raise SaplingNoteDecryptionError(
                "invalid Sapling full viewing key"
            ) from exc
    elif isinstance(viewing_key, bool):
        raise SaplingNoteDecryptionError("invalid Sapling incoming viewing key")
    elif isinstance(viewing_key, int):
        ivk = viewing_key
    elif isinstance(viewing_key, bytes):
        if len(viewing_key) == 32:
            ivk = int.from_bytes(viewing_key, "little")
        elif len(viewing_key) == 169:
            ivk = decode_full_viewing_key(viewing_key)
        else:
            raise SaplingNoteDecryptionError(
                "raw Sapling viewing keys must be 32-byte IVKs or 169-byte FVKs"
            )
    elif isinstance(viewing_key, str):
        try:
            hrp, data = bech32_decode(viewing_key)
        except ValueError as exc:
            raise SaplingNoteDecryptionError(
                "invalid encoded Sapling viewing key"
            ) from exc
        sapling = network.sapling
        if hrp == sapling.get("incoming_viewing_key_hrp"):
            if len(data) != 32:
                raise SaplingNoteDecryptionError(
                    "encoded Sapling IVKs must contain exactly 32 bytes"
                )
            ivk = int.from_bytes(data, "little")
        elif hrp == sapling.get("full_viewing_key_hrp"):
            ivk = decode_full_viewing_key(data)
        else:
            raise SaplingNoteDecryptionError(
                "Sapling viewing key belongs to another network or has an unsupported prefix"
            )
    else:
        raise SaplingNoteDecryptionError(
            "viewing_key must be an IVK or full viewing key"
        )

    if isinstance(ivk, bool) or not isinstance(ivk, int) or not 0 < ivk < (1 << 251):
        raise SaplingNoteDecryptionError("invalid Sapling incoming viewing key")
    return ivk


def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xFFFFFFFF
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xFFFFFFFF
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xFFFFFFFF


def _chacha20_block(key, counter, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 requires a 32-byte key and 12-byte nonce")
    initial = [
        int.from_bytes(_CHACHA_CONSTANTS[index:index + 4], "little")
        for index in range(0, 16, 4)
    ]
    initial.extend(
        int.from_bytes(key[index:index + 4], "little")
        for index in range(0, 32, 4)
    )
    initial.append(counter)
    initial.extend(
        int.from_bytes(nonce[index:index + 4], "little")
        for index in range(0, 12, 4)
    )
    working = initial[:]
    for _ in range(10):
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)
    return b"".join(
        ((working[index] + initial[index]) & 0xFFFFFFFF).to_bytes(4, "little")
        for index in range(16)
    )


def _chacha20_xor(key, data):
    output = bytearray(len(data))
    for block_number, offset in enumerate(range(0, len(data), 64), start=1):
        if block_number > 0xFFFFFFFF:
            raise ValueError("ChaCha20 counter overflow")
        keystream = _chacha20_block(key, block_number, b"\x00" * 12)
        chunk = data[offset:offset + 64]
        output[offset:offset + len(chunk)] = bytes(
            left ^ right for left, right in zip(chunk, keystream)
        )
    return bytes(output)


@lru_cache(maxsize=32)
def _pedersen_segment_base(index):
    return find_group_hash(
        b"Zcash_PH",
        (index - 1).to_bytes(4, "little"),
    )


@lru_cache(maxsize=1)
def _pedersen_randomness_base():
    return find_group_hash(b"Zcash_PH", b"r")


def _little_endian_bits(data):
    return [
        (byte >> bit) & 1
        for byte in data
        for bit in range(8)
    ]


def _pedersen_hash_to_point(bits):
    padded = bits + [0] * ((-len(bits)) % 3)
    segment_size = 3 * 63
    result = IDENTITY
    for segment_index, start in enumerate(range(0, len(padded), segment_size), 1):
        segment_bits = padded[start:start + segment_size]
        encoded = 0
        for chunk_index in range(0, len(segment_bits), 3):
            s0, s1, s2 = segment_bits[chunk_index:chunk_index + 3]
            chunk_value = (1 - 2 * s2) * (1 + s0 + 2 * s1)
            encoded += chunk_value << (4 * (chunk_index // 3))
        result = result + _pedersen_segment_base(segment_index).multiply(encoded)
    return result


def _note_commitment_point(rcm, diversifier_base, transmission_key, value):
    bits = (
        [1] * 6
        + [(value >> bit) & 1 for bit in range(64)]
        + _little_endian_bits(diversifier_base.encode())
        + _little_endian_bits(transmission_key.encode())
    )
    point = _pedersen_hash_to_point(bits)
    return point + _pedersen_randomness_base().multiply(rcm)


def _note_commitment_u(rcm, diversifier_base, transmission_key, value):
    return _note_commitment_point(
        rcm,
        diversifier_base,
        transmission_key,
        value,
    ).u.to_bytes(32, "little")


@dataclass(frozen=True)
class _CompactOutputFields:
    cmu: bytes
    ephemeral_key: bytes
    ciphertext_prefix: bytes
    txid: Optional[str]
    height: int
    transaction_index: Optional[int]
    output_index: Optional[int]
    metadata: Mapping[str, Any]


def _compact_output_fields(output):
    try:
        if hasattr(output, "ephemeral_key"):
            return _CompactOutputFields(
                cmu=bytes(output.cmu),
                ephemeral_key=bytes(output.ephemeral_key),
                ciphertext_prefix=bytes(output.ciphertext_prefix),
                txid=output.txid,
                height=output.height,
                transaction_index=output.transaction_index,
                output_index=output.output_index,
                metadata=output.metadata,
            )
        return _CompactOutputFields(
            cmu=bytes(output.cmu),
            ephemeral_key=bytes(output.ephemeralKey),
            ciphertext_prefix=bytes(output.ciphertext),
            txid=None,
            height=0,
            transaction_index=None,
            output_index=None,
            metadata={"compact_output": output.SerializeToString()},
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise SaplingNoteDecryptionError(
            "malformed compact Sapling output"
        ) from exc


def decrypt_sapling_compact_output(
    compact_output,
    viewing_key,
    network,
    *,
    height=None,
    is_coinbase=False,
):
    """Trial-decrypt and commitment-check a compact Sapling output.

    Returns ``None`` for a non-matching key or invalid candidate plaintext.
    Compact outputs omit the AEAD tag and memo, so successful results are
    validated by ZIP-212 rules and the note commitment, not AEAD authentication.
    """
    sapling = _require_network_capability(network)
    ivk = normalize_viewing_key(viewing_key, network)
    fields = _compact_output_fields(compact_output)
    block_height = fields.height if height is None else height
    if (
        isinstance(block_height, bool)
        or not isinstance(block_height, int)
        or block_height < sapling["activation_height"]
    ):
        raise SaplingNoteDecryptionError(
            "note height must be an integer at or above Sapling activation"
        )
    if not isinstance(is_coinbase, bool):
        raise SaplingNoteDecryptionError("is_coinbase must be a boolean")
    if len(fields.cmu) != 32 or len(fields.ephemeral_key) != 32:
        raise SaplingNoteDecryptionError(
            "compact Sapling cmu and ephemeral key must be 32 bytes"
        )
    if len(fields.ciphertext_prefix) != 52:
        raise SaplingNoteDecryptionError(
            "compact Sapling ciphertext prefix must be exactly 52 bytes"
        )

    cmu_value = int.from_bytes(fields.cmu, "little")
    if cmu_value >= FIELD_MODULUS:
        raise SaplingNoteDecryptionError("non-canonical Sapling note commitment")
    try:
        ephemeral_key = Point.from_bytes(
            fields.ephemeral_key,
            check_subgroup=True,
        )
    except (TypeError, ValueError) as exc:
        raise SaplingNoteDecryptionError(
            "invalid Sapling ephemeral public key"
        ) from exc
    if ephemeral_key == IDENTITY:
        raise SaplingNoteDecryptionError("Sapling ephemeral key cannot be identity")

    shared_secret = ephemeral_key.multiply(ivk * 8).encode()
    key = blake2b(
        shared_secret + fields.ephemeral_key,
        digest_size=32,
        person=b"Zcash_SaplingKDF",
    ).digest()
    plaintext = _chacha20_xor(key, fields.ciphertext_prefix)
    version = plaintext[0]
    activation_height = sapling["zip212_activation_height"]
    grace_period_blocks = sapling["zip212_grace_period_blocks"]
    if block_height < activation_height:
        allowed_versions = {1}
    elif block_height < activation_height + grace_period_blocks:
        allowed_versions = {1, 2}
        if is_coinbase or fields.transaction_index == 0:
            allowed_versions = {2}
    else:
        allowed_versions = {2}
    if version not in allowed_versions:
        return None

    diversifier = plaintext[1:12]
    value = int.from_bytes(plaintext[12:20], "little")
    randomness = plaintext[20:52]
    if version == 1:
        rcm = int.from_bytes(randomness, "little")
        if rcm >= SCALAR_MODULUS:
            return None
    else:
        rcm = _to_scalar(_prf_expand(randomness, b"\x04"))
        esk = _to_scalar(_prf_expand(randomness, b"\x05"))
        if esk == 0:
            return None

    diversifier_base = group_hash(b"Zcash_gd", diversifier)
    if diversifier_base is None:
        return None
    transmission_key = diversifier_base.multiply(ivk)
    if transmission_key == IDENTITY:
        return None
    if version == 2 and diversifier_base.multiply(esk) != ephemeral_key:
        return None

    try:
        commitment = _note_commitment_u(
            rcm,
            diversifier_base,
            transmission_key,
            value,
        )
    except (ValueError, TypeError) as exc:
        raise SaplingNoteDecryptionError(
            "could not validate Sapling note commitment"
        ) from exc
    if commitment != fields.cmu:
        return None

    return SaplingDecryptedNote(
        txid=fields.txid,
        height=block_height,
        transaction_index=fields.transaction_index,
        output_index=fields.output_index,
        value=value,
        diversifier=diversifier,
        note_commitment=fields.cmu,
        plaintext_prefix=plaintext,
        zip212_version=version,
        metadata={
            **fields.metadata,
            "ephemeral_key": fields.ephemeral_key,
            "ciphertext_prefix": fields.ciphertext_prefix,
            "aead_authenticated": False,
            "memo_available": False,
        },
    )
