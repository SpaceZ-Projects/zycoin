"""Sapling note nullifier derivation for validated note commitments."""

from dataclasses import dataclass, field
from functools import lru_cache
from hashlib import blake2s

from .derivation import (
    ExtendedFullViewingKey,
    ExtendedSpendingKey,
    SCALAR_MODULUS,
    _prf_expand,
    _to_scalar,
)
from .jubjub import FIELD_MODULUS, IDENTITY, Point, find_group_hash, group_hash
from .note_decryption import (
    SaplingDecryptedNote,
    _note_commitment_point,
    normalize_viewing_key,
)

SAPLING_MERKLE_DEPTH = 32
_SAPLING_POSITION_LIMIT = 1 << SAPLING_MERKLE_DEPTH


class SaplingNullifierError(ValueError):
    """Raised when a note or key is invalid for Sapling nullifier derivation."""


@dataclass(frozen=True)
class SaplingNote:
    """A note whose complete commitment inputs have been independently checked."""

    note_commitment: bytes
    diversifier_base: bytes
    transmission_key: bytes
    value: int
    commitment_randomness: int
    zip212_version: int
    _commitment_point: Point = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.note_commitment, bytes) or len(self.note_commitment) != 32:
            raise SaplingNullifierError(
                "note commitment must be exactly 32 bytes"
            )
        commitment_u = int.from_bytes(self.note_commitment, "little")
        if commitment_u >= FIELD_MODULUS:
            raise SaplingNullifierError("note commitment is non-canonical")
        points = []
        for value, name in (
            (self.diversifier_base, "diversifier base"),
            (self.transmission_key, "transmission key"),
        ):
            if not isinstance(value, bytes) or len(value) != 32:
                raise SaplingNullifierError(f"{name} must be exactly 32 bytes")
            try:
                point = Point.from_bytes(value, check_subgroup=True)
            except ValueError as exc:
                raise SaplingNullifierError(f"{name} is not a valid Sapling point") from exc
            if point == IDENTITY:
                raise SaplingNullifierError(f"{name} cannot be the identity")
            points.append(point)
        if (
            isinstance(self.value, bool)
            or not isinstance(self.value, int)
            or not 0 <= self.value < (1 << 64)
        ):
            raise SaplingNullifierError("note value must be an unsigned 64-bit integer")
        if (
            isinstance(self.commitment_randomness, bool)
            or not isinstance(self.commitment_randomness, int)
            or not 0 <= self.commitment_randomness < SCALAR_MODULUS
        ):
            raise SaplingNullifierError(
                "note commitment randomness must be a canonical Sapling scalar"
            )
        if (
            isinstance(self.zip212_version, bool)
            or not isinstance(self.zip212_version, int)
            or self.zip212_version not in (1, 2)
        ):
            raise SaplingNullifierError("ZIP-212 note version must be 1 or 2")

        commitment_point = _note_commitment_point(
            self.commitment_randomness,
            points[0],
            points[1],
            self.value,
        )
        if commitment_point.u != commitment_u:
            raise SaplingNullifierError(
                "note fields do not match the supplied note commitment"
            )
        object.__setattr__(self, "_commitment_point", commitment_point)

    @classmethod
    def from_decrypted(cls, note, viewing_key, network):
        """Create a validated note from commitment-checked trial decryption."""
        if not isinstance(note, SaplingDecryptedNote):
            raise SaplingNullifierError(
                "note must be a SaplingDecryptedNote returned by the decryptor"
            )
        if (
            not isinstance(note.plaintext_prefix, bytes)
            or len(note.plaintext_prefix) != 52
        ):
            raise SaplingNullifierError("decrypted Sapling plaintext is malformed")
        if (
            isinstance(note.zip212_version, bool)
            or not isinstance(note.zip212_version, int)
            or note.zip212_version not in (1, 2)
            or isinstance(note.value, bool)
            or not isinstance(note.value, int)
            or not 0 <= note.value < (1 << 64)
            or note.plaintext_prefix[0] != note.zip212_version
            or note.plaintext_prefix[1:12] != note.diversifier
            or note.plaintext_prefix[12:20]
            != note.value.to_bytes(8, "little", signed=False)
        ):
            raise SaplingNullifierError(
                "decrypted note fields do not match the plaintext"
            )
        ivk = normalize_viewing_key(viewing_key, network)
        diversifier_base = group_hash(b"Zcash_gd", note.diversifier)
        if diversifier_base is None:
            raise SaplingNullifierError(
                "decrypted note contains an invalid Sapling diversifier"
            )
        transmission_key = diversifier_base.multiply(ivk)
        randomness = note.plaintext_prefix[20:52]
        if note.zip212_version == 1:
            commitment_randomness = int.from_bytes(randomness, "little")
        else:
            commitment_randomness = _to_scalar(_prf_expand(randomness, b"\x04"))
        if commitment_randomness >= SCALAR_MODULUS:
            raise SaplingNullifierError(
                "decrypted note commitment randomness is non-canonical"
            )
        try:
            return cls(
                note_commitment=note.note_commitment,
                diversifier_base=diversifier_base.encode(),
                transmission_key=transmission_key.encode(),
                value=note.value,
                commitment_randomness=commitment_randomness,
                zip212_version=note.zip212_version,
            )
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, SaplingNullifierError):
                raise
            raise SaplingNullifierError(
                "decrypted note does not form a valid Sapling note"
            ) from exc


@lru_cache(maxsize=1)
def _note_position_base():
    return find_group_hash(b"Zcash_J_", b"")


def nullifier_deriving_key(key):
    """Return the canonical 32-byte Sapling nk point from an extended key."""
    if isinstance(key, (ExtendedSpendingKey, ExtendedFullViewingKey)):
        encoded = key.nk
    elif isinstance(key, bytes):
        encoded = key
    else:
        raise SaplingNullifierError(
            "nullifier key must be an extended Sapling spending/viewing key or 32 bytes"
        )
    if not isinstance(encoded, bytes) or len(encoded) != 32:
        raise SaplingNullifierError(
            "nullifier-deriving key must be exactly 32 bytes"
        )
    try:
        point = Point.from_bytes(encoded, check_subgroup=True)
    except ValueError as exc:
        raise SaplingNullifierError(
            "nullifier-deriving key is not a valid Sapling point"
        ) from exc
    if point == IDENTITY:
        raise SaplingNullifierError(
            "nullifier-deriving key cannot be the identity"
        )
    return point.encode()


def derive_sapling_nullifier(nk, note, position):
    """Derive a Sapling nullifier from an nk point, validated note, and tree position."""
    if not isinstance(note, SaplingNote):
        raise SaplingNullifierError("note must be a validated SaplingNote")
    if (
        isinstance(position, bool)
        or not isinstance(position, int)
        or not 0 <= position < _SAPLING_POSITION_LIMIT
    ):
        raise SaplingNullifierError(
            "Sapling note position must be an unsigned 32-bit integer"
        )
    encoded_nk = nullifier_deriving_key(nk)
    rho = note._commitment_point + _note_position_base().multiply(position)
    return blake2s(
        encoded_nk + rho.encode(),
        digest_size=32,
        person=b"Zcash_nf",
    ).digest()


__all__ = [
    "SAPLING_MERKLE_DEPTH",
    "SaplingNote",
    "SaplingNullifierError",
    "derive_sapling_nullifier",
    "nullifier_deriving_key",
]
