"""Independent consistency checks for deterministic Sapling Spend witnesses.

This module deliberately does not import the Spend reference generator. The
checks recompute relations through the separately implemented Sapling note,
tree, and gadget helpers; they do not turn un-published seeded outputs into
independent expected vectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .derivation import _ivk
from .jubjub import (
    FIELD_MODULUS,
    IDENTITY,
    SCALAR_MODULUS,
    Point,
    group_hash,
    proving_key_base,
)
from .note_decryption import _note_commitment_point
from .nullifiers import SaplingNote, derive_sapling_nullifier
from .sapling_gadgets import (
    make_sapling_randomized_authorization_key_witness,
    make_sapling_value_commitment_witness,
)
from .sapling_tree import merkle_hash

SPEND_PUBLIC_INPUT_ORDER = (
    "rk.u",
    "rk.v",
    "cv.u",
    "cv.v",
    "anchor",
    "nullifier_chunk_0",
    "nullifier_chunk_1",
)


class SpendWitness(Protocol):
    value: int
    rcv: int
    ak: Point
    nsk: int
    nk: Point
    ivk: int
    diversifier: bytes
    diversifier_base: Point
    transmission_key: Point
    rcm: int
    note_commitment: Point
    ar: int
    randomized_key: Point
    value_commitment: Point
    authentication_path: tuple[tuple[int, bool], ...]
    position: int
    anchor: int
    nullifier: bytes
    public_inputs: tuple[int, ...]


@dataclass(frozen=True)
class SpendWitnessVerification:
    """Result of recomputing witness relations without the reference generator."""

    checked_fields: tuple[str, ...]
    mismatches: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.mismatches


def _record(
    checked: list[str],
    mismatches: list[str],
    field: str,
    condition: bool,
) -> None:
    checked.append(field)
    if not condition:
        mismatches.append(field)


def verify_spend_reference_witness(
    witness: SpendWitness,
) -> SpendWitnessVerification:
    """Recompute Sapling witness relations and report inconsistent fields.

    A valid result means the witness is internally consistent under these
    independent code paths. Fields sampled by the pinned test still lack
    independent literal outputs, so this is not a full-witness oracle.
    """
    checked: list[str] = []
    mismatches: list[str] = []

    for field in ("value", "rcv", "nsk", "ivk", "rcm", "ar", "position"):
        value = getattr(witness, field)
        if type(value) is not int:
            _record(checked, mismatches, field, False)
    if mismatches:
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))

    _record(checked, mismatches, "value", 0 <= witness.value < (1 << 64))
    for field in ("rcv", "nsk", "rcm", "ar"):
        _record(
            checked,
            mismatches,
            field,
            0 <= getattr(witness, field) < SCALAR_MODULUS,
        )
    _record(
        checked,
        mismatches,
        "ivk",
        0 < witness.ivk < (1 << 251),
    )
    _record(
        checked,
        mismatches,
        "position",
        0 <= witness.position < (1 << 32),
    )
    if any(
        not 0 <= getattr(witness, field) < SCALAR_MODULUS
        for field in ("rcv", "nsk", "rcm", "ar")
    ):
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    _record(
        checked,
        mismatches,
        "ak",
        isinstance(witness.ak, Point)
        and witness.ak.is_on_curve()
        and witness.ak != IDENTITY
        and witness.ak.multiply(8) != IDENTITY
        and witness.ak.is_in_subgroup(),
    )
    if not isinstance(witness.ak, Point):
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    if (
        not witness.ak.is_on_curve()
        or witness.ak == IDENTITY
        or witness.ak.multiply(8) == IDENTITY
        or not witness.ak.is_in_subgroup()
    ):
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))

    expected_nk = proving_key_base().multiply(witness.nsk)
    _record(checked, mismatches, "nk", witness.nk == expected_nk)
    encoded_ak = witness.ak.encode()
    encoded_nk = expected_nk.encode()
    _record(
        checked,
        mismatches,
        "ivk_derivation",
        witness.ivk == _ivk(encoded_ak, encoded_nk),
    )
    _record(
        checked,
        mismatches,
        "diversifier",
        isinstance(witness.diversifier, bytes)
        and len(witness.diversifier) == 11,
    )
    if not isinstance(witness.diversifier, bytes) or len(witness.diversifier) != 11:
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    derived_base = group_hash(b"Zcash_gd", witness.diversifier)
    _record(
        checked,
        mismatches,
        "diversifier_base",
        derived_base is not None and witness.diversifier_base == derived_base,
    )
    if derived_base is None:
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    expected_transmission_key = derived_base.multiply(witness.ivk)
    _record(
        checked,
        mismatches,
        "transmission_key",
        witness.transmission_key == expected_transmission_key,
    )

    if not isinstance(witness.transmission_key, Point):
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    expected_note = _note_commitment_point(
        witness.rcm,
        derived_base,
        expected_transmission_key,
        witness.value,
    )
    _record(
        checked,
        mismatches,
        "note_commitment",
        isinstance(witness.note_commitment, Point)
        and witness.note_commitment == expected_note,
    )
    if not isinstance(witness.note_commitment, Point):
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))

    expected_cv = make_sapling_value_commitment_witness(
        witness.value, witness.rcv
    ).commitment
    _record(
        checked,
        mismatches,
        "value_commitment",
        isinstance(witness.value_commitment, Point)
        and witness.value_commitment == expected_cv,
    )
    expected_rk = make_sapling_randomized_authorization_key_witness(
        witness.ak, witness.ar
    ).randomized_key
    _record(
        checked,
        mismatches,
        "randomized_key",
        isinstance(witness.randomized_key, Point)
        and witness.randomized_key == expected_rk,
    )

    path_valid = (
        isinstance(witness.authentication_path, tuple)
        and len(witness.authentication_path) == 32
        and all(
            isinstance(node, tuple)
            and len(node) == 2
            and type(node[0]) is int
            and 0 <= node[0] < FIELD_MODULUS
            and type(node[1]) is bool
            for node in witness.authentication_path
        )
    )
    _record(checked, mismatches, "authentication_path", path_valid)
    if not path_valid:
        return SpendWitnessVerification(tuple(checked), tuple(mismatches))
    position = 0
    node = expected_note.u.to_bytes(32, "little")
    for depth, (sibling, direction) in enumerate(witness.authentication_path):
        sibling_bytes = sibling.to_bytes(32, "little")
        if direction:
            position |= 1 << depth
            left, right = sibling_bytes, node
        else:
            left, right = node, sibling_bytes
        node = merkle_hash(depth, left, right)
    computed_anchor = int.from_bytes(node, "little")
    _record(checked, mismatches, "position", witness.position == position)
    _record(checked, mismatches, "anchor", witness.anchor == computed_anchor)

    note = SaplingNote(
        note_commitment=expected_note.u.to_bytes(32, "little"),
        diversifier_base=derived_base.encode(),
        transmission_key=expected_transmission_key.encode(),
        value=witness.value,
        commitment_randomness=witness.rcm,
        zip212_version=1,
    )
    expected_nullifier = derive_sapling_nullifier(
        expected_nk.encode(), note, position
    )
    _record(
        checked,
        mismatches,
        "nullifier",
        witness.nullifier == expected_nullifier,
    )

    chunks = (
        int.from_bytes(expected_nullifier, "little") & ((1 << 254) - 1),
        int.from_bytes(expected_nullifier, "little") >> 254,
    )
    expected_inputs = (
        expected_rk.u,
        expected_rk.v,
        expected_cv.u,
        expected_cv.v,
        computed_anchor,
        *chunks,
    )
    _record(
        checked,
        mismatches,
        "public_inputs",
        isinstance(witness.public_inputs, tuple)
        and len(witness.public_inputs) == len(SPEND_PUBLIC_INPUT_ORDER)
        and witness.public_inputs == expected_inputs,
    )
    return SpendWitnessVerification(tuple(checked), tuple(mismatches))


__all__ = [
    "SPEND_PUBLIC_INPUT_ORDER",
    "SpendWitnessVerification",
    "verify_spend_reference_witness",
]
