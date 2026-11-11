"""Pure-Python R1CS assembly for the pinned Sapling Spend relations.

This module assembles constraints only. It does not create Groth16 proofs or
enable transaction spending.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import blake2s

from .blake2s_gadget import (
    CircuitBit,
    bits_to_bytes_le,
    constrain_sapling_ivk,
    constrain_sapling_nullifier_hash,
)
from .bls12_381 import SCALAR_MODULUS as CIRCUIT_FIELD_MODULUS
from .jubjub import SCALAR_MODULUS, Point, group_hash
from .r1cs import R1CS, LinearCombination, R1CSError, Variable
from .sapling_gadgets import (
    CircuitPoint,
    MerklePathResult,
    MerklePathWitness,
    NoteCommitmentWitness,
    SaplingNullifierMultipackingWitness,
    SaplingNullifierRhoWitness,
    SaplingRandomizedAuthorizationKeyWitness,
    SaplingValueCommitmentWitness,
    allocate_jubjub_point,
    constrain_fixed_base_jubjub_mul,
    constrain_jubjub_not_small_order,
    constrain_jubjub_point,
    constrain_jubjub_repr,
    constrain_jubjub_scalar_mul,
    constrain_merkle_authentication_path,
    constrain_note_commitment,
    constrain_sapling_nullifier_multipacking,
    constrain_sapling_nullifier_rho,
    constrain_sapling_randomized_authorization_key,
    constrain_sapling_value_commitment,
    make_fixed_base_jubjub_witness,
    make_jubjub_scalar_mul_witness,
    make_merkle_path_witness,
    make_note_commitment_witness,
    make_sapling_nullifier_multipacking_witness,
    make_sapling_nullifier_rho_witness,
    make_sapling_randomized_authorization_key_witness,
    make_sapling_value_commitment_witness,
    sapling_fixed_base_generator,
)

SPEND_PUBLIC_INPUT_ORDER = (
    "rk.u",
    "rk.v",
    "cv.u",
    "cv.v",
    "anchor",
    "nullifier_chunk_0",
    "nullifier_chunk_1",
)
_SPEND_INPUT_COUNT = len(SPEND_PUBLIC_INPUT_ORDER)
_SCALAR_BITS = SCALAR_MODULUS.bit_length()


@dataclass(frozen=True)
class SaplingSpendWitness:
    """Host-side Spend witness fields required by the pinned circuit."""

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
class SaplingSpendAssembly:
    """Allocated variables and relation counts for one assembled Spend."""

    public_inputs: tuple[Variable, ...]
    authorization_key: CircuitPoint
    authorization_randomizer_bits: tuple[Variable, ...]
    nsk_bits: tuple[Variable, ...]
    nullifier_key: CircuitPoint
    ak_repr_bits: tuple[Variable, ...]
    nk_repr_bits: tuple[Variable, ...]
    ivk_bits: tuple[CircuitBit, ...]
    diversifier_base: CircuitPoint
    transmission_key: CircuitPoint
    transmission_key_repr_bits: tuple[Variable, ...]
    value: LinearCombination
    value_bits: tuple[Variable, ...]
    value_commitment_randomness_bits: tuple[Variable, ...]
    commitment_randomness_bits: tuple[Variable, ...]
    note_commitment: CircuitPoint
    merkle_path: MerklePathResult
    rho: CircuitPoint
    rho_repr_bits: tuple[Variable, ...]
    nullifier_bits: tuple[CircuitBit, ...]
    relation_constraint_counts: tuple[tuple[str, int], ...]

    @property
    def constraint_count(self) -> int:
        return sum(count for _, count in self.relation_constraint_counts)


@dataclass(frozen=True)
class _PreparedSpendWitness:
    value_commitment: SaplingValueCommitmentWitness
    randomized_key: SaplingRandomizedAuthorizationKeyWitness
    note_commitment: NoteCommitmentWitness
    merkle_path: MerklePathWitness
    rho: SaplingNullifierRhoWitness
    nullifier_packing: SaplingNullifierMultipackingWitness


def _bits_le(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> index) & 1 for index in range(width))


def _prepare_witness(witness: SaplingSpendWitness) -> _PreparedSpendWitness:
    if not isinstance(witness, SaplingSpendWitness):
        raise TypeError("witness must be a SaplingSpendWitness")
    if type(witness.value) is not int or not 0 <= witness.value < 1 << 64:
        raise R1CSError("Sapling Spend value must be an unsigned 64-bit integer")
    for name in ("rcv", "nsk", "rcm", "ar"):
        value = getattr(witness, name)
        if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
            raise R1CSError(f"Sapling Spend {name} is outside jubjub::Fr")
    if type(witness.ivk) is not int or not 0 <= witness.ivk < 1 << 251:
        raise R1CSError("Sapling Spend ivk must be a 251-bit value")
    if not isinstance(witness.diversifier, bytes) or len(witness.diversifier) != 11:
        raise R1CSError("Sapling Spend diversifier must contain exactly 11 bytes")
    if not isinstance(witness.authentication_path, tuple) or len(
        witness.authentication_path
    ) != 32:
        raise R1CSError("Sapling Spend authentication path must contain 32 entries")
    for sibling, direction in witness.authentication_path:
        if type(sibling) is not int or not 0 <= sibling < CIRCUIT_FIELD_MODULUS:
            raise R1CSError("Sapling Spend sibling is not a canonical field element")
        if type(direction) is not bool:
            raise R1CSError("Sapling Spend path direction must be a Boolean")
    if type(witness.position) is not int or not 0 <= witness.position < 1 << 32:
        raise R1CSError("Sapling Spend position must be an unsigned 32-bit integer")
    derived_position = sum(
        int(direction) << level
        for level, (_, direction) in enumerate(witness.authentication_path)
    )
    if witness.position != derived_position:
        raise R1CSError("Spend position does not match authentication-path directions")
    if type(witness.anchor) is not int or not 0 <= witness.anchor < CIRCUIT_FIELD_MODULUS:
        raise R1CSError("Sapling Spend anchor is not a canonical field element")
    if not isinstance(witness.nullifier, bytes) or len(witness.nullifier) != 32:
        raise R1CSError("Sapling Spend nullifier must contain exactly 32 bytes")
    if (
        not isinstance(witness.public_inputs, tuple)
        or len(witness.public_inputs) != _SPEND_INPUT_COUNT
        or any(
            type(value) is not int or not 0 <= value < CIRCUIT_FIELD_MODULUS
            for value in witness.public_inputs
        )
    ):
        raise R1CSError("Sapling Spend must provide seven canonical public inputs")

    for name in (
        "ak",
        "nk",
        "diversifier_base",
        "transmission_key",
        "note_commitment",
        "randomized_key",
        "value_commitment",
    ):
        if not isinstance(getattr(witness, name), Point):
            raise R1CSError(f"Sapling Spend {name} must be a Jubjub point")

    randomized_key = make_sapling_randomized_authorization_key_witness(
        witness.ak, witness.ar
    )
    expected_nk = sapling_fixed_base_generator("proof_generation_key").multiply(
        witness.nsk
    )
    if witness.nk != expected_nk:
        raise R1CSError("Sapling Spend nk does not match nsk")
    ivk_digest = blake2s(
        _pack_point_repr(witness.ak) + _pack_point_repr(witness.nk),
        digest_size=32,
        person=b"Zcashivk",
    ).digest()
    expected_ivk = int.from_bytes(ivk_digest, "little") & ((1 << 251) - 1)
    if witness.ivk != expected_ivk:
        raise R1CSError("Sapling Spend ivk does not match ak and nk")

    expected_g_d = group_hash(b"Zcash_gd", witness.diversifier)
    if expected_g_d is None or witness.diversifier_base != expected_g_d:
        raise R1CSError("Sapling Spend diversifier base does not match diversifier")
    expected_pk_d = expected_g_d.multiply(witness.ivk)
    if witness.transmission_key != expected_pk_d:
        raise R1CSError("Sapling Spend transmission key does not match g_d and ivk")

    value_commitment = make_sapling_value_commitment_witness(
        witness.value, witness.rcv
    )
    if witness.value_commitment != value_commitment.commitment:
        raise R1CSError("Sapling Spend value commitment does not match its opening")
    if witness.randomized_key != randomized_key.randomized_key:
        raise R1CSError("Sapling Spend randomized key does not match ak and ar")
    note_commitment = make_note_commitment_witness(
        witness.value,
        witness.diversifier_base,
        witness.transmission_key,
        witness.rcm,
    )
    if witness.note_commitment != note_commitment.commitment:
        raise R1CSError("Sapling Spend note commitment does not match its opening")

    siblings = tuple(sibling for sibling, _ in witness.authentication_path)
    merkle_path = make_merkle_path_witness(
        note_commitment.commitment.u,
        siblings,
        witness.position,
    )
    computed_anchor = merkle_path.pedersen_hashes[-1].result.u
    if witness.value != 0 and witness.anchor != computed_anchor:
        raise R1CSError("nonzero Sapling Spend value requires the computed anchor")

    rho = make_sapling_nullifier_rho_witness(
        note_commitment.commitment, witness.position
    )
    nullifier_packing = make_sapling_nullifier_multipacking_witness(
        witness.nullifier
    )
    expected_public_inputs = (
        witness.randomized_key.u,
        witness.randomized_key.v,
        witness.value_commitment.u,
        witness.value_commitment.v,
        witness.anchor,
        *nullifier_packing.packed_values,
    )
    if witness.public_inputs != expected_public_inputs:
        raise R1CSError("Sapling Spend public inputs do not match witness fields")
    return _PreparedSpendWitness(
        value_commitment,
        randomized_key,
        note_commitment,
        merkle_path,
        rho,
        nullifier_packing,
    )


def _pack_point_repr(point: Point) -> bytes:
    return point.encode()


def constrain_sapling_spend(
    system: R1CS,
    witness: SaplingSpendWitness,
    label: str = "Sapling Spend",
) -> SaplingSpendAssembly:
    """Assemble all pinned Spend relations and bind seven public inputs.

    Before allocating any variables, host admission requires canonical Jubjub
    scalar inputs, a prime-subgroup non-identity `ak`, and a valid diversifier
    whose group hash equals the supplied `g_d`. These are typed-input/address
    invariants of the pinned host API; not all are proven by the R1CS itself.
    Bellman's implicit ``ONE`` is represented by R1CS variable zero, not an
    application input. This builder allocates all public inputs first because
    :class:`R1CS` requires that ordering; the pinned Bellman synthesizer
    calls ``inputize`` between auxiliary allocations. Bellman tracks input and
    auxiliary indices separately, so that temporal interleaving does not by
    itself change the public-input column identities.
    """
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(witness, SaplingSpendWitness):
        raise TypeError("witness must be a SaplingSpendWitness")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if (
        system.public_input_count != 0
        or len(system.variables) != 1
        or system.constraint_count != 0
    ):
        raise R1CSError("Sapling Spend synthesis requires a fresh R1CS")
    prepared = _prepare_witness(witness)

    public_inputs = tuple(
        system.alloc_public(f"{label} public {name}", value)
        for name, value in zip(SPEND_PUBLIC_INPUT_ORDER, witness.public_inputs)
    )
    rk_public = public_inputs[:2]
    cv_public = public_inputs[2:4]
    anchor_public = public_inputs[4]
    nullifier_public = public_inputs[5:7]
    counts: list[tuple[str, int]] = []

    start = system.constraint_count
    authorization_key = allocate_jubjub_point(
        system, f"{label} ak", witness.ak
    )
    authorization_randomizer_bits = tuple(
        system.alloc_private(f"{label} ar bit[{index}]", bit)
        for index, bit in enumerate(prepared.randomized_key.ar_bits)
    )
    constrain_sapling_randomized_authorization_key(
        system,
        authorization_key,
        authorization_randomizer_bits,
        (rk_public[0], rk_public[1]),
        prepared.randomized_key,
        f"{label} randomized authorization key",
    )
    counts.append(("ak and randomized authorization key", system.constraint_count - start))

    start = system.constraint_count
    nsk_bits = tuple(
        system.alloc_private(f"{label} nsk bit[{index}]", bit)
        for index, bit in enumerate(_bits_le(witness.nsk, _SCALAR_BITS))
    )
    nk_witness = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("proof_generation_key"),
        _bits_le(witness.nsk, _SCALAR_BITS),
    )
    nullifier_key = constrain_fixed_base_jubjub_mul(
        system,
        sapling_fixed_base_generator("proof_generation_key"),
        nsk_bits,
        nk_witness,
        f"{label} nk multiplication",
        enforce_scalar_range=False,
    )
    ak_repr_bits = constrain_jubjub_repr(
        system, authorization_key, f"{label} ak representation"
    )
    nk_repr_bits = constrain_jubjub_repr(
        system, nullifier_key, f"{label} nk representation"
    )
    ivk_bits = constrain_sapling_ivk(
        system,
        ak_repr_bits,
        nk_repr_bits,
        f"{label} ivk",
        input_bits_preconstrained=True,
        materialize_output=False,
    )
    counts.append(("nsk, nk, point representations, and ivk", system.constraint_count - start))

    start = system.constraint_count
    diversifier_base = allocate_jubjub_point(
        system, f"{label} g_d", witness.diversifier_base
    )
    constrain_jubjub_point(
        system, diversifier_base, f"{label} g_d curve"
    )
    constrain_jubjub_not_small_order(
        system, diversifier_base, f"{label} g_d"
    )
    ivk_scalar_bits = tuple(ivk_bits)
    pk_d_witness = make_jubjub_scalar_mul_witness(
        witness.diversifier_base,
        _bits_le(witness.ivk, len(ivk_scalar_bits)),
    )
    transmission_key = constrain_jubjub_scalar_mul(
        system,
        diversifier_base,
        ivk_scalar_bits,
        pk_d_witness,
        f"{label} pk_d multiplication",
        bits_preconstrained=True,
    )
    transmission_key_repr_bits = constrain_jubjub_repr(
        system, transmission_key, f"{label} pk_d representation"
    )
    counts.append(("g_d and pk_d", system.constraint_count - start))

    start = system.constraint_count
    value_bits = tuple(
        system.alloc_private(f"{label} value bit[{index}]", bit)
        for index, bit in enumerate(prepared.value_commitment.value_bits)
    )
    value_randomness_bits = tuple(
        system.alloc_private(f"{label} rcv bit[{index}]", bit)
        for index, bit in enumerate(prepared.value_commitment.randomness_bits)
    )
    value = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(value_bits))
    )
    constrained_value_commitment = constrain_sapling_value_commitment(
        system,
        value_bits,
        value_randomness_bits,
        (cv_public[0], cv_public[1]),
        prepared.value_commitment,
        f"{label} value commitment",
        enforce_scalar_range=False,
    )
    commitment_randomness_bits = tuple(
        system.alloc_private(
            f"{label} rcm bit[{index}]", bit
        )
        for index, bit in enumerate(prepared.note_commitment.rcm_bits)
    )
    for index, bit in enumerate(commitment_randomness_bits):
        system.boolean(bit, f"{label} rcm bit[{index}]")
    note_commitment = constrain_note_commitment(
        system,
        value,
        diversifier_base,
        transmission_key_repr_bits,
        commitment_randomness_bits,
        prepared.note_commitment,
        label=f"{label} note commitment",
        value_bits=value_bits,
        transmission_key_repr_preconstrained=True,
        randomness_bits_preconstrained=True,
        validate_diversifier_base=False,
        value_bits_preconstrained=True,
        enforce_scalar_range=False,
        pedersen_representation="montgomery",
    )
    if constrained_value_commitment is None:
        raise AssertionError("value commitment gadget returned no point")
    counts.append(("value commitment and note commitment", system.constraint_count - start))

    start = system.constraint_count
    merkle_path = constrain_merkle_authentication_path(
        system,
        note_commitment[0],
        anchor_public,
        prepared.merkle_path,
        f"{label} Merkle path",
        note_value=value,
        pedersen_representation="montgomery",
    )
    counts.append(("Merkle path, position, and conditional anchor", system.constraint_count - start))

    start = system.constraint_count
    rho = constrain_sapling_nullifier_rho(
        system,
        note_commitment,
        merkle_path.position_bits,
        prepared.rho,
        f"{label} rho",
    )
    rho_repr_bits = constrain_jubjub_repr(
        system, rho, f"{label} rho representation"
    )
    nullifier_bits = constrain_sapling_nullifier_hash(
        system,
        nk_repr_bits,
        rho_repr_bits,
        f"{label} nullifier PRF",
        input_bits_preconstrained=True,
        materialize_output=False,
    )
    if bits_to_bytes_le(nullifier_bits, system) != witness.nullifier:
        raise R1CSError("Sapling Spend nullifier does not match constrained PRF")
    constrain_sapling_nullifier_multipacking(
        system,
        nullifier_bits,
        nullifier_public,
        prepared.nullifier_packing,
        f"{label} nullifier multipacking",
        digest_bits_preconstrained=True,
    )
    counts.append(("rho, nullifier PRF, and multipacking", system.constraint_count - start))

    if system.public_input_count != _SPEND_INPUT_COUNT:
        raise R1CSError("Sapling Spend must expose exactly seven public inputs")
    return SaplingSpendAssembly(
        public_inputs=public_inputs,
        authorization_key=authorization_key,
        authorization_randomizer_bits=authorization_randomizer_bits,
        nsk_bits=nsk_bits,
        nullifier_key=nullifier_key,
        ak_repr_bits=tuple(ak_repr_bits),
        nk_repr_bits=tuple(nk_repr_bits),
        ivk_bits=tuple(ivk_bits),
        diversifier_base=diversifier_base,
        transmission_key=transmission_key,
        transmission_key_repr_bits=tuple(transmission_key_repr_bits),
        value=value,
        value_bits=value_bits,
        value_commitment_randomness_bits=value_randomness_bits,
        commitment_randomness_bits=commitment_randomness_bits,
        note_commitment=note_commitment,
        merkle_path=merkle_path,
        rho=rho,
        rho_repr_bits=tuple(rho_repr_bits),
        nullifier_bits=tuple(nullifier_bits),
        relation_constraint_counts=tuple(counts),
    )


__all__ = [
    "SPEND_PUBLIC_INPUT_ORDER",
    "SaplingSpendAssembly",
    "SaplingSpendWitness",
    "constrain_sapling_spend",
]
