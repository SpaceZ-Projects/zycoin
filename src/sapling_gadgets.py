"""Reusable Sapling R1CS gadgets based on pinned sapling-crypto semantics."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, cast, overload

from .bellman_synthesis import RecorderVariable
from .blake2s_gadget import (
    CircuitBit as BlakeCircuitBit,
)
from .blake2s_gadget import (
    _NegatedBit,
)
from .blake2s_gadget import (
    _read_bit as _read_blake_bit,
)
from .bls12_381 import SCALAR_MODULUS as CIRCUIT_FIELD_MODULUS
from .jubjub import (
    CURVE_D,
    FIELD_MODULUS,
    IDENTITY,
    SCALAR_MODULUS,
    Point,
    find_group_hash,
    group_hash,
)
from .r1cs import R1CS, LinearCombination, R1CSError, Variable
from .synthesis import (
    FreshSynthesisBackend,
    LinearCombinationLike,
    SynthesisBackend,
    VariableLike,
)

CircuitBit = BlakeCircuitBit
CircuitPoint = tuple[Variable, Variable]

_PEDERSEN_CHUNKS_PER_GENERATOR = 63
_PEDERSEN_GENERATOR_COUNT = 6
_PEDERSEN_PERSONALIZATION = b"Zcash_PH"
_PEDERSEN_MONTGOMERY_A = 40962
_PEDERSEN_MONTGOMERY_SCALE_LIMBS = (
    0x8F4535F7CF82B8D9,
    0xCE4069703DA88ABD,
    0x31DE341E77D764E5,
    0x2762DE61E862645E,
)
_PEDERSEN_MONTGOMERY_SCALE = sum(
    limb << (64 * index)
    for index, limb in enumerate(_PEDERSEN_MONTGOMERY_SCALE_LIMBS)
) % CIRCUIT_FIELD_MODULUS
_FIXED_BASE_WINDOW_BITS = 3
_FIXED_BASE_WINDOW_COUNT = 84
_JUBJUB_SCALAR_BITS = SCALAR_MODULUS.bit_length()
_NULLIFIER_BITS = 256
_MULTIPACK_CHUNK_BITS = CIRCUIT_FIELD_MODULUS.bit_length() - 1
_NULLIFIER_PACK_CHUNK_WIDTHS = (
    _MULTIPACK_CHUNK_BITS,
    _NULLIFIER_BITS - _MULTIPACK_CHUNK_BITS,
)
_NULLIFIER_PUBLIC_INPUT_INDICES = (6, 7)
PedersenRepresentation = Literal["edwards", "montgomery"]


@dataclass(frozen=True)
class _PedersenNum:
    expression: LinearCombinationLike
    value: int
    variable: VariableLike | None = None

    def lc(self) -> LinearCombinationLike:
        return self.expression


@dataclass(frozen=True)
class PedersenWitness:
    bit_values: tuple[int, ...]
    selected_points: tuple[Point, ...]
    segment_accumulators: tuple[tuple[Point, ...], ...]
    combined_results: tuple[Point, ...]
    result: Point


@dataclass(frozen=True)
class JubjubScalarMulWitness:
    bit_values: tuple[int, ...]
    bases: tuple[Point, ...]
    selected_points: tuple[Point, ...]
    accumulators: tuple[Point, ...]
    result: Point


@dataclass(frozen=True)
class FixedBaseJubjubWitness:
    bit_values: tuple[int, ...]
    selected_points: tuple[Point, ...]
    accumulators: tuple[Point, ...]
    result: Point


@dataclass(frozen=True)
class SaplingValueCommitmentWitness:
    value: int
    randomness: int
    value_bits: tuple[int, ...]
    randomness_bits: tuple[int, ...]
    value_mul: FixedBaseJubjubWitness
    randomness_mul: FixedBaseJubjubWitness
    commitment: Point


@dataclass(frozen=True)
class SaplingEphemeralKeyWitness:
    esk: int
    esk_bits: tuple[int, ...]
    multiplication: JubjubScalarMulWitness
    ephemeral_key: Point


@dataclass(frozen=True)
class SaplingNullifierMultipackingWitness:
    digest_bits: tuple[int, ...]
    packed_values: tuple[int, int]


@dataclass(frozen=True)
class SaplingNullifierRhoWitness:
    position: int
    position_bits: tuple[int, ...]
    position_multiplication: FixedBaseJubjubWitness
    rho: Point


@dataclass(frozen=True)
class SaplingRandomizedAuthorizationKeyWitness:
    ar: int
    ar_bits: tuple[int, ...]
    multiplication: FixedBaseJubjubWitness
    authorization_key: Point
    randomized_key: Point


@dataclass(frozen=True)
class NoteCommitmentWitness:
    value: int
    rcm_bits: tuple[int, ...]
    note_hash: PedersenWitness
    randomness_mul: FixedBaseJubjubWitness
    commitment: Point


@dataclass(frozen=True)
class SaplingOutputWitness:
    value: int
    diversifier: bytes
    diversifier_base: Point
    transmission_key: Point
    value_commitment_randomness: int
    commitment_randomness: int
    esk: int
    value_commitment: SaplingValueCommitmentWitness
    ephemeral_key: SaplingEphemeralKeyWitness
    note_commitment: NoteCommitmentWitness


@dataclass(frozen=True)
class SaplingOutputResult:
    public_inputs: tuple[Variable, ...]
    value_commitment: CircuitPoint
    ephemeral_key: CircuitPoint
    note_commitment: CircuitPoint


@dataclass(frozen=True)
class MerklePathWitness:
    position: int
    siblings: tuple[int, ...]
    pedersen_hashes: tuple[PedersenWitness, ...]


@dataclass(frozen=True)
class MerklePathResult:
    root: Variable
    position_bits: tuple[Variable, ...]
    siblings: tuple[Variable, ...]
    intermediate_roots: tuple[Variable, ...]


@overload
def allocate_jubjub_point(
    system: R1CS, name: str, point: Point | None
) -> CircuitPoint: ...


@overload
def allocate_jubjub_point(
    system: SynthesisBackend,
    name: str,
    point: Point | None,
) -> tuple[VariableLike, VariableLike]: ...


def allocate_jubjub_point(
    system: SynthesisBackend,
    name: str,
    point: Point | None,
) -> tuple[VariableLike, VariableLike]:
    if point is not None and not isinstance(point, Point):
        raise TypeError("point must be a Jubjub Point or None")
    return (
        system.alloc_private(f"{name}.u", None if point is None else point.u),
        system.alloc_private(f"{name}.v", None if point is None else point.v),
    )


def constrain_jubjub_point(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    label: str = "Jubjub point",
    *,
    bellman_factorization: bool = False,
) -> None:
    backend = system.namespace(label)
    _require_point(backend, point)
    u2 = backend.multiply(point[0], point[0], "u squared")
    v2 = backend.multiply(point[1], point[1], "v squared")
    u2v2 = backend.multiply(u2, v2, "coordinate product")
    if bellman_factorization:
        backend.enforce(
            -1 * u2.lc() + v2.lc(),
            1,
            1 + CURVE_D * u2v2.lc(),
            "twisted Edwards equation",
        )
    else:
        backend.enforce_equal(
            -1 * u2.lc() + v2.lc() - 1,
            CURVE_D * u2v2.lc(),
            "twisted Edwards equation",
        )


def constrain_jubjub_select(
    system: SynthesisBackend,
    selector: VariableLike,
    when_true: tuple[VariableLike | int, VariableLike | int],
    when_false: tuple[VariableLike | int, VariableLike | int],
    selected: tuple[VariableLike, VariableLike],
    u_label: str,
    v_label: str,
    *,
    bellman_factorization: bool = False,
) -> None:
    """Constrain a Boolean selector to choose one already represented point.

    The selector must be Boolean-constrained by the caller, and each point
    must have any required curve and canonical-representation constraints.
    """
    system.require_owned(selector)
    _require_point(system, selected)
    expressions: list[tuple[LinearCombinationLike, LinearCombinationLike]] = []
    for branch in (when_true, when_false):
        if not isinstance(branch, tuple) or len(branch) != 2:
            raise TypeError("Jubjub selection branches must be coordinate pairs")
        coordinates = []
        for coordinate in branch:
            if type(coordinate) is int:
                coordinates.append(system.linear_combination((), coordinate))
            else:
                system.require_owned(coordinate)
                coordinates.append(coordinate.lc())
        expressions.append((coordinates[0], coordinates[1]))

    true_u, true_v = expressions[0]
    false_u, false_v = expressions[1]
    if bellman_factorization:
        system.enforce(
            true_u - false_u,
            selector,
            selected[0].lc() - false_u,
            u_label,
        )
        system.enforce(
            true_v,
            selector,
            selector + selected[1].lc() - 1,
            v_label,
        )
    else:
        system.enforce(
            selector,
            true_u - false_u,
            selected[0].lc() - false_u,
            u_label,
        )
        system.enforce(
            selector,
            true_v - false_v,
            selected[1].lc() - false_v,
            v_label,
        )


@overload
def constrain_jubjub_add(
    system: R1CS,
    left: CircuitPoint,
    right: CircuitPoint,
    result: CircuitPoint,
    label: str = "Jubjub addition",
) -> None: ...


@overload
def constrain_jubjub_add(
    system: SynthesisBackend,
    left: tuple[VariableLike, VariableLike],
    right: tuple[VariableLike, VariableLike],
    result: tuple[VariableLike, VariableLike],
    label: str = "Jubjub addition",
) -> None: ...


def constrain_jubjub_add(
    system: SynthesisBackend,
    left: tuple[VariableLike, VariableLike],
    right: tuple[VariableLike, VariableLike],
    result: tuple[VariableLike, VariableLike],
    label: str = "Jubjub addition",
) -> None:
    """Constrain upstream affine addition for already-constrained curve points.

    The caller must constrain both inputs with ``constrain_jubjub_point`` and
    supply points in the affine-addition domain. This incomplete affine
    formula does not establish subgroup membership or handle denominator
    poles outside the intended subgroup domain.
    """
    for point in (left, right, result):
        _require_point(system, point)

    uppercase_u = system.multiply(
        left[0].lc() + left[1],
        right[0].lc() + right[1],
        f"{label} U",
    )
    a = system.multiply(right[1], left[0], f"{label} A")
    b = system.multiply(right[0], left[1], f"{label} B")
    c = system.multiply(CURVE_D * a.lc(), b, f"{label} C")

    system.enforce(
        1 + c.lc(),
        result[0],
        a.lc() + b.lc(),
        f"{label} u division relation",
    )
    system.enforce(
        1 - c.lc(),
        result[1],
        uppercase_u.lc() - a.lc() - b.lc(),
        f"{label} v division relation",
    )


def _constrain_jubjub_add_with_allocated_result(
    system: SynthesisBackend,
    left: tuple[VariableLike, VariableLike],
    right: tuple[VariableLike, VariableLike],
    result_witness: Point,
    allocation_label: str,
    relation_label: str,
) -> tuple[VariableLike, VariableLike]:
    """Allocate addition intermediates before the result, as Bellman does."""
    _require_point(system, left)
    _require_point(system, right)
    if not isinstance(result_witness, Point):
        raise TypeError("result_witness must be a Jubjub Point")
    if result_witness != _point_witness(system, left) + _point_witness(system, right):
        raise R1CSError("Jubjub addition result witness is inconsistent")

    uppercase_u = system.multiply(
        left[0].lc() + left[1],
        right[0].lc() + right[1],
        f"{relation_label} U",
    )
    a = system.multiply(right[1], left[0], f"{relation_label} A")
    b = system.multiply(right[0], left[1], f"{relation_label} B")
    c = system.multiply(CURVE_D * a.lc(), b, f"{relation_label} C")
    result = allocate_jubjub_point(system, allocation_label, result_witness)
    system.enforce(
        1 + c.lc(),
        result[0],
        a.lc() + b.lc(),
        f"{relation_label} u division relation",
    )
    system.enforce(
        1 - c.lc(),
        result[1],
        uppercase_u.lc() - a.lc() - b.lc(),
        f"{relation_label} v division relation",
    )
    return result


def _constrain_jubjub_double_with_allocated_result(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    result_witness: Point,
    allocation_label: str,
    relation_label: str,
) -> tuple[VariableLike, VariableLike]:
    """Allocate doubling intermediates before the result, as Bellman does."""
    _require_point(system, point)
    if not isinstance(result_witness, Point):
        raise TypeError("result_witness must be a Jubjub Point")
    if result_witness != _point_witness(system, point) + _point_witness(
        system, point
    ):
        raise R1CSError("Jubjub doubling result witness is inconsistent")

    t = system.multiply(
        point[0].lc() + point[1],
        point[0].lc() + point[1],
        f"{relation_label} T",
    )
    a = system.multiply(point[0], point[1], f"{relation_label} A")
    c = system.multiply(CURVE_D * a.lc(), a, f"{relation_label} C")
    result = allocate_jubjub_point(system, allocation_label, result_witness)
    system.enforce(
        1 + c.lc(),
        result[0],
        2 * a.lc(),
        f"{relation_label} u division relation",
    )
    system.enforce(
        1 - c.lc(),
        result[1],
        t.lc() - 2 * a.lc(),
        f"{relation_label} v division relation",
    )
    return result


@overload
def constrain_jubjub_double(
    system: R1CS,
    point: CircuitPoint,
    result: CircuitPoint,
    label: str = "Jubjub doubling",
) -> None: ...


@overload
def constrain_jubjub_double(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    result: tuple[VariableLike, VariableLike],
    label: str = "Jubjub doubling",
) -> None: ...


def constrain_jubjub_double(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    result: tuple[VariableLike, VariableLike],
    label: str = "Jubjub doubling",
) -> None:
    """Constrain upstream affine doubling for an already-constrained point."""
    _require_point(system, point)
    _require_point(system, result)

    t = system.multiply(
        point[0].lc() + point[1],
        point[0].lc() + point[1],
        f"{label} T",
    )
    a = system.multiply(point[0], point[1], f"{label} A")
    c = system.multiply(CURVE_D * a.lc(), a, f"{label} C")
    system.enforce(
        1 + c.lc(),
        result[0],
        2 * a.lc(),
        f"{label} u division relation",
    )
    system.enforce(
        1 - c.lc(),
        result[1],
        t.lc() - 2 * a.lc(),
        f"{label} v division relation",
    )


@overload
def constrain_jubjub_not_small_order(
    system: R1CS,
    point: CircuitPoint,
    label: str = "Jubjub non-small-order",
    *,
    bellman_allocation_order: bool = False,
) -> CircuitPoint: ...


@overload
def constrain_jubjub_not_small_order(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    label: str = "Jubjub non-small-order",
    *,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def constrain_jubjub_not_small_order(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    label: str = "Jubjub non-small-order",
    *,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Constrain the pinned three-doubling nonzero-u test.

    The point must already be constrained on-curve.
    """
    _require_point(system, point)
    if type(bellman_allocation_order) is not bool:
        raise TypeError("bellman_allocation_order must be a bool")
    point_value = _point_witness(system, point)
    current = point
    for index in range(3):
        doubled_value = point_value + point_value
        if bellman_allocation_order:
            doubled = _constrain_jubjub_double_with_allocated_result(
                system,
                current,
                doubled_value,
                f"{label} double[{index}]",
                f"{label} doubling[{index}]",
            )
        else:
            doubled = allocate_jubjub_point(
                system, f"{label} double[{index}]", doubled_value
            )
            constrain_jubjub_double(
                system, current, doubled, f"{label} doubling[{index}]"
            )
        current = doubled
        point_value = doubled_value

    u_value = system.witness_value(current[0])
    inverse = (
        0
        if u_value is None or u_value == 0
        else pow(u_value, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    )
    inverse_variable = system.alloc_private(f"{label} u inverse", inverse)
    system.enforce(
        current[0],
        inverse_variable,
        1,
        f"{label} nonzero u",
    )
    return current


@overload
def constrain_jubjub_repr(
    system: R1CS,
    point: CircuitPoint,
    label: str = "Jubjub representation",
    *,
    bellman_factorization: bool = False,
) -> tuple[Variable, ...]: ...


@overload
def constrain_jubjub_repr(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    label: str = "Jubjub representation",
    *,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, ...]: ...


def constrain_jubjub_repr(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
    label: str = "Jubjub representation",
    *,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, ...]:
    backend = system.namespace(label)
    _require_point(backend, point)

    u_bits = _constrain_strict_field_bits(
        backend, point[0], "u bit", bellman_factorization=bellman_factorization
    )
    v_bits = _constrain_strict_field_bits(
        backend, point[1], "v bit", bellman_factorization=bellman_factorization
    )
    return v_bits + (u_bits[0],)


@overload
def _constrain_strict_field_bits(
    system: R1CS, value: Variable, name: str
) -> tuple[Variable, ...]: ...


@overload
def _constrain_strict_field_bits(
    system: SynthesisBackend,
    value: VariableLike,
    name: str,
) -> tuple[VariableLike, ...]: ...


def _constrain_strict_field_bits(
    system: SynthesisBackend,
    value: VariableLike,
    name: str,
    *,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, ...]:
    """Constrain the canonical little-endian field representation.

    The prefix-AND comparator follows Bellman 0.15's
    ``AllocatedNum.to_bits_le_strict`` structure: Boolean-constrained bits
    corresponding to one-bits of ``modulus - 1``, conditionally-zero bits at
    its zero-bits, and accumulated prefix ANDs.
    """
    system.require_owned(value)
    if not isinstance(name, str) or not name:
        raise R1CSError("strict field-bit name must be a non-empty string")

    modulus = CIRCUIT_FIELD_MODULUS
    bit_length = modulus.bit_length()
    if (modulus - 1).bit_length() != bit_length:
        raise R1CSError("strict field-bit comparator requires a full-width modulus")

    assigned_value = system.witness_value(value)
    high_to_low: list[VariableLike] = []
    current_run: list[VariableLike] = []
    previous_prefix: VariableLike | None = None

    for offset, bound_bit in enumerate(
        reversed(_bits_le(modulus - 1, bit_length))
    ):
        bit_index = bit_length - offset - 1
        bit_value = (
            None
            if assigned_value is None
            else (assigned_value >> bit_index) & 1
        )
        bit = (
            None
            if bellman_factorization
            else system.alloc_private(f"{name}[{bit_index}]", bit_value)
        )

        if bound_bit:
            if bit is None:
                bit = system.alloc_private(f"{name}[{bit_index}]", bit_value)
            if bellman_factorization:
                system.enforce(
                    1 - bit.lc(),
                    bit,
                    0,
                    f"{name}[{bit_index}] boolean",
                )
            else:
                system.enforce(
                    bit,
                    bit.lc() - 1,
                    0,
                    f"{name}[{bit_index}] boolean",
                )
            current_run.append(bit)
        else:
            if current_run:
                conjunction = current_run + (
                    [] if previous_prefix is None else [previous_prefix]
                )
                previous_prefix = conjunction[0]
                for run_index, run_bit in enumerate(conjunction[1:]):
                    previous_prefix = system.multiply(
                        previous_prefix,
                        run_bit,
                        f"{name} prefix AND[{bit_index}:{run_index}]",
                    )
                current_run.clear()

            # Bellman allocates these prefix products before the next zero bit.
            if bit is None:
                bit = system.alloc_private(f"{name}[{bit_index}]", bit_value)
            if previous_prefix is None:
                if bellman_factorization:
                    system.enforce(
                        1 - bit.lc(),
                        bit,
                        0,
                        f"{name}[{bit_index}] boolean",
                    )
                else:
                    system.enforce(
                        bit,
                        bit.lc() - 1,
                        0,
                        f"{name}[{bit_index}] boolean",
                    )
            else:
                system.enforce(
                    1 - previous_prefix.lc() - bit.lc(),
                    bit,
                    0,
                    f"{name}[{bit_index}] conditional boolean",
                )
        high_to_low.append(bit)

    if current_run:
        raise R1CSError("strict field-bit comparator ended with an open prefix")

    little_endian = tuple(reversed(high_to_low))
    reconstruction = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(little_endian))
    )
    if bellman_factorization:
        system.enforce(
            0,
            0,
            reconstruction - value.lc(),
            f"{name} reconstruction",
        )
    else:
        system.enforce_equal(value, reconstruction, f"{name} reconstruction")
    return little_endian


@overload
def allocate_unchecked_jubjub_repr(
    system: R1CS, name: str, point: Point
) -> tuple[Variable, ...]: ...


@overload
def allocate_unchecked_jubjub_repr(
    system: SynthesisBackend, name: str, point: Point
) -> tuple[VariableLike, ...]: ...


def allocate_unchecked_jubjub_repr(
    system: SynthesisBackend, name: str, point: Point
) -> tuple[VariableLike, ...]:
    """Allocate Output-circuit pk_d representation without a curve check."""
    if not isinstance(point, Point):
        raise TypeError("point must be a Jubjub Point")
    bits = _point_repr_bits(point)
    return tuple(
        system.alloc_private(f"{name}.v bit[{index}]", bit)
        for index, bit in enumerate(bits)
    )


def jubjub_add_witness(left: Point, right: Point) -> Point:
    """Generate an affine addition witness independently of R1CS evaluation."""
    if not isinstance(left, Point) or not isinstance(right, Point):
        raise TypeError("left and right must be Jubjub Points")
    return left + right


def jubjub_double_witness(point: Point) -> Point:
    if not isinstance(point, Point):
        raise TypeError("point must be a Jubjub Point")
    return point + point


def make_jubjub_scalar_mul_witness(
    base: Point, bits_le: Sequence[int]
) -> JubjubScalarMulWitness:
    if not isinstance(base, Point):
        raise TypeError("base must be a Jubjub Point")
    if not bits_le:
        raise R1CSError("scalar multiplication requires at least one bit")
    bits = tuple(_require_bit(bit) for bit in bits_le)
    bases = []
    selected = []
    accumulators = []
    current_base = base
    accumulator = IDENTITY
    for bit in bits:
        bases.append(current_base)
        selected_point = current_base if bit else IDENTITY
        selected.append(selected_point)
        accumulator = accumulator + selected_point
        accumulators.append(accumulator)
        current_base = current_base + current_base
    return JubjubScalarMulWitness(
        bits, tuple(bases), tuple(selected), tuple(accumulators), accumulator
    )


@overload
def _constrain_jubjub_scalar_mul_accumulation(
    system: R1CS,
    accumulator: CircuitPoint | None,
    selected: CircuitPoint,
    next_witness: Point | None,
    allocation_label: str,
    relation_label: str,
    bellman_allocation_order: bool = False,
) -> CircuitPoint: ...


@overload
def _constrain_jubjub_scalar_mul_accumulation(
    system: SynthesisBackend,
    accumulator: tuple[VariableLike, VariableLike] | None,
    selected: tuple[VariableLike, VariableLike],
    next_witness: Point | None,
    allocation_label: str,
    relation_label: str,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def _constrain_jubjub_scalar_mul_accumulation(
    system: SynthesisBackend,
    accumulator: tuple[VariableLike, VariableLike] | None,
    selected: tuple[VariableLike, VariableLike],
    next_witness: Point | None,
    allocation_label: str,
    relation_label: str,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Apply one existing little-endian scalar-multiplication accumulation step."""
    _require_point(system, selected)
    if accumulator is None:
        return selected
    _require_point(system, accumulator)
    if bellman_allocation_order:
        if next_witness is None:
            raise R1CSError("Jubjub accumulation witness is required")
        next_accumulator = _constrain_jubjub_add_with_allocated_result(
            system,
            accumulator,
            selected,
            next_witness,
            allocation_label,
            relation_label,
        )
    else:
        next_accumulator = allocate_jubjub_point(
            system, allocation_label, next_witness
        )
        constrain_jubjub_add(
            system, accumulator, selected, next_accumulator, relation_label
        )
    return next_accumulator


@overload
def constrain_jubjub_scalar_mul(
    system: R1CS,
    base: CircuitPoint,
    bits_le: Sequence[CircuitBit],
    witness: JubjubScalarMulWitness,
    label: str = "Jubjub scalar multiplication",
    *,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> CircuitPoint: ...


@overload
def constrain_jubjub_scalar_mul(
    system: SynthesisBackend,
    base: tuple[VariableLike, VariableLike],
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: JubjubScalarMulWitness,
    label: str = "Jubjub scalar multiplication",
    *,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def constrain_jubjub_scalar_mul(
    system: SynthesisBackend,
    base: tuple[VariableLike, VariableLike],
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: JubjubScalarMulWitness,
    label: str = "Jubjub scalar multiplication",
    *,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Constrain upstream little-endian multiplication.

    The caller must constrain the base point with ``constrain_jubjub_point``.
    ``bits_preconstrained`` is valid only when each scalar bit is already
    Boolean-constrained by the caller.
    """
    _require_point(system, base)
    if not isinstance(bits_le, Sequence) or isinstance(bits_le, (str, bytes)):
        raise TypeError("scalar multiplication bits must be a sequence")
    if not bits_le:
        raise R1CSError("scalar multiplication requires at least one bit")
    if not isinstance(witness, JubjubScalarMulWitness):
        raise TypeError("witness must be a JubjubScalarMulWitness")
    if len(bits_le) != len(witness.bit_values):
        raise R1CSError("scalar multiplication witness has an invalid bit length")
    if type(bits_preconstrained) is not bool:
        raise TypeError("bits_preconstrained must be a bool")
    if isinstance(system, R1CS):
        if any(not isinstance(bit, (Variable, _NegatedBit)) for bit in bits_le):
            raise TypeError("scalar multiplication bits must be R1CS-backed bits")
        if not bits_preconstrained and any(
            not isinstance(bit, Variable) for bit in bits_le
        ):
            raise TypeError("non-variable scalar bits must be marked preconstrained")
        bit_values = tuple(_read_blake_bit(system, bit) for bit in bits_le)
    else:
        if any(not isinstance(bit, RecorderVariable) for bit in bits_le):
            raise TypeError("scalar multiplication bits must be recorder-backed bits")
        if not bits_preconstrained and any(
            not isinstance(bit, RecorderVariable) for bit in bits_le
        ):
            raise TypeError("non-variable scalar bits must be marked preconstrained")
        bit_values = tuple(_read_backend_bit(system, bit) for bit in bits_le)
    if bit_values != witness.bit_values:
        raise R1CSError("scalar multiplication witness does not match its bits")
    if any(
        len(items) != len(bits_le)
        for items in (
            witness.bases,
            witness.selected_points,
            witness.accumulators,
        )
    ):
        raise R1CSError("scalar multiplication witness has an invalid trace")
    if bellman_factorization and not bits_preconstrained:
        for index, bit in enumerate(bits_le):
            if not isinstance(bit, (Variable, RecorderVariable)):
                raise TypeError(
                    "preconstrained aliases are required for non-variable scalar bits"
                )
            _constrain_jubjub_scalar_bit(
                system,
                bit,
                f"{label} bit[{index}]",
                bellman_factorization=True,
            )
    current_base = base
    accumulator = None
    for index, bit in enumerate(bits_le):
        if not bits_preconstrained and not bellman_factorization:
            if not isinstance(bit, (Variable, RecorderVariable)):
                raise TypeError(
                    "preconstrained aliases are required for non-variable scalar bits"
                )
            _constrain_jubjub_scalar_bit(
                system,
                bit,
                f"{label} bit[{index}]",
                bellman_factorization=bellman_factorization,
            )
        if index:
            if bellman_factorization:
                doubled = _constrain_jubjub_double_with_allocated_result(
                    system,
                    current_base,
                    witness.bases[index],
                    f"{label} base[{index}]",
                    f"{label} base doubling[{index}]",
                )
            else:
                doubled = allocate_jubjub_point(
                    system, f"{label} base[{index}]", witness.bases[index]
                )
                constrain_jubjub_double(
                    system,
                    current_base,
                    doubled,
                    f"{label} base doubling[{index}]",
                )
            current_base = doubled

        selected = allocate_jubjub_point(
            system,
            f"{label} selected[{index}]",
            witness.selected_points[index],
        )
        if isinstance(bit, (Variable, RecorderVariable)):
            constrain_jubjub_select(
                system,
                bit,
                current_base,
                (0, 1),
                selected,
                f"{label} select u[{index}]",
                f"{label} select v[{index}]",
                bellman_factorization=bellman_factorization,
            )
        else:
            if not isinstance(system, R1CS):
                raise TypeError(
                    "recorder scalar multiplication bits must be variables"
                )
            r1cs_base = cast(CircuitPoint, current_base)
            r1cs_selected = cast(CircuitPoint, selected)
            system.enforce(
                _bit_expression(system, ((bit, 1),), 0),
                r1cs_base[0],
                r1cs_selected[0],
                f"{label} select u[{index}]",
            )
            system.enforce(
                _bit_expression(system, ((bit, 1),), 0),
                r1cs_base[1].lc() - 1,
                r1cs_selected[1].lc() - 1,
                f"{label} select v[{index}]",
            )
        accumulator = _constrain_jubjub_scalar_mul_accumulation(
            system,
            accumulator,
            selected,
            witness.accumulators[index],
            f"{label} accumulator[{index}]",
            f"{label} accumulation[{index}]",
            bellman_allocation_order=bellman_factorization,
        )
    if accumulator is None:
        raise R1CSError("scalar multiplication requires at least one bit")
    return accumulator


def make_sapling_ephemeral_key_witness(
    diversifier_base: Point, esk: int
) -> SaplingEphemeralKeyWitness:
    """Prepare a 252-bit variable-base witness for ``epk = [esk]g_d``."""
    if not isinstance(diversifier_base, Point) or not diversifier_base.is_on_curve():
        raise R1CSError("diversifier base must be a valid Jubjub point")
    if diversifier_base.multiply(8) == IDENTITY:
        raise R1CSError("diversifier base must not be small order")
    if type(esk) is not int or not 0 <= esk < SCALAR_MODULUS:
        raise R1CSError("ephemeral secret key is outside the Jubjub scalar field")

    esk_bits = _bits_le(esk, _JUBJUB_SCALAR_BITS)
    multiplication = make_jubjub_scalar_mul_witness(
        diversifier_base, esk_bits
    )
    return SaplingEphemeralKeyWitness(
        esk, esk_bits, multiplication, multiplication.result
    )


@overload
def constrain_sapling_ephemeral_key(
    system: R1CS,
    diversifier_base: CircuitPoint,
    esk_bits: Sequence[Variable],
    ephemeral_key: CircuitPoint,
    witness: SaplingEphemeralKeyWitness,
    label: str = "Sapling Output ephemeral key",
    *,
    bellman_factorization: bool = False,
) -> CircuitPoint: ...


@overload
def constrain_sapling_ephemeral_key(
    system: SynthesisBackend,
    diversifier_base: tuple[VariableLike, VariableLike],
    esk_bits: Sequence[VariableLike],
    ephemeral_key: tuple[VariableLike, VariableLike],
    witness: SaplingEphemeralKeyWitness,
    label: str = "Sapling Output ephemeral key",
    *,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def constrain_sapling_ephemeral_key(
    system: SynthesisBackend,
    diversifier_base: tuple[VariableLike, VariableLike],
    esk_bits: Sequence[VariableLike],
    ephemeral_key: tuple[VariableLike, VariableLike],
    witness: SaplingEphemeralKeyWitness,
    label: str = "Sapling Output ephemeral key",
    *,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]:
    return _constrain_sapling_ephemeral_key(
        system,
        diversifier_base,
        esk_bits,
        ephemeral_key,
        witness,
        label,
        bellman_factorization=bellman_factorization,
        diversifier_base_preconstrained=False,
    )


def _constrain_sapling_ephemeral_key(
    system: SynthesisBackend,
    diversifier_base: tuple[VariableLike, VariableLike],
    esk_bits: Sequence[VariableLike],
    ephemeral_key: tuple[VariableLike, VariableLike],
    witness: SaplingEphemeralKeyWitness,
    label: str = "Sapling Output ephemeral key",
    *,
    bellman_factorization: bool = False,
    diversifier_base_preconstrained: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Constrain ``epk = [esk]g_d`` and bind its public ``u, v`` coordinates.

    `g_d` must be allocated as a private witness and the two public `epk`
    coordinates must be allocated before any private witnesses. As in the
    pinned Output circuit, `g_d` is supplied after host-side diversifier
    validation; the diversifier hash is not part of this R1CS relation.
    """
    _require_point(system, diversifier_base)
    _require_point(system, ephemeral_key)
    scalar_bits = tuple(esk_bits)
    if len(scalar_bits) != _JUBJUB_SCALAR_BITS:
        raise R1CSError(
            f"ephemeral secret key must contain exactly {_JUBJUB_SCALAR_BITS} bits"
        )
    if any(not isinstance(bit, VariableLike) for bit in scalar_bits):
        raise TypeError("ephemeral secret-key bits must be variables")
    for bit in scalar_bits:
        system.require_owned(bit)
    public_positions = tuple(
        system.public_input_position(coordinate) for coordinate in ephemeral_key
    )
    if any(position is None for position in public_positions):
        raise R1CSError("ephemeral-key coordinates must be public inputs")
    if public_positions[0] >= public_positions[1]:
        raise R1CSError("ephemeral-key public coordinates must be ordered u then v")
    if not isinstance(witness, SaplingEphemeralKeyWitness):
        raise TypeError("witness must be a SaplingEphemeralKeyWitness")
    if type(bellman_factorization) is not bool:
        raise TypeError("bellman_factorization must be a bool")
    if type(diversifier_base_preconstrained) is not bool:
        raise TypeError("diversifier_base_preconstrained must be a bool")
    if (
        type(witness.esk) is not int
        or not 0 <= witness.esk < SCALAR_MODULUS
        or len(witness.esk_bits) != _JUBJUB_SCALAR_BITS
        or not isinstance(witness.multiplication, JubjubScalarMulWitness)
        or not isinstance(witness.ephemeral_key, Point)
    ):
        raise R1CSError("ephemeral-key witness has an invalid shape")
    if witness.esk != sum(
        bit << index for index, bit in enumerate(witness.esk_bits)
    ):
        raise R1CSError("ephemeral-key witness scalar is inconsistent")
    if (
        witness.multiplication.bit_values != witness.esk_bits
        or witness.ephemeral_key != witness.multiplication.result
    ):
        raise R1CSError("ephemeral-key multiplication witness is inconsistent")
    if tuple(_read_backend_bit(system, bit) for bit in scalar_bits) != witness.esk_bits:
        raise R1CSError("ephemeral-key witness does not match scalar bits")

    base_value = _point_witness(system, diversifier_base)
    if witness.ephemeral_key != base_value.multiply(witness.esk):
        raise R1CSError("ephemeral-key witness does not match g_d and esk")

    if not diversifier_base_preconstrained:
        constrain_jubjub_point(
            system,
            diversifier_base,
            f"{label} g_d curve",
            bellman_factorization=bellman_factorization,
        )
        constrain_jubjub_not_small_order(
            system,
            diversifier_base,
            f"{label} g_d",
            bellman_allocation_order=bellman_factorization,
        )
    result = constrain_jubjub_scalar_mul(
        system,
        diversifier_base,
        scalar_bits,
        witness.multiplication,
        f"{label} multiplication",
        bellman_factorization=bellman_factorization,
    )
    if bellman_factorization:
        system.enforce(ephemeral_key[0], 1, result[0], f"{label} public epk.u")
        system.enforce(ephemeral_key[1], 1, result[1], f"{label} public epk.v")
    else:
        system.enforce_equal(
            result[0], ephemeral_key[0], f"{label} public epk.u"
        )
        system.enforce_equal(
            result[1], ephemeral_key[1], f"{label} public epk.v"
        )
    return result


@overload
def _allocate_jubjub_scalar_bits(
    system: R1CS,
    bits_le: Sequence[int | None],
    name: str,
) -> tuple[Variable, ...]: ...


@overload
def _allocate_jubjub_scalar_bits(
    system: SynthesisBackend,
    bits_le: Sequence[int | None],
    name: str,
) -> tuple[VariableLike, ...]: ...


def _allocate_jubjub_scalar_bits(
    system: R1CS | SynthesisBackend,
    bits_le: Sequence[int | None],
    name: str,
) -> tuple[VariableLike, ...]:
    if len(bits_le) != _JUBJUB_SCALAR_BITS:
        raise R1CSError(
            f"Jubjub scalar must contain exactly {_JUBJUB_SCALAR_BITS} bits"
        )
    return tuple(
        system.alloc_private(f"{name}[{index}]", bit)
        for index, bit in enumerate(bits_le)
    )


def _constrain_jubjub_scalar_bit(
    system: R1CS | SynthesisBackend,
    bit: VariableLike,
    label: str,
    *,
    bellman_factorization: bool = False,
) -> None:
    system.require_owned(bit)
    if bellman_factorization:
        system.enforce(1 - bit.lc(), bit, 0, label)
    else:
        system.enforce(bit, bit.lc() - 1, 0, label)


def make_sapling_nullifier_rho_witness(
    note_commitment: Point, position: int
) -> SaplingNullifierRhoWitness:
    """Prepare ``rho = cm + [position]J`` from a note commitment and position."""
    if not isinstance(note_commitment, Point) or not note_commitment.is_on_curve():
        raise R1CSError("note commitment must be a valid Jubjub point")
    if type(position) is not int or not 0 <= position < 1 << 32:
        raise R1CSError("Sapling note position must be an unsigned 32-bit integer")

    position_bits = _bits_le(position, 32)
    position_multiplication = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("nullifier_position"),
        position_bits,
    )
    return SaplingNullifierRhoWitness(
        position,
        position_bits,
        position_multiplication,
        note_commitment + position_multiplication.result,
    )


def constrain_sapling_nullifier_rho(
    system: R1CS,
    note_commitment: CircuitPoint,
    position_bits: Sequence[Variable],
    witness: SaplingNullifierRhoWitness,
    label: str = "Sapling nullifier rho",
) -> CircuitPoint:
    """Constrain ``rho = cm + [position]J`` for the Spend nullifier preimage.

    The note point must be bound by the caller to the constrained note
    commitment, and position bits must come from the authentication path.
    """
    _require_point(system, note_commitment)
    bits = tuple(position_bits)
    if len(bits) != 32:
        raise R1CSError("Sapling nullifier position must contain exactly 32 bits")
    if any(not isinstance(bit, Variable) for bit in bits):
        raise TypeError("Sapling nullifier position bits must be R1CS variables")
    if not isinstance(witness, SaplingNullifierRhoWitness):
        raise TypeError("witness must be a SaplingNullifierRhoWitness")
    if (
        type(witness.position) is not int
        or not 0 <= witness.position < 1 << 32
        or len(witness.position_bits) != 32
        or witness.position_bits != _bits_le(witness.position, 32)
        or not isinstance(
            witness.position_multiplication, FixedBaseJubjubWitness
        )
        or not isinstance(witness.rho, Point)
    ):
        raise R1CSError("Sapling nullifier rho witness has an invalid shape")
    if tuple(_read_bit(system, bit) for bit in bits) != witness.position_bits:
        raise R1CSError("nullifier rho witness does not match position bits")

    note_point = _point_witness(system, note_commitment)
    position_base = sapling_fixed_base_generator("nullifier_position")
    if witness.rho != note_point + position_base.multiply(witness.position):
        raise R1CSError("nullifier rho witness does not match note and position")
    position_point = _constrain_fixed_base_jubjub_mul(
        system,
        position_base,
        bits,
        witness.position_multiplication,
        f"{label} position multiplication",
        bits_preconstrained=True,
    )
    rho = allocate_jubjub_point(system, f"{label} point", witness.rho)
    constrain_jubjub_add(
        system,
        note_commitment,
        position_point,
        rho,
        f"{label} commitment addition",
    )
    return rho


def make_sapling_randomized_authorization_key_witness(
    authorization_key: Point, ar: int
) -> SaplingRandomizedAuthorizationKeyWitness:
    """Prepare ``rk = ak + [ar]SPENDING_KEY_GENERATOR`` witness data."""
    if not isinstance(authorization_key, Point):
        raise TypeError("authorization key must be a Jubjub Point")
    if (
        not authorization_key.is_on_curve()
        or authorization_key.multiply(8) == IDENTITY
        or not authorization_key.is_in_subgroup()
    ):
        raise R1CSError(
            "authorization key must be a non-small-order Jubjub subgroup point"
        )
    if type(ar) is not int or not 0 <= ar < SCALAR_MODULUS:
        raise R1CSError("authorization randomizer is outside the Jubjub scalar field")

    ar_bits = _bits_le(ar, _JUBJUB_SCALAR_BITS)
    multiplication = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("spending_key"), ar_bits
    )
    randomized_key = authorization_key + multiplication.result
    return SaplingRandomizedAuthorizationKeyWitness(
        ar,
        ar_bits,
        multiplication,
        authorization_key,
        randomized_key,
    )


def constrain_sapling_randomized_authorization_key(
    system: R1CS,
    authorization_key: CircuitPoint,
    ar: Variable | Sequence[Variable],
    randomized_key: CircuitPoint,
    witness: SaplingRandomizedAuthorizationKeyWitness,
    label: str = "Sapling randomized authorization key",
) -> CircuitPoint:
    """Constrain the upstream Spend ``rk = ak + [ar]G`` relation.

    ``ar`` may be a scalar variable, which is decomposed into 252 Boolean bits,
    or an existing sequence of those bits. The latter matches Spend synthesis,
    where Bellman passes the field decomposition directly to multiplication.
    No separate less-than-modulus gadget is added. The two public randomized-key
    coordinates must be the first application inputs, in ``u, v`` order.
    """
    _require_point(system, authorization_key)
    _require_point(system, randomized_key)
    if isinstance(ar, Variable):
        system._require_owned(ar)
        if ar.kind != "private":
            raise R1CSError("authorization randomizer must be private")
        ar_bits = system.range_check(
            ar,
            _JUBJUB_SCALAR_BITS,
            f"{label} ar bit",
        )
    else:
        if not isinstance(ar, Sequence):
            raise TypeError(
                "authorization randomizer must be a variable or bit sequence"
            )
        ar_bits = tuple(ar)
        if len(ar_bits) != _JUBJUB_SCALAR_BITS:
            raise R1CSError("authorization randomizer must contain 252 bits")
        for index, bit in enumerate(ar_bits):
            system._require_owned(bit)
            if bit.kind != "private":
                raise R1CSError("authorization randomizer bits must be private")
            system.boolean(bit, f"{label} ar bit[{index}]")
    if any(coordinate.kind != "public" for coordinate in randomized_key):
        raise R1CSError("randomized-key coordinates must be public inputs")
    if (
        randomized_key[0].index != 1
        or randomized_key[1].index != 2
        or randomized_key[0].index >= randomized_key[1].index
    ):
        raise R1CSError(
            "randomized-key public coordinates must occupy inputs 0 and 1 in u, v order"
        )
    if not isinstance(witness, SaplingRandomizedAuthorizationKeyWitness):
        raise TypeError(
            "witness must be a SaplingRandomizedAuthorizationKeyWitness"
        )
    if (
        type(witness.ar) is not int
        or not 0 <= witness.ar < SCALAR_MODULUS
        or len(witness.ar_bits) != _JUBJUB_SCALAR_BITS
        or not isinstance(witness.multiplication, FixedBaseJubjubWitness)
        or witness.multiplication.bit_values != witness.ar_bits
        or not isinstance(witness.authorization_key, Point)
        or not isinstance(witness.randomized_key, Point)
    ):
        raise R1CSError("randomized authorization-key witness has an invalid shape")

    if tuple(_read_bit(system, bit) for bit in ar_bits) != witness.ar_bits:
        raise R1CSError("randomized authorization-key witness does not match ar")
    authorization_key_value = _point_witness(system, authorization_key)
    if (
        authorization_key_value != witness.authorization_key
        or not authorization_key_value.is_on_curve()
        or authorization_key_value.multiply(8) == IDENTITY
        or not authorization_key_value.is_in_subgroup()
    ):
        raise R1CSError(
            "authorization key witness must be the expected non-small-order subgroup point"
        )
    if witness.randomized_key != (
        authorization_key_value
        + sapling_fixed_base_generator("spending_key").multiply(witness.ar)
    ):
        raise R1CSError("randomized authorization-key witness is inconsistent")

    constrain_jubjub_point(system, authorization_key, f"{label} ak curve")
    constrain_jubjub_not_small_order(
        system, authorization_key, f"{label} ak"
    )
    spending_key_generator = sapling_fixed_base_generator("spending_key")
    randomization = constrain_fixed_base_jubjub_mul(
        system,
        spending_key_generator,
        ar_bits,
        witness.multiplication,
        f"{label} ar multiplication",
        enforce_scalar_range=False,
        bits_preconstrained=True,
    )
    result = allocate_jubjub_point(
        system, f"{label} result", witness.randomized_key
    )
    constrain_jubjub_add(
        system,
        authorization_key,
        randomization,
        result,
        f"{label} authorization-key addition",
    )
    system.enforce_equal(
        result[0], randomized_key[0], f"{label} public rk.u"
    )
    system.enforce_equal(
        result[1], randomized_key[1], f"{label} public rk.v"
    )
    return result


def sapling_fixed_base_generator(name: str) -> Point:
    """Return one of the six fixed generators pinned by sapling-crypto."""
    generators = {
        "proof_generation_key": (b"Zcash_H_", b""),
        "note_commitment_randomness": (b"Zcash_PH", b"r"),
        "nullifier_position": (b"Zcash_J_", b""),
        "value_commitment_value": (b"Zcash_cv", b"v"),
        "value_commitment_randomness": (b"Zcash_cv", b"r"),
        "spending_key": (b"Zcash_G_", b""),
    }
    try:
        personalization, message = generators[name]
    except (KeyError, TypeError) as error:
        raise ValueError(
            f"unsupported Sapling fixed-base generator: {name!r}"
        ) from error
    return find_group_hash(personalization, message)


def make_fixed_base_jubjub_witness(
    base: Point, bits_le: Sequence[int]
) -> FixedBaseJubjubWitness:
    """Generate the pinned 3-bit fixed-base multiplication trace."""
    if not isinstance(base, Point) or not _is_valid_fixed_base(base):
        raise R1CSError("fixed base must be a valid Jubjub point")
    if not 1 <= len(bits_le) <= _JUBJUB_SCALAR_BITS:
        raise R1CSError(
            f"fixed-base scalar must contain 1 to {_JUBJUB_SCALAR_BITS} bits"
        )
    bits = tuple(_require_bit(bit) for bit in bits_le)
    if sum(bit << index for index, bit in enumerate(bits)) >= SCALAR_MODULUS:
        raise R1CSError("fixed-base scalar is outside the Jubjub scalar field")

    selected_points = []
    accumulators = []
    accumulator = None
    window_count = (
        len(bits) + _FIXED_BASE_WINDOW_BITS - 1
    ) // _FIXED_BASE_WINDOW_BITS
    for window, table in enumerate(_fixed_base_tables(base)[:window_count]):
        start = window * _FIXED_BASE_WINDOW_BITS
        pattern = sum(
            bits[start + bit_index] << bit_index
            for bit_index in range(_FIXED_BASE_WINDOW_BITS)
            if start + bit_index < len(bits)
        )
        selected = table[pattern]
        selected_points.append(selected)
        accumulator = selected if accumulator is None else accumulator + selected
        accumulators.append(accumulator)

    if accumulator is None:
        raise R1CSError("fixed-base multiplication requires a non-empty scalar")
    return FixedBaseJubjubWitness(
        bits, tuple(selected_points), tuple(accumulators), accumulator
    )


def constrain_fixed_base_jubjub_mul(
    system: R1CS,
    base: Point,
    bits_le: Sequence[CircuitBit],
    witness: FixedBaseJubjubWitness,
    label: str = "Sapling fixed-base Jubjub multiplication",
    *,
    enforce_scalar_range: bool = True,
    bits_preconstrained: bool = False,
) -> CircuitPoint:
    """Constrain fixed-base multiplication and its assigned scalar bits."""
    return _constrain_fixed_base_jubjub_mul(
        system, base, bits_le, witness, label,
        enforce_scalar_range=enforce_scalar_range,
        bits_preconstrained=bits_preconstrained,
    )


@overload
def _constrain_fixed_base_jubjub_mul(
    system: R1CS,
    base: Point,
    bits_le: Sequence[CircuitBit],
    witness: FixedBaseJubjubWitness,
    label: str = "Sapling fixed-base Jubjub multiplication",
    enforce_scalar_range: bool = True,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> CircuitPoint: ...


@overload
def _constrain_fixed_base_jubjub_mul(
    system: SynthesisBackend,
    base: Point,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str = "Sapling fixed-base Jubjub multiplication",
    enforce_scalar_range: bool = True,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def _constrain_fixed_base_jubjub_mul(
    system: SynthesisBackend,
    base: Point,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str = "Sapling fixed-base Jubjub multiplication",
    enforce_scalar_range: bool = True,
    bits_preconstrained: bool = False,
    bellman_factorization: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Constrain fixed-base scalar validation, lookup, and point addition."""
    if not isinstance(base, Point) or not _is_valid_fixed_base(base):
        raise R1CSError("fixed base must be a valid Jubjub point")
    _constrain_fixed_base_scalar(
        system,
        bits_le,
        witness,
        label,
        enforce_scalar_range,
        bits_preconstrained,
        bellman_factorization,
    )
    return _constrain_fixed_base_windows(
        system,
        base,
        bits_le,
        witness,
        label,
        bellman_allocation_order=bellman_factorization,
    )


@overload
def _constrain_fixed_base_scalar(
    system: R1CS,
    bits_le: Sequence[CircuitBit],
    witness: FixedBaseJubjubWitness,
    label: str,
    enforce_scalar_range: bool,
    bits_preconstrained: bool,
    bellman_factorization: bool = False,
) -> tuple[int, ...]: ...


@overload
def _constrain_fixed_base_scalar(
    system: SynthesisBackend,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str,
    enforce_scalar_range: bool,
    bits_preconstrained: bool,
    bellman_factorization: bool = False,
) -> tuple[int, ...]: ...


def _constrain_fixed_base_scalar(
    system: SynthesisBackend,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str,
    enforce_scalar_range: bool,
    bits_preconstrained: bool,
    bellman_factorization: bool = False,
) -> tuple[int, ...]:
    """Validate assigned fixed-base scalar bits and emit their range rows."""
    if not 1 <= len(bits_le) <= _JUBJUB_SCALAR_BITS:
        raise R1CSError(
            f"fixed-base scalar must contain 1 to {_JUBJUB_SCALAR_BITS} bits"
        )
    for bit in bits_le:
        variable = _fixed_base_scalar_variable(bit)
        if variable is None:
            raise TypeError(
                "fixed-base scalar bits must be backend variables"
            )
    if type(enforce_scalar_range) is not bool:
        raise TypeError("enforce_scalar_range must be a bool")
    if type(bits_preconstrained) is not bool:
        raise TypeError("bits_preconstrained must be a bool")
    if not bits_preconstrained and any(
        not _is_fixed_base_scalar_variable(bit) for bit in bits_le
    ):
        raise TypeError(
            "non-variable scalar bits must be marked preconstrained"
        )
    if not isinstance(witness, FixedBaseJubjubWitness):
        raise TypeError("witness must be a FixedBaseJubjubWitness")
    window_count = (
        len(bits_le) + _FIXED_BASE_WINDOW_BITS - 1
    ) // _FIXED_BASE_WINDOW_BITS
    if len(witness.bit_values) != len(bits_le) or len(
        witness.selected_points
    ) != window_count or len(witness.accumulators) != window_count:
        raise R1CSError("fixed-base multiplication witness has an invalid shape")
    if witness.result != witness.accumulators[-1]:
        raise R1CSError(
            "fixed-base witness result does not match its final accumulator"
        )
    for bit in bits_le:
        variable = _fixed_base_scalar_variable(bit)
        if variable is None:
            raise TypeError("fixed-base scalar bits must be backend variables")
        system.require_owned(variable)
    bit_values = tuple(_read_lookup_bit(system, bit) for bit in bits_le)
    if bit_values != witness.bit_values:
        raise R1CSError("fixed-base witness does not match the assigned scalar bits")
    if enforce_scalar_range and (
        sum(bit << index for index, bit in enumerate(witness.bit_values))
        >= SCALAR_MODULUS
    ):
        raise R1CSError("fixed-base scalar is outside the Jubjub scalar field")

    if enforce_scalar_range and len(bits_le) == _JUBJUB_SCALAR_BITS:
        if any(
            not _is_fixed_base_scalar_variable(bit) for bit in bits_le
        ):
            raise TypeError(
                "range-checked fixed-base scalar bits must be variables"
            )
        packed_scalar = _pack_bits_backend(
            system,
            bits_le,
            f"{label} scalar",
        )
        _range_check_backend(
            system,
            packed_scalar,
            _JUBJUB_SCALAR_BITS,
            f"{label} scalar range",
            upper_bound=SCALAR_MODULUS,
        )
    else:
        if not bits_preconstrained:
            for index, bit in enumerate(bits_le):
                if not _is_fixed_base_scalar_variable(bit):
                    raise TypeError(
                        "preconstrained aliases are required for non-variable scalar bits"
                    )
                _constrain_jubjub_scalar_bit(
                    system,
                    bit,
                    f"{label} scalar bit[{index}]",
                    bellman_factorization=bellman_factorization,
                )

    return bit_values


def _fixed_base_scalar_variable(
    bit: CircuitBit | VariableLike,
) -> VariableLike | None:
    if isinstance(bit, _NegatedBit):
        return bit.variable
    if isinstance(bit, VariableLike):
        return bit
    return None


def _is_fixed_base_scalar_variable(
    bit: CircuitBit | VariableLike,
) -> bool:
    variable = _fixed_base_scalar_variable(bit)
    return variable is not None and not isinstance(bit, _NegatedBit)


def _pack_bits_backend(
    system: SynthesisBackend,
    bits: Sequence[VariableLike],
    name: str,
) -> VariableLike:
    if not bits:
        raise R1CSError("at least one bit is required")
    if len(bits) > CIRCUIT_FIELD_MODULUS.bit_length() - 1:
        raise R1CSError(
            "packed bit width must be below the scalar-field bit length"
        )
    for index, bit in enumerate(bits):
        system.require_owned(bit)
        _constrain_jubjub_scalar_bit(system, bit, f"{name} bit[{index}]")
    reconstruction = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(bits))
    )
    values = tuple(system.witness_value(bit) for bit in bits)
    packed_value = (
        None
        if any(value is None for value in values)
        else sum(
            value << index
            for index, value in enumerate(values)
            if value is not None
        )
        % CIRCUIT_FIELD_MODULUS
    )
    packed = system.alloc_private(name, packed_value)
    system.enforce_equal(packed, reconstruction, f"{name} bit packing")
    return packed


def _range_check_backend(
    system: SynthesisBackend,
    value: VariableLike,
    bit_length: int,
    name: str,
    upper_bound: int | None = None,
) -> tuple[VariableLike, ...]:
    system.require_owned(value)
    if type(bit_length) is not int or bit_length < 1:
        raise R1CSError("bit length must be a positive integer")
    if upper_bound is not None and (
        type(upper_bound) is not int
        or upper_bound < 1
        or upper_bound > 1 << bit_length
    ):
        raise R1CSError("upper bound must fit within the requested bit width")
    witness = system.witness_value(value)
    if witness is not None and witness >= (
        upper_bound if upper_bound is not None else 1 << bit_length
    ):
        raise R1CSError(f"{value.name} is outside the requested range")
    bits = tuple(
        system.alloc_private(
            f"{name}[{index}]",
            None if witness is None else (witness >> index) & 1,
        )
        for index in range(bit_length)
    )
    for index, bit in enumerate(bits):
        _constrain_jubjub_scalar_bit(system, bit, f"{name}[{index}] boolean")
    reconstruction = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(bits))
    )
    system.enforce_equal(value, reconstruction, f"{name} reconstruction")
    if upper_bound is not None and upper_bound < 1 << bit_length:
        equal: int | LinearCombinationLike = 1
        less: int | LinearCombinationLike = 0
        for index in range(bit_length - 1, -1, -1):
            bit = bits[index]
            if upper_bound >> index & 1:
                first_difference = system.multiply(
                    equal,
                    1 - bit.lc(),
                    f"{name} less-than term[{index}]",
                )
                less = less + first_difference.lc()
                equal = system.multiply(
                    equal, bit, f"{name} equal term[{index}]"
                ).lc()
            else:
                equal = system.multiply(
                    equal, 1 - bit.lc(), f"{name} equal term[{index}]"
                ).lc()
        system.enforce_equal(less, 1, f"{name} strict upper bound")
    return bits


@overload
def _constrain_fixed_base_windows(
    system: R1CS,
    base: Point,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str,
    *,
    bellman_allocation_order: bool = False,
) -> CircuitPoint: ...


@overload
def _constrain_fixed_base_windows(
    system: SynthesisBackend,
    base: Point,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str,
    *,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]: ...


def _constrain_fixed_base_windows(
    system: SynthesisBackend,
    base: Point,
    bits_le: Sequence[CircuitBit | VariableLike],
    witness: FixedBaseJubjubWitness,
    label: str,
    *,
    bellman_allocation_order: bool = False,
) -> tuple[VariableLike, VariableLike]:
    """Synthesize the ordered lookup and point-accumulation windows."""
    for bit in bits_le:
        variable = _lookup_bit_backing_variable(bit)
        if variable is None:
            raise TypeError("fixed-base scalar bits must be backend-backed bits")
        system.require_owned(variable)
    if type(bellman_allocation_order) is not bool:
        raise TypeError("bellman_allocation_order must be a bool")

    window_count = (
        len(bits_le) + _FIXED_BASE_WINDOW_BITS - 1
    ) // _FIXED_BASE_WINDOW_BITS
    tables = _fixed_base_tables(base)
    accumulator = None
    for window in range(window_count):
        start = window * _FIXED_BASE_WINDOW_BITS
        window_bits = tuple(
            bits_le[index] if index < len(bits_le) else 0
            for index in range(start, start + _FIXED_BASE_WINDOW_BITS)
        )
        selected = allocate_jubjub_point(
            system,
            f"{label} selected[{window}]",
            witness.selected_points[window],
        )
        _constrain_lookup3_point(
            system,
            window_bits,
            tables[window],
            selected,
            f"{label} lookup[{window}]",
        )
        if accumulator is None:
            accumulator = selected
        else:
            if bellman_allocation_order:
                next_accumulator = _constrain_jubjub_add_with_allocated_result(
                    system,
                    accumulator,
                    selected,
                    witness.accumulators[window],
                    f"{label} accumulator[{window}]",
                    f"{label} addition[{window}]",
                )
            else:
                next_accumulator = allocate_jubjub_point(
                    system,
                    f"{label} accumulator[{window}]",
                    witness.accumulators[window],
                )
                constrain_jubjub_add(
                    system,
                    accumulator,
                    selected,
                    next_accumulator,
                    f"{label} addition[{window}]",
                )
            accumulator = next_accumulator
    if accumulator is None:
        raise R1CSError("fixed-base multiplication requires a non-empty scalar")
    return accumulator


def make_sapling_value_commitment_witness(
    value: int, randomness: int
) -> SaplingValueCommitmentWitness:
    """Prepare witness data for ``[value]G_v + [randomness]G_r``."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise R1CSError("Sapling value must be an unsigned 64-bit integer")
    if (
        type(randomness) is not int
        or not 0 <= randomness < SCALAR_MODULUS
    ):
        raise R1CSError("Sapling value-commitment randomness is out of range")

    value_bits = _bits_le(value, 64)
    randomness_bits = _bits_le(randomness, _JUBJUB_SCALAR_BITS)
    value_mul = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("value_commitment_value"), value_bits
    )
    randomness_mul = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("value_commitment_randomness"),
        randomness_bits,
    )
    commitment = value_mul.result + randomness_mul.result
    return SaplingValueCommitmentWitness(
        value,
        randomness,
        value_bits,
        randomness_bits,
        value_mul,
        randomness_mul,
        commitment,
    )


def constrain_sapling_value_commitment(
    system: R1CS,
    value_bits: Sequence[Variable],
    randomness_bits: Sequence[Variable],
    commitment: CircuitPoint,
    witness: SaplingValueCommitmentWitness,
    label: str = "Sapling value commitment",
    *,
    enforce_scalar_range: bool = True,
) -> CircuitPoint:
    """Constrain a value commitment, optionally enforcing canonical ``rcv``."""
    return _constrain_sapling_value_commitment(
        system,
        value_bits,
        randomness_bits,
        commitment,
        witness,
        label,
        enforce_scalar_range=enforce_scalar_range,
    )


def _constrain_sapling_value_commitment(
    system: SynthesisBackend,
    value_bits: Sequence[VariableLike],
    randomness_bits: Sequence[VariableLike],
    commitment: tuple[VariableLike, VariableLike],
    witness: SaplingValueCommitmentWitness,
    label: str,
    enforce_scalar_range: bool,
    *,
    bellman_factorization: bool = False,
    randomness_bit_allocator: Callable[[], Sequence[VariableLike]] | None = None,
) -> tuple[VariableLike, VariableLike]:
    """Constrain 64-bit value and ``rcv`` bits to public ``(u, v)``.

    Allocate the commitment coordinates as public inputs before allocating
    either private bit sequence, in ``u`` then ``v`` order. ``enforce_scalar_range``
    selects whether the circuit also enforces canonical ``rcv`` encoding.
    """
    value_bit_variables = tuple(value_bits)
    randomness_bit_variables = tuple(randomness_bits)
    if len(value_bit_variables) != 64:
        raise R1CSError("Sapling value must contain exactly 64 little-endian bits")
    if randomness_bit_allocator is not None:
        if randomness_bit_variables:
            raise R1CSError(
                "deferred randomness allocation cannot include preallocated bits"
            )
        if not callable(randomness_bit_allocator):
            raise TypeError("randomness bit allocator must be callable")
    elif len(randomness_bit_variables) != _JUBJUB_SCALAR_BITS:
        raise R1CSError(
            "Sapling value-commitment randomness must use the full Jubjub scalar width"
        )
    if any(
        not isinstance(bit, VariableLike)
        for bit in value_bit_variables + randomness_bit_variables
    ):
        raise TypeError("value and randomness decompositions must be backend variables")
    _require_point(system, commitment)
    public_positions = tuple(
        system.public_input_position(coordinate) for coordinate in commitment
    )
    if any(position is None for position in public_positions):
        raise R1CSError("value-commitment coordinates must be public inputs")
    if public_positions[0] >= public_positions[1]:
        raise R1CSError("public value-commitment coordinates must be ordered u then v")
    if not isinstance(witness, SaplingValueCommitmentWitness):
        raise TypeError("witness must be a SaplingValueCommitmentWitness")
    if (
        len(witness.value_bits) != 64
        or len(witness.randomness_bits) != _JUBJUB_SCALAR_BITS
        or not isinstance(witness.value_mul, FixedBaseJubjubWitness)
        or not isinstance(witness.randomness_mul, FixedBaseJubjubWitness)
        or not isinstance(witness.commitment, Point)
    ):
        raise R1CSError("value-commitment witness has an invalid bit width")
    if witness.value_mul.bit_values != witness.value_bits:
        raise R1CSError("value multiplication witness uses different scalar bits")
    if witness.randomness_mul.bit_values != witness.randomness_bits:
        raise R1CSError("randomness multiplication witness uses different scalar bits")
    if tuple(_read_backend_bit(system, bit) for bit in value_bit_variables) != witness.value_bits:
        raise R1CSError("value-commitment witness does not match value bits")
    if randomness_bit_allocator is None and (
        tuple(_read_backend_bit(system, bit) for bit in randomness_bit_variables)
        != witness.randomness_bits
    ):
        raise R1CSError("value-commitment witness does not match randomness bits")
    if witness.value != sum(
        bit << index for index, bit in enumerate(witness.value_bits)
    ):
        raise R1CSError("value-commitment witness value is inconsistent")
    if witness.randomness != sum(
        bit << index for index, bit in enumerate(witness.randomness_bits)
    ) or not 0 <= witness.randomness < SCALAR_MODULUS:
        raise R1CSError("value-commitment witness randomness is inconsistent")
    if (
        witness.commitment
        != witness.value_mul.result + witness.randomness_mul.result
    ):
        raise R1CSError("value-commitment witness result is inconsistent")

    if type(enforce_scalar_range) is not bool:
        raise TypeError("enforce_scalar_range must be a bool")
    value_point = _constrain_fixed_base_jubjub_mul(
        system,
        sapling_fixed_base_generator("value_commitment_value"),
        value_bit_variables,
        witness.value_mul,
        f"{label} value multiplication",
        enforce_scalar_range=False,
        bellman_factorization=bellman_factorization,
    )
    if randomness_bit_allocator is not None:
        randomness_bit_variables = tuple(randomness_bit_allocator())
        if len(randomness_bit_variables) != _JUBJUB_SCALAR_BITS:
            raise R1CSError(
                "allocated value-commitment randomness has an invalid bit width"
            )
        if any(not isinstance(bit, VariableLike) for bit in randomness_bit_variables):
            raise TypeError(
                "allocated randomness decomposition must use backend variables"
            )
        for bit in randomness_bit_variables:
            system.require_owned(bit)
        if (
            tuple(
                _read_backend_bit(system, bit)
                for bit in randomness_bit_variables
            )
            != witness.randomness_bits
        ):
            raise R1CSError(
                "value-commitment witness does not match randomness bits"
            )
    randomness_point = _constrain_fixed_base_jubjub_mul(
        system,
        sapling_fixed_base_generator("value_commitment_randomness"),
        randomness_bit_variables,
        witness.randomness_mul,
        f"{label} randomness multiplication",
        enforce_scalar_range=enforce_scalar_range,
        bellman_factorization=bellman_factorization,
    )
    if bellman_factorization:
        result = _constrain_jubjub_add_with_allocated_result(
            system,
            value_point,
            randomness_point,
            witness.commitment,
            f"{label} result",
            f"{label} addition",
        )
    else:
        result = allocate_jubjub_point(
            system, f"{label} result", witness.commitment
        )
        constrain_jubjub_add(
            system, value_point, randomness_point, result, f"{label} addition"
        )
    if bellman_factorization:
        system.enforce(commitment[0], 1, result[0], f"{label} public commitment u")
        system.enforce(commitment[1], 1, result[1], f"{label} public commitment v")
    else:
        system.enforce_equal(
            commitment[0], result[0], f"{label} public commitment u"
        )
        system.enforce_equal(
            commitment[1], result[1], f"{label} public commitment v"
        )
    return result


def _read_backend_bit(system: SynthesisBackend, bit: VariableLike) -> int:
    value = system.witness_value(bit)
    if value not in (0, 1):
        raise R1CSError("Pedersen input bit is unassigned or invalid")
    return int(value)


def make_sapling_nullifier_multipacking_witness(
    digest: bytes,
) -> SaplingNullifierMultipackingWitness:
    """Prepare little-endian 254-bit Bellman chunks for a 32-byte nullifier."""
    if not isinstance(digest, bytes) or len(digest) != _NULLIFIER_BITS // 8:
        raise R1CSError("Sapling nullifier digest must contain exactly 32 bytes")
    digest_bits = tuple(
        (byte >> bit) & 1 for byte in digest for bit in range(8)
    )
    packed_values = []
    bit_offset = 0
    for width in _NULLIFIER_PACK_CHUNK_WIDTHS:
        packed_values.append(
            sum(
                bit << index
                for index, bit in enumerate(
                    digest_bits[bit_offset:bit_offset + width]
                )
            )
        )
        bit_offset += width
    if bit_offset != _NULLIFIER_BITS:
        raise R1CSError("internal Sapling nullifier multipacking width mismatch")
    return SaplingNullifierMultipackingWitness(
        digest_bits, (packed_values[0], packed_values[1])
    )


def constrain_sapling_nullifier_multipacking(
    system: R1CS,
    digest_bits: Sequence[CircuitBit],
    public_chunks: Sequence[Variable],
    witness: SaplingNullifierMultipackingWitness,
    label: str = "Sapling nullifier multipacking",
    *,
    digest_bits_preconstrained: bool = False,
) -> tuple[Variable, Variable]:
    """Constrain 256 little-endian digest bits to Spend public inputs 6 and 7.

    The Spend public-input order is ``rk.u, rk.v, cv.u, cv.v, anchor, nf[0],
    nf[1]``. Allocate those seven inputs before private variables. Bellman's
    field-capacity chunks are 254 bits followed by the remaining two bits.
    """
    bits = tuple(digest_bits)
    outputs = tuple(public_chunks)
    if len(bits) != _NULLIFIER_BITS:
        raise R1CSError("Sapling nullifier digest must contain exactly 256 bits")
    if len(outputs) != len(_NULLIFIER_PACK_CHUNK_WIDTHS):
        raise R1CSError("Sapling nullifier must use exactly two public chunks")
    if type(digest_bits_preconstrained) is not bool:
        raise TypeError("digest_bits_preconstrained must be a bool")
    if any(not isinstance(bit, (Variable, _NegatedBit)) for bit in bits):
        raise TypeError("Sapling nullifier digest bits must be R1CS-backed bits")
    if not digest_bits_preconstrained and any(
        not isinstance(bit, Variable) for bit in bits
    ):
        raise TypeError(
            "non-variable nullifier bits must be marked preconstrained"
        )
    if any(not isinstance(chunk, Variable) for chunk in outputs):
        raise TypeError("Sapling nullifier chunks must be R1CS public variables")
    backing_bits = tuple(
        bit.variable if isinstance(bit, _NegatedBit) else bit for bit in bits
    )
    for bit in backing_bits:
        system._require_owned(bit)
    for chunk in outputs:
        system._require_owned(chunk)
    if any(bit.kind != "private" for bit in backing_bits):
        raise R1CSError("Sapling nullifier digest bits must be private variables")
    if len({bit.index for bit in backing_bits}) != _NULLIFIER_BITS:
        raise R1CSError("Sapling nullifier digest bits must be distinct variables")
    if any(chunk.kind != "public" for chunk in outputs):
        raise R1CSError("Sapling nullifier chunks must be public inputs")
    if system.public_input_count != 7:
        raise R1CSError("Sapling Spend must expose exactly seven public inputs")
    if tuple(chunk.index for chunk in outputs) != _NULLIFIER_PUBLIC_INPUT_INDICES:
        raise R1CSError(
            "Sapling nullifier public inputs must occupy Spend positions 6 and 7"
        )
    if not isinstance(witness, SaplingNullifierMultipackingWitness):
        raise TypeError("witness must be a SaplingNullifierMultipackingWitness")
    if (
        not isinstance(witness.digest_bits, tuple)
        or not isinstance(witness.packed_values, tuple)
        or len(witness.digest_bits) != _NULLIFIER_BITS
        or len(witness.packed_values) != len(_NULLIFIER_PACK_CHUNK_WIDTHS)
        or any(type(value) is not int for value in witness.packed_values)
    ):
        raise R1CSError("Sapling nullifier multipacking witness has an invalid shape")

    assigned_bits = tuple(_read_blake_bit(system, bit) for bit in bits)
    if assigned_bits != witness.digest_bits:
        raise R1CSError("nullifier multipacking witness does not match digest bits")
    if any(type(bit) is not int or bit not in (0, 1) for bit in witness.digest_bits):
        raise R1CSError("nullifier multipacking witness contains a non-Boolean bit")

    offset = 0
    for index, width in enumerate(_NULLIFIER_PACK_CHUNK_WIDTHS):
        chunk_bits = witness.digest_bits[offset:offset + width]
        value = sum(bit << bit_index for bit_index, bit in enumerate(chunk_bits))
        if witness.packed_values[index] != value:
            raise R1CSError("nullifier multipacking witness chunk is inconsistent")
        if value >= 1 << width or value >= CIRCUIT_FIELD_MODULUS:
            raise R1CSError("nullifier chunk is not a canonical scalar-field value")
        offset += width

    if offset != _NULLIFIER_BITS:
        raise R1CSError("internal Sapling nullifier multipacking width mismatch")
    if any((1 << width) > CIRCUIT_FIELD_MODULUS for width in _NULLIFIER_PACK_CHUNK_WIDTHS):
        raise R1CSError("nullifier multipacking chunks are not injective in the field")

    offset = 0
    for index, (chunk, width) in enumerate(
        zip(outputs, _NULLIFIER_PACK_CHUNK_WIDTHS)
    ):
        chunk_bits = bits[offset:offset + width]
        if not digest_bits_preconstrained:
            for bit_index, bit in enumerate(chunk_bits):
                if not isinstance(bit, Variable):
                    raise TypeError(
                        "preconstrained aliases are required for nullifier digest bits"
                    )
                system.boolean(bit, f"{label} bit[{offset + bit_index}]")
        packed_expression = _bit_expression(
            system,
            tuple((bit, 1 << bit_index) for bit_index, bit in enumerate(chunk_bits)),
            0,
        )
        system.enforce_equal(
            chunk, packed_expression, f"{label} public chunk[{index}]"
        )
        offset += width
    return outputs[0], outputs[1]


@lru_cache(maxsize=64)
def _is_valid_fixed_base(base: Point) -> bool:
    return base.is_on_curve() and base.is_in_subgroup()


@lru_cache(maxsize=64)
def _fixed_base_window(base: Point) -> tuple[Point, ...]:
    entries = [IDENTITY]
    multiple = base
    for _ in range(7):
        entries.append(multiple)
        multiple = multiple + base
    return tuple(entries)


@lru_cache(maxsize=64)
def _fixed_base_tables(base: Point) -> tuple[tuple[Point, ...], ...]:
    windows = []
    window_base = base
    for _ in range(_FIXED_BASE_WINDOW_COUNT):
        windows.append(_fixed_base_window(window_base))
        window_base = windows[-1][-1] + window_base
    return tuple(windows)


def make_pedersen_witness(
    personalization_bits: Sequence[int], message_bits: Sequence[int]
) -> PedersenWitness:
    """Generate witness points for the upstream 3-bit Sapling Pedersen lookup."""
    if len(personalization_bits) != 6:
        raise R1CSError("Pedersen personalization must contain exactly six bits")
    values = tuple(_require_bit(bit) for bit in personalization_bits) + tuple(
        _require_bit(bit) for bit in message_bits
    )
    padded = values + (0,) * (-len(values) % 3)
    chunks = len(padded) // 3
    segment_count = (
        chunks + _PEDERSEN_CHUNKS_PER_GENERATOR - 1
    ) // _PEDERSEN_CHUNKS_PER_GENERATOR
    if segment_count > _PEDERSEN_GENERATOR_COUNT:
        raise R1CSError("Pedersen input exceeds the pinned generator capacity")

    tables = _pedersen_tables()
    selected = []
    segment_accumulators = []
    segment_results = []
    for segment_index in range(segment_count):
        start = segment_index * _PEDERSEN_CHUNKS_PER_GENERATOR
        end = min(start + _PEDERSEN_CHUNKS_PER_GENERATOR, chunks)
        accumulators = []
        accumulator = None
        for chunk_index in range(start, end):
            bits = padded[3 * chunk_index:3 * chunk_index + 3]
            pattern = bits[0] | bits[1] << 1 | bits[2] << 2
            point = tables[segment_index][chunk_index - start][pattern]
            selected.append(point)
            accumulator = point if accumulator is None else accumulator + point
            accumulators.append(accumulator)
        if accumulator is None:
            raise R1CSError("Pedersen input must not be empty")
        segment_accumulators.append(tuple(accumulators))
        segment_results.append(accumulator)

    combined_results = []
    result = segment_results[0]
    for segment in segment_results[1:]:
        result = result + segment
        combined_results.append(result)
    return PedersenWitness(
        values,
        tuple(selected),
        tuple(segment_accumulators),
        tuple(combined_results),
        result,
    )


def make_note_commitment_witness(
    value: int,
    diversifier_base: Point,
    transmission_key: Point,
    commitment_randomness: int,
) -> NoteCommitmentWitness:
    """Generate the upstream note-commitment witness trace from note fields."""
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise R1CSError("Sapling note value must be an unsigned 64-bit integer")
    if not isinstance(diversifier_base, Point) or not diversifier_base.is_on_curve():
        raise R1CSError("diversifier base must be a valid Jubjub point")
    if diversifier_base.multiply(8) == IDENTITY:
        raise R1CSError("diversifier base must not be small order")
    if not isinstance(transmission_key, Point):
        raise TypeError("transmission key must be a Jubjub Point")
    if (
        type(commitment_randomness) is not int
        or not 0 <= commitment_randomness < SCALAR_MODULUS
    ):
        raise R1CSError("note commitment randomness is outside the Jubjub scalar field")

    rcm_bits = tuple(
        (commitment_randomness >> index) & 1
        for index in range(SCALAR_MODULUS.bit_length())
    )
    message_bits = (
        _bits_le(value, 64)
        + _point_repr_bits(diversifier_base)
        + _point_repr_bits(transmission_key)
    )
    note_hash = make_pedersen_witness((1,) * 6, message_bits)
    randomness_mul = make_fixed_base_jubjub_witness(
        sapling_fixed_base_generator("note_commitment_randomness"),
        rcm_bits,
    )
    commitment = note_hash.result + randomness_mul.result
    return NoteCommitmentWitness(
        value,
        rcm_bits,
        note_hash,
        randomness_mul,
        commitment,
    )


def make_sapling_output_witness(
    value: int,
    diversifier: bytes,
    transmission_key: Point,
    value_commitment_randomness: int,
    commitment_randomness: int,
    esk: int,
) -> SaplingOutputWitness:
    """Generate an Output witness from a validated Sapling payment address."""
    if not isinstance(diversifier, bytes) or len(diversifier) != 11:
        raise R1CSError("Sapling diversifier must contain exactly 11 bytes")
    diversifier_base = group_hash(b"Zcash_gd", diversifier)
    if diversifier_base is None:
        raise R1CSError("Sapling diversifier does not map to a Jubjub point")
    if not isinstance(transmission_key, Point):
        raise TypeError("transmission key must be a Jubjub Point")
    if (
        not transmission_key.is_on_curve()
        or not transmission_key.is_in_subgroup()
        or transmission_key == IDENTITY
    ):
        raise R1CSError(
            "transmission key must be a non-identity Jubjub subgroup point"
        )

    value_commitment = make_sapling_value_commitment_witness(
        value, value_commitment_randomness
    )
    ephemeral_key = make_sapling_ephemeral_key_witness(
        diversifier_base, esk
    )
    note_commitment = make_note_commitment_witness(
        value,
        diversifier_base,
        transmission_key,
        commitment_randomness,
    )
    return SaplingOutputWitness(
        value,
        diversifier,
        diversifier_base,
        transmission_key,
        value_commitment_randomness,
        commitment_randomness,
        esk,
        value_commitment,
        ephemeral_key,
        note_commitment,
    )


def _validate_sapling_output_witness(witness: SaplingOutputWitness) -> None:
    if not isinstance(witness, SaplingOutputWitness):
        raise TypeError("witness must be a SaplingOutputWitness")
    if type(witness.value) is not int or not 0 <= witness.value < 1 << 64:
        raise R1CSError("Sapling value must be an unsigned 64-bit integer")
    for name in (
        "value_commitment_randomness",
        "commitment_randomness",
        "esk",
    ):
        scalar = getattr(witness, name)
        if type(scalar) is not int or not 0 <= scalar < SCALAR_MODULUS:
            raise R1CSError(f"Sapling Output {name} is outside jubjub::Fr")
    if not isinstance(witness.diversifier, bytes) or len(witness.diversifier) != 11:
        raise R1CSError("Sapling diversifier must contain exactly 11 bytes")
    if not isinstance(witness.diversifier_base, Point):
        raise R1CSError("Sapling diversifier base must be a Jubjub point")
    derived_base = group_hash(b"Zcash_gd", witness.diversifier)
    if derived_base is None or derived_base != witness.diversifier_base:
        raise R1CSError("Output witness diversifier base is inconsistent")
    if (
        not isinstance(witness.transmission_key, Point)
        or not witness.transmission_key.is_on_curve()
        or not witness.transmission_key.is_in_subgroup()
        or witness.transmission_key == IDENTITY
    ):
        raise R1CSError(
            "transmission key must be a non-identity Jubjub subgroup point"
        )
    if (
        not isinstance(witness.value_commitment, SaplingValueCommitmentWitness)
        or not isinstance(witness.ephemeral_key, SaplingEphemeralKeyWitness)
        or not isinstance(witness.note_commitment, NoteCommitmentWitness)
    ):
        raise TypeError("Output witness contains an invalid component witness")

    expected = make_sapling_output_witness(
        witness.value,
        witness.diversifier,
        witness.transmission_key,
        witness.value_commitment_randomness,
        witness.commitment_randomness,
        witness.esk,
    )
    if witness != expected:
        raise R1CSError(
            "Output witness components do not match their source inputs"
        )


def constrain_sapling_output(
    system: FreshSynthesisBackend,
    witness: SaplingOutputWitness,
    label: str = "Sapling Output",
) -> SaplingOutputResult:
    """Constrain the pinned Output relations and bind its five public inputs.

    The composed gadgets preserve the pinned Bellman allocation and row
    ordering. The complete witness is validated before allocation, and the
    backend must be fresh so these inputs occupy the Output public slots.
    """
    if not isinstance(system, FreshSynthesisBackend):
        raise TypeError("system must be a fresh SynthesisBackend")
    if not isinstance(witness, SaplingOutputWitness):
        raise TypeError("witness must be a SaplingOutputWitness")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if not system.is_fresh:
        raise R1CSError("Sapling Output synthesis requires a fresh backend")
    _validate_sapling_output_witness(witness)

    cv = witness.value_commitment.commitment
    epk = witness.ephemeral_key.ephemeral_key
    cmu = witness.note_commitment.commitment.u
    public_inputs = tuple(
        system.alloc_public(f"{label} public input[{index}]", value)
        for index, value in enumerate((cv.u, cv.v, epk.u, epk.v, cmu))
    )

    value_bits = tuple(
        system.alloc_private(f"{label} value bit[{index}]", bit)
        for index, bit in enumerate(witness.value_commitment.value_bits)
    )
    def allocate_value_randomness_bits() -> tuple[VariableLike, ...]:
        return tuple(
            system.alloc_private(f"{label} rcv bit[{index}]", bit)
            for index, bit in enumerate(
                witness.value_commitment.randomness_bits
            )
        )

    value_commitment = _constrain_sapling_value_commitment(
        system,
        value_bits,
        (),
        public_inputs[:2],
        witness.value_commitment,
        f"{label} value commitment",
        enforce_scalar_range=False,
        bellman_factorization=True,
        randomness_bit_allocator=allocate_value_randomness_bits,
    )

    value = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(value_bits))
    )

    diversifier_base = allocate_jubjub_point(
        system, f"{label} g_d", witness.diversifier_base
    )
    constrain_jubjub_point(
        system,
        diversifier_base,
        f"{label} ephemeral key g_d curve",
        bellman_factorization=True,
    )
    constrain_jubjub_not_small_order(
        system,
        diversifier_base,
        f"{label} ephemeral key g_d",
        bellman_allocation_order=True,
    )
    diversifier_repr = constrain_jubjub_repr(
        system,
        diversifier_base,
        f"{label} note commitment g_d representation",
        bellman_factorization=True,
    )
    esk_bits = _allocate_jubjub_scalar_bits(
        system,
        witness.ephemeral_key.esk_bits,
        f"{label} esk bit",
    )
    ephemeral_key = _constrain_sapling_ephemeral_key(
        system,
        diversifier_base,
        esk_bits,
        public_inputs[2:4],
        witness.ephemeral_key,
        f"{label} ephemeral key",
        bellman_factorization=True,
        diversifier_base_preconstrained=True,
    )

    transmission_key_repr = allocate_unchecked_jubjub_repr(
        system, f"{label} pk_d representation", witness.transmission_key
    )

    def allocate_commitment_randomness_bits() -> tuple[VariableLike, ...]:
        return tuple(
            system.alloc_private(f"{label} rcm bit[{index}]", bit)
            for index, bit in enumerate(witness.note_commitment.rcm_bits)
        )

    note_commitment = _constrain_note_commitment(
        system,
        value,
        diversifier_base,
        transmission_key_repr,
        (),
        witness.note_commitment,
        public_inputs[4],
        f"{label} note commitment",
        value_bits=value_bits,
        value_bits_preconstrained=True,
        validate_diversifier_base=False,
        enforce_scalar_range=False,
        pedersen_representation="montgomery",
        bellman_factorization=True,
        diversifier_repr=diversifier_repr,
        randomness_bit_allocator=allocate_commitment_randomness_bits,
    )
    return SaplingOutputResult(
        public_inputs,
        value_commitment,
        ephemeral_key,
        note_commitment,
    )


def constrain_note_commitment(
    system: R1CS,
    value: Variable | LinearCombination,
    diversifier_base: CircuitPoint,
    transmission_key_repr: Sequence[Variable],
    randomness_bits: Sequence[Variable],
    witness: NoteCommitmentWitness,
    commitment_u: Variable | None = None,
    label: str = "Sapling note commitment",
    value_bits: Sequence[Variable] | None = None,
    validate_diversifier_base: bool = True,
    *,
    value_bits_preconstrained: bool = False,
    transmission_key_repr_preconstrained: bool = False,
    randomness_bits_preconstrained: bool = False,
    enforce_scalar_range: bool = True,
    pedersen_representation: PedersenRepresentation = "edwards",
) -> CircuitPoint:
    """Constrain a note commitment without assuming caller bit constraints."""
    _validate_pedersen_representation(pedersen_representation)
    return _constrain_note_commitment(
        system,
        value,
        diversifier_base,
        transmission_key_repr,
        randomness_bits,
        witness,
        commitment_u,
        label,
        value_bits,
        value_bits_preconstrained=value_bits_preconstrained,
        transmission_key_repr_preconstrained=(
            transmission_key_repr_preconstrained
        ),
        randomness_bits_preconstrained=randomness_bits_preconstrained,
        validate_diversifier_base=validate_diversifier_base,
        enforce_scalar_range=enforce_scalar_range,
        pedersen_representation=pedersen_representation,
    )


def _constrain_note_commitment(
    system: SynthesisBackend,
    value: VariableLike | LinearCombinationLike,
    diversifier_base: tuple[VariableLike, VariableLike],
    transmission_key_repr: Sequence[VariableLike],
    randomness_bits: Sequence[VariableLike],
    witness: NoteCommitmentWitness,
    commitment_u: VariableLike | None = None,
    label: str = "Sapling note commitment",
    value_bits: Sequence[VariableLike] | None = None,
    value_bits_preconstrained: bool = False,
    transmission_key_repr_preconstrained: bool = False,
    randomness_bits_preconstrained: bool = False,
    validate_diversifier_base: bool = True,
    enforce_scalar_range: bool = True,
    pedersen_representation: PedersenRepresentation = "edwards",
    *,
    bellman_factorization: bool = False,
    diversifier_repr: Sequence[VariableLike] | None = None,
    randomness_bit_allocator: Callable[[], Sequence[VariableLike]] | None = None,
) -> tuple[VariableLike, VariableLike]:
    """Constrain value, recipient representation, Pedersen hash, and rcm point.

    `diversifier_base` is the circuit's g_d point, not the diversifier bytes.
    The upstream circuit derives g_d from the address diversifier before
    synthesis, then constrains g_d on-curve and not-small-order. `pk_d` is
    represented by 255 v bits and a u sign bit; the Output circuit does not
    separately constrain pk_d curve membership. `value_bits` can reuse an
    already range-checked value decomposition;
    `value_bits_preconstrained=True` is only valid when the caller has already
    constrained every supplied bit to Boolean. Set
    `transmission_key_repr_preconstrained=True` only for a representation
    already produced by the constrained Jubjub representation gadget, and
    `randomness_bits_preconstrained=True` only when the caller has already
    Boolean-constrained every `rcm` bit. Set
    `validate_diversifier_base=False` only when the caller has already
    constrained that same base to be on-curve and non-small-order.
    """
    if isinstance(value, VariableLike):
        system.require_owned(value)
        value_expression = value.lc()
    elif isinstance(value, LinearCombinationLike):
        value_expression = value
    else:
        raise TypeError("note value must be a variable or linear combination")
    _require_point(system, diversifier_base)
    if len(transmission_key_repr) != 256:
        raise R1CSError("transmission-key representation must contain 256 bits")
    deferred_randomness = randomness_bit_allocator is not None
    if deferred_randomness:
        if randomness_bits:
            raise R1CSError(
                "deferred note randomness allocation cannot include preallocated bits"
            )
        if not callable(randomness_bit_allocator):
            raise TypeError("randomness bit allocator must be callable")
    elif len(randomness_bits) != SCALAR_MODULUS.bit_length():
        raise R1CSError(
            "note randomness must contain the Jubjub scalar field bit width"
        )
    if type(validate_diversifier_base) is not bool:
        raise TypeError("validate_diversifier_base must be a bool")
    if type(enforce_scalar_range) is not bool:
        raise TypeError("enforce_scalar_range must be a bool")
    if type(bellman_factorization) is not bool:
        raise TypeError("bellman_factorization must be a bool")
    if type(value_bits_preconstrained) is not bool:
        raise TypeError("value_bits_preconstrained must be a bool")
    if type(transmission_key_repr_preconstrained) is not bool:
        raise TypeError("transmission_key_repr_preconstrained must be a bool")
    if type(randomness_bits_preconstrained) is not bool:
        raise TypeError("randomness_bits_preconstrained must be a bool")
    if not isinstance(witness, NoteCommitmentWitness):
        raise TypeError("witness must be a NoteCommitmentWitness")
    note_value_bits = None if value_bits is None else tuple(value_bits)
    if note_value_bits is not None and len(note_value_bits) != 64:
        raise R1CSError("note value must contain exactly 64 little-endian bits")
    for bit in (
        (() if note_value_bits is None else note_value_bits)
        + tuple(transmission_key_repr)
        + (() if deferred_randomness else tuple(randomness_bits))
    ):
        system.require_owned(bit)
    if commitment_u is not None:
        if system.public_input_position(commitment_u) is None:
            raise R1CSError("commitment_u must be allocated as a public input")

    value_value = system.linear_combination_value(value_expression)
    if value_value != witness.value:
        raise R1CSError("note-commitment witness value does not match the assignment")
    if not deferred_randomness and tuple(
        _read_backend_bit(
            system, bit, "Pedersen input bit is unassigned or invalid"
        )
        for bit in randomness_bits
    ) != witness.rcm_bits:
        raise R1CSError("note randomness witness does not match its assigned bits")
    if len(witness.note_hash.bit_values) != 6 + 64 + 256 + 256:
        raise R1CSError("note hash witness has an invalid input length")

    if note_value_bits is None:
        if not isinstance(value, VariableLike):
            raise R1CSError(
                "note value bits are required when value is a linear combination"
            )
        note_value_bits = _range_check_backend(
            system, value, 64, f"{label} value bit"
        )
    else:
        if not value_bits_preconstrained:
            for index, bit in enumerate(note_value_bits):
                system.boolean(bit, f"{label} shared value bit[{index}]")
        value_encoding = system.linear_combination(
            tuple((bit, 1 << index) for index, bit in enumerate(note_value_bits))
        )
        if value_expression != value_encoding:
            system.enforce_equal(
                value_expression, value_encoding, f"{label} value encoding"
            )

    if validate_diversifier_base:
        constrain_jubjub_point(system, diversifier_base, f"{label} g_d curve")
        constrain_jubjub_not_small_order(
            system,
            diversifier_base,
            f"{label} g_d",
            bellman_allocation_order=bellman_factorization,
        )
    if diversifier_repr is None:
        diversifier_repr = constrain_jubjub_repr(
            system,
            diversifier_base,
            f"{label} g_d representation",
            bellman_factorization=bellman_factorization,
        )
    elif len(diversifier_repr) != 256:
        raise R1CSError("diversifier representation must contain 256 bits")
    else:
        for bit in diversifier_repr:
            system.require_owned(bit)
    if not transmission_key_repr_preconstrained:
        for index, bit in enumerate(transmission_key_repr):
            _constrain_jubjub_scalar_bit(
                system,
                bit,
                f"{label} pk_d representation[{index}]",
                bellman_factorization=bellman_factorization,
            )
    if not randomness_bits_preconstrained and not bellman_factorization:
        for index, bit in enumerate(randomness_bits):
            _constrain_jubjub_scalar_bit(
                system,
                bit,
                f"{label} rcm bit[{index}]",
                bellman_factorization=bellman_factorization,
            )

    message_bits = note_value_bits + diversifier_repr + tuple(transmission_key_repr)
    expected_message = (
        _bits_le(witness.value, 64)
        + witness.note_hash.bit_values[6 + 64:6 + 64 + 256]
        + witness.note_hash.bit_values[-256:]
    )
    if tuple(
        _read_backend_bit(
            system, bit, "Pedersen input bit is unassigned or invalid"
        )
        for bit in message_bits
    ) != expected_message:
        raise R1CSError("note fields do not match the Pedersen witness")
    note_hash = constrain_pedersen_hash(
        system,
        (1,) * 6,
        message_bits,
        witness.note_hash,
        f"{label} content hash",
        message_bits_preconstrained=True,
        representation=pedersen_representation,
    )

    if randomness_bit_allocator is not None:
        randomness_bits = tuple(randomness_bit_allocator())
        if len(randomness_bits) != SCALAR_MODULUS.bit_length():
            raise R1CSError("allocated note randomness has an invalid bit width")
        for bit in randomness_bits:
            if not isinstance(bit, VariableLike):
                raise TypeError(
                    "allocated note randomness must use backend variables"
                )
            system.require_owned(bit)
        if tuple(
            _read_backend_bit(
                system, bit, "Pedersen input bit is unassigned or invalid"
            )
            for bit in randomness_bits
        ) != witness.rcm_bits:
            raise R1CSError("note randomness witness does not match its assigned bits")

    if not randomness_bits_preconstrained and bellman_factorization:
        for index, bit in enumerate(randomness_bits):
            _constrain_jubjub_scalar_bit(
                system,
                bit,
                f"{label} rcm bit[{index}]",
                bellman_factorization=True,
            )

    randomness_point = _constrain_fixed_base_jubjub_mul(
        system,
        sapling_fixed_base_generator("note_commitment_randomness"),
        randomness_bits,
        witness.randomness_mul,
        f"{label} randomness multiplication",
        enforce_scalar_range=enforce_scalar_range,
        bits_preconstrained=(
            randomness_bits_preconstrained or not enforce_scalar_range
        ),
        bellman_factorization=bellman_factorization,
    )
    if bellman_factorization:
        commitment = _constrain_jubjub_add_with_allocated_result(
            system,
            note_hash,
            randomness_point,
            witness.commitment,
            f"{label} randomized point",
            f"{label} randomization",
        )
    else:
        commitment = allocate_jubjub_point(
            system, f"{label} randomized point", witness.commitment
        )
        constrain_jubjub_add(
            system,
            note_hash,
            randomness_point,
            commitment,
            f"{label} randomization",
        )
    if commitment_u is not None:
        if bellman_factorization:
            system.enforce(commitment_u, 1, commitment[0], f"{label} public commitment u")
        else:
            system.enforce_equal(
                commitment[0], commitment_u, f"{label} public commitment u"
            )
    return commitment


def make_merkle_path_witness(
    leaf: int, siblings: Sequence[int], position: int
) -> MerklePathWitness:
    """Generate the 32-level little-endian authentication-path trace."""
    _validate_merkle_path_inputs(leaf, siblings, position)
    current = leaf
    hashes = []
    for level, sibling in enumerate(siblings):
        if position >> level & 1:
            left, right = sibling, current
        else:
            left, right = current, sibling
        personalization = _bits_le(level, 6)
        preimage = personalization + _bits_le(left, 255) + _bits_le(right, 255)
        pedersen = make_pedersen_witness(personalization, preimage[6:])
        hashes.append(pedersen)
        current = pedersen.result.u
    return MerklePathWitness(position, tuple(siblings), tuple(hashes))


def constrain_merkle_authentication_path(
    system: R1CS,
    leaf: Variable,
    anchor: Variable,
    witness: MerklePathWitness,
    label: str = "Sapling Merkle authentication path",
    *,
    note_value: Variable | LinearCombination | None = None,
    pedersen_representation: PedersenRepresentation = "edwards",
) -> MerklePathResult:
    """Constrain a 32-level path and its anchor relation.

    Pass the already-constrained note value to use Sapling Spend's
    value-conditional anchor relation. Without it, this standalone Merkle
    gadget retains its strict root-to-anchor equality behavior.
    """
    _validate_pedersen_representation(pedersen_representation)
    system._require_owned(leaf)
    system._require_owned(anchor)
    if anchor.kind != "public":
        raise R1CSError("Merkle anchor must be allocated as a public input")
    if not isinstance(witness, MerklePathWitness):
        raise TypeError("witness must be a MerklePathWitness")
    _validate_merkle_path_inputs(
        system._witness_value(leaf), witness.siblings, witness.position
    )
    if len(witness.pedersen_hashes) != 32:
        raise R1CSError("Sapling authentication path must contain exactly 32 hashes")

    position = system.alloc_private(f"{label} position", witness.position)
    position_bits = system.range_check(position, 32, f"{label} position bit")
    current = leaf
    siblings = []
    intermediate_roots = []
    for level, sibling_value in enumerate(witness.siblings):
        sibling = system.alloc_private(
            f"{label} sibling[{level}]", sibling_value
        )
        siblings.append(sibling)
        bit = position_bits[level]
        current_value = system._witness_value(current)
        bit_value = system._witness_value(bit)
        selected_left_value = (
            sibling_value if bit_value else current_value
        )
        selected_right_value = (
            current_value if bit_value else sibling_value
        )
        left = system.alloc_private(
            f"{label} left[{level}]", selected_left_value
        )
        right = system.alloc_private(
            f"{label} right[{level}]", selected_right_value
        )
        system.enforce(
            sibling.lc() - current,
            bit,
            left.lc() - current,
            f"{label} left select[{level}]",
        )
        system.enforce(
            current.lc() - sibling,
            bit,
            right.lc() - sibling,
            f"{label} right select[{level}]",
        )
        left_bits = system.range_check(left, 255, f"{label} left bit[{level}]")
        right_bits = system.range_check(right, 255, f"{label} right bit[{level}]")
        personalization = _bits_le(level, 6)
        parent = constrain_pedersen_hash(
            system,
            personalization,
            left_bits + right_bits,
            witness.pedersen_hashes[level],
            f"{label} hash[{level}]",
            message_bits_preconstrained=True,
            representation=pedersen_representation,
        )
        current = parent[0]
        intermediate_roots.append(current)
    if note_value is None:
        system.enforce_equal(current, anchor, f"{label} anchor equality")
    else:
        constrain_sapling_conditional_anchor(
            system,
            current,
            anchor,
            note_value,
            f"{label} conditional anchor",
        )
    return MerklePathResult(
        current,
        position_bits,
        tuple(siblings),
        tuple(intermediate_roots),
    )


def constrain_sapling_conditional_anchor(
    system: R1CS,
    root: Variable,
    anchor: Variable,
    note_value: Variable | LinearCombination,
    label: str = "Sapling conditional anchor",
) -> None:
    """Require ``root == anchor`` when the bit-derived note value is nonzero.

    The caller must pass the same 64-bit value-opening bits used by note
    commitment. A zero value intentionally leaves the public anchor
    unconstrained, matching the pinned Spend circuit.
    """
    for variable in (root, anchor):
        system._require_owned(variable)
    if isinstance(note_value, Variable):
        system._require_owned(note_value)
        note_value_expression = note_value.lc()
        note_value_is_private = note_value.kind == "private"
    elif isinstance(note_value, LinearCombination):
        system._validate_linear_combination(note_value)
        note_value_expression = note_value
        note_value_is_private = all(
            system.variables[index].kind in ("one", "private")
            for index, _ in note_value.terms
        ) and any(
            system.variables[index].kind == "private"
            for index, _ in note_value.terms
        )
    else:
        raise TypeError(
            "Sapling note value must be a variable or linear combination"
        )
    if root.kind != "private":
        raise R1CSError("computed Merkle root must be a private variable")
    if anchor.kind != "public":
        raise R1CSError("Sapling anchor must be allocated as a public input")
    if not note_value_is_private:
        raise R1CSError(
            "Sapling note value must be private or composed from private variables"
        )
    system.enforce(
        root.lc() - anchor,
        note_value_expression,
        0,
        label,
    )


@overload
def constrain_pedersen_hash(
    system: R1CS,
    personalization_bits: Sequence[CircuitBit],
    message_bits: Sequence[CircuitBit],
    witness: PedersenWitness,
    label: str = "Sapling Pedersen hash",
    *,
    message_bits_preconstrained: bool = False,
    representation: PedersenRepresentation = "edwards",
) -> CircuitPoint:
    ...


@overload
def constrain_pedersen_hash(
    system: SynthesisBackend,
    personalization_bits: Sequence[CircuitBit | VariableLike],
    message_bits: Sequence[CircuitBit | VariableLike],
    witness: PedersenWitness,
    label: str = "Sapling Pedersen hash",
    *,
    message_bits_preconstrained: bool = False,
    representation: PedersenRepresentation = "edwards",
) -> tuple[VariableLike, VariableLike]:
    ...


def constrain_pedersen_hash(
    system: SynthesisBackend,
    personalization_bits: Sequence[CircuitBit | VariableLike],
    message_bits: Sequence[CircuitBit | VariableLike],
    witness: PedersenWitness,
    label: str = "Sapling Pedersen hash",
    *,
    message_bits_preconstrained: bool = False,
    representation: PedersenRepresentation = "edwards",
) -> tuple[VariableLike, VariableLike]:
    """Constrain a Pedersen hash with the selected intermediate representation."""
    _validate_pedersen_representation(representation)
    if representation == "montgomery":
        return _constrain_pedersen_hash_montgomery(
            system,
            personalization_bits,
            message_bits,
            witness,
            label,
            message_bits_preconstrained,
        )
    return _constrain_pedersen_hash(
        system,
        personalization_bits,
        message_bits,
        witness,
        label,
        message_bits_preconstrained=message_bits_preconstrained,
    )


def _constrain_pedersen_hash(
    system: SynthesisBackend,
    personalization_bits: Sequence[CircuitBit | VariableLike],
    message_bits: Sequence[CircuitBit | VariableLike],
    witness: PedersenWitness,
    label: str = "Sapling Pedersen hash",
    message_bits_preconstrained: bool = False,
) -> CircuitPoint:
    """Constrain the six-bit prefix, lookup windows, and group additions.

    ``message_bits_preconstrained=True`` skips Boolean equations only for
    message bits already constrained by the caller.
    """
    if len(personalization_bits) != 6:
        raise R1CSError("Pedersen personalization must contain exactly six bits")
    if type(message_bits_preconstrained) is not bool:
        raise TypeError("message_bits_preconstrained must be a bool")
    bits = tuple(personalization_bits) + tuple(message_bits)
    if not bits:
        raise R1CSError("Pedersen input must not be empty")
    if not isinstance(witness, PedersenWitness):
        raise TypeError("witness must be a PedersenWitness")
    padded: tuple[CircuitBit | VariableLike, ...] = bits + (0,) * (-len(bits) % 3)
    if tuple(_read_pedersen_bit(system, bit) for bit in bits) != witness.bit_values:
        raise R1CSError("Pedersen witness does not match the assigned input bits")
    chunks = len(padded) // 3
    segment_count = (
        chunks + _PEDERSEN_CHUNKS_PER_GENERATOR - 1
    ) // _PEDERSEN_CHUNKS_PER_GENERATOR
    if segment_count > _PEDERSEN_GENERATOR_COUNT:
        raise R1CSError("Pedersen input exceeds the pinned generator capacity")
    if len(witness.selected_points) != chunks or len(
        witness.segment_accumulators
    ) != segment_count:
        raise R1CSError("Pedersen witness has an invalid shape")
    if len(witness.combined_results) != segment_count - 1:
        raise R1CSError("Pedersen witness has an invalid segment combination trace")

    for index, bit in enumerate(padded):
        should_constrain = not (
            message_bits_preconstrained and index >= len(personalization_bits)
        )
        if isinstance(bit, VariableLike):
            if should_constrain:
                _constrain_jubjub_scalar_bit(
                    system, bit, f"{label} input bit[{index}]"
                )
        elif bit not in (0, 1) or type(bit) not in (int, bool):
            raise R1CSError("Pedersen input must contain only bit variables or bits")

    tables = _pedersen_tables()
    selected_points = []
    for chunk_index in range(chunks):
        segment_index, segment_offset = divmod(
            chunk_index, _PEDERSEN_CHUNKS_PER_GENERATOR
        )
        a, b, c = padded[3 * chunk_index:3 * chunk_index + 3]
        selected = allocate_jubjub_point(
            system,
            f"{label} selected[{chunk_index}]",
            witness.selected_points[chunk_index],
        )
        table = tables[segment_index][segment_offset]
        _constrain_signed_lookup3_point(
            system,
            (a, b, c),
            table,
            selected,
            f"{label} lookup[{chunk_index}]",
        )
        selected_points.append(selected)

    segment_points = []
    for segment_index, accumulators in enumerate(witness.segment_accumulators):
        first = segment_index * _PEDERSEN_CHUNKS_PER_GENERATOR
        last = min(first + _PEDERSEN_CHUNKS_PER_GENERATOR, chunks)
        if len(accumulators) != last - first:
            raise R1CSError("Pedersen witness has an invalid segment trace")
        current = selected_points[first]
        for offset in range(1, last - first):
            next_point = allocate_jubjub_point(
                system,
                f"{label} segment[{segment_index}] sum[{offset}]",
                accumulators[offset],
            )
            constrain_jubjub_add(
                system,
                current,
                selected_points[first + offset],
                next_point,
                f"{label} segment[{segment_index}] addition[{offset}]",
            )
            current = next_point
        segment_points.append(current)

    result = segment_points[0]
    if len(witness.combined_results) != len(segment_points) - 1:
        raise R1CSError("Pedersen witness has an invalid segment combination trace")
    for index, segment in enumerate(segment_points[1:]):
        combined = allocate_jubjub_point(
            system,
            f"{label} segment combination[{index}]",
            witness.combined_results[index],
        )
        constrain_jubjub_add(
            system,
            result,
            segment,
            combined,
            f"{label} segment addition[{index}]",
        )
        result = combined
    return result


def _constrain_pedersen_hash_montgomery(
    system: SynthesisBackend,
    personalization_bits: Sequence[CircuitBit | VariableLike],
    message_bits: Sequence[CircuitBit | VariableLike],
    witness: PedersenWitness,
    label: str,
    message_bits_preconstrained: bool,
) -> CircuitPoint:
    if len(personalization_bits) != 6:
        raise R1CSError("Pedersen personalization must contain exactly six bits")
    if type(message_bits_preconstrained) is not bool:
        raise TypeError("message_bits_preconstrained must be a bool")
    bits = tuple(personalization_bits) + tuple(message_bits)
    if not bits:
        raise R1CSError("Pedersen input must not be empty")
    if not isinstance(witness, PedersenWitness):
        raise TypeError("witness must be a PedersenWitness")
    if tuple(_read_pedersen_bit(system, bit) for bit in bits) != witness.bit_values:
        raise R1CSError("Pedersen witness does not match the assigned input bits")

    chunks = (len(bits) + 2) // 3
    segment_count = (chunks + _PEDERSEN_CHUNKS_PER_GENERATOR - 1) // (
        _PEDERSEN_CHUNKS_PER_GENERATOR
    )
    if segment_count > _PEDERSEN_GENERATOR_COUNT:
        raise R1CSError("Pedersen input exceeds the pinned generator capacity")
    if len(witness.selected_points) != chunks or len(
        witness.segment_accumulators
    ) != segment_count:
        raise R1CSError("Pedersen witness has an invalid shape")

    for index, bit in enumerate(bits):
        should_constrain = not (
            message_bits_preconstrained and index >= 6
        )
        if isinstance(bit, VariableLike):
            if should_constrain:
                _constrain_jubjub_scalar_bit(
                    system, bit, f"{label} input bit[{index}]"
                )
        elif isinstance(bit, _NegatedBit):
            if should_constrain:
                _constrain_jubjub_scalar_bit(
                    system, bit.variable, f"{label} input bit[{index}]"
                )
        else:
            _require_bit(bit)

    tables = _pedersen_montgomery_tables()
    edwards_result: tuple[_PedersenNum, _PedersenNum] | None = None
    bit_offset = 0
    for segment_index in range(segment_count):
        first_chunk = segment_index * _PEDERSEN_CHUNKS_PER_GENERATOR
        segment_chunks = min(
            _PEDERSEN_CHUNKS_PER_GENERATOR, chunks - first_chunk
        )
        if len(witness.segment_accumulators[segment_index]) != segment_chunks:
            raise R1CSError("Pedersen witness has an invalid segment trace")

        segment_result: tuple[_PedersenNum, _PedersenNum] | None = None
        for window_index in range(segment_chunks):
            chunk = bits[bit_offset:bit_offset + 3]
            bit_offset += len(chunk)
            chunk = chunk + (0,) * (3 - len(chunk))
            selected = _constrain_pedersen_montgomery_lookup(
                system,
                chunk,
                tables[segment_index][window_index],
                f"{label} segment[{segment_index}] window[{window_index}]",
            )
            if segment_result is None:
                segment_result = selected
            else:
                segment_result = _constrain_pedersen_montgomery_add(
                    system,
                    selected,
                    segment_result,
                    f"{label} segment[{segment_index}] addition[{window_index}]",
                )
        if segment_result is None:
            raise R1CSError("Pedersen segment has no windows")
        converted = _constrain_pedersen_montgomery_to_edwards(
            system,
            segment_result,
            f"{label} segment[{segment_index}] conversion",
        )
        if edwards_result is None:
            edwards_result = converted
        else:
            edwards_result = _constrain_pedersen_edwards_add(
                system,
                converted,
                edwards_result,
                f"{label} segment[{segment_index}] combination",
            )
    if edwards_result is None:
        raise R1CSError("Pedersen input must not be empty")
    result = edwards_result
    if result[0].value != witness.result.u or result[1].value != witness.result.v:
        raise R1CSError("Pedersen witness result does not match its assigned inputs")
    if result[0].variable is None or result[1].variable is None:
        raise AssertionError("Montgomery Pedersen output coordinates are unallocated")
    return result[0].variable, result[1].variable


def _pedersen_mobius_coefficients(
    values: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    zero, one, two, three = values
    return zero, one - zero, two - zero, three - two - one + zero


def _pedersen_lookup_expression(
    system: SynthesisBackend,
    values: tuple[int, int, int, int],
    first: CircuitBit | VariableLike,
    second: CircuitBit | VariableLike,
    precomp: CircuitBit | VariableLike,
) -> LinearCombinationLike:
    coefficients = _pedersen_mobius_coefficients(values)
    constant = coefficients[0]
    terms: list[tuple[VariableLike, int]] = []
    for bit, coefficient in zip((first, second, precomp), coefficients[1:]):
        if isinstance(bit, VariableLike):
            terms.append((bit, coefficient))
        elif isinstance(bit, _NegatedBit):
            terms.append((bit.variable, -coefficient))
            constant += coefficient
        elif type(bit) in (int, bool) and bit in (0, 1):
            constant += int(bit) * coefficient
        else:
            raise R1CSError("Pedersen lookup input must be a bit")
    return system.linear_combination(terms, constant)


def _constrain_pedersen_montgomery_lookup(
    system: SynthesisBackend,
    bits: tuple[CircuitBit | VariableLike, CircuitBit | VariableLike, CircuitBit | VariableLike],
    table: tuple[tuple[int, int], ...],
    label: str,
) -> tuple[_PedersenNum, _PedersenNum]:
    if len(table) != 4:
        raise R1CSError("signed Pedersen lookup requires four Montgomery points")
    a, b, sign = bits
    index = _read_pedersen_bit(system, a) + 2 * _read_pedersen_bit(system, b)
    sign_value = _read_pedersen_bit(system, sign)
    x_values = tuple(point[0] for point in table)
    y_values = tuple(point[1] for point in table)
    x_value = x_values[index]
    y_value = (y_values[index] * (-1 if sign_value else 1)) % (
        CIRCUIT_FIELD_MODULUS
    )

    y = system.alloc_private(f"{label} y", y_value)
    precomp = _constrained_bit_and(system, a, b, f"{label} precomp")
    x_expression = _pedersen_lookup_expression(
        system, x_values, a, b, precomp
    )
    y_expression = _pedersen_lookup_expression(
        system, y_values, a, b, precomp
    )
    system.enforce(
        2 * y_expression,
        _bit_expression(system, ((sign, 1),), 0),
        y_expression - y,
        f"{label} conditional y lookup",
    )
    return (
        _PedersenNum(x_expression, x_value),
        _PedersenNum(y.lc(), y_value, y),
    )


def _constrain_pedersen_montgomery_add(
    system: SynthesisBackend,
    left: tuple[_PedersenNum, _PedersenNum],
    right: tuple[_PedersenNum, _PedersenNum],
    label: str,
) -> tuple[_PedersenNum, _PedersenNum]:
    x1, y1 = left
    x2, y2 = right
    denominator = (x2.value - x1.value) % CIRCUIT_FIELD_MODULUS
    if denominator == 0:
        raise R1CSError("Montgomery Pedersen addition has equal x coordinates")
    lam_value = (
        (y2.value - y1.value)
        * pow(denominator, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    ) % CIRCUIT_FIELD_MODULUS
    lam = system.alloc_private(f"{label} lambda", lam_value)
    system.enforce(
        x2.expression - x1.expression,
        lam,
        y2.expression - y1.expression,
        f"{label} evaluate lambda",
    )

    x_value = (
        lam_value * lam_value
        - _PEDERSEN_MONTGOMERY_A
        - x1.value
        - x2.value
    ) % CIRCUIT_FIELD_MODULUS
    x = system.alloc_private(f"{label} xprime", x_value)
    system.enforce(
        lam,
        lam,
        _PEDERSEN_MONTGOMERY_A + x1.expression + x2.expression + x,
        f"{label} evaluate xprime",
    )

    y_value = (
        -y1.value - lam_value * (x_value - x1.value)
    ) % CIRCUIT_FIELD_MODULUS
    y = system.alloc_private(f"{label} yprime", y_value)
    system.enforce(
        x1.expression - x,
        lam,
        y + y1.expression,
        f"{label} evaluate yprime",
    )
    return _PedersenNum(x.lc(), x_value, x), _PedersenNum(y.lc(), y_value, y)


def _constrain_pedersen_montgomery_to_edwards(
    system: SynthesisBackend,
    point: tuple[_PedersenNum, _PedersenNum],
    label: str,
) -> tuple[_PedersenNum, _PedersenNum]:
    x, y = point
    if y.value == 0 or (x.value + 1) % CIRCUIT_FIELD_MODULUS == 0:
        raise R1CSError("Montgomery Pedersen conversion has a zero denominator")
    u_value = (
        _PEDERSEN_MONTGOMERY_SCALE
        * x.value
        * pow(y.value, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    ) % CIRCUIT_FIELD_MODULUS
    u = system.alloc_private(f"{label} u", u_value)
    system.enforce(
        y.expression,
        u,
        _PEDERSEN_MONTGOMERY_SCALE * x.expression,
        f"{label} u computation",
    )

    v_value = (
        (x.value - 1)
        * pow(x.value + 1, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    ) % CIRCUIT_FIELD_MODULUS
    v = system.alloc_private(f"{label} v", v_value)
    system.enforce(
        x.expression + 1,
        v,
        x.expression - 1,
        f"{label} v computation",
    )
    return _PedersenNum(u.lc(), u_value, u), _PedersenNum(v.lc(), v_value, v)


def _constrain_pedersen_edwards_add(
    system: SynthesisBackend,
    left: tuple[_PedersenNum, _PedersenNum],
    right: tuple[_PedersenNum, _PedersenNum],
    label: str,
) -> tuple[_PedersenNum, _PedersenNum]:
    u1, v1 = left
    u2, v2 = right
    uppercase_value = (
        (u1.value + v1.value) * (u2.value + v2.value)
    ) % CIRCUIT_FIELD_MODULUS
    uppercase = system.alloc_private(f"{label} U", uppercase_value)
    system.enforce(
        u1.expression + v1.expression,
        u2.expression + v2.expression,
        uppercase,
        f"{label} U computation",
    )

    a_value = v2.value * u1.value % CIRCUIT_FIELD_MODULUS
    a = system.alloc_private(f"{label} A", a_value)
    system.enforce(v2.expression, u1.expression, a, f"{label} A computation")

    b_value = u2.value * v1.value % CIRCUIT_FIELD_MODULUS
    b = system.alloc_private(f"{label} B", b_value)
    system.enforce(u2.expression, v1.expression, b, f"{label} B computation")

    c_value = CURVE_D * a_value * b_value % CIRCUIT_FIELD_MODULUS
    c = system.alloc_private(f"{label} C", c_value)
    system.enforce(CURVE_D * a.lc(), b, c, f"{label} C computation")
    if (1 + c_value) % CIRCUIT_FIELD_MODULUS == 0 or (
        1 - c_value
    ) % CIRCUIT_FIELD_MODULUS == 0:
        raise R1CSError("Pedersen Edwards addition has a zero denominator")

    u3_value = (
        (a_value + b_value)
        * pow(1 + c_value, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    ) % CIRCUIT_FIELD_MODULUS
    u3 = system.alloc_private(f"{label} u3", u3_value)
    system.enforce(
        1 + c.lc(),
        u3,
        a.lc() + b.lc(),
        f"{label} u3 computation",
    )

    v3_value = (
        (uppercase_value - a_value - b_value)
        * pow(1 - c_value, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
    ) % CIRCUIT_FIELD_MODULUS
    v3 = system.alloc_private(f"{label} v3", v3_value)
    system.enforce(
        1 - c.lc(),
        v3,
        uppercase.lc() - a.lc() - b.lc(),
        f"{label} v3 computation",
    )
    return _PedersenNum(u3.lc(), u3_value, u3), _PedersenNum(v3.lc(), v3_value, v3)


@lru_cache(maxsize=1)
def _pedersen_montgomery_tables() -> tuple[
    tuple[tuple[tuple[int, int], ...], ...], ...
]:
    return tuple(
        tuple(
            tuple(
                _pedersen_point_to_montgomery(point)
                for point in window[:4]
            )
            for window in segment
        )
        for segment in _pedersen_tables()
    )


def _pedersen_point_to_montgomery(point: Point) -> tuple[int, int]:
    if point.v == 1:
        raise R1CSError("Pedersen table unexpectedly contains the identity")
    if point.u == 0:
        return 0, 0
    x = (1 + point.v) * pow(
        1 - point.v, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS
    ) % CIRCUIT_FIELD_MODULUS
    y = (
        x
        * pow(point.u, CIRCUIT_FIELD_MODULUS - 2, CIRCUIT_FIELD_MODULUS)
        * _PEDERSEN_MONTGOMERY_SCALE
    ) % CIRCUIT_FIELD_MODULUS
    return x, y


@lru_cache(maxsize=1)
def _pedersen_tables() -> tuple[tuple[tuple[Point, ...], ...], ...]:
    generators = tuple(
        find_group_hash(_PEDERSEN_PERSONALIZATION, index.to_bytes(4, "little"))
        for index in range(_PEDERSEN_GENERATOR_COUNT)
    )
    tables = []
    for generator in generators:
        segment = []
        power = generator
        for _ in range(_PEDERSEN_CHUNKS_PER_GENERATOR):
            entries = []
            for pattern in range(8):
                a = pattern & 1
                b = pattern >> 1 & 1
                c = pattern >> 2 & 1
                scalar = (1 + a + 2 * b) * (-1 if c else 1)
                entries.append(_small_multiple(power, abs(scalar), scalar < 0))
            segment.append(tuple(entries))
            power = _small_multiple(power, 16)
        tables.append(tuple(segment))
    return tuple(tables)


def _constrain_lookup3_point(
    system: SynthesisBackend,
    bits: Sequence[CircuitBit | VariableLike],
    table: Sequence[Point],
    selected: tuple[VariableLike, VariableLike],
    label: str,
) -> None:
    if len(bits) != 3 or len(table) != 8:
        raise R1CSError("three-bit lookup requires three bits and eight points")
    for index, bit in enumerate(bits):
        _validate_lookup_bit(
            system,
            bit,
            invalid_constant_error=(
                "BLAKE2s bits must be zero or one"
                if index in (1, 2)
                else "lookup input must be a bit"
            ),
        )
    for variable in selected:
        system.require_owned(variable)
    a, b, c = bits
    bc = _constrained_bit_and(system, b, c, f"{label} bc")
    for coordinate, variable in enumerate(selected):
        values = tuple(getattr(point, ("u", "v")[coordinate]) for point in table)
        base = _bit_expression(
            system,
            ((b, values[2] - values[0]), (c, values[4] - values[0]),
             (bc, values[6] - values[4] - values[2] + values[0])),
            values[0],
        )
        factor = _bit_expression(
            system,
            (
                (b, values[3] - values[2] - values[1] + values[0]),
                (c, values[5] - values[4] - values[1] + values[0]),
                (
                    bc,
                    values[7] - values[6] - values[5] + values[4]
                    - values[3] + values[2] + values[1] - values[0],
                ),
            ),
            values[1] - values[0],
        )
        system.enforce(
            factor,
            _bit_expression(system, ((a, 1),), 0),
            variable.lc() - base,
            f"{label} coordinate[{coordinate}]",
        )


def _constrain_signed_lookup3_point(
    system: SynthesisBackend,
    bits: Sequence[CircuitBit | VariableLike],
    table: Sequence[Point],
    selected: tuple[VariableLike, VariableLike],
    label: str,
) -> None:
    if len(bits) != 3 or len(table) != 8:
        raise R1CSError("signed three-bit lookup requires three bits and eight points")
    a, b, sign = bits
    ab = _constrained_bit_and(system, a, b, f"{label} ab")
    positive = table[:4]

    def base_expression(coordinate: int) -> LinearCombinationLike:
        values = tuple(
            getattr(point, ("u", "v")[coordinate]) for point in positive
        )
        return _bit_expression(
            system,
            (
                (a, values[1] - values[0]),
                (b, values[2] - values[0]),
                (
                    ab,
                    values[3] - values[2] - values[1] + values[0],
                ),
            ),
            values[0],
        )

    values_v = tuple(point.v for point in positive)

    factor_v = _bit_expression(
        system,
        ((b, values_v[3] - values_v[2] - values_v[1] + values_v[0]),),
        values_v[1] - values_v[0],
    )
    system.enforce(
        factor_v,
        a,
        selected[1].lc() - _bit_expression(
            system, ((b, values_v[2] - values_v[0]),), values_v[0]
        ),
        f"{label} v lookup",
    )

    base_u = base_expression(0)
    system.enforce(
        sign,
        base_u * 2,
        base_u - selected[0].lc(),
        f"{label} conditional negation",
    )


def _constrained_bit_and(
    system: SynthesisBackend,
    left: CircuitBit | VariableLike,
    right: CircuitBit | VariableLike,
    label: str,
) -> CircuitBit | VariableLike:
    left_variable = _lookup_bit_backing_variable(left)
    right_variable = _lookup_bit_backing_variable(right)
    for variable in (left_variable, right_variable):
        if variable is not None:
            system.require_owned(variable)
    if left_variable is None and right_variable is None:
        left_value = _read_lookup_bit(system, left)
        right_value = _read_lookup_bit(system, right)
        return left_value & right_value
    if left_variable is None:
        return right if _read_lookup_bit(system, left) else 0
    if right_variable is None:
        return left if _read_lookup_bit(system, right) else 0
    return system.multiply(
        _bit_expression(system, ((left, 1),), 0),
        _bit_expression(system, ((right, 1),), 0),
        label,
    )


def _lookup_bit_backing_variable(
    bit: CircuitBit | VariableLike,
) -> VariableLike | None:
    if isinstance(bit, _NegatedBit):
        return bit.variable
    if isinstance(bit, VariableLike):
        return bit
    return None


def _validate_lookup_bit(
    system: SynthesisBackend,
    bit: CircuitBit | VariableLike,
    *,
    invalid_constant_error: str,
) -> None:
    variable = _lookup_bit_backing_variable(bit)
    if variable is not None:
        system.require_owned(variable)
    elif type(bit) not in (int, bool):
        raise R1CSError("lookup input must be a bit")
    elif bit not in (0, 1):
        raise R1CSError(invalid_constant_error)


def _read_lookup_bit(
    system: SynthesisBackend,
    bit: CircuitBit | VariableLike,
) -> int:
    variable = _lookup_bit_backing_variable(bit)
    if variable is not None:
        value = system.witness_value(variable)
        if value not in (0, 1):
            raise R1CSError("BLAKE2s bit is unassigned or invalid")
        return 1 - int(value) if isinstance(bit, _NegatedBit) else int(value)
    if type(bit) not in (int, bool) or bit not in (0, 1):
        raise R1CSError("BLAKE2s bits must be zero or one")
    return int(bit)


@overload
def _bit_expression(
    system: R1CS,
    terms: Sequence[tuple[CircuitBit, int]],
    constant: int,
) -> LinearCombination: ...


@overload
def _bit_expression(
    system: SynthesisBackend,
    terms: Sequence[tuple[CircuitBit | VariableLike, int]],
    constant: int,
) -> LinearCombinationLike: ...


def _bit_expression(
    system: SynthesisBackend,
    terms: Sequence[tuple[CircuitBit | VariableLike, int]],
    constant: int,
) -> LinearCombinationLike:
    variables = []
    for bit, coefficient in terms:
        if isinstance(bit, (Variable, RecorderVariable)):
            variables.append((bit, coefficient))
        elif isinstance(bit, _NegatedBit):
            variables.append((bit.variable, -coefficient))
            constant += coefficient
        elif bit in (0, 1) and type(bit) in (int, bool):
            constant += int(bit) * coefficient
        else:
            raise R1CSError("lookup input must be a bit")
    return system.linear_combination(tuple(variables), constant)


def _read_backend_bit(
    system: SynthesisBackend,
    bit: VariableLike,
    error_message: str = "scalar multiplication bit is unassigned or invalid",
) -> int:
    system.require_owned(bit)
    value = system.witness_value(bit)
    if value not in (0, 1):
        raise R1CSError(error_message)
    return int(value)


def _small_multiple(point: Point, scalar: int, negate: bool = False) -> Point:
    if type(scalar) is not int or scalar < 0:
        raise R1CSError("point multiple must be a non-negative integer")
    result = IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = result + addend
        addend = addend + addend
        scalar >>= 1
    if negate:
        return Point(-result.u, result.v)
    return result


def _point_witness(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
) -> Point:
    _require_point(system, point)
    u = system.witness_value(point[0])
    v = system.witness_value(point[1])
    if u is None or v is None:
        raise R1CSError("Jubjub point witness is unassigned")
    result = Point(u, v)
    if not result.is_on_curve():
        raise R1CSError("Jubjub point witness is not on-curve")
    return result


def _point_repr_bits(point: Point) -> tuple[int, ...]:
    return _bits_le(point.v, 255) + (point.u & 1,)


def _bits_le(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> index) & 1 for index in range(width))


def _validate_merkle_path_inputs(
    leaf: int | None, siblings: Sequence[int], position: int
) -> None:
    if type(leaf) is not int or not 0 <= leaf < FIELD_MODULUS:
        raise R1CSError("Merkle leaf must be a canonical Sapling field element")
    if not isinstance(siblings, Sequence) or isinstance(siblings, (str, bytes)):
        raise R1CSError("Merkle siblings must be a 32-element sequence")
    if len(siblings) != 32:
        raise R1CSError("Sapling authentication path must contain exactly 32 nodes")
    if type(position) is not int or not 0 <= position < 1 << 32:
        raise R1CSError("Merkle position must be an unsigned 32-bit integer")
    for sibling in siblings:
        if type(sibling) is not int or not 0 <= sibling < FIELD_MODULUS:
            raise R1CSError(
                "Merkle sibling must be a canonical Sapling field element"
            )


def _read_bit(system: R1CS, bit: CircuitBit) -> int:
    if isinstance(bit, Variable):
        value = system._witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("Pedersen input bit is unassigned or invalid")
        return int(value)
    if isinstance(bit, _NegatedBit):
        return 1 - _read_bit(system, bit.variable)
    return _require_bit(bit)


def _read_pedersen_bit(
    system: SynthesisBackend,
    bit: CircuitBit | VariableLike,
) -> int:
    if isinstance(bit, _NegatedBit):
        system.require_owned(bit.variable)
        value = system.witness_value(bit.variable)
        if value not in (0, 1):
            raise R1CSError("Pedersen input bit is unassigned or invalid")
        return 1 - int(value)
    if isinstance(bit, VariableLike):
        system.require_owned(bit)
        value = system.witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("Pedersen input bit is unassigned or invalid")
        return int(value)
    return _require_bit(bit)


def _require_bit(value: int) -> int:
    if type(value) not in (int, bool) or value not in (0, 1):
        raise R1CSError("bit values must be zero or one")
    return int(value)


def _validate_pedersen_representation(value: PedersenRepresentation) -> None:
    if value not in ("edwards", "montgomery"):
        raise ValueError("Pedersen representation must be 'edwards' or 'montgomery'")


def _require_point(
    system: SynthesisBackend,
    point: tuple[VariableLike, VariableLike],
) -> None:
    if not isinstance(point, tuple) or len(point) != 2:
        raise TypeError("Jubjub circuit points must be (u, v) variable pairs")
    system.require_owned(point[0])
    system.require_owned(point[1])
