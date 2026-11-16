"""Isolated source-faithful ports for pinned Sapling Spend gadget units."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from typing import TypeAlias

from src.blake2s_gadget import CircuitBit, _NegatedBit, _read_bit
from src.bls12_381 import SCALAR_MODULUS
from src.bls12_381 import SCALAR_MODULUS as CIRCUIT_FIELD_MODULUS
from src.jubjub import (
    CURVE_D,
    IDENTITY,
    Point,
    find_group_hash,
)
from src.jubjub import SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS
from src.r1cs import R1CS, LinearCombination, R1CSError, Variable
from src.sapling_gadgets import sapling_fixed_base_generator
from tests.bellman_blake2s_reference import _Negated as _BellmanNegated
from tests.bellman_blake2s_reference import constrain_bellman_blake2s_reference

SpendBoolean: TypeAlias = Variable | bool | _NegatedBit | _BellmanNegated
SpendCircuitBit: TypeAlias = CircuitBit | _BellmanNegated

_FIXED_BASE_WINDOW_BITS = 3
_FIXED_BASE_WINDOW_COUNT = 84
_JUBJUB_SCALAR_MODULUS = JUBJUB_SCALAR_MODULUS
_MONTGOMERY_A = 40962
_MONTGOMERY_SCALE_LIMBS = (
    0x8F4535F7CF82B8D9,
    0xCE4069703DA88ABD,
    0x31DE341E77D764E5,
    0x2762DE61E862645E,
)
_MONTGOMERY_SCALE = sum(
    limb << (64 * index) for index, limb in enumerate(_MONTGOMERY_SCALE_LIMBS)
) % SCALAR_MODULUS


@dataclass(frozen=True)
class EdwardsPointWitnessVariables:
    u: Variable
    v: Variable


@dataclass(frozen=True)
class MontgomeryNumberWitness:
    expression: Variable | LinearCombination
    value: int


@dataclass(frozen=True)
class MontgomeryPointWitness:
    x: MontgomeryNumberWitness
    y: MontgomeryNumberWitness


@dataclass(frozen=True)
class SignedLookupWitness:
    x: MontgomeryNumberWitness
    y: MontgomeryNumberWitness
    selected_index: int
    negative: bool


@dataclass(frozen=True)
class PedersenHashResult:
    variables: EdwardsPointWitnessVariables
    witness: Point


@dataclass(frozen=True)
class NoteCommitmentResult:
    value_bits: tuple[Variable, ...]
    note_contents: tuple[Variable, ...]
    note_hash: PedersenHashResult
    randomization_variables: EdwardsPointWitnessVariables
    commitment_variables: EdwardsPointWitnessVariables
    commitment_witness: Point


@dataclass(frozen=True)
class ValueCommitmentResult:
    value_bits: tuple[Variable, ...]
    randomness_bits: tuple[Variable, ...]
    value_variables: EdwardsPointWitnessVariables
    randomness_variables: EdwardsPointWitnessVariables
    commitment_variables: EdwardsPointWitnessVariables
    input_variables: tuple[Variable, Variable]
    commitment_witness: Point


@dataclass(frozen=True)
class MerkleAuthenticationResult:
    leaf_variable: Variable
    position_bits: tuple[Variable, ...]
    path_nodes: tuple[Variable, ...]
    root_variable: Variable
    root_value: int


@dataclass(frozen=True)
class ConditionalAnchorResult:
    root_variable: Variable
    value_variable: Variable
    anchor_variable: Variable
    conditional_anchor_variable: Variable
    anchor_value: int


@dataclass(frozen=True)
class IvkBlake2sResult:
    preimage_bits: tuple[Variable, ...]
    digest_bits: tuple[SpendCircuitBit, ...]
    ivk_bits: tuple[SpendCircuitBit, ...]


@dataclass(frozen=True)
class NullifierBlake2sResult:
    preimage_bits: tuple[Variable, ...]
    digest_bits: tuple[SpendCircuitBit, ...]


@dataclass(frozen=True)
class NullifierMultipackingResult:
    digest_bits: tuple[SpendCircuitBit, ...]
    chunk_sizes: tuple[int, ...]
    input_variables: tuple[Variable, ...]


@dataclass(frozen=True)
class SpendReferenceWitness:
    ak: Point
    ar: int
    nsk: int
    g_d: Point
    value: int
    rcv: int
    rcm: int
    authentication_path: tuple[tuple[int, bool], ...]
    anchor: int


@dataclass(frozen=True)
class SourceOrderedConditionalAnchorResult:
    root_variable: Variable
    value_num: LinearCombination
    conditional_anchor_variable: Variable
    anchor_variable: Variable
    anchor_value: int


@dataclass(frozen=True)
class SpendReferenceAssembly:
    public_inputs: tuple[Variable, ...]
    randomized_key: EdwardsPointWitnessVariables
    nullifier_key: EdwardsPointWitnessVariables
    ak_repr_bits: tuple[Variable, ...]
    nk_repr_bits: tuple[Variable, ...]
    ivk_bits: tuple[SpendCircuitBit, ...]
    diversifier_base: EdwardsPointWitnessVariables
    transmission_key: EdwardsPointWitnessVariables
    transmission_key_repr_bits: tuple[Variable, ...]
    value_commitment: ValueCommitmentResult
    note_commitment: NoteCommitmentResult
    merkle_path: MerkleAuthenticationResult
    conditional_anchor: SourceOrderedConditionalAnchorResult
    rho: EdwardsPointWitnessVariables
    rho_repr_bits: tuple[Variable, ...]
    nullifier_hash: NullifierBlake2sResult
    nullifier_multipacking: NullifierMultipackingResult


class SpendReferenceR1CS(R1CS):
    """Test-only R1CS adapter preserving Bellman's late inputization order."""

    supports_temporal_public_inputs = True

    def __init__(self) -> None:
        super().__init__()
        self._temporal_public_variables: list[Variable] = []
        self._public_positions_by_index: dict[int, int] = {}
        self._auxiliary_indices_by_variable_index: dict[int, int] = {}
        self._auxiliary_count = 0

    def alloc_public(self, name: str, value: int | None) -> Variable:
        variable = self._allocate("public", name, value)
        self._public_input_count += 1
        self._temporal_public_variables.append(variable)
        self._public_positions_by_index[variable.index] = self._public_input_count
        return variable

    def alloc_private(self, name: str, value: int | None) -> Variable:
        variable = super().alloc_private(name, value)
        self._auxiliary_indices_by_variable_index[variable.index] = (
            self._auxiliary_count
        )
        self._auxiliary_count += 1
        return variable

    def public_input_position(self, variable: Variable) -> int | None:
        self.require_owned(variable)
        if variable.kind != "public":
            return None
        return self._public_positions_by_index[variable.index]

    def auxiliary_index(self, variable: Variable) -> int:
        self.require_owned(variable)
        if variable.kind != "private":
            raise R1CSError("variable is not an auxiliary variable")
        return self._auxiliary_indices_by_variable_index[variable.index]

    def public_inputs(self) -> tuple[int, ...]:
        values = tuple(
            self.witness_value(variable)
            for variable in self._temporal_public_variables
        )
        if any(value is None for value in values):
            raise R1CSError("public inputs contain unassigned values")
        return tuple(int(value) for value in values)

    def canonical_column(self, variable_index: int) -> int:
        if variable_index == 0:
            return 0
        variable = self._variables[variable_index]
        if variable.kind == "public":
            return self._public_positions_by_index[variable_index]
        if variable.kind == "private":
            return (
                self._public_input_count
                + self._auxiliary_indices_by_variable_index[variable_index]
                + 1
            )
        raise R1CSError("unexpected variable kind in Spend reference R1CS")

    def serialize_matrix(self) -> bytes:
        def canonical_terms(terms: tuple[tuple[int, int], ...]) -> list[list[str | int]]:
            combined: dict[int, int] = {}
            for variable_index, coefficient in terms:
                column = self.canonical_column(variable_index)
                combined[column] = (
                    combined.get(column, 0) + coefficient
                ) % SCALAR_MODULUS
            return [
                [column, str(coefficient)]
                for column, coefficient in sorted(combined.items())
                if coefficient
            ]

        private_count = sum(
            variable.kind == "private" for variable in self._variables
        )
        document = {
            "format": "zycoin-r1cs-matrix-v1",
            "field_modulus": str(SCALAR_MODULUS),
            "column_count": len(self._variables),
            "one_column": 0,
            "public_input_count": self._public_input_count,
            "auxiliary_variable_count": private_count,
            "variable_kinds": (
                ["one"]
                + ["public"] * self._public_input_count
                + ["private"] * private_count
            ),
            "constraints": [
                [
                    canonical_terms(expression.terms)
                    for expression in (row.left, row.right, row.output)
                ]
                for row in self._constraints
            ],
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")


def spend_edwards_to_montgomery_coordinates(
    point: Point,
) -> tuple[int, int] | None:
    """Port the pinned host-side Edwards-to-Montgomery table conversion."""
    if not isinstance(point, Point):
        raise TypeError("point must be a Jubjub Point")
    if not point.is_on_curve():
        raise R1CSError("Edwards-to-Montgomery conversion requires an on-curve point")
    if point.v == 1:
        return None
    if point.u == 0:
        return 0, 0
    modulus = SCALAR_MODULUS
    x = (1 + point.v) * pow(1 - point.v, modulus - 2, modulus) % modulus
    y = (
        x
        * pow(point.u, modulus - 2, modulus)
        * _MONTGOMERY_SCALE
    ) % modulus
    return x, y


def allocate_spend_montgomery_point(
    system: R1CS,
    x: int | None,
    y: int | None,
    label: str = "montgomery point",
) -> MontgomeryPointWitness:
    """Allocate unchecked Montgomery coordinates, as Pedersen lookup does."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if type(x) is not int or type(y) is not int:
        raise R1CSError("Montgomery coordinates must be assigned integers")
    if not 0 <= x < SCALAR_MODULUS or not 0 <= y < SCALAR_MODULUS:
        raise R1CSError("Montgomery coordinates must be canonical field elements")
    x_variable = system.alloc_private(f"{label}/x/num", x)
    y_variable = system.alloc_private(f"{label}/y/num", y)
    return MontgomeryPointWitness(
        MontgomeryNumberWitness(x_variable, x),
        MontgomeryNumberWitness(y_variable, y),
    )


def _validate_montgomery_number(
    system: R1CS, number: MontgomeryNumberWitness
) -> None:
    if not isinstance(number, MontgomeryNumberWitness):
        raise TypeError("Montgomery coordinate must be a Montgomery number witness")
    if type(number.value) is not int or not 0 <= number.value < SCALAR_MODULUS:
        raise R1CSError("Montgomery coordinate witness is out of range")
    expression = number.expression
    if isinstance(expression, Variable):
        system.require_owned(expression)
        actual = system.witness_value(expression)
        if actual is None:
            raise R1CSError("Montgomery coordinate witness is unassigned")
    elif isinstance(expression, LinearCombination):
        if expression._owner is not system._owner:
            raise R1CSError("Montgomery coordinate expression belongs to another system")
        for index, _ in expression.terms:
            if index >= len(system.variables):
                raise R1CSError("Montgomery coordinate expression has an invalid variable")
            if system.witness_value(system.variables[index]) is None:
                raise R1CSError("Montgomery coordinate expression is unassigned")
        actual = system._evaluate(expression, system._values)
    else:
        raise TypeError("Montgomery coordinate expression is malformed")
    if actual != number.value:
        raise R1CSError("Montgomery coordinate does not match its witness")


def _montgomery_lc(
    system: R1CS, number: MontgomeryNumberWitness
) -> LinearCombination:
    expression = number.expression
    if isinstance(expression, Variable):
        return expression.lc()
    if isinstance(expression, LinearCombination):
        return expression
    raise TypeError("Montgomery coordinate expression is malformed")


def constrain_spend_montgomery_add(
    system: R1CS,
    point: MontgomeryPointWitness,
    other: MontgomeryPointWitness,
    label: str = "montgomery addition",
) -> MontgomeryPointWitness:
    """Port pinned `MontgomeryPoint::add` without curve or infinity handling."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if not isinstance(point, MontgomeryPointWitness) or not isinstance(
        other, MontgomeryPointWitness
    ):
        raise TypeError("Montgomery addition requires two Montgomery points")
    for coordinate in (point.x, point.y, other.x, other.y):
        _validate_montgomery_number(system, coordinate)

    modulus = SCALAR_MODULUS
    denominator = (other.x.value - point.x.value) % modulus
    if denominator == 0:
        raise R1CSError("Montgomery addition has equal x coordinates")
    slope = (
        (other.y.value - point.y.value)
        * pow(denominator, modulus - 2, modulus)
    ) % modulus
    lam = system.alloc_private(f"{label}/lambda/num", slope)
    system.enforce(
        _montgomery_lc(system, other.x) - _montgomery_lc(system, point.x),
        lam,
        _montgomery_lc(system, other.y) - _montgomery_lc(system, point.y),
        f"{label}/evaluate lambda",
    )

    x_value = (
        slope * slope
        - _MONTGOMERY_A
        - point.x.value
        - other.x.value
    ) % modulus
    x_prime = system.alloc_private(f"{label}/xprime/num", x_value)
    system.enforce(
        lam,
        lam,
        _MONTGOMERY_A
        + _montgomery_lc(system, point.x)
        + _montgomery_lc(system, other.x)
        + x_prime,
        f"{label}/evaluate xprime",
    )

    y_value = (
        -point.y.value - slope * (x_value - point.x.value)
    ) % modulus
    y_prime = system.alloc_private(f"{label}/yprime/num", y_value)
    system.enforce(
        _montgomery_lc(system, point.x) - x_prime,
        lam,
        y_prime + _montgomery_lc(system, point.y),
        f"{label}/evaluate yprime",
    )
    return MontgomeryPointWitness(
        MontgomeryNumberWitness(x_prime, x_value),
        MontgomeryNumberWitness(y_prime, y_value),
    )


def constrain_spend_montgomery_into_edwards(
    system: R1CS,
    point: MontgomeryPointWitness,
    label: str = "montgomery conversion",
) -> EdwardsPointWitnessVariables:
    """Port pinned `MontgomeryPoint::into_edwards` in allocation order."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if not isinstance(point, MontgomeryPointWitness):
        raise TypeError("conversion requires a Montgomery point")
    _validate_montgomery_number(system, point.x)
    _validate_montgomery_number(system, point.y)

    modulus = SCALAR_MODULUS
    if point.y.value == 0:
        raise R1CSError("Montgomery-to-Edwards u conversion has a zero denominator")
    u_value = (
        point.x.value
        * _MONTGOMERY_SCALE
        * pow(point.y.value, modulus - 2, modulus)
    ) % modulus
    u = system.alloc_private(f"{label}/u/num", u_value)
    system.enforce(
        _montgomery_lc(system, point.y),
        u,
        _MONTGOMERY_SCALE * _montgomery_lc(system, point.x),
        f"{label}/u computation",
    )

    v_denominator = (point.x.value + 1) % modulus
    if v_denominator == 0:
        raise R1CSError("Montgomery-to-Edwards v conversion has a zero denominator")
    v_value = (
        (point.x.value - 1)
        * pow(v_denominator, modulus - 2, modulus)
    ) % modulus
    v = system.alloc_private(f"{label}/v/num", v_value)
    system.enforce(
        _montgomery_lc(system, point.x) + 1,
        v,
        _montgomery_lc(system, point.x) - 1,
        f"{label}/v computation",
    )
    return EdwardsPointWitnessVariables(u, v)


def constrain_spend_signed_montgomery_lookup(
    system: R1CS,
    bits: tuple[SpendBoolean, ...] | list[SpendBoolean],
    table: tuple[tuple[int, int], ...] | list[tuple[int, int]],
    label: str = "signed lookup",
) -> SignedLookupWitness:
    """Port Bellman `lookup3_xy_with_conditional_negation` for four entries."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if len(bits) != 3:
        raise R1CSError("signed lookup requires exactly three selector bits")
    if len(table) != 4:
        raise R1CSError("signed lookup requires exactly four Montgomery points")
    for bit in bits:
        if isinstance(bit, Variable):
            system.require_owned(bit)
            if system.witness_value(bit) not in (0, 1):
                raise R1CSError("signed lookup selectors must be assigned booleans")
        elif type(bit) is not bool:
            raise TypeError("signed lookup selectors must be variables or booleans")
    for coordinate_pair in table:
        if (
            not isinstance(coordinate_pair, tuple)
            or len(coordinate_pair) != 2
            or any(
                type(coordinate) is not int
                or not 0 <= coordinate < SCALAR_MODULUS
                for coordinate in coordinate_pair
            )
        ):
            raise R1CSError("signed lookup table coordinates must be canonical pairs")

    values = tuple(_spend_boolean_value(system, bit) for bit in bits)
    selected_index = int(values[0]) + 2 * int(values[1])
    negative = values[2]
    x_values = tuple(pair[0] for pair in table)
    y_values = tuple(pair[1] for pair in table)
    x_coefficients = _signed_lookup_coefficients(x_values)
    y_coefficients = _signed_lookup_coefficients(y_values)

    selected_y = y_values[selected_index]
    if negative:
        selected_y = -selected_y % SCALAR_MODULUS
    y_variable = system.alloc_private(f"{label}/y/num", selected_y)

    precomp = _spend_boolean_and(
        system, bits[0], bits[1], f"{label}/precomp"
    )
    x_expression = _signed_lookup_expression(
        system, x_coefficients, bits[0], bits[1], precomp
    )
    y_expression = _signed_lookup_expression(
        system, y_coefficients, bits[0], bits[1], precomp
    )
    system.enforce(
        y_expression + y_expression,
        _spend_boolean_lc(system, bits[2]),
        y_expression - y_variable,
        f"{label}/y-coordinate lookup",
    )
    x_value = x_values[selected_index]
    return SignedLookupWitness(
        MontgomeryNumberWitness(x_expression, x_value),
        MontgomeryNumberWitness(y_variable, selected_y),
        selected_index,
        negative,
    )


def _signed_lookup_coefficients(
    values: tuple[int, ...],
) -> tuple[int, int, int, int]:
    if len(values) != 4:
        raise R1CSError("signed lookup coefficient calculation requires four values")
    zero, one, two, three = values
    return (
        zero % SCALAR_MODULUS,
        (one - zero) % SCALAR_MODULUS,
        (two - zero) % SCALAR_MODULUS,
        (three - two - one + zero) % SCALAR_MODULUS,
    )


def _signed_lookup_expression(
    system: R1CS,
    coefficients: tuple[int, int, int, int],
    first: SpendBoolean,
    second: SpendBoolean,
    precomp: SpendBoolean,
) -> LinearCombination:
    expression = system.linear_combination((), coefficients[0])
    for bit, coefficient in zip(
        (first, second, precomp), coefficients[1:], strict=True
    ):
        expression += _spend_boolean_lc(system, bit) * coefficient
    return expression


@lru_cache(maxsize=1)
def spend_pedersen_montgomery_tables() -> tuple[
    tuple[tuple[tuple[int, int], ...], ...], ...
]:
    """Generate the six pinned Pedersen generator tables independently."""
    tables = []
    for generator_index in range(6):
        generator = find_group_hash(b"Zcash_PH", generator_index.to_bytes(4, "little"))
        windows = []
        window_base = generator
        for _ in range(63):
            entries = []
            multiple = window_base
            for _ in range(4):
                coordinates = spend_edwards_to_montgomery_coordinates(multiple)
                if coordinates is None:
                    raise R1CSError("Pedersen generator table contains infinity")
                entries.append(coordinates)
                multiple = multiple + window_base
            windows.append(tuple(entries))
            window_base = window_base.multiply(16)
        tables.append(tuple(windows))
    return tuple(tables)


def constrain_spend_pedersen_hash(
    system: R1CS,
    message_bits: tuple[SpendBoolean, ...] | list[SpendBoolean],
    label: str = "pedersen hash",
    personalization_bits: tuple[SpendBoolean, ...] | list[SpendBoolean] = (
        True,
        True,
        True,
        True,
        True,
        True,
    ),
) -> PedersenHashResult:
    """Port the pinned circuit Pedersen hash over Montgomery segment tables."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if len(personalization_bits) != 6:
        raise R1CSError("Pedersen personalization requires six bits")
    for bit in (*personalization_bits, *message_bits):
        if isinstance(bit, Variable):
            system.require_owned(bit)
            if system.witness_value(bit) not in (0, 1):
                raise R1CSError("Pedersen input bits must be assigned booleans")
        elif type(bit) is not bool:
            raise TypeError("Pedersen input bits must be variables or booleans")

    all_bits = tuple(personalization_bits) + tuple(message_bits)
    if not all_bits:
        raise R1CSError("Pedersen input must not be empty")
    chunk_count = (len(all_bits) + 2) // 3
    segment_count = (chunk_count + 62) // 63
    if segment_count > 6:
        raise R1CSError("Pedersen input exceeds the pinned generator capacity")
    tables = spend_pedersen_montgomery_tables()
    if len(tables) != 6 or any(
        len(segment) != 63 or any(len(window) != 4 for window in segment)
        for segment in tables
    ):
        raise R1CSError("Pedersen generator table has an invalid shape")
    for segment in tables:
        for window in segment:
            for x, y in window:
                if (
                    type(x) is not int
                    or type(y) is not int
                    or not 0 <= x < SCALAR_MODULUS
                    or not 0 <= y < SCALAR_MODULUS
                ):
                    raise R1CSError("Pedersen table has noncanonical coordinates")

    edwards_accumulator_variables: EdwardsPointWitnessVariables | None = None
    edwards_accumulator_witness: Point | None = None
    bit_offset = 0
    for segment_index in range(segment_count):
        segment_window_count = min(63, chunk_count - segment_index * 63)
        segment_accumulator: MontgomeryPointWitness | None = None
        for window_index in range(segment_window_count):
            chunk = all_bits[bit_offset : bit_offset + 3]
            bit_offset += len(chunk)
            selectors = chunk + (False,) * (3 - len(chunk))
            lookup = constrain_spend_signed_montgomery_lookup(
                system,
                selectors,
                tables[segment_index][window_index],
                f"{label}/segment {segment_index}, window {window_index}",
            )
            selected = MontgomeryPointWitness(lookup.x, lookup.y)
            if segment_accumulator is None:
                segment_accumulator = selected
            else:
                segment_accumulator = constrain_spend_montgomery_add(
                    system,
                    selected,
                    segment_accumulator,
                    f"{label}/addition of segment {segment_index}, window {window_index}",
                )
        if segment_accumulator is None:
            raise R1CSError("Pedersen segment has no lookup windows")

        converted_variables = constrain_spend_montgomery_into_edwards(
            system,
            segment_accumulator,
            f"{label}/conversion of segment {segment_index} into edwards",
        )
        converted_witness = Point(
            system.witness_value(converted_variables.u),
            system.witness_value(converted_variables.v),
        )
        if edwards_accumulator_variables is None:
            edwards_accumulator_variables = converted_variables
            edwards_accumulator_witness = converted_witness
        else:
            assert edwards_accumulator_witness is not None
            edwards_accumulator_variables = constrain_spend_edwards_point_add(
                system,
                converted_variables,
                converted_witness,
                edwards_accumulator_variables,
                edwards_accumulator_witness,
                f"{label}/addition of segment {segment_index} to accumulator",
            )
            edwards_accumulator_witness = Point(
                system.witness_value(edwards_accumulator_variables.u),
                system.witness_value(edwards_accumulator_variables.v),
            )

    if edwards_accumulator_variables is None or edwards_accumulator_witness is None:
        raise R1CSError("Pedersen hash produced no segment result")
    return PedersenHashResult(
        edwards_accumulator_variables, edwards_accumulator_witness
    )


def constrain_spend_merkle_authentication_path(
    system: R1CS,
    leaf_variable: Variable,
    leaf_value: int,
    authentication_path: tuple[tuple[int, bool], ...]
    | list[tuple[int, bool]],
    label: str = "merkle tree hash",
) -> MerkleAuthenticationResult:
    """Port Spend's per-level direction, ordering, and Merkle-root logic."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(leaf_variable, Variable):
        raise TypeError("Merkle leaf must be an allocated field variable")
    if type(leaf_value) is not int or not 0 <= leaf_value < SCALAR_MODULUS:
        raise R1CSError("Merkle leaf must be a canonical assigned field element")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if not isinstance(authentication_path, (tuple, list)):
        raise TypeError("authentication path must be a tuple or list")
    if len(authentication_path) > 32:
        raise R1CSError("Sapling authentication path exceeds 32 levels")
    system.require_owned(leaf_variable)
    if system.witness_value(leaf_variable) != leaf_value:
        raise R1CSError("Merkle leaf witness does not match its assigned variable")
    for level, entry in enumerate(authentication_path):
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise TypeError("authentication path entries must be (sibling, direction)")
        sibling, direction = entry
        if type(sibling) is not int or not 0 <= sibling < SCALAR_MODULUS:
            raise R1CSError(f"authentication path sibling {level} is out of range")
        if type(direction) is not bool:
            raise TypeError(f"authentication path direction {level} must be boolean")

    current_value = leaf_value
    current_variable = leaf_variable
    position_bits: list[Variable] = []
    path_nodes: list[Variable] = []

    for level, (sibling_value, direction) in enumerate(authentication_path):
        level_label = f"{label} {level}"
        position = system.alloc_private(
            f"{level_label}/position bit/boolean", int(direction)
        )
        system.enforce(
            1 - position.lc(),
            position,
            0,
            f"{level_label}/position bit/boolean constraint",
        )
        position_bits.append(position)

        sibling = system.alloc_private(
            f"{level_label}/path element/num", sibling_value
        )
        path_nodes.append(sibling)

        left_value, right_value = (
            (sibling_value, current_value)
            if direction
            else (current_value, sibling_value)
        )
        left = system.alloc_private(
            f"{level_label}/conditional reversal of preimage/"
            "conditional reversal result 1/num",
            left_value,
        )
        system.enforce(
            current_variable.lc() - sibling.lc(),
            position,
            current_variable.lc() - left.lc(),
            f"{level_label}/conditional reversal of preimage/"
            "first conditional reversal",
        )
        right = system.alloc_private(
            f"{level_label}/conditional reversal of preimage/"
            "conditional reversal result 2/num",
            right_value,
        )
        system.enforce(
            sibling.lc() - current_variable.lc(),
            position,
            sibling.lc() - right.lc(),
            f"{level_label}/conditional reversal of preimage/"
            "second conditional reversal",
        )

        current_bits = _constrain_spend_unchecked_field_bits(
            system, left, left_value, f"{level_label}/ul into bits"
        )
        sibling_bits = _constrain_spend_unchecked_field_bits(
            system, right, right_value, f"{level_label}/ur into bits"
        )
        personalization = tuple(
            bool((level >> bit) & 1) for bit in range(6)
        )
        preimage = current_bits + sibling_bits
        hash_result = constrain_spend_pedersen_hash(
            system,
            preimage,
            f"{level_label}/computation of pedersen hash",
            personalization,
        )
        current_variable = hash_result.variables.u
        current_value = hash_result.witness.u

    return MerkleAuthenticationResult(
        leaf_variable,
        tuple(position_bits),
        tuple(path_nodes),
        current_variable,
        current_value,
    )


def constrain_spend_conditional_anchor(
    system: R1CS,
    root_variable: Variable,
    root_value: int,
    value_variable: Variable,
    note_value: int,
    anchor_variable: Variable,
    anchor_value: int,
) -> ConditionalAnchorResult:
    """Port Spend's conditional root check and subsequent anchor inputization."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    variables = (root_variable, value_variable, anchor_variable)
    if any(not isinstance(variable, Variable) for variable in variables):
        raise TypeError("root, value, and anchor must be allocated variables")
    values = (root_value, note_value, anchor_value)
    if any(
        type(value) is not int or not 0 <= value < SCALAR_MODULUS
        for value in values
    ):
        raise R1CSError("conditional-anchor witnesses must be canonical field elements")
    for variable in variables:
        system.require_owned(variable)
    if root_variable.kind != "private" or value_variable.kind != "private":
        raise R1CSError("Merkle root and note value must be private variables")
    if anchor_variable.kind != "public":
        raise R1CSError("anchor must occupy a public-input position")
    if system.witness_value(root_variable) != root_value:
        raise R1CSError("Merkle root witness does not match its assigned variable")
    if system.witness_value(value_variable) != note_value:
        raise R1CSError("note-value witness does not match its assigned variable")
    if system.witness_value(anchor_variable) != anchor_value:
        raise R1CSError("anchor witness does not match its assigned public input")

    conditional_anchor = system.alloc_private(
        "conditional anchor/num", anchor_value
    )
    system.enforce(
        root_variable.lc() - conditional_anchor.lc(),
        value_variable.lc(),
        0,
        "conditionally enforce correct root",
    )
    system.enforce(
        anchor_variable.lc(),
        system.one.lc(),
        conditional_anchor.lc(),
        "anchor/enforce input is correct",
    )
    return ConditionalAnchorResult(
        root_variable,
        value_variable,
        anchor_variable,
        conditional_anchor,
        anchor_value,
    )


def constrain_spend_source_order_conditional_anchor(
    system: SpendReferenceR1CS,
    root_variable: Variable,
    root_value: int,
    value_bits: tuple[Variable, ...] | list[Variable],
    note_value: int,
    anchor_value: int,
) -> SourceOrderedConditionalAnchorResult:
    """Apply the full Spend anchor relation, including late inputization."""
    if not isinstance(system, SpendReferenceR1CS):
        raise R1CSError("source-order anchor requires the Spend reference R1CS")
    if not isinstance(root_variable, Variable):
        raise TypeError("Merkle root must be an allocated field variable")
    if (
        type(root_value) is not int
        or not 0 <= root_value < SCALAR_MODULUS
        or type(note_value) is not int
        or not 0 <= note_value < 1 << 64
        or type(anchor_value) is not int
        or not 0 <= anchor_value < SCALAR_MODULUS
    ):
        raise R1CSError("conditional-anchor witnesses are outside their ranges")
    system.require_owned(root_variable)
    if root_variable.kind != "private":
        raise R1CSError("Merkle root must be a private variable")
    if system.witness_value(root_variable) != root_value:
        raise R1CSError("Merkle root witness does not match its assigned variable")

    expected_value_bits = tuple((note_value >> index) & 1 for index in range(64))
    checked_value_bits = _reuse_spend_bits(
        system, value_bits, expected_value_bits, "note value"
    )
    value_num = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(checked_value_bits))
    )

    conditional_anchor = system.alloc_private(
        "conditional anchor/num", anchor_value
    )
    system.enforce(
        root_variable.lc() - conditional_anchor.lc(),
        value_num,
        0,
        "conditionally enforce correct root",
    )
    anchor_variable = system.alloc_public("anchor/input variable", anchor_value)
    system.enforce(
        anchor_variable.lc(),
        system.one.lc(),
        conditional_anchor.lc(),
        "anchor/enforce input is correct",
    )
    return SourceOrderedConditionalAnchorResult(
        root_variable,
        value_num,
        conditional_anchor,
        anchor_variable,
        anchor_value,
    )


def constrain_spend_ivk_blake2s(
    system: R1CS,
    ak_repr_bits: tuple[Variable, ...] | list[Variable],
    nk_repr_bits: tuple[Variable, ...] | list[Variable],
) -> IvkBlake2sResult:
    """Port the pinned 512-bit CRH^ivk stage using constrained BLAKE2s."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(ak_repr_bits, (tuple, list)) or not isinstance(
        nk_repr_bits, (tuple, list)
    ):
        raise TypeError("IVK representations must be tuples or lists of variables")
    preimage_bits = tuple(ak_repr_bits) + tuple(nk_repr_bits)
    if len(ak_repr_bits) != 256 or len(nk_repr_bits) != 256:
        raise R1CSError("IVK point representations must each contain 256 bits")
    for bit in preimage_bits:
        if not isinstance(bit, Variable):
            raise TypeError("IVK representation bits must be allocated variables")
        system.require_owned(bit)
        value = system.witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("IVK representation bit is unassigned or non-Boolean")

    digest_bits = constrain_bellman_blake2s_reference(
        system,
        preimage_bits,
        b"Zcashivk",
        annotation_prefix="computation of ivk",
    )
    return IvkBlake2sResult(
        preimage_bits,
        digest_bits,
        digest_bits[:251],
    )


def constrain_spend_nullifier_blake2s(
    system: R1CS,
    nk_repr_bits: tuple[Variable, ...] | list[Variable],
    rho_repr_bits: tuple[Variable, ...] | list[Variable],
) -> NullifierBlake2sResult:
    """Port the pinned 512-bit PRF^nf synthesis before nullifier multipacking."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(nk_repr_bits, (tuple, list)) or not isinstance(
        rho_repr_bits, (tuple, list)
    ):
        raise TypeError("nullifier representations must be tuples or lists of variables")
    preimage_bits = tuple(nk_repr_bits) + tuple(rho_repr_bits)
    if len(nk_repr_bits) != 256 or len(rho_repr_bits) != 256:
        raise R1CSError("nullifier point representations must each contain 256 bits")
    for bit in preimage_bits:
        if not isinstance(bit, Variable):
            raise TypeError("nullifier representation bits must be allocated variables")
        system.require_owned(bit)
        value = system.witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("nullifier representation bit is unassigned or non-Boolean")

    digest_bits = constrain_bellman_blake2s_reference(
        system,
        preimage_bits,
        b"Zcash_nf",
        annotation_prefix="nf computation",
    )
    return NullifierBlake2sResult(preimage_bits, digest_bits)


def constrain_spend_nullifier_multipacking(
    system: R1CS,
    digest_bits: tuple[SpendCircuitBit, ...] | list[SpendCircuitBit],
    label: str = "pack nullifier",
) -> NullifierMultipackingResult:
    """Port Bellman multipack::pack_into_inputs for the 256 nf bits."""
    if not isinstance(system, SpendReferenceR1CS):
        raise R1CSError(
            "nullifier multipacking requires the temporal-input Spend reference R1CS"
        )
    if not isinstance(digest_bits, (tuple, list)):
        raise TypeError("nullifier digest bits must be a tuple or list")
    if len(digest_bits) != 256:
        raise R1CSError("nullifier multipacking requires exactly 256 digest bits")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")

    for bit in digest_bits:
        if isinstance(bit, Variable):
            system.require_owned(bit)
        elif isinstance(bit, (_NegatedBit, _BellmanNegated)):
            system.require_owned(bit.variable)
        elif type(bit) not in (int, bool):
            raise TypeError("nullifier digest bits must be assigned circuit bits")
        if _spend_circuit_bit_value(system, bit) not in (0, 1):
            raise R1CSError("nullifier digest bits must be assigned booleans")

    capacity = SCALAR_MODULUS.bit_length() - 1
    chunk_sizes = tuple(
        min(capacity, len(digest_bits) - offset)
        for offset in range(0, len(digest_bits), capacity)
    )
    input_variables: list[Variable] = []
    bit_offset = 0
    for chunk_index, chunk_size in enumerate(chunk_sizes):
        packed_value = 0
        packed_lc = system.linear_combination(())
        coefficient = 1
        for bit in digest_bits[bit_offset : bit_offset + chunk_size]:
            packed_value += _spend_circuit_bit_value(system, bit) * coefficient
            if isinstance(bit, Variable):
                bit_lc = bit.lc()
            elif isinstance(bit, (_NegatedBit, _BellmanNegated)):
                bit_lc = 1 - bit.variable.lc()
            else:
                bit_lc = system.linear_combination((), int(bit))
            packed_lc += bit_lc * coefficient
            coefficient <<= 1
        bit_offset += chunk_size

        packed_input = system.alloc_public(
            f"{label}/input {chunk_index}", packed_value
        )
        system.enforce(
            packed_lc,
            1,
            packed_input,
            f"{label}/packing constraint {chunk_index}",
        )
        input_variables.append(packed_input)

    return NullifierMultipackingResult(
        tuple(digest_bits), chunk_sizes, tuple(input_variables)
    )


def _spend_circuit_bit_value(system: R1CS, bit: SpendCircuitBit) -> int:
    if isinstance(bit, _BellmanNegated):
        value = system.witness_value(bit.variable)
        if value not in (0, 1):
            raise R1CSError("nullifier digest bit is unassigned or non-Boolean")
        return 1 - int(value)
    return _read_bit(system, bit)


def _constrain_spend_unchecked_field_bits(
    system: R1CS, variable: Variable, value: int, label: str
) -> tuple[Variable, ...]:
    bits: list[Variable] = []
    for index in range(SCALAR_MODULUS.bit_length()):
        bit = system.alloc_private(
            f"{label}/bit {index}/boolean", (value >> index) & 1
        )
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{label}/bit {index}/boolean constraint",
        )
        bits.append(bit)
    reconstruction = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(bits))
    )
    system.enforce(
        0,
        0,
        reconstruction - variable.lc(),
        f"{label}/unpacking constraint",
    )
    return tuple(bits)


def constrain_spend_note_commitment(
    system: R1CS,
    value: int,
    g_d_variables: EdwardsPointWitnessVariables,
    g_d_witness: Point,
    pk_d_variables: EdwardsPointWitnessVariables,
    pk_d_witness: Point,
    rcm: int,
    *,
    value_bits: tuple[Variable, ...] | list[Variable] | None = None,
    g_d_repr_bits: tuple[Variable, ...] | list[Variable] | None = None,
    pk_d_repr_bits: tuple[Variable, ...] | list[Variable] | None = None,
) -> NoteCommitmentResult:
    """Port Spend's note-content hash and commitment-randomness addition."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise R1CSError("note value must be an assigned u64")
    if type(rcm) is not int or not 0 <= rcm < _JUBJUB_SCALAR_MODULUS:
        raise R1CSError("note commitment randomness is missing or out of range")
    _validate_point_assignment(system, g_d_variables, g_d_witness)
    _validate_point_assignment(system, pk_d_variables, pk_d_witness)

    expected_value_bits = tuple((value >> index) & 1 for index in range(64))
    value_bits = _reuse_or_allocate_spend_bits(
        system,
        value_bits,
        expected_value_bits,
        "value commitment/value",
    )
    expected_g_d_bits = tuple(
        (g_d_witness.v >> index) & 1 for index in range(255)
    ) + (g_d_witness.u & 1,)
    if g_d_repr_bits is None:
        g_d_bits = constrain_spend_edwards_point_repr(
            system, g_d_variables, g_d_witness, "representation of g_d"
        )
    else:
        g_d_bits = _reuse_spend_bits(
            system,
            g_d_repr_bits,
            expected_g_d_bits,
            "representation of g_d",
        )
    expected_pk_d_bits = tuple(
        (pk_d_witness.v >> index) & 1 for index in range(255)
    ) + (pk_d_witness.u & 1,)
    if pk_d_repr_bits is None:
        pk_d_bits = constrain_spend_edwards_point_repr(
            system, pk_d_variables, pk_d_witness, "representation of pk_d"
        )
    else:
        pk_d_bits = _reuse_spend_bits(
            system,
            pk_d_repr_bits,
            expected_pk_d_bits,
            "representation of pk_d",
        )
    note_contents = value_bits + g_d_bits + pk_d_bits
    if len(note_contents) != 64 + 256 + 256:
        raise R1CSError("note commitment input must contain exactly 576 bits")
    note_hash = constrain_spend_pedersen_hash(
        system, note_contents, "note content hash"
    )

    rcm_bits = allocate_spend_fixed_base_scalar_bits(
        system, rcm, 252, "rcm"
    )
    randomization_variables = constrain_spend_fixed_base_mul(
        system,
        rcm_bits,
        sapling_fixed_base_generator("note_commitment_randomness"),
        "computation of commitment randomness",
    )
    randomization_witness = Point(
        system.witness_value(randomization_variables.u),
        system.witness_value(randomization_variables.v),
    )
    commitment_variables = constrain_spend_edwards_point_add(
        system,
        note_hash.variables,
        note_hash.witness,
        randomization_variables,
        randomization_witness,
        "randomization of note commitment",
    )
    commitment_witness = Point(
        system.witness_value(commitment_variables.u),
        system.witness_value(commitment_variables.v),
    )
    return NoteCommitmentResult(
        value_bits,
        note_contents,
        note_hash,
        randomization_variables,
        commitment_variables,
        commitment_witness,
    )


def _reuse_or_allocate_spend_bits(
    system: R1CS,
    bits: tuple[Variable, ...] | list[Variable] | None,
    expected_values: tuple[int, ...],
    label: str,
) -> tuple[Variable, ...]:
    if bits is not None:
        return _reuse_spend_bits(system, bits, expected_values, label)

    allocated: list[Variable] = []
    for index, value in enumerate(expected_values):
        bit = system.alloc_private(f"{label}/bit {index}/boolean", value)
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{label}/bit {index}/boolean constraint",
        )
        allocated.append(bit)
    return tuple(allocated)


def _reuse_spend_bits(
    system: R1CS,
    bits: tuple[Variable, ...] | list[Variable],
    expected_values: tuple[int, ...],
    label: str,
) -> tuple[Variable, ...]:
    if not isinstance(bits, (tuple, list)) or len(bits) != len(expected_values):
        raise R1CSError(f"{label} must contain exactly {len(expected_values)} bits")
    for index, (bit, expected) in enumerate(zip(bits, expected_values, strict=True)):
        if not isinstance(bit, Variable):
            raise TypeError(f"{label} bit {index} must be an allocated variable")
        system.require_owned(bit)
        if system.witness_value(bit) != expected:
            raise R1CSError(f"{label} bit {index} does not match its witness")
    return tuple(bits)


def constrain_spend_value_commitment(
    system: R1CS,
    value: int,
    randomness: int,
    label: str = "value commitment",
) -> ValueCommitmentResult:
    """Port Sapling ``expose_value_commitment`` with source-ordered inputs."""
    if not isinstance(system, SpendReferenceR1CS):
        raise R1CSError(
            "value commitment requires the temporal-input Spend reference R1CS"
        )
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise R1CSError("value commitment value must be an assigned u64")
    if (
        type(randomness) is not int
        or not 0 <= randomness < _JUBJUB_SCALAR_MODULUS
    ):
        raise R1CSError("value commitment randomness is missing or out of range")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")

    value_bits = allocate_spend_fixed_base_scalar_bits(
        system, value, 64, f"{label}/value"
    )
    value_variables = constrain_spend_fixed_base_mul(
        system,
        value_bits,
        sapling_fixed_base_generator("value_commitment_value"),
        f"{label}/compute the value in the exponent",
    )

    randomness_bits = allocate_spend_fixed_base_scalar_bits(
        system, randomness, 252, f"{label}/rcv"
    )
    randomness_variables = constrain_spend_fixed_base_mul(
        system,
        randomness_bits,
        sapling_fixed_base_generator("value_commitment_randomness"),
        f"{label}/computation of rcv",
    )
    commitment_variables = constrain_spend_edwards_point_add(
        system,
        value_variables,
        Point(
            system.witness_value(value_variables.u),
            system.witness_value(value_variables.v),
        ),
        randomness_variables,
        Point(
            system.witness_value(randomness_variables.u),
            system.witness_value(randomness_variables.v),
        ),
        f"{label}/computation of cv",
    )
    commitment_witness = Point(
        system.witness_value(commitment_variables.u),
        system.witness_value(commitment_variables.v),
    )

    input_u = system.alloc_public(
        f"{label}/commitment point/u/input variable", commitment_witness.u
    )
    system.enforce(
        input_u,
        1,
        commitment_variables.u,
        f"{label}/commitment point/u/enforce input is correct",
    )
    input_v = system.alloc_public(
        f"{label}/commitment point/v/input variable", commitment_witness.v
    )
    system.enforce(
        input_v,
        1,
        commitment_variables.v,
        f"{label}/commitment point/v/enforce input is correct",
    )

    return ValueCommitmentResult(
        value_bits,
        randomness_bits,
        value_variables,
        randomness_variables,
        commitment_variables,
        (input_u, input_v),
        commitment_witness,
    )


def _validate_point_assignment(
    system: R1CS,
    variables: EdwardsPointWitnessVariables,
    witness: Point,
) -> None:
    if not isinstance(variables, EdwardsPointWitnessVariables):
        raise TypeError("point variables must be Edwards point witness variables")
    if not isinstance(witness, Point):
        raise TypeError("point witness must be a Jubjub Point")
    system.require_owned(variables.u)
    system.require_owned(variables.v)
    if (
        system.witness_value(variables.u) != witness.u
        or system.witness_value(variables.v) != witness.v
    ):
        raise R1CSError("point witness does not match the assigned coordinates")


def constrain_spend_edwards_point_witness(
    system: R1CS,
    point: Point | None,
    label: str = "point",
) -> EdwardsPointWitnessVariables:
    """Port Bellman's EdwardsPoint witness and interpretation sequence.

    The implementation is test-only. It mirrors
    `EdwardsPoint::witness` and `EdwardsPoint::interpret` from the pinned
    Sapling source, including the two coordinate allocations, three
    intermediate products, and the original on-curve factorization.
    """
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if point is None:
        raise R1CSError("Edwards point witness is unassigned")
    if not isinstance(point, Point):
        raise TypeError("point must be a Jubjub Point")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")

    modulus = SCALAR_MODULUS
    u = system.alloc_private(f"{label}/u/num", point.u)
    v = system.alloc_private(f"{label}/v/num", point.v)

    u_squared_value = point.u * point.u % modulus
    u_squared = system.alloc_private(
        f"{label}/point interpretation/u^2/squared num",
        u_squared_value,
    )
    system.enforce(
        u,
        u,
        u_squared,
        f"{label}/point interpretation/u^2/squaring constraint",
    )

    v_squared_value = point.v * point.v % modulus
    v_squared = system.alloc_private(
        f"{label}/point interpretation/v^2/squared num",
        v_squared_value,
    )
    system.enforce(
        v,
        v,
        v_squared,
        f"{label}/point interpretation/v^2/squaring constraint",
    )

    product = system.alloc_private(
        f"{label}/point interpretation/u^2 v^2/product num",
        u_squared_value * v_squared_value % modulus,
    )
    system.enforce(
        u_squared,
        v_squared,
        product,
        f"{label}/point interpretation/u^2 v^2/multiplication constraint",
    )

    system.enforce(
        -1 * u_squared.lc() + v_squared.lc(),
        1,
        1 + CURVE_D * product.lc(),
        f"{label}/point interpretation/on curve check",
    )
    return EdwardsPointWitnessVariables(u, v)


def constrain_spend_edwards_point_double(
    system: R1CS,
    point_variables: EdwardsPointWitnessVariables,
    point_witness: Point,
    label: str = "doubling",
) -> EdwardsPointWitnessVariables:
    """Port Bellman's `EdwardsPoint::double` with its exact row sequence."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    _validate_point_assignment(system, point_variables, point_witness)

    modulus = SCALAR_MODULUS
    u = point_witness.u
    v = point_witness.v
    t_value = (u + v) * (u + v) % modulus
    t = system.alloc_private(f"{label}/T/num", t_value)
    system.enforce(
        point_variables.u.lc() + point_variables.v,
        point_variables.u.lc() + point_variables.v,
        t,
        f"{label}/T computation",
    )

    a_value = u * v % modulus
    a = system.alloc_private(f"{label}/A computation/product num", a_value)
    system.enforce(
        point_variables.u,
        point_variables.v,
        a,
        f"{label}/A computation/multiplication constraint",
    )

    c_value = CURVE_D * a_value * a_value % modulus
    c = system.alloc_private(f"{label}/C/num", c_value)
    system.enforce(
        CURVE_D * a.lc(),
        a,
        c,
        f"{label}/C computation",
    )

    u_denominator = (1 + c_value) % modulus
    if u_denominator == 0:
        raise R1CSError("point doubling witness has a zero denominator")
    u3_value = 2 * a_value * pow(u_denominator, modulus - 2, modulus) % modulus
    u3 = system.alloc_private(f"{label}/u3/num", u3_value)
    system.enforce(
        1 + c.lc(),
        u3,
        a.lc() + a,
        f"{label}/u3 computation",
    )

    v_denominator = (1 - c_value) % modulus
    if v_denominator == 0:
        raise R1CSError("point doubling witness has a zero denominator")
    v3_value = (t_value - 2 * a_value) * pow(
        v_denominator, modulus - 2, modulus
    ) % modulus
    v3 = system.alloc_private(f"{label}/v3/num", v3_value)
    system.enforce(
        1 - c.lc(),
        v3,
        t.lc() - a - a,
        f"{label}/v3 computation",
    )
    return EdwardsPointWitnessVariables(u3, v3)


def constrain_spend_edwards_point_add(
    system: R1CS,
    left_variables: EdwardsPointWitnessVariables,
    left_witness: Point,
    right_variables: EdwardsPointWitnessVariables,
    right_witness: Point,
    label: str = "addition",
) -> EdwardsPointWitnessVariables:
    """Port Bellman's `EdwardsPoint::add` with its exact row sequence."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    _validate_point_assignment(system, left_variables, left_witness)
    _validate_point_assignment(system, right_variables, right_witness)

    modulus = SCALAR_MODULUS
    left_sum = (left_witness.u + left_witness.v) % modulus
    right_sum = (right_witness.u + right_witness.v) % modulus
    uppercase_u_value = left_sum * right_sum % modulus
    uppercase_u = system.alloc_private(f"{label}/U/num", uppercase_u_value)
    system.enforce(
        left_variables.u.lc() + left_variables.v,
        right_variables.u.lc() + right_variables.v,
        uppercase_u,
        f"{label}/U computation",
    )

    a_value = right_witness.v * left_witness.u % modulus
    a = system.alloc_private(f"{label}/A computation/product num", a_value)
    system.enforce(
        right_variables.v,
        left_variables.u,
        a,
        f"{label}/A computation/multiplication constraint",
    )

    b_value = right_witness.u * left_witness.v % modulus
    b = system.alloc_private(f"{label}/B computation/product num", b_value)
    system.enforce(
        right_variables.u,
        left_variables.v,
        b,
        f"{label}/B computation/multiplication constraint",
    )

    c_value = CURVE_D * a_value * b_value % modulus
    c = system.alloc_private(f"{label}/C/num", c_value)
    system.enforce(
        CURVE_D * a.lc(),
        b,
        c,
        f"{label}/C computation",
    )

    u_denominator = (1 + c_value) % modulus
    if u_denominator == 0:
        raise R1CSError("point addition witness has a zero denominator")
    u3_value = (a_value + b_value) * pow(
        u_denominator, modulus - 2, modulus
    ) % modulus
    u3 = system.alloc_private(f"{label}/u3/num", u3_value)
    system.enforce(
        1 + c.lc(),
        u3,
        a.lc() + b,
        f"{label}/u3 computation",
    )

    v_denominator = (1 - c_value) % modulus
    if v_denominator == 0:
        raise R1CSError("point addition witness has a zero denominator")
    v3_value = (uppercase_u_value - a_value - b_value) * pow(
        v_denominator, modulus - 2, modulus
    ) % modulus
    v3 = system.alloc_private(f"{label}/v3/num", v3_value)
    system.enforce(
        1 - c.lc(),
        v3,
        uppercase_u.lc() - a - b,
        f"{label}/v3 computation",
    )
    return EdwardsPointWitnessVariables(u3, v3)


def constrain_spend_edwards_point_not_small_order(
    system: R1CS,
    point_variables: EdwardsPointWitnessVariables,
    point_witness: Point,
    label: str = "non-small-order",
) -> EdwardsPointWitnessVariables:
    """Port `EdwardsPoint::assert_not_small_order` in pinned source order."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    _validate_point_assignment(system, point_variables, point_witness)

    current_variables = point_variables
    current_witness = point_witness
    for name in ("first doubling", "second doubling", "third doubling"):
        doubled_witness = current_witness + current_witness
        current_variables = constrain_spend_edwards_point_double(
            system,
            current_variables,
            current_witness,
            f"{label}/{name}",
        )
        current_witness = doubled_witness

    u_value = system.witness_value(current_variables.u)
    if u_value is None:
        raise R1CSError("small-order check input is unassigned")
    if u_value == 0:
        raise R1CSError("small-order check rejected a zero u coordinate")
    inverse = pow(u_value, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    inverse_variable = system.alloc_private(
        f"{label}/check u != 0/ephemeral inverse", inverse
    )
    system.enforce(
        current_variables.u,
        inverse_variable,
        1,
        f"{label}/check u != 0/nonzero assertion constraint",
    )
    return current_variables


def constrain_spend_edwards_point_repr(
    system: R1CS,
    point_variables: EdwardsPointWitnessVariables,
    point_witness: Point,
    label: str = "representation",
) -> tuple[Variable, ...]:
    """Port `EdwardsPoint::repr` and Bellman's strict field-bit unpacking."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    _validate_point_assignment(system, point_variables, point_witness)

    u_bits = _constrain_spend_strict_field_bits(
        system, point_variables.u, f"{label}/unpack u"
    )
    v_bits = _constrain_spend_strict_field_bits(
        system, point_variables.v, f"{label}/unpack v"
    )
    return v_bits + (u_bits[0],)


def _constrain_spend_strict_field_bits(
    system: R1CS, value: Variable, label: str
) -> tuple[Variable, ...]:
    system.require_owned(value)
    field_modulus = SCALAR_MODULUS
    bit_length = field_modulus.bit_length()
    assigned_value = system.witness_value(value)
    if assigned_value is None:
        raise R1CSError("strict field-bit witness is unassigned")

    result: list[Variable] = []
    current_run: list[Variable] = []
    last_run: Variable | None = None
    found_one = False
    bit_index = 0

    for field_bit_index in range(bit_length - 1, -1, -1):
        bound_bit = ((field_modulus - 1) >> field_bit_index) & 1
        witness_bit = (assigned_value >> field_bit_index) & 1
        found_one = found_one or bool(bound_bit)
        if not found_one:
            if witness_bit:
                raise R1CSError("strict field-bit witness exceeds field width")
            continue

        bit_label = f"{label}/bit {bit_index}"
        if bound_bit:
            bit = system.alloc_private(f"{bit_label}/boolean", witness_bit)
            system.enforce(
                1 - bit.lc(),
                bit,
                0,
                f"{bit_label}/boolean constraint",
            )
            current_run.append(bit)
        else:
            if current_run:
                conjunction = current_run + (
                    [] if last_run is None else [last_run]
                )
                previous = conjunction[0]
                for and_index, right in enumerate(conjunction[1:], start=1):
                    and_label = (
                        f"{label}/run ending at {bit_index}/and {and_index}"
                    )
                    left_value = system.witness_value(previous)
                    right_value = system.witness_value(right)
                    if left_value is None or right_value is None:
                        raise R1CSError("strict field-bit witness is unassigned")
                    result_value = left_value * right_value % field_modulus
                    combined = system.alloc_private(
                        f"{and_label}/and result", result_value
                    )
                    system.enforce(
                        previous,
                        right,
                        combined,
                        f"{and_label}/and constraint",
                    )
                    previous = combined
                last_run = previous
                current_run.clear()

            bit = system.alloc_private(f"{bit_label}/boolean", witness_bit)
            if last_run is None:
                system.enforce(
                    1 - bit.lc(),
                    bit,
                    0,
                    f"{bit_label}/boolean constraint",
                )
            else:
                system.enforce(
                    1 - last_run.lc() - bit.lc(),
                    bit,
                    0,
                    f"{bit_label}/boolean constraint",
                )
        result.append(bit)
        bit_index += 1

    if current_run:
        raise R1CSError("strict field-bit comparator ended with an open prefix")

    little_endian = tuple(reversed(result))
    reconstruction = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(little_endian))
    )
    system.enforce(
        0,
        0,
        reconstruction - value.lc(),
        f"{label}/unpacking constraint",
    )
    return little_endian


def allocate_spend_fixed_base_scalar_bits(
    system: R1CS,
    scalar: int | None,
    bit_length: int,
    label: str = "scalar bits",
) -> tuple[Variable, ...]:
    """Allocate source-ordered Bellman boolean bits for a scalar witness."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if type(bit_length) is not int or bit_length < 1:
        raise R1CSError("fixed-base bit length must be a positive integer")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if type(scalar) is not int or not 0 <= scalar < 1 << bit_length:
        raise R1CSError("fixed-base scalar witness is missing or out of range")
    if bit_length == 252 and scalar >= _JUBJUB_SCALAR_MODULUS:
        raise R1CSError("fixed-base scalar is outside the Jubjub scalar field")

    bits: list[Variable] = []
    for index in range(bit_length):
        bit = system.alloc_private(f"{label}/bit {index}/boolean", (scalar >> index) & 1)
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{label}/bit {index}/boolean constraint",
        )
        bits.append(bit)
    return tuple(bits)


def spend_fixed_base_tables(
    base: Point,
) -> tuple[tuple[Point, ...], ...]:
    """Generate the pinned 84 windows of eight consecutive multiples."""
    if not isinstance(base, Point) or not _is_spend_fixed_base_base(base.u, base.v):
        raise R1CSError("fixed-base table source must be a subgroup point")

    windows: list[tuple[Point, ...]] = []
    window_base = base
    for _ in range(_FIXED_BASE_WINDOW_COUNT):
        table = [IDENTITY]
        multiple = window_base
        for _ in range(7):
            table.append(multiple)
            multiple = multiple + window_base
        windows.append(tuple(table))
        window_base = multiple
    return tuple(windows)


@lru_cache(maxsize=32)
def _spend_fixed_base_tables_cached(
    base_u: int, base_v: int
) -> tuple[tuple[Point, ...], ...]:
    return spend_fixed_base_tables(Point(base_u, base_v))


@lru_cache(maxsize=32)
def _is_spend_fixed_base_base(base_u: int, base_v: int) -> bool:
    base = Point(base_u, base_v)
    return base.is_on_curve() and base.is_in_subgroup()


def constrain_spend_fixed_base_mul(
    system: R1CS,
    bits_le: tuple[SpendBoolean, ...] | list[SpendBoolean],
    base: Point,
    label: str = "fixed base multiplication",
) -> EdwardsPointWitnessVariables:
    """Port Sapling ``ecc::fixed_base_multiplication`` in isolation."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    if not isinstance(base, Point) or not _is_spend_fixed_base_base(base.u, base.v):
        raise R1CSError("fixed-base multiplication requires a subgroup base")
    if not bits_le:
        raise R1CSError("fixed-base multiplication requires at least one bit")
    for bit in bits_le:
        if isinstance(bit, Variable):
            system.require_owned(bit)
            value = system.witness_value(bit)
            if value not in (0, 1):
                raise R1CSError("fixed-base selector must be an assigned boolean")
        elif isinstance(bit, (_NegatedBit, _BellmanNegated)):
            system.require_owned(bit.variable)
            if system.witness_value(bit.variable) not in (0, 1):
                raise R1CSError("fixed-base selector must be an assigned boolean")
        elif type(bit) is not bool:
            raise TypeError("fixed-base selectors must be circuit booleans")

    tables = _spend_fixed_base_tables_cached(base.u, base.v)
    window_count = (len(bits_le) + _FIXED_BASE_WINDOW_BITS - 1) // _FIXED_BASE_WINDOW_BITS
    if window_count > len(tables):
        raise R1CSError("fixed-base scalar exceeds the 252-bit table")

    accumulator: EdwardsPointWitnessVariables | None = None
    accumulator_witness: Point | None = None
    for window in range(window_count):
        start = window * _FIXED_BASE_WINDOW_BITS
        window_bits: tuple[SpendBoolean, SpendBoolean, SpendBoolean] = tuple(
            bits_le[index] if index < len(bits_le) else False
            for index in range(start, start + _FIXED_BASE_WINDOW_BITS)
        )  # type: ignore[assignment]
        values = tuple(_spend_boolean_value(system, bit) for bit in window_bits)
        selector = sum(value << index for index, value in enumerate(values))
        selected_witness = tables[window][selector]
        selected = _constrain_spend_lookup3_xy(
            system,
            window_bits,
            tables[window],
            selected_witness,
            f"{label}/window table lookup {window}",
        )
        if accumulator is None:
            accumulator = selected
            accumulator_witness = selected_witness
        else:
            assert accumulator_witness is not None
            accumulator_witness = accumulator_witness + selected_witness
            accumulator = constrain_spend_edwards_point_add(
                system,
                accumulator,
                Point(
                    system.witness_value(accumulator.u),
                    system.witness_value(accumulator.v),
                ),
                selected,
                selected_witness,
                f"{label}/addition {window}",
            )
    assert accumulator is not None
    return accumulator


def _spend_boolean_value(system: R1CS, bit: SpendBoolean) -> bool:
    if isinstance(bit, Variable):
        value = system.witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("fixed-base selector must be an assigned boolean")
        return bool(value)
    if isinstance(bit, (_NegatedBit, _BellmanNegated)):
        value = system.witness_value(bit.variable)
        if value not in (0, 1):
            raise R1CSError("fixed-base selector must be an assigned boolean")
        return not bool(value)
    return bit


def _spend_boolean_lc(system: R1CS, bit: SpendBoolean):
    if isinstance(bit, Variable):
        system.require_owned(bit)
        return bit.lc()
    if isinstance(bit, (_NegatedBit, _BellmanNegated)):
        system.require_owned(bit.variable)
        return 1 - bit.variable.lc()
    return system.linear_combination((), int(bit))


def _constrain_spend_lookup3_xy(
    system: R1CS,
    bits: tuple[SpendBoolean, SpendBoolean, SpendBoolean],
    table: tuple[Point, ...],
    selected_witness: Point,
    label: str,
) -> EdwardsPointWitnessVariables:
    if len(table) != 8:
        raise R1CSError("fixed-base lookup requires an eight-entry window")
    x = system.alloc_private(f"{label}/x/num", selected_witness.u)
    y = system.alloc_private(f"{label}/y/num", selected_witness.v)

    def coefficients(coordinate: str) -> tuple[int, ...]:
        values = [0] * 8
        for index, point in enumerate(table):
            current = (getattr(point, coordinate) - values[index]) % CIRCUIT_FIELD_MODULUS
            values[index] = current
            for position in range(index + 1, 8):
                if position & index == index:
                    values[position] = (
                        values[position] + current
                    ) % CIRCUIT_FIELD_MODULUS
        return tuple(values)

    x_coefficients = coefficients("u")
    y_coefficients = coefficients("v")
    precomp = _spend_boolean_and(system, bits[1], bits[2], f"{label}/precomp")
    one = system.one

    def lookup_row(
        name: str,
        coeffs: tuple[int, ...],
        result: Variable,
    ) -> None:
        left = (
            coeffs[1] * one.lc()
            + coeffs[3] * _spend_boolean_lc(system, bits[1])
            + coeffs[5] * _spend_boolean_lc(system, bits[2])
            + coeffs[7] * _spend_boolean_lc(system, precomp)
        )
        right = _spend_boolean_lc(system, bits[0])
        output = (
            result.lc()
            - coeffs[0] * one.lc()
            - coeffs[2] * _spend_boolean_lc(system, bits[1])
            - coeffs[4] * _spend_boolean_lc(system, bits[2])
            - coeffs[6] * _spend_boolean_lc(system, precomp)
        )
        system.enforce(left, right, output, f"{label}/{name}")

    lookup_row("x-coordinate lookup", x_coefficients, x)
    lookup_row("y-coordinate lookup", y_coefficients, y)
    return EdwardsPointWitnessVariables(x, y)


def _spend_boolean_and(
    system: R1CS, left: SpendBoolean, right: SpendBoolean, label: str
) -> SpendBoolean:
    if type(left) is bool:
        return right if left else False
    if type(right) is bool:
        return left if right else False

    left_value = _spend_boolean_value(system, left)
    right_value = _spend_boolean_value(system, right)
    left_negated = isinstance(left, (_NegatedBit, _BellmanNegated))
    right_negated = isinstance(right, (_NegatedBit, _BellmanNegated))
    if left_negated and right_negated:
        left_variable = left.variable
        right_variable = right.variable
        result_label = "nor result"
        constraint_label = "nor constraint"
        left_lc = 1 - left_variable.lc()
        right_lc = 1 - right_variable.lc()
    elif left_negated or right_negated:
        negated = left if left_negated else right
        positive = right if left_negated else left
        left_variable = positive
        right_variable = negated.variable
        result_label = "and not result"
        constraint_label = "and not constraint"
        left_lc = left_variable.lc()
        right_lc = 1 - right_variable.lc()
    else:
        left_variable = left
        right_variable = right
        result_label = "and result"
        constraint_label = "and constraint"
        left_lc = left_variable.lc()
        right_lc = right_variable.lc()

    system.require_owned(left_variable)
    system.require_owned(right_variable)
    result = system.alloc_private(
        f"{label}/{result_label}", int(left_value and right_value)
    )
    system.enforce(
        left_lc,
        right_lc,
        result,
        f"{label}/{constraint_label}",
    )
    return result


def constrain_spend_edwards_point_mul(
    system: R1CS,
    point_variables: EdwardsPointWitnessVariables,
    point_witness: Point,
    bits_le: tuple[SpendBoolean, ...] | list[SpendBoolean],
    label: str = "variable base multiplication",
) -> EdwardsPointWitnessVariables:
    """Port `EdwardsPoint::mul` with source-ordered double/select/add steps."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(label, str) or not label:
        raise R1CSError("label must be a non-empty string")
    _validate_point_assignment(system, point_variables, point_witness)
    if not bits_le:
        raise R1CSError("variable-base multiplication requires at least one bit")
    for bit in bits_le:
        if isinstance(bit, Variable):
            system.require_owned(bit)
            if system.witness_value(bit) not in (0, 1):
                raise R1CSError(
                    "variable-base scalar bits must be assigned booleans"
                )
        elif isinstance(bit, (_NegatedBit, _BellmanNegated)):
            system.require_owned(bit.variable)
            if system.witness_value(bit.variable) not in (0, 1):
                raise R1CSError(
                    "variable-base scalar bits must be assigned booleans"
                )
        elif type(bit) is not bool:
            raise TypeError("variable-base scalar bits must be variables or booleans")

    current_base_variables: EdwardsPointWitnessVariables | None = None
    current_base_witness: Point | None = None
    result_variables: EdwardsPointWitnessVariables | None = None
    result_witness: Point | None = None

    for index, bit in enumerate(bits_le):
        if current_base_variables is None:
            current_base_variables = point_variables
            current_base_witness = point_witness
        else:
            assert current_base_witness is not None
            previous_base_witness = current_base_witness
            current_base_witness = previous_base_witness + previous_base_witness
            doubled_variables = constrain_spend_edwards_point_double(
                system,
                current_base_variables,
                previous_base_witness,
                f"{label}/doubling {index}",
            )
            current_base_variables = doubled_variables

        assert current_base_witness is not None
        selected_witness = (
            current_base_witness if _spend_boolean_value(system, bit) else IDENTITY
        )
        selected_variables = _constrain_spend_edwards_point_select(
            system,
            current_base_variables,
            current_base_witness,
            bit,
            selected_witness,
            f"{label}/selection {index}",
        )
        if result_variables is None:
            result_variables = selected_variables
            result_witness = selected_witness
        else:
            assert result_witness is not None
            result_witness = result_witness + selected_witness
            result_variables = constrain_spend_edwards_point_add(
                system,
                result_variables,
                Point(
                    system.witness_value(result_variables.u),
                    system.witness_value(result_variables.v),
                ),
                selected_variables,
                selected_witness,
                f"{label}/addition {index}",
            )

    assert result_variables is not None
    return result_variables


def _constrain_spend_edwards_point_select(
    system: R1CS,
    point_variables: EdwardsPointWitnessVariables,
    point_witness: Point,
    condition: SpendBoolean,
    result_witness: Point,
    label: str,
) -> EdwardsPointWitnessVariables:
    _validate_point_assignment(system, point_variables, point_witness)
    condition_value = _spend_boolean_value(system, condition)
    expected = point_witness if condition_value else IDENTITY
    if result_witness != expected:
        raise R1CSError("conditional-selection witness does not match selector")
    u_prime = system.alloc_private(f"{label}/u'/num", result_witness.u)
    system.enforce(
        point_variables.u,
        _spend_boolean_lc(system, condition),
        u_prime,
        f"{label}/u' computation",
    )

    v_prime = system.alloc_private(f"{label}/v'/num", result_witness.v)
    not_condition = 1 - _spend_boolean_lc(system, condition)
    system.enforce(
        point_variables.v,
        _spend_boolean_lc(system, condition),
        v_prime.lc() - not_condition,
        f"{label}/v' computation",
    )
    return EdwardsPointWitnessVariables(u_prime, v_prime)


def _validate_spend_reference_witness(witness: SpendReferenceWitness) -> None:
    if not isinstance(witness, SpendReferenceWitness):
        raise TypeError("witness must be a SpendReferenceWitness")
    if not isinstance(witness.ak, Point) or not isinstance(witness.g_d, Point):
        raise TypeError("ak and g_d witnesses must be Jubjub points")
    for name in ("ar", "nsk", "rcv", "rcm"):
        value = getattr(witness, name)
        if type(value) is not int or not 0 <= value < _JUBJUB_SCALAR_MODULUS:
            raise R1CSError(f"{name} witness is outside the Jubjub scalar field")
    if type(witness.value) is not int or not 0 <= witness.value < 1 << 64:
        raise R1CSError("value witness must be an unsigned 64-bit integer")
    if not isinstance(witness.authentication_path, tuple) or len(
        witness.authentication_path
    ) != 32:
        raise R1CSError("Spend authentication path must contain 32 entries")
    for level, entry in enumerate(witness.authentication_path):
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise TypeError("authentication path entries must be (sibling, direction)")
        sibling, direction = entry
        if type(sibling) is not int or not 0 <= sibling < SCALAR_MODULUS:
            raise R1CSError(f"authentication path sibling {level} is out of range")
        if type(direction) is not bool:
            raise TypeError(f"authentication path direction {level} must be boolean")
    if type(witness.anchor) is not int or not 0 <= witness.anchor < SCALAR_MODULUS:
        raise R1CSError("anchor witness is outside the circuit field")


def _spend_point_witness(
    system: R1CS, variables: EdwardsPointWitnessVariables
) -> Point:
    u = system.witness_value(variables.u)
    v = system.witness_value(variables.v)
    if u is None or v is None:
        raise R1CSError("Spend point witness is unassigned")
    return Point(u, v)


def _inputize_spend_point(
    system: SpendReferenceR1CS,
    variables: EdwardsPointWitnessVariables,
    witness: Point,
    label: str,
) -> tuple[Variable, Variable]:
    _validate_point_assignment(system, variables, witness)
    input_u = system.alloc_public(f"{label}/u/input variable", witness.u)
    system.enforce(
        input_u,
        system.one,
        variables.u,
        f"{label}/u/enforce input is correct",
    )
    input_v = system.alloc_public(f"{label}/v/input variable", witness.v)
    system.enforce(
        input_v,
        system.one,
        variables.v,
        f"{label}/v/enforce input is correct",
    )
    return input_u, input_v


def constrain_source_faithful_spend(
    system: SpendReferenceR1CS,
    witness: SpendReferenceWitness,
) -> SpendReferenceAssembly:
    """Compose the pinned Spend stages in their upstream synthesis order."""
    if not isinstance(system, SpendReferenceR1CS):
        raise TypeError("complete Spend reference synthesis requires SpendReferenceR1CS")
    if not system.is_fresh:
        raise R1CSError("complete Spend reference synthesis requires a fresh system")
    _validate_spend_reference_witness(witness)

    ak_variables = constrain_spend_edwards_point_witness(system, witness.ak, "ak")
    constrain_spend_edwards_point_not_small_order(
        system, ak_variables, witness.ak, "ak not small order"
    )

    ar_bits = allocate_spend_fixed_base_scalar_bits(
        system, witness.ar, 252, "ar"
    )
    ar_point_variables = constrain_spend_fixed_base_mul(
        system,
        ar_bits,
        sapling_fixed_base_generator("spending_key"),
        "computation of randomization for the signing key",
    )
    ar_point_witness = _spend_point_witness(system, ar_point_variables)
    randomized_key_variables = constrain_spend_edwards_point_add(
        system,
        ak_variables,
        witness.ak,
        ar_point_variables,
        ar_point_witness,
        "computation of rk",
    )
    randomized_key_witness = _spend_point_witness(system, randomized_key_variables)
    randomized_key_inputs = _inputize_spend_point(
        system, randomized_key_variables, randomized_key_witness, "rk"
    )

    nsk_bits = allocate_spend_fixed_base_scalar_bits(
        system, witness.nsk, 252, "nsk"
    )
    nullifier_key_variables = constrain_spend_fixed_base_mul(
        system,
        nsk_bits,
        sapling_fixed_base_generator("proof_generation_key"),
        "computation of nk",
    )
    ak_repr_bits = constrain_spend_edwards_point_repr(
        system, ak_variables, witness.ak, "representation of ak"
    )
    nullifier_key_witness = _spend_point_witness(system, nullifier_key_variables)
    nk_repr_bits = constrain_spend_edwards_point_repr(
        system,
        nullifier_key_variables,
        nullifier_key_witness,
        "representation of nk",
    )
    ivk = constrain_spend_ivk_blake2s(system, ak_repr_bits, nk_repr_bits)

    diversifier_base_variables = constrain_spend_edwards_point_witness(
        system, witness.g_d, "witness g_d"
    )
    constrain_spend_edwards_point_not_small_order(
        system,
        diversifier_base_variables,
        witness.g_d,
        "g_d not small order",
    )
    transmission_key_variables = constrain_spend_edwards_point_mul(
        system,
        diversifier_base_variables,
        witness.g_d,
        ivk.ivk_bits,
        "compute pk_d",
    )
    transmission_key_witness = _spend_point_witness(
        system, transmission_key_variables
    )

    value_commitment = constrain_spend_value_commitment(
        system, witness.value, witness.rcv
    )
    g_d_repr_bits = constrain_spend_edwards_point_repr(
        system,
        diversifier_base_variables,
        witness.g_d,
        "representation of g_d",
    )
    transmission_key_repr_bits = constrain_spend_edwards_point_repr(
        system,
        transmission_key_variables,
        transmission_key_witness,
        "representation of pk_d",
    )
    note_commitment = constrain_spend_note_commitment(
        system,
        witness.value,
        diversifier_base_variables,
        witness.g_d,
        transmission_key_variables,
        transmission_key_witness,
        witness.rcm,
        value_bits=value_commitment.value_bits,
        g_d_repr_bits=g_d_repr_bits,
        pk_d_repr_bits=transmission_key_repr_bits,
    )

    merkle_path = constrain_spend_merkle_authentication_path(
        system,
        note_commitment.commitment_variables.u,
        note_commitment.commitment_witness.u,
        witness.authentication_path,
    )
    conditional_anchor = constrain_spend_source_order_conditional_anchor(
        system,
        merkle_path.root_variable,
        merkle_path.root_value,
        value_commitment.value_bits,
        witness.value,
        witness.anchor,
    )

    position_variables = constrain_spend_fixed_base_mul(
        system,
        merkle_path.position_bits,
        sapling_fixed_base_generator("nullifier_position"),
        "g^position",
    )
    position_witness = _spend_point_witness(system, position_variables)
    rho_variables = constrain_spend_edwards_point_add(
        system,
        note_commitment.commitment_variables,
        note_commitment.commitment_witness,
        position_variables,
        position_witness,
        "faerie gold prevention",
    )
    rho_witness = _spend_point_witness(system, rho_variables)
    rho_repr_bits = constrain_spend_edwards_point_repr(
        system, rho_variables, rho_witness, "representation of rho"
    )
    nullifier_hash = constrain_spend_nullifier_blake2s(
        system, nk_repr_bits, rho_repr_bits
    )
    nullifier_multipacking = constrain_spend_nullifier_multipacking(
        system, nullifier_hash.digest_bits
    )

    public_inputs = (
        *randomized_key_inputs,
        *value_commitment.input_variables,
        conditional_anchor.anchor_variable,
        *nullifier_multipacking.input_variables,
    )
    if len(public_inputs) != 7 or tuple(
        system.public_input_position(variable) for variable in public_inputs
    ) != tuple(range(1, 8)):
        raise R1CSError("source-ordered Spend inputs did not occupy positions 1 through 7")
    return SpendReferenceAssembly(
        public_inputs,
        randomized_key_variables,
        nullifier_key_variables,
        ak_repr_bits,
        nk_repr_bits,
        ivk.ivk_bits,
        diversifier_base_variables,
        transmission_key_variables,
        transmission_key_repr_bits,
        value_commitment,
        note_commitment,
        merkle_path,
        conditional_anchor,
        rho_variables,
        rho_repr_bits,
        nullifier_hash,
        nullifier_multipacking,
    )
