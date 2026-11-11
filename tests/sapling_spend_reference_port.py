"""Isolated source-faithful ports for pinned Sapling Spend gadget units."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import TypeAlias

from src.bls12_381 import SCALAR_MODULUS
from src.bls12_381 import SCALAR_MODULUS as CIRCUIT_FIELD_MODULUS
from src.jubjub import (
    CURVE_D,
    IDENTITY,
    Point,
)
from src.jubjub import SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS
from src.r1cs import R1CS, R1CSError, Variable

SpendBoolean: TypeAlias = Variable | bool

_FIXED_BASE_WINDOW_BITS = 3
_FIXED_BASE_WINDOW_COUNT = 84
_JUBJUB_SCALAR_MODULUS = JUBJUB_SCALAR_MODULUS


@dataclass(frozen=True)
class EdwardsPointWitnessVariables:
    u: Variable
    v: Variable


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
        elif type(bit) is not bool:
            raise TypeError("fixed-base selectors must be variables or booleans")

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
    return bit


def _spend_boolean_lc(system: R1CS, bit: SpendBoolean):
    if isinstance(bit, Variable):
        system.require_owned(bit)
        return bit.lc()
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
    if left is False or right is False:
        return False
    if left is True:
        return right
    if right is True:
        return left
    if not isinstance(left, Variable) or not isinstance(right, Variable):
        raise R1CSError("invalid fixed-base selector")
    left_value = system.witness_value(left)
    right_value = system.witness_value(right)
    if left_value not in (0, 1) or right_value not in (0, 1):
        raise R1CSError("fixed-base selector must be an assigned boolean")
    result = system.alloc_private(
        f"{label}/and result", left_value * right_value
    )
    system.enforce(left, right, result, f"{label}/and constraint")
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
    not_condition = (
        1 - condition.lc()
        if isinstance(condition, Variable)
        else int(not condition)
    )
    system.enforce(
        point_variables.v,
        _spend_boolean_lc(system, condition),
        v_prime.lc() - not_condition,
        f"{label}/v' computation",
    )
    return EdwardsPointWitnessVariables(u_prime, v_prime)
