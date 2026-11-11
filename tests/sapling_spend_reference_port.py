"""Isolated source-faithful ports for pinned Sapling Spend gadget units."""

from __future__ import annotations

from dataclasses import dataclass

from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import CURVE_D, Point
from src.r1cs import R1CS, R1CSError, Variable


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
