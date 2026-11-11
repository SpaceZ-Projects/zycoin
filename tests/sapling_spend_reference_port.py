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
