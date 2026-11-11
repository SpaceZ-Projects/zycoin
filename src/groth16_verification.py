"""Pure-Python Groth16 verification over validated BLS12-381 points.

Verification uses synthetic/local key material only. This module does not
authenticate verification keys or establish circuit compatibility.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .bls12_381 import (
    FIELD_MODULUS,
    SCALAR_MODULUS,
    Fp2,
    Fp12,
    G1Point,
    G2Point,
    add_g1,
    final_exponentiate,
    miller_loop,
    multiply_g1,
)
from .groth16_queries import ValidatedG1Point, ValidatedG2Point


class Groth16VerificationError(ValueError):
    """Raised when a proof, verification key, or public-input vector is malformed."""


@dataclass(frozen=True)
class Groth16VerificationKey:
    """Immutable Groth16 verification key with validated curve/subgroup points.

    ``ic_query[0]`` is the implicit ONE coefficient. Subsequent entries
    correspond positionally to the application public inputs.
    """

    alpha_g1: ValidatedG1Point | G1Point
    beta_g2: ValidatedG2Point | G2Point
    gamma_g2: ValidatedG2Point | G2Point
    delta_g2: ValidatedG2Point | G2Point
    ic_query: Sequence[ValidatedG1Point | G1Point]

    def __post_init__(self) -> None:
        if isinstance(self.alpha_g1, G1Point):
            object.__setattr__(self, "alpha_g1", ValidatedG1Point(self.alpha_g1))
        if not isinstance(self.alpha_g1, ValidatedG1Point):
            raise TypeError("alpha_g1 must be a G1Point")
        for name in ("beta_g2", "gamma_g2", "delta_g2"):
            value = getattr(self, name)
            if isinstance(value, G2Point):
                value = ValidatedG2Point(value)
                object.__setattr__(self, name, value)
            if not isinstance(value, ValidatedG2Point):
                raise TypeError(f"{name} must be a G2Point")
        if not isinstance(self.ic_query, Sequence):
            raise TypeError("ic_query must be a sequence of G1 points")
        points: list[ValidatedG1Point] = []
        for index, value in enumerate(self.ic_query):
            if isinstance(value, ValidatedG1Point):
                points.append(value)
            elif isinstance(value, G1Point):
                points.append(ValidatedG1Point(value))
            else:
                raise TypeError(
                    f"IC query point at index {index} must be a G1Point"
                )
        if not points:
            raise Groth16VerificationError(
                "verification key IC query must contain the implicit ONE point"
            )
        object.__setattr__(self, "ic_query", tuple(points))

    @property
    def public_input_count(self) -> int:
        """Number of application inputs supported by the IC query."""
        return len(self.ic_query) - 1


@dataclass(frozen=True)
class Groth16Proof:
    """Immutable proof elements validated for curve and prime-subgroup membership."""

    a: ValidatedG1Point | G1Point
    b: ValidatedG2Point | G2Point
    c: ValidatedG1Point | G1Point

    def __post_init__(self) -> None:
        for name in ("a", "c"):
            value = getattr(self, name)
            if isinstance(value, G1Point):
                value = ValidatedG1Point(value)
            if not isinstance(value, ValidatedG1Point):
                raise TypeError(f"{name} must be a G1Point")
            object.__setattr__(self, name, value)
        if isinstance(self.b, G2Point):
            object.__setattr__(self, "b", ValidatedG2Point(self.b))
        if not isinstance(self.b, ValidatedG2Point):
            raise TypeError("b must be a G2Point")


def _validate_public_inputs(public_inputs: Sequence[int]) -> tuple[int, ...]:
    if not isinstance(public_inputs, Sequence):
        raise TypeError("public_inputs must be a sequence of canonical scalars")
    values = tuple(public_inputs)
    for index, value in enumerate(values):
        if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
            raise Groth16VerificationError(
                f"public input at index {index} is not a canonical scalar"
            )
    return values


def public_input_accumulator(
    verification_key: Groth16VerificationKey,
    public_inputs: Sequence[int],
) -> G1Point:
    """Compute ``IC[0] + sum(public_inputs[i] * IC[i+1])`` in order."""
    if not isinstance(verification_key, Groth16VerificationKey):
        raise TypeError("verification_key must be a Groth16VerificationKey")
    values = _validate_public_inputs(public_inputs)
    if len(values) != verification_key.public_input_count:
        raise Groth16VerificationError(
            f"expected {verification_key.public_input_count} public inputs, "
            f"got {len(values)}"
        )

    accumulator = verification_key.ic_query[0].point
    for value, wrapped_point in zip(values, verification_key.ic_query[1:]):
        if value:
            accumulator = add_g1(
                accumulator,
                multiply_g1(wrapped_point.point, value),
            )
    return accumulator


def _negate_g1(point: G1Point) -> G1Point:
    if point.is_infinity:
        return point
    return G1Point(point.x, (-point.y) % FIELD_MODULUS)


def _negate_g2(point: G2Point) -> G2Point:
    if point.is_infinity:
        return point
    return G2Point(point.x, Fp2(-point.y.c0, -point.y.c1))


def verify_groth16_proof(
    verification_key: Groth16VerificationKey,
    proof: Groth16Proof,
    public_inputs: Sequence[int],
) -> bool:
    """Verify a proof; return ``False`` for a well-formed invalid proof.

    Malformed inputs raise ``TypeError`` or ``Groth16VerificationError``.
    The pairing product is evaluated with four Miller loops and one final
    exponentiation, matching Bellman's single-final-exponent verification
    strategy.
    """
    if not isinstance(verification_key, Groth16VerificationKey):
        raise TypeError("verification_key must be a Groth16VerificationKey")
    if not isinstance(proof, Groth16Proof):
        raise TypeError("proof must be a Groth16Proof")
    values = _validate_public_inputs(public_inputs)
    if len(values) != verification_key.public_input_count:
        raise Groth16VerificationError(
            f"expected {verification_key.public_input_count} public inputs, "
            f"got {len(values)}"
        )

    accumulator = public_input_accumulator(verification_key, values)
    alpha = verification_key.alpha_g1.point
    beta = verification_key.beta_g2.point
    negative_gamma = _negate_g2(verification_key.gamma_g2.point)
    negative_delta = _negate_g2(verification_key.delta_g2.point)
    negative_alpha = _negate_g1(alpha)

    miller_product = (
        miller_loop(proof.b.point, proof.a.point)
        * miller_loop(negative_gamma, accumulator)
        * miller_loop(negative_delta, proof.c.point)
        * miller_loop(beta, negative_alpha)
    )
    return final_exponentiate(miller_product) == Fp12.one()


SAPLING_SPEND_PUBLIC_INPUT_ORDER = (
    "rk.u",
    "rk.v",
    "cv.u",
    "cv.v",
    "anchor",
    "nullifier_chunk_0",
    "nullifier_chunk_1",
)


def verify_sapling_spend_proof(
    verification_key: Groth16VerificationKey,
    proof: Groth16Proof,
    public_inputs: Sequence[int],
) -> bool:
    """Verify Sapling Spend inputs in their established seven-value order.

    The sequence positions are ``rk.u, rk.v, cv.u, cv.v, anchor,
    nullifier_chunk_0, nullifier_chunk_1``. The verification key remains
    caller-supplied and unauthenticated.
    """
    values = _validate_public_inputs(public_inputs)
    if len(values) != len(SAPLING_SPEND_PUBLIC_INPUT_ORDER):
        raise Groth16VerificationError(
            "Sapling Spend requires exactly seven ordered public inputs"
        )
    if verification_key.public_input_count != len(SAPLING_SPEND_PUBLIC_INPUT_ORDER):
        raise Groth16VerificationError(
            "verification key does not have seven Sapling Spend public-input slots"
        )
    return verify_groth16_proof(verification_key, proof, values)


__all__ = [
    "SAPLING_SPEND_PUBLIC_INPUT_ORDER",
    "Groth16Proof",
    "Groth16VerificationError",
    "Groth16VerificationKey",
    "public_input_accumulator",
    "verify_groth16_proof",
    "verify_sapling_spend_proof",
]
