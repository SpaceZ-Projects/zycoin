"""Deterministic Groth16 proof-equation assembly from explicit validated inputs.

The module assembles A/B/C group elements only. It does not generate
randomizers, load/authenticate parameters, serialize proofs, or verify them.
Callers must supply trusted randomness and establish parameter compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass

from .bls12_381 import (
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    multiply_g1,
    multiply_g2,
)
from .groth16_qap import QAP, QAPAssignment, QAPError
from .groth16_queries import (
    G1Query,
    G2Query,
    QueryError,
    QueryScalarAssignment,
    ValidatedG1Point,
    ValidatedG2Point,
    msm_g1,
    msm_g2,
)


class ProofAssemblyError(ValueError):
    """Raised when proof-equation inputs are invalid or dimensionally wrong."""


@dataclass(frozen=True)
class Groth16ProvingQueries:
    """Validated key points and ordered query vectors for proof assembly."""

    alpha_g1: ValidatedG1Point
    beta_g1: ValidatedG1Point
    beta_g2: ValidatedG2Point
    delta_g1: ValidatedG1Point
    delta_g2: ValidatedG2Point
    a_query: G1Query
    b_g1_query: G1Query
    b_g2_query: G2Query
    l_query: G1Query
    h_query: G1Query

    def __post_init__(self) -> None:
        for name in ("alpha_g1", "beta_g1", "delta_g1"):
            if not isinstance(getattr(self, name), ValidatedG1Point):
                raise TypeError(f"{name} must be a ValidatedG1Point")
        for name in ("beta_g2", "delta_g2"):
            if not isinstance(getattr(self, name), ValidatedG2Point):
                raise TypeError(f"{name} must be a ValidatedG2Point")
        for name in ("a_query", "b_g1_query", "l_query", "h_query"):
            if not isinstance(getattr(self, name), G1Query):
                raise TypeError(f"{name} must be a G1Query")
        if not isinstance(self.b_g2_query, G2Query):
            raise TypeError("b_g2_query must be a G2Query")


@dataclass(frozen=True)
class ProofAssemblyResult:
    """Unserialized A/B/C group elements from the Groth16 proof equations."""

    a: G1Point
    b: G2Point
    c: G1Point


def _validate_scalar(value: int, name: str) -> None:
    if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
        raise ProofAssemblyError(
            f"{name} must be a canonical BLS12-381 scalar-field element"
        )


def _validate_dimensions(qap: QAP, queries: Groth16ProvingQueries) -> None:
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(queries, Groth16ProvingQueries):
        raise TypeError("queries must be Groth16ProvingQueries")
    try:
        qap._validate_shape()
    except QAPError as error:
        raise ProofAssemblyError("QAP dimensions are inconsistent") from error

    expected_variable_count = qap.variable_count
    expected_auxiliary_count = qap.auxiliary_variable_count
    expected_h_count = qap.domain.size - 1
    query_lengths = (
        ("A", queries.a_query, expected_variable_count),
        ("B G1", queries.b_g1_query, expected_variable_count),
        ("B G2", queries.b_g2_query, expected_variable_count),
        ("L", queries.l_query, expected_auxiliary_count),
        ("H", queries.h_query, expected_h_count),
    )
    for label, query, expected in query_lengths:
        if len(query.points) != expected:
            raise ProofAssemblyError(
                f"{label}-query length {len(query.points)} does not match "
                f"expected {expected}"
            )


def assemble_proof_elements(
    qap: QAP,
    assignment: QAPAssignment,
    queries: Groth16ProvingQueries,
    r: int,
    s: int,
) -> ProofAssemblyResult:
    """Evaluate the pinned Bellman A/B/C proof equations deterministically.

    Randomizers are explicit canonical Fr inputs. The function validates all
    query dimensions before witness/QAP work, verifies the assignment, builds
    its QAP quotient, and then evaluates the five query MSMs. No RNG or
    parameter source is consulted.
    """
    _validate_scalar(r, "r")
    _validate_scalar(s, "s")
    _validate_dimensions(qap, queries)
    if queries.delta_g1.point.is_infinity or queries.delta_g2.point.is_infinity:
        raise ProofAssemblyError(
            "Bellman rejects identity delta key elements for proof creation"
        )
    if not isinstance(assignment, QAPAssignment):
        raise TypeError("assignment must be a QAPAssignment")

    try:
        scalar_assignment = QueryScalarAssignment.from_qap(qap, assignment)
    except QueryError as error:
        raise ProofAssemblyError("assignment is invalid or does not satisfy QAP") from error

    quotient = qap.quotient(assignment)
    if len(quotient) != qap.domain.size - 1:
        raise ProofAssemblyError("QAP quotient length does not match H query domain")

    try:
        a_query = msm_g1(queries.a_query, scalar_assignment.values)
        b_g1_query = msm_g1(queries.b_g1_query, scalar_assignment.values)
        b_g2_query = msm_g2(queries.b_g2_query, scalar_assignment.values)
        l_query = msm_g1(queries.l_query, scalar_assignment.auxiliary_values)
        h_query = msm_g1(queries.h_query, quotient)
    except QueryError as error:
        raise ProofAssemblyError("validated query evaluation failed") from error

    alpha_g1 = queries.alpha_g1.point
    beta_g1 = queries.beta_g1.point
    beta_g2 = queries.beta_g2.point
    delta_g1 = queries.delta_g1.point
    delta_g2 = queries.delta_g2.point

    proof_a = add_g1(
        add_g1(alpha_g1, multiply_g1(delta_g1, r)),
        a_query,
    )
    proof_b = add_g2(
        add_g2(beta_g2, multiply_g2(delta_g2, s)),
        b_g2_query,
    )

    proof_c = multiply_g1(delta_g1, r * s % SCALAR_MODULUS)
    proof_c = add_g1(proof_c, multiply_g1(alpha_g1, s))
    proof_c = add_g1(proof_c, multiply_g1(beta_g1, r))
    proof_c = add_g1(proof_c, multiply_g1(a_query, s))
    proof_c = add_g1(proof_c, multiply_g1(b_g1_query, r))
    proof_c = add_g1(proof_c, h_query)
    proof_c = add_g1(proof_c, l_query)

    return ProofAssemblyResult(proof_a, proof_b, proof_c)


__all__ = [
    "Groth16ProvingQueries",
    "ProofAssemblyError",
    "ProofAssemblyResult",
    "assemble_proof_elements",
]
