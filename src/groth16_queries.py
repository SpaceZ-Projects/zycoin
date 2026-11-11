"""Pure-Python Groth16 proving-query MSMs over validated BLS12-381 points.

This module evaluates mathematical query linear combinations only. It does
not load/authenticate parameters, randomize proofs, or construct proofs.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TypeVar

from .bls12_381 import (
    G1_INFINITY,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    multi_scalar_multiply_g1,
    multi_scalar_multiply_g2,
    multiply_g1,
    multiply_g2,
)
from .groth16_qap import QAP, QAPAssignment, QAPError


class QueryError(ValueError):
    """Raised when a query or scalar assignment has invalid dimensions/data."""


@dataclass(frozen=True)
class ValidatedG1Point:
    """A curve-valid, prime-subgroup G1 point (identity is allowed)."""

    point: G1Point

    def __post_init__(self) -> None:
        if not isinstance(self.point, G1Point):
            raise TypeError("validated G1 point must wrap a G1Point")
        if not self.point.is_on_curve():
            raise QueryError("G1 query point is not on the curve")
        if not self.point.is_in_subgroup():
            raise QueryError("G1 query point is not in the prime-order subgroup")


@dataclass(frozen=True)
class ValidatedG2Point:
    """A curve-valid, prime-subgroup G2 point (identity is allowed)."""

    point: G2Point

    def __post_init__(self) -> None:
        if not isinstance(self.point, G2Point):
            raise TypeError("validated G2 point must wrap a G2Point")
        if not self.point.is_on_curve():
            raise QueryError("G2 query point is not on the curve")
        if not self.point.is_in_subgroup():
            raise QueryError("G2 query point is not in the prime-order subgroup")


ValidatedPointT = TypeVar("ValidatedPointT", ValidatedG1Point, ValidatedG2Point)
GroupPointT = TypeVar("GroupPointT", G1Point, G2Point)


def _validated_points(
    points: Sequence[ValidatedPointT] | Sequence[GroupPointT],
    point_type: type[ValidatedPointT],
    raw_type: type[GroupPointT],
    group_name: str,
) -> tuple[ValidatedPointT, ...]:
    if not isinstance(points, Sequence):
        raise TypeError(f"{group_name} query points must be a sequence")
    result: list[ValidatedPointT] = []
    for index, value in enumerate(points):
        if isinstance(value, point_type):
            result.append(value)
        elif isinstance(value, raw_type):
            result.append(point_type(value))
        else:
            raise TypeError(
                f"{group_name} query point at index {index} has the wrong type"
            )
    return tuple(result)


@dataclass(frozen=True)
class G1Query:
    """Immutable ordered query vector in G1."""

    points: tuple[ValidatedG1Point, ...] | Sequence[ValidatedG1Point] | Sequence[G1Point]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "points",
            _validated_points(self.points, ValidatedG1Point, G1Point, "G1"),
        )

    @classmethod
    def from_points(cls, points: Sequence[G1Point]) -> G1Query:
        return cls(points)


@dataclass(frozen=True)
class G2Query:
    """Immutable ordered query vector in G2."""

    points: tuple[ValidatedG2Point, ...] | Sequence[ValidatedG2Point] | Sequence[G2Point]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "points",
            _validated_points(self.points, ValidatedG2Point, G2Point, "G2"),
        )

    @classmethod
    def from_points(cls, points: Sequence[G2Point]) -> G2Query:
        return cls(points)


@dataclass(frozen=True, init=False)
class QueryScalarAssignment:
    """Canonical full witness scalars and explicit input/auxiliary boundaries."""

    values: tuple[int, ...]
    public_input_count: int
    auxiliary_variable_count: int
    _qap: QAP = field(repr=False, compare=False)

    @classmethod
    def from_qap(
        cls, qap: QAP, assignment: QAPAssignment
    ) -> QueryScalarAssignment:
        if not isinstance(qap, QAP):
            raise TypeError("qap must be a QAP")
        try:
            values = qap.validate_assignment(assignment)
        except QAPError as error:
            raise QueryError("assignment is invalid or does not satisfy the QAP") from error
        result = object.__new__(cls)
        object.__setattr__(result, "values", values)
        object.__setattr__(result, "public_input_count", qap.public_input_count)
        object.__setattr__(
            result, "auxiliary_variable_count", qap.auxiliary_variable_count
        )
        object.__setattr__(result, "_qap", qap)
        return result

    @property
    def public_values(self) -> tuple[int, ...]:
        end = self.public_input_count + 1
        return self.values[1:end]

    @property
    def auxiliary_values(self) -> tuple[int, ...]:
        return self.values[self.public_input_count + 1 :]


def _validate_g1_msm(query: G1Query, scalars: Sequence[int]) -> None:
    if not isinstance(query, G1Query):
        raise TypeError("query must be a G1Query")
    if not isinstance(scalars, Sequence):
        raise TypeError("MSM scalars must be a sequence")
    if len(query.points) != len(scalars):
        raise QueryError(
            f"G1 query length {len(query.points)} does not match scalar length "
            f"{len(scalars)}"
        )
    for index, scalar in enumerate(scalars):
        if type(scalar) is not int or not 0 <= scalar < SCALAR_MODULUS:
            raise QueryError(f"MSM scalar at index {index} is not canonical")


def _validate_g2_msm(query: G2Query, scalars: Sequence[int]) -> None:
    if not isinstance(query, G2Query):
        raise TypeError("query must be a G2Query")
    if not isinstance(scalars, Sequence):
        raise TypeError("MSM scalars must be a sequence")
    if len(query.points) != len(scalars):
        raise QueryError(
            f"G2 query length {len(query.points)} does not match scalar length "
            f"{len(scalars)}"
        )
    for index, scalar in enumerate(scalars):
        if type(scalar) is not int or not 0 <= scalar < SCALAR_MODULUS:
            raise QueryError(f"MSM scalar at index {index} is not canonical")


def msm_g1(query: G1Query, scalars: Sequence[int]) -> G1Point:
    """Evaluate an ordered G1 linear combination using existing primitives."""
    _validate_g1_msm(query, scalars)
    if len(query.points) >= 32:
        return multi_scalar_multiply_g1(
            [wrapped.point for wrapped in query.points], list(scalars)
        )
    result = G1_INFINITY
    for wrapped_point, scalar in zip(query.points, scalars):
        if scalar and not wrapped_point.point.is_infinity:
            result = add_g1(result, multiply_g1(wrapped_point.point, scalar))
    return result


def msm_g2(query: G2Query, scalars: Sequence[int]) -> G2Point:
    """Evaluate an ordered G2 linear combination using existing primitives."""
    _validate_g2_msm(query, scalars)
    if len(query.points) >= 32:
        return multi_scalar_multiply_g2(
            [wrapped.point for wrapped in query.points], list(scalars)
        )
    result = G2_INFINITY
    for wrapped_point, scalar in zip(query.points, scalars):
        if scalar and not wrapped_point.point.is_infinity:
            result = add_g2(result, multiply_g2(wrapped_point.point, scalar))
    return result


def _check_assignment_dimensions(
    qap: QAP, assignment: QueryScalarAssignment
) -> None:
    if not isinstance(assignment, QueryScalarAssignment):
        raise TypeError("assignment must be a QueryScalarAssignment")
    qap._validate_shape()
    if (
        assignment._qap is not qap
        or assignment.public_input_count != qap.public_input_count
        or assignment.auxiliary_variable_count != qap.auxiliary_variable_count
        or len(assignment.values) != qap.variable_count
    ):
        raise QueryError("scalar assignment dimensions do not match the QAP")


def evaluate_a_query(
    query: G1Query, qap: QAP, assignment: QueryScalarAssignment
) -> G1Point:
    """Evaluate A-query over ONE, public inputs, then auxiliary assignments."""
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(query, G1Query):
        raise TypeError("query must be a G1Query")
    if len(query.points) != qap.variable_count:
        raise QueryError(
            f"A-query length {len(query.points)} does not match variable count "
            f"{qap.variable_count}"
        )
    _check_assignment_dimensions(qap, assignment)
    return msm_g1(query, assignment.values)


def evaluate_b_g1_query(
    query: G1Query, qap: QAP, assignment: QueryScalarAssignment
) -> G1Point:
    """Evaluate Bellman's G1 B-query over the full variable assignment."""
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(query, G1Query):
        raise TypeError("query must be a G1Query")
    if len(query.points) != qap.variable_count:
        raise QueryError(
            f"B G1-query length {len(query.points)} does not match variable count "
            f"{qap.variable_count}"
        )
    _check_assignment_dimensions(qap, assignment)
    return msm_g1(query, assignment.values)


def evaluate_b_g2_query(
    query: G2Query, qap: QAP, assignment: QueryScalarAssignment
) -> G2Point:
    """Evaluate Bellman's G2 B-query over the full variable assignment."""
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(query, G2Query):
        raise TypeError("query must be a G2Query")
    if len(query.points) != qap.variable_count:
        raise QueryError(
            f"B G2-query length {len(query.points)} does not match variable count "
            f"{qap.variable_count}"
        )
    _check_assignment_dimensions(qap, assignment)
    return msm_g2(query, assignment.values)


def evaluate_l_query(
    query: G1Query, qap: QAP, assignment: QueryScalarAssignment
) -> G1Point:
    """Evaluate L-query over private auxiliary scalars only."""
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(query, G1Query):
        raise TypeError("query must be a G1Query")
    if len(query.points) != qap.auxiliary_variable_count:
        raise QueryError(
            f"L-query length {len(query.points)} does not match auxiliary count "
            f"{qap.auxiliary_variable_count}"
        )
    _check_assignment_dimensions(qap, assignment)
    return msm_g1(query, assignment.auxiliary_values)


def evaluate_h_query(
    query: G1Query, qap: QAP, quotient_coefficients: Sequence[int]
) -> G1Point:
    """Evaluate H-query against QAP quotient coefficients in degree order."""
    if not isinstance(qap, QAP):
        raise TypeError("qap must be a QAP")
    if not isinstance(query, G1Query):
        raise TypeError("query must be a G1Query")
    if not isinstance(quotient_coefficients, Sequence):
        raise TypeError("quotient coefficients must be a sequence")
    expected_length = qap.domain.size - 1
    if len(query.points) != expected_length:
        raise QueryError(
            f"H-query length {len(query.points)} does not match domain H length "
            f"{expected_length}"
        )
    if len(quotient_coefficients) != expected_length:
        raise QueryError(
            f"quotient length {len(quotient_coefficients)} does not match H length "
            f"{expected_length}"
        )
    return msm_g1(query, quotient_coefficients)


__all__ = [
    "G1Query",
    "G2Query",
    "QueryError",
    "QueryScalarAssignment",
    "ValidatedG1Point",
    "ValidatedG2Point",
    "evaluate_a_query",
    "evaluate_b_g1_query",
    "evaluate_b_g2_query",
    "evaluate_h_query",
    "evaluate_l_query",
    "msm_g1",
    "msm_g2",
]
