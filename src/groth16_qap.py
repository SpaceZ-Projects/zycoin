"""Witness-specific R1CS-to-QAP construction over the BLS12-381 scalar field.

This module implements the polynomial arithmetic used before Groth16
proving-key evaluation. It does not construct keys, proofs, or verifiers.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .bls12_381 import SCALAR_MODULUS
from .groth16_fft import MAX_DOMAIN_SIZE, FFTDomain
from .r1cs import R1CS, LinearCombination


class QAPError(ValueError):
    """Raised when a QAP shape, assignment, or polynomial is invalid."""


class UnsatisfiedAssignmentError(QAPError):
    """Raised when an assignment fails one or more R1CS constraints."""


def _canonical_values(values: Sequence[int], name: str) -> tuple[int, ...]:
    if not isinstance(values, Sequence):
        raise TypeError(f"{name} must be a sequence of canonical field elements")
    result = tuple(values)
    for index, value in enumerate(result):
        if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
            raise QAPError(
                f"{name}[{index}] is not a canonical scalar-field value"
            )
    return result


@dataclass(frozen=True)
class QAPAssignment:
    """Assignment with public inputs and auxiliary values kept distinct.

    The implicit ONE value is not supplied; QAP construction inserts it at
    variable index zero. Public values and auxiliary values retain their
    respective R1CS column order.
    """

    public_inputs: Sequence[int]
    auxiliary_assignments: Sequence[int]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "public_inputs", _canonical_values(self.public_inputs, "public_inputs")
        )
        object.__setattr__(
            self,
            "auxiliary_assignments",
            _canonical_values(self.auxiliary_assignments, "auxiliary_assignments"),
        )


@dataclass(frozen=True)
class QAPDomain:
    """Bellman-style row domain, including dummy input constraints."""

    constraint_count: int
    input_count: int
    row_count: int
    padding_count: int
    fft_domain: FFTDomain

    def __post_init__(self) -> None:
        if (
            type(self.constraint_count) is not int
            or self.constraint_count < 0
            or type(self.input_count) is not int
            or self.input_count < 1
            or type(self.row_count) is not int
            or type(self.padding_count) is not int
            or not isinstance(self.fft_domain, FFTDomain)
        ):
            raise QAPError("invalid QAP domain metadata")
        if (
            self.row_count != self.constraint_count + self.input_count
            or self.padding_count != self.fft_domain.size - self.row_count
            or self.padding_count < 0
        ):
            raise QAPError("inconsistent QAP domain row or padding counts")

    @classmethod
    def create(cls, constraint_count: int, input_count: int) -> QAPDomain:
        if type(constraint_count) is not int or constraint_count < 0:
            raise QAPError("constraint count must be a non-negative integer")
        if type(input_count) is not int or input_count < 1:
            raise QAPError("input count must include the implicit ONE variable")

        row_count = constraint_count + input_count
        domain_size = 1 << (row_count - 1).bit_length()
        if domain_size > MAX_DOMAIN_SIZE:
            raise QAPError(
                f"QAP domain size exceeds Bellman limit {MAX_DOMAIN_SIZE}"
            )
        fft_domain = FFTDomain.create(domain_size)
        return cls(
            constraint_count=constraint_count,
            input_count=input_count,
            row_count=row_count,
            padding_count=domain_size - row_count,
            fft_domain=fft_domain,
        )

    @property
    def size(self) -> int:
        return self.fft_domain.size


@dataclass(frozen=True)
class QAPEvaluations:
    """A, B, and C values in natural-order QAP domain order."""

    a: tuple[int, ...]
    b: tuple[int, ...]
    c: tuple[int, ...]


@dataclass(frozen=True)
class QAPPolynomials:
    """A, B, and C polynomial coefficients in ascending degree order."""

    a: tuple[int, ...]
    b: tuple[int, ...]
    c: tuple[int, ...]


@dataclass(frozen=True)
class QAP:
    """R1CS shape and domain for witness-specific Groth16 QAP polynomials.

    The R1CS rows remain sparse and are iterated in place. This avoids
    materializing a polynomial for every variable, which would be prohibitive
    for large circuits.
    """

    system: R1CS
    domain: QAPDomain
    variable_count: int
    public_input_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.system, R1CS) or not isinstance(self.domain, QAPDomain):
            raise TypeError("QAP requires an R1CS and a QAPDomain")
        self._validate_shape()

    @classmethod
    def from_r1cs(cls, system: R1CS) -> QAP:
        if not isinstance(system, R1CS):
            raise TypeError("system must be an R1CS")
        variable_count = len(system.variables)
        public_input_count = system.public_input_count
        domain = QAPDomain.create(
            system.constraint_count,
            public_input_count + 1,
        )
        return cls(
            system=system,
            domain=domain,
            variable_count=variable_count,
            public_input_count=public_input_count,
        )

    @property
    def auxiliary_variable_count(self) -> int:
        return self.variable_count - self.public_input_count - 1

    def _validate_shape(self) -> None:
        if (
            self.system.constraint_count != self.domain.constraint_count
            or len(self.system.variables) != self.variable_count
            or self.system.public_input_count != self.public_input_count
            or self.domain.input_count != self.public_input_count + 1
            or self.variable_count < self.domain.input_count
        ):
            raise QAPError("R1CS shape changed or QAP domain is inconsistent")

    def _assignment_values(self, assignment: QAPAssignment) -> tuple[int, ...]:
        if not isinstance(assignment, QAPAssignment):
            raise TypeError("assignment must be a QAPAssignment")
        if len(assignment.public_inputs) != self.public_input_count:
            raise QAPError(
                f"expected {self.public_input_count} public inputs, got "
                f"{len(assignment.public_inputs)}"
            )
        if len(assignment.auxiliary_assignments) != self.auxiliary_variable_count:
            raise QAPError(
                f"expected {self.auxiliary_variable_count} auxiliary assignments, "
                f"got {len(assignment.auxiliary_assignments)}"
            )
        return (1,) + tuple(assignment.public_inputs) + tuple(
            assignment.auxiliary_assignments
        )

    def assignment_values(self, assignment: QAPAssignment) -> tuple[int, ...]:
        """Return the full assignment ordered as ONE, public, then auxiliary."""
        self._validate_shape()
        return self._assignment_values(assignment)

    def validate_assignment(self, assignment: QAPAssignment) -> tuple[int, ...]:
        """Return full values only when every synthesized R1CS row is satisfied."""
        values = self.assignment_values(assignment)
        for row, constraint in enumerate(self.system.iter_constraints()):
            left = self._evaluate_expression(constraint.left, values)
            right = self._evaluate_expression(constraint.right, values)
            output = self._evaluate_expression(constraint.output, values)
            if left * right % SCALAR_MODULUS != output:
                raise UnsatisfiedAssignmentError(
                    f"assignment violates R1CS constraint {row}"
                )
        return values

    @staticmethod
    def _evaluate_expression(
        expression: LinearCombination, assignment_values: tuple[int, ...]
    ) -> int:
        value = 0
        for variable_index, coefficient in expression.terms:
            if variable_index >= len(assignment_values):
                raise QAPError(
                    f"linear-combination variable index {variable_index} is out of range"
                )
            value += coefficient * assignment_values[variable_index]
        return value % SCALAR_MODULUS

    def _evaluation_vectors(
        self, assignment_values: tuple[int, ...]
    ) -> tuple[list[int], list[int], list[int]]:
        self._validate_shape()
        a = [0] * self.domain.size
        b = [0] * self.domain.size
        c = [0] * self.domain.size
        row = 0
        for constraint in self.system.iter_constraints():
            a[row] = self._evaluate_expression(constraint.left, assignment_values)
            b[row] = self._evaluate_expression(constraint.right, assignment_values)
            c[row] = self._evaluate_expression(constraint.output, assignment_values)
            row += 1
        if row != self.domain.constraint_count:
            raise QAPError("R1CS constraint count changed during QAP construction")

        # Bellman adds x * 0 = 0 once for every input, including implicit ONE.
        for input_index, value in enumerate(
            assignment_values[: self.domain.input_count]
        ):
            a[row + input_index] = value
        return a, b, c

    def evaluations(self, assignment: QAPAssignment) -> QAPEvaluations:
        """Return A/B/C evaluations, including Bellman dummy and padding rows."""
        self._validate_shape()
        values = self._assignment_values(assignment)
        a, b, c = self._evaluation_vectors(values)
        return QAPEvaluations(tuple(a), tuple(b), tuple(c))

    def polynomials(self, assignment: QAPAssignment) -> QAPPolynomials:
        """Interpolate witness-specific A/B/C polynomials from domain values."""
        evaluations = self.evaluations(assignment)
        fft = self.domain.fft_domain
        return QAPPolynomials(
            tuple(fft.ifft(evaluations.a)),
            tuple(fft.ifft(evaluations.b)),
            tuple(fft.ifft(evaluations.c)),
        )

    def quotient(self, assignment: QAPAssignment) -> tuple[int, ...]:
        """Return H=(A*B-C)/(X^n-1), rejecting unsatisfied assignments.

        The quotient has ``n - 1`` coefficients, matching Bellman's H-query
        length. R1CS satisfaction establishes divisibility on the constraint
        domain; the final coefficient is also required to be zero so an
        unexpected non-divisible result cannot be truncated silently.
        """
        self._validate_shape()
        values = self._assignment_values(assignment)
        a_evaluations, b_evaluations, c_evaluations = self._evaluation_vectors(
            values
        )
        for row in range(self.domain.constraint_count):
            if (
                a_evaluations[row] * b_evaluations[row] - c_evaluations[row]
            ) % SCALAR_MODULUS:
                raise UnsatisfiedAssignmentError(
                    f"assignment violates R1CS constraint {row}"
                )

        fft = self.domain.fft_domain

        def to_coset(evaluations: list[int]) -> list[int]:
            coefficients = fft.ifft(evaluations)
            del evaluations
            result = fft.coset_fft(coefficients)
            del coefficients
            return result

        a_coset = to_coset(a_evaluations)
        del a_evaluations
        b_coset = to_coset(b_evaluations)
        del b_evaluations
        c_coset = to_coset(c_evaluations)
        del c_evaluations

        vanishing = (pow(fft.coset_generator, fft.size, SCALAR_MODULUS) - 1) % (
            SCALAR_MODULUS
        )
        if vanishing == 0:
            raise QAPError("coset intersects the QAP constraint domain")
        vanishing_inverse = pow(vanishing, -1, SCALAR_MODULUS)
        for index in range(fft.size):
            a_coset[index] = (
                (a_coset[index] * b_coset[index] - c_coset[index])
                * vanishing_inverse
            ) % SCALAR_MODULUS
        del b_coset, c_coset

        quotient_coefficients = fft.icoset_fft(a_coset)
        if quotient_coefficients[-1] != 0:
            raise QAPError(
                "QAP quotient has a nonzero degree-(n-1) coefficient; "
                "divisibility check failed"
            )
        return tuple(quotient_coefficients[:-1])


__all__ = [
    "QAP",
    "QAPAssignment",
    "QAPDomain",
    "QAPError",
    "QAPEvaluations",
    "QAPPolynomials",
    "UnsatisfiedAssignmentError",
]
