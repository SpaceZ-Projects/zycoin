"""Small deterministic R1CS builder over the BLS12-381 scalar field.

This is a constraint-system foundation only; it does not define Sapling
Spend or Output circuits.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Union

from .bls12_381 import SCALAR_MODULUS

_MATRIX_SERIALIZATION_FORMAT = "zycoin-r1cs-matrix-v1"
_MATRIX_FINGERPRINT_DOMAIN = b"zycoin-r1cs-matrix-fingerprint-v1\0"


class R1CSError(ValueError):
    """Raised when an R1CS expression or witness is malformed."""


@dataclass(frozen=True)
class Variable:
    index: int
    kind: str
    name: str
    _owner: object

    def lc(self) -> "LinearCombination":
        return LinearCombination(((self.index, 1),), self._owner)


@dataclass(frozen=True)
class LinearCombination:
    terms: Tuple[Tuple[int, int], ...]
    _owner: object

    def __post_init__(self) -> None:
        canonical = _canonical_terms(self.terms)
        object.__setattr__(self, "terms", canonical)

    def __add__(
        self, other: Union[int, Variable, "LinearCombination"]
    ) -> "LinearCombination":
        right = _coerce_lc(other, self._owner)
        return LinearCombination(self.terms + right.terms, self._owner)

    __radd__ = __add__

    def __sub__(
        self, other: Union[int, Variable, "LinearCombination"]
    ) -> "LinearCombination":
        right = _coerce_lc(other, self._owner)
        return LinearCombination(
            self.terms + tuple((index, -coefficient) for index, coefficient in right.terms),
            self._owner,
        )

    def __rsub__(
        self, other: Union[int, Variable, "LinearCombination"]
    ) -> "LinearCombination":
        left = _coerce_lc(other, self._owner)
        return LinearCombination(
            left.terms + tuple((index, -coefficient) for index, coefficient in self.terms),
            self._owner,
        )

    def __mul__(self, coefficient: int) -> "LinearCombination":
        if type(coefficient) is not int:
            return NotImplemented
        return LinearCombination(
            tuple((index, coefficient * value) for index, value in self.terms),
            self._owner,
        )

    __rmul__ = __mul__


@dataclass(frozen=True)
class Constraint:
    left: LinearCombination
    right: LinearCombination
    output: LinearCombination
    label: str


def _canonical_terms(
    terms: Iterable[Tuple[int, int]]
) -> Tuple[Tuple[int, int], ...]:
    combined: Dict[int, int] = {}
    for index, coefficient in terms:
        if type(index) is not int or index < 0:
            raise R1CSError("linear-combination variable index must be non-negative")
        if type(coefficient) is not int:
            raise TypeError("linear-combination coefficients must be integers")
        combined[index] = (combined.get(index, 0) + coefficient) % SCALAR_MODULUS
    return tuple(
        (index, coefficient)
        for index, coefficient in sorted(combined.items())
        if coefficient
    )


def _coerce_lc(
    value: Union[int, Variable, LinearCombination], owner: object
) -> LinearCombination:
    if isinstance(value, LinearCombination):
        if value._owner is not owner:
            raise R1CSError("cannot combine expressions from different systems")
        return value
    if isinstance(value, Variable):
        if value._owner is not owner:
            raise R1CSError("cannot combine variables from different systems")
        return value.lc()
    if type(value) is int:
        return LinearCombination(((0, value),), owner)
    raise TypeError("expected an integer, variable, or linear combination")


class R1CS:
    """Build and evaluate rank-1 constraints ``A(w) * B(w) = C(w)``."""

    def __init__(self) -> None:
        self._owner = object()
        self._variables = [Variable(0, "one", "ONE", self._owner)]
        self._values: list[Optional[int]] = [1]
        self._constraints: list[Constraint] = []
        self._public_input_count = 0
        self._private_allocations_started = False

    @property
    def one(self) -> Variable:
        return self._variables[0]

    def namespace(self, name: str):
        from .synthesis import R1CSNamespace

        return R1CSNamespace(self, name)

    def require_owned(self, variable: Variable) -> None:
        self._require_owned(variable)

    @property
    def is_fresh(self) -> bool:
        return (
            self._public_input_count == 0
            and len(self._variables) == 1
            and not self._constraints
        )

    def public_input_position(self, variable: Variable) -> int | None:
        self.require_owned(variable)
        if variable.kind != "public":
            return None
        return variable.index

    @property
    def variables(self) -> Tuple[Variable, ...]:
        return tuple(self._variables)

    @property
    def constraints(self) -> Tuple[Constraint, ...]:
        return tuple(self._constraints)

    def iter_constraints(self) -> Iterator[Constraint]:
        """Iterate constraints in synthesis order without copying the row list."""
        return iter(self._constraints)

    @property
    def public_input_count(self) -> int:
        return self._public_input_count

    @property
    def constraint_count(self) -> int:
        return len(self._constraints)

    def alloc_public(self, name: str, value: Optional[int]) -> Variable:
        if self._private_allocations_started:
            raise R1CSError("public inputs must be allocated before private inputs")
        variable = self._allocate("public", name, value)
        self._public_input_count += 1
        return variable

    def alloc_private(self, name: str, value: Optional[int]) -> Variable:
        self._private_allocations_started = True
        return self._allocate("private", name, value)

    def _allocate(self, kind: str, name: str, value: Optional[int]) -> Variable:
        if not isinstance(name, str) or not name:
            raise R1CSError("variable name must be a non-empty string")
        if value is not None and type(value) is not int:
            raise TypeError("witness values must be integers or None")
        variable = Variable(len(self._variables), kind, name, self._owner)
        self._variables.append(variable)
        self._values.append(None if value is None else value % SCALAR_MODULUS)
        return variable

    def linear_combination(
        self, terms: Iterable[Tuple[Variable, int]], constant: int = 0
    ) -> LinearCombination:
        if type(constant) is not int:
            raise TypeError("linear-combination constant must be an integer")
        combined = [(0, constant)]
        for variable, coefficient in terms:
            self._require_owned(variable)
            if type(coefficient) is not int:
                raise TypeError("linear-combination coefficients must be integers")
            combined.append((variable.index, coefficient))
        return LinearCombination(tuple(combined), self._owner)

    def enforce(
        self,
        left: Union[int, Variable, LinearCombination],
        right: Union[int, Variable, LinearCombination],
        output: Union[int, Variable, LinearCombination],
        label: str = "",
    ) -> None:
        if not isinstance(label, str):
            raise TypeError("constraint label must be a string")
        left_lc = _coerce_lc(left, self._owner)
        right_lc = _coerce_lc(right, self._owner)
        output_lc = _coerce_lc(output, self._owner)
        for expression in (left_lc, right_lc, output_lc):
            self._validate_linear_combination(expression)
        self._constraints.append(
            Constraint(
                left_lc,
                right_lc,
                output_lc,
                label,
            )
        )

    def enforce_equal(
        self,
        left: Union[int, Variable, LinearCombination],
        right: Union[int, Variable, LinearCombination],
        label: str = "",
    ) -> None:
        self.enforce(_coerce_lc(left, self._owner) - right, 1, 0, label)

    def multiply(
        self,
        left: Union[int, Variable, LinearCombination],
        right: Union[int, Variable, LinearCombination],
        name: str,
    ) -> Variable:
        left_lc = _coerce_lc(left, self._owner)
        right_lc = _coerce_lc(right, self._owner)
        left_value = self._evaluate(left_lc, self._values)
        right_value = self._evaluate(right_lc, self._values)
        output_value = (
            None
            if left_value is None or right_value is None
            else left_value * right_value % SCALAR_MODULUS
        )
        output = self.alloc_private(name, output_value)
        self.enforce(left_lc, right_lc, output, f"{name} multiplication")
        return output

    def boolean(self, variable: Variable, label: str = "") -> None:
        self._require_owned(variable)
        self.enforce(
            variable,
            variable.lc() - 1,
            0,
            label or f"{variable.name} boolean",
        )

    def range_check(
        self,
        value: Variable,
        bit_length: int,
        name: str,
        upper_bound: Optional[int] = None,
    ) -> Tuple[Variable, ...]:
        self._require_owned(value)
        if type(bit_length) is not int or bit_length < 1:
            raise R1CSError("bit length must be a positive integer")
        if upper_bound is not None and (
            type(upper_bound) is not int
            or upper_bound < 1
            or upper_bound > 1 << bit_length
        ):
            raise R1CSError("upper bound must fit within the requested bit width")
        witness = self._values[value.index]
        if witness is not None and witness >= (
            upper_bound if upper_bound is not None else 1 << bit_length
        ):
            raise R1CSError(f"{value.name} is outside the requested range")
        bits = tuple(
            self.alloc_private(
                f"{name}[{index}]",
                None if witness is None else (witness >> index) & 1,
            )
            for index in range(bit_length)
        )
        for index, bit in enumerate(bits):
            self.boolean(bit, f"{name}[{index}] boolean")
        reconstruction = self.linear_combination(
            tuple((bit, 1 << index) for index, bit in enumerate(bits))
        )
        self.enforce_equal(value, reconstruction, f"{name} reconstruction")
        if upper_bound is not None and upper_bound < 1 << bit_length:
            equal: Union[int, LinearCombination] = 1
            less: Union[int, LinearCombination] = 0
            for index in range(bit_length - 1, -1, -1):
                bit = bits[index]
                if upper_bound >> index & 1:
                    first_difference = self.multiply(
                        equal,
                        1 - bit.lc(),
                        f"{name} less-than term[{index}]",
                    )
                    less = less + first_difference.lc()
                    equal = self.multiply(
                        equal, bit, f"{name} equal term[{index}]"
                    ).lc()
                else:
                    equal = self.multiply(
                        equal, 1 - bit.lc(), f"{name} equal term[{index}]"
                    ).lc()
            self.enforce_equal(less, 1, f"{name} strict upper bound")
        return bits

    def pack_bits(
        self, bits: Iterable[Variable], name: str, public: bool = False
    ) -> Variable:
        bit_variables = tuple(bits)
        if not bit_variables:
            raise R1CSError("at least one bit is required")
        if len(bit_variables) > SCALAR_MODULUS.bit_length() - 1:
            raise R1CSError(
                "packed bit width must be below the scalar-field bit length"
            )
        for index, bit in enumerate(bit_variables):
            self._require_owned(bit)
            self.boolean(bit, f"{name} bit[{index}]")
        reconstruction = self.linear_combination(
            tuple((bit, 1 << index) for index, bit in enumerate(bit_variables))
        )
        witness = self._evaluate(reconstruction, self._values)
        packed = (
            self.alloc_public(name, witness)
            if public
            else self.alloc_private(name, witness)
        )
        self.enforce_equal(packed, reconstruction, f"{name} bit packing")
        return packed

    def _witness_value(self, variable: Variable) -> Optional[int]:
        self._require_owned(variable)
        return self._values[variable.index]

    def witness_value(self, variable: Variable) -> Optional[int]:
        """Return an owned variable's assignment for gadget synthesis."""
        return self._witness_value(variable)

    def is_satisfied(self, assignments: Optional[Dict[int, int]] = None) -> bool:
        values = list(self._values)
        if assignments is not None:
            for index, value in assignments.items():
                if type(index) is not int or index <= 0 or index >= len(values):
                    raise R1CSError(f"invalid assignment variable index: {index!r}")
                if type(value) is not int:
                    raise TypeError("assignments must be integers")
                values[index] = value % SCALAR_MODULUS
        if any(value is None for value in values):
            raise R1CSError("constraint system has unassigned variables")
        concrete = [int(value) for value in values]
        for constraint in self._constraints:
            left = self._evaluate(constraint.left, concrete)
            right = self._evaluate(constraint.right, concrete)
            output = self._evaluate(constraint.output, concrete)
            if left * right % SCALAR_MODULUS != output:
                return False
        return True

    def public_inputs(self) -> Tuple[int, ...]:
        end = self._public_input_count + 1
        values = self._values[1:end]
        if any(value is None for value in values):
            raise R1CSError("public inputs contain unassigned values")
        return tuple(int(value) for value in values)

    def serialize(self) -> bytes:
        """Serialize shape and public-input order, never private witness values."""
        document = {
            "format": "zycoin-r1cs-v1",
            "field_modulus": str(SCALAR_MODULUS),
            "public_input_count": self._public_input_count,
            "variables": [
                {"index": variable.index, "kind": variable.kind, "name": variable.name}
                for variable in self._variables
            ],
            "constraints": [
                {
                    "a": [[index, str(coefficient)] for index, coefficient in item.left.terms],
                    "b": [[index, str(coefficient)] for index, coefficient in item.right.terms],
                    "c": [[index, str(coefficient)] for index, coefficient in item.output.terms],
                    "label": item.label,
                }
                for item in self._constraints
            ],
        }
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def serialize_matrix(self) -> bytes:
        """Serialize the canonical, ordered matrices without witness values.

        Columns use this system's variable indices, with ``ONE`` at zero and
        public inputs immediately following it. Remaining columns are private
        auxiliary variables. Constraint rows retain insertion order; terms
        within each A/B/C row are sorted by column index and duplicate columns
        are combined modulo the scalar field. Coefficients are decimal strings
        containing canonical field representatives. Variable names, labels,
        and assignments are excluded.
        """
        self._validate_matrix()
        document = {
            "format": _MATRIX_SERIALIZATION_FORMAT,
            "field_modulus": str(SCALAR_MODULUS),
            "column_count": len(self._variables),
            "one_column": 0,
            "public_input_count": self._public_input_count,
            "auxiliary_variable_count": (
                len(self._variables) - 1 - self._public_input_count
            ),
            "variable_kinds": [variable.kind for variable in self._variables],
            "constraints": [
                [
                    [[index, str(coefficient)] for index, coefficient in row.terms]
                    for row in (item.left, item.right, item.output)
                ]
                for item in self._constraints
            ],
        }
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")

    def matrix_fingerprint(self) -> str:
        """Return the versioned SHA-256 fingerprint of the canonical matrix."""
        return hashlib.sha256(
            _MATRIX_FINGERPRINT_DOMAIN + self.serialize_matrix()
        ).hexdigest()

    def _require_owned(self, variable: Variable) -> None:
        if (
            not isinstance(variable, Variable)
            or variable._owner is not self._owner
            or not 0 <= variable.index < len(self._variables)
            or self._variables[variable.index] is not variable
        ):
            raise R1CSError("variable does not belong to this system")

    def _validate_linear_combination(self, expression: LinearCombination) -> None:
        if expression._owner is not self._owner:
            raise R1CSError("linear combination belongs to a different system")
        for index, coefficient in expression.terms:
            if index >= len(self._variables):
                raise R1CSError(
                    f"linear-combination variable index is out of range: {index}"
                )
            if not 0 < coefficient < SCALAR_MODULUS:
                raise R1CSError(
                    "linear-combination coefficient is not a canonical field element"
                )

    def _validate_matrix(self) -> None:
        if (
            not self._variables
            or self._variables[0].index != 0
            or self._variables[0].kind != "one"
            or self._variables[0]._owner is not self._owner
        ):
            raise R1CSError("R1CS column zero must be its implicit ONE variable")
        if not 0 <= self._public_input_count < len(self._variables):
            if not (self._public_input_count == 0 and len(self._variables) == 1):
                raise R1CSError("R1CS public-input boundary is invalid")
        public_end = self._public_input_count + 1
        for index, variable in enumerate(self._variables):
            expected_kind = (
                "one" if index == 0 else
                "public" if index < public_end else
                "private"
            )
            if (
                variable.index != index
                or variable.kind != expected_kind
                or variable._owner is not self._owner
            ):
                raise R1CSError("R1CS column allocation boundaries are invalid")
        for constraint in self._constraints:
            for expression in (
                constraint.left,
                constraint.right,
                constraint.output,
            ):
                self._validate_linear_combination(expression)

    def linear_combination_value(
        self, expression: LinearCombination
    ) -> Optional[int]:
        """Evaluate an owned expression against the current witness."""
        self._validate_linear_combination(expression)
        return self._evaluate(expression, self._values)

    @staticmethod
    def _evaluate(
        expression: LinearCombination, values: Iterable[Optional[int]]
    ) -> Optional[int]:
        result = 0
        assignments = values if isinstance(values, (list, tuple)) else tuple(values)
        for index, coefficient in expression.terms:
            if index >= len(assignments):
                raise R1CSError(f"unknown variable index: {index}")
            value = assignments[index]
            if value is None:
                return None
            result = (result + coefficient * value) % SCALAR_MODULUS
        return result
