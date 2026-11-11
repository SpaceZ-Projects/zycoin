"""Pure-Python recorder for a bounded subset of Bellman 0.15 synthesis.

This recorder models variable allocation and ordered A/B/C expressions. It
does not execute Rust Bellman or claim to produce an authoritative upstream
matrix.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeAlias

from .bls12_381 import SCALAR_MODULUS

_MATRIX_FORMAT = "zycoin-bellman-recorder-matrix-v1"
_MATRIX_FINGERPRINT_DOMAIN = (
    b"zycoin-bellman-recorder-matrix-fingerprint-v1\0"
)

Annotation: TypeAlias = str | Callable[[], str]
Assignment: TypeAlias = int | None | Callable[[], int | None]
LinearCombinationBuilder: TypeAlias = Callable[
    ["RecorderLinearCombination"], "RecorderLinearCombination"
]


class BellmanRecorderError(ValueError):
    """Raised when a recorder operation is outside its supported semantics."""


@dataclass(frozen=True)
class RecorderIndex:
    kind: str
    index: int

    def __post_init__(self) -> None:
        if self.kind not in ("input", "aux") or type(self.index) is not int:
            raise BellmanRecorderError("invalid recorder variable index")
        if self.index < 0:
            raise BellmanRecorderError("variable index must be non-negative")


@dataclass(frozen=True)
class RecorderVariable:
    index: RecorderIndex
    name: str
    value: int | None
    _owner: object

    def lc(self) -> RecorderLinearCombination:
        return RecorderLinearCombination(((self, 1),), self._owner)


class _RecorderOwner:
    def __init__(self) -> None:
        self.one: RecorderVariable | None = None
        self.variables: dict[RecorderIndex, RecorderVariable] = {}


@dataclass(frozen=True)
class RecorderLinearCombination:
    """An ordered Bellman-style sequence of (variable, coefficient) terms."""

    terms: tuple[tuple[RecorderVariable, int], ...]
    _owner: object

    def __add__(
        self,
        other: int
        | RecorderVariable
        | RecorderLinearCombination
        | tuple[int, RecorderVariable],
    ) -> RecorderLinearCombination:
        if isinstance(other, RecorderLinearCombination):
            self._require_owner(other)
            return RecorderLinearCombination(self.terms + other.terms, self._owner)
        if isinstance(other, RecorderVariable):
            self._require_variable(other)
            return RecorderLinearCombination(self.terms + ((other, 1),), self._owner)
        if isinstance(other, tuple) and len(other) == 2:
            coefficient, variable = other
            if type(coefficient) is not int:
                raise TypeError("linear-combination coefficient must be an integer")
            self._require_variable(variable)
            return RecorderLinearCombination(
                self.terms + ((variable, coefficient % SCALAR_MODULUS),),
                self._owner,
            )
        if type(other) is int:
            one = self._one()
            return RecorderLinearCombination(
                self.terms + ((one, other % SCALAR_MODULUS),), self._owner
            )
        return NotImplemented

    __radd__ = __add__

    def __sub__(
        self,
        other: int
        | RecorderVariable
        | RecorderLinearCombination
        | tuple[int, RecorderVariable],
    ) -> RecorderLinearCombination:
        if isinstance(other, RecorderLinearCombination):
            self._require_owner(other)
            terms = tuple(
                (variable, -coefficient % SCALAR_MODULUS)
                for variable, coefficient in other.terms
            )
            return RecorderLinearCombination(self.terms + terms, self._owner)
        if isinstance(other, RecorderVariable):
            self._require_variable(other)
            return RecorderLinearCombination(
                self.terms + ((other, SCALAR_MODULUS - 1),), self._owner
            )
        if isinstance(other, tuple) and len(other) == 2:
            coefficient, variable = other
            if type(coefficient) is not int:
                raise TypeError("linear-combination coefficient must be an integer")
            self._require_variable(variable)
            return RecorderLinearCombination(
                self.terms
                + ((variable, -coefficient % SCALAR_MODULUS),),
                self._owner,
            )
        if type(other) is int:
            return RecorderLinearCombination(
                self.terms
                + ((self._one(), -other % SCALAR_MODULUS),),
                self._owner,
            )
        return NotImplemented

    def __rsub__(
        self, other: int | RecorderVariable
    ) -> RecorderLinearCombination:
        if isinstance(other, RecorderVariable):
            self._require_variable(other)
            return RecorderLinearCombination(((other, 1),), self._owner) - self
        if type(other) is int:
            return RecorderLinearCombination(
                ((self._one(), other % SCALAR_MODULUS),), self._owner
            ) - self
        return NotImplemented

    def __mul__(self, coefficient: int) -> RecorderLinearCombination:
        if type(coefficient) is not int:
            return NotImplemented
        multiplier = coefficient % SCALAR_MODULUS
        return RecorderLinearCombination(
            tuple(
                (variable, value * multiplier % SCALAR_MODULUS)
                for variable, value in self.terms
            ),
            self._owner,
        )

    __rmul__ = __mul__

    def _one(self) -> RecorderVariable:
        variable = getattr(self._owner, "one", None)
        if not isinstance(variable, RecorderVariable):
            raise BellmanRecorderError("recorder is missing Input(0)=ONE")
        self._require_variable(variable)
        return variable

    def _require_owner(self, expression: RecorderLinearCombination) -> None:
        if expression._owner is not self._owner:
            raise BellmanRecorderError(
                "cannot combine expressions from different recorders"
            )

    def _require_variable(self, variable: RecorderVariable) -> None:
        if (
            not isinstance(variable, RecorderVariable)
            or variable._owner is not self._owner
            or self._owner.variables.get(variable.index) is not variable
        ):
            raise BellmanRecorderError("variable does not belong to this recorder")


@dataclass(frozen=True)
class RecordedConstraint:
    name: str
    a: RecorderLinearCombination
    b: RecorderLinearCombination
    c: RecorderLinearCombination
    is_dummy_input_constraint: bool = False


class BellmanSynthesisRecorder:
    """Record Bellman input/aux allocations and ordered constraint rows.

    Supported behavior: separate Input/Aux namespaces, implicit ONE,
    nested named namespaces, ordered LC terms, appended enforce rows, setup
    dummy input constraints, query indexing, and deterministic serialization.
    """

    def __init__(self) -> None:
        self._owner = _RecorderOwner()
        self._inputs: list[RecorderVariable] = []
        self._aux: list[RecorderVariable] = []
        self._constraints: list[RecordedConstraint] = []
        self._named_objects: set[str] = set()
        self._dummy_inputs_added = False
        one = RecorderVariable(
            RecorderIndex("input", 0), "ONE", 1, self._owner
        )
        self._inputs.append(one)
        self._owner.one = one
        self._owner.variables[one.index] = one
        self._named_objects.add("ONE")

    @property
    def inputs(self) -> tuple[RecorderVariable, ...]:
        return tuple(self._inputs)

    @property
    def auxiliary_variables(self) -> tuple[RecorderVariable, ...]:
        return tuple(self._aux)

    @property
    def constraints(self) -> tuple[RecordedConstraint, ...]:
        return tuple(self._constraints)

    @property
    def constraint_count(self) -> int:
        return len(self._constraints)

    def one(self) -> RecorderVariable:
        return self._inputs[0]

    def namespace(self, name: Annotation) -> RecorderNamespace:
        return RecorderNamespace(self, self._path((), name))

    def alloc(self, annotation: Annotation, assignment: Assignment) -> RecorderVariable:
        return self._alloc("aux", (), annotation, assignment)

    def alloc_input(
        self, annotation: Annotation, assignment: Assignment
    ) -> RecorderVariable:
        return self._alloc("input", (), annotation, assignment)

    def enforce(
        self,
        annotation: Annotation,
        a: LinearCombinationBuilder,
        b: LinearCombinationBuilder,
        c: LinearCombinationBuilder,
    ) -> None:
        self._enforce((), annotation, a, b, c)

    def alloc_private(self, name: str, value: int | None) -> RecorderVariable:
        """Allocate one auxiliary variable using the local transcriber API."""
        return self._alloc("aux", (), name, value)

    def linear_combination(
        self,
        terms: Iterable[tuple[RecorderVariable, int]],
        constant: int = 0,
    ) -> RecorderLinearCombination:
        if type(constant) is not int:
            raise TypeError("linear-combination constant must be an integer")
        expression = RecorderLinearCombination((), self._owner)
        if constant:
            expression = expression + constant
        for variable, coefficient in terms:
            if type(coefficient) is not int:
                raise TypeError("linear-combination coefficient must be an integer")
            expression = expression + (coefficient, variable)
        return expression

    def _witness_value(self, variable: RecorderVariable) -> int | None:
        self._require_owned(variable)
        return variable.value

    def add_constraint(
        self,
        a: RecorderLinearCombination | RecorderVariable | int,
        b: RecorderLinearCombination | RecorderVariable | int,
        c: RecorderLinearCombination | RecorderVariable | int,
        label: str,
    ) -> None:
        """Append a row through the local transcription adapter."""
        self._ensure_open()
        self._append_constraint((), label, a, b, c, False)

    def append_dummy_input_constraints(self) -> None:
        """Append Bellman's setup rows ``input[i] * 0 = 0`` once."""
        if self._dummy_inputs_added:
            raise BellmanRecorderError("dummy input constraints were already added")
        self._dummy_inputs_added = True
        for variable in self._inputs:
            name = f"__setup_dummy_input_{variable.index.index}"
            self._append_constraint(
                (),
                name,
                variable,
                RecorderLinearCombination((), self._owner),
                RecorderLinearCombination((), self._owner),
                True,
            )

    def query_index(self, variable: RecorderVariable) -> int:
        self._require_owned(variable)
        if variable.index.kind == "input":
            return variable.index.index
        return len(self._inputs) + variable.index.index

    @property
    def query_variable_order(self) -> tuple[RecorderVariable, ...]:
        return tuple(self._inputs) + tuple(self._aux)

    @property
    def ic_query_variables(self) -> tuple[RecorderVariable, ...]:
        return tuple(self._inputs)

    @property
    def l_query_variables(self) -> tuple[RecorderVariable, ...]:
        return tuple(self._aux)

    @property
    def h_query_count(self) -> int:
        return max(0, self.domain_size - 1)

    @property
    def domain_size(self) -> int:
        row_count = self.constraint_count
        return 1 if row_count <= 1 else 1 << (row_count - 1).bit_length()

    def serialize(self) -> bytes:
        """Serialize recorder provenance, typed indices, namespaces, and rows."""
        document = {
            "format": "zycoin-bellman-synthesis-recorder-v1",
            "inputs": [
                {
                    "index": variable.index.index,
                    "name": variable.name,
                    "value": _value_json(variable.value),
                }
                for variable in self._inputs
            ],
            "auxiliary_variables": [
                {
                    "index": variable.index.index,
                    "name": variable.name,
                    "value": _value_json(variable.value),
                }
                for variable in self._aux
            ],
            "constraints": [
                self._constraint_json(constraint, canonical=False)
                for constraint in self._constraints
            ],
        }
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def serialize_matrix(self) -> bytes:
        """Serialize canonical LC semantics in typed Bellman index namespaces."""
        document = self._matrix_document()
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def matrix_fingerprint(self) -> str:
        """Return the recorder-specific versioned SHA-256 matrix fingerprint."""
        return hashlib.sha256(
            _MATRIX_FINGERPRINT_DOMAIN + self.serialize_matrix()
        ).hexdigest()

    def serialize_local_matrix(self) -> bytes:
        """Map recorder Input/Aux IDs into explicit local R1CS column order.

        This compatibility view combines duplicate terms and maps Input(0)
        to column zero, remaining inputs next, and Aux variables last.
        """
        variable_kinds = ["one"] + ["public"] * (len(self._inputs) - 1)
        variable_kinds.extend("private" for _ in self._aux)
        document = {
            "format": "zycoin-r1cs-matrix-v1",
            "field_modulus": str(SCALAR_MODULUS),
            "column_count": len(variable_kinds),
            "one_column": 0,
            "public_input_count": len(self._inputs) - 1,
            "auxiliary_variable_count": len(self._aux),
            "variable_kinds": variable_kinds,
            "constraints": [
                [
                    self._linear_combination_json(
                        row,
                        canonical=True,
                        local_columns=True,
                    )
                    for row in (constraint.a, constraint.b, constraint.c)
                ]
                for constraint in self._constraints
            ],
        }
        return json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")

    def _matrix_document(self) -> dict[str, object]:
        return {
            "format": _MATRIX_FORMAT,
            "field_modulus": str(SCALAR_MODULUS),
            "input_count_including_one": len(self._inputs),
            "auxiliary_variable_count": len(self._aux),
            "constraint_count": self.constraint_count,
            "constraints": [
                {
                    "a": self._linear_combination_json(
                        constraint.a, canonical=True, local_columns=False
                    ),
                    "b": self._linear_combination_json(
                        constraint.b, canonical=True, local_columns=False
                    ),
                    "c": self._linear_combination_json(
                        constraint.c, canonical=True, local_columns=False
                    ),
                }
                for constraint in self._constraints
            ],
        }

    def _constraint_json(
        self, constraint: RecordedConstraint, *, canonical: bool
    ) -> dict[str, object]:
        return {
            "name": constraint.name,
            "a": self._linear_combination_json(constraint.a, canonical=canonical),
            "b": self._linear_combination_json(constraint.b, canonical=canonical),
            "c": self._linear_combination_json(constraint.c, canonical=canonical),
            "is_dummy_input_constraint": constraint.is_dummy_input_constraint,
        }

    def _linear_combination_json(
        self,
        expression: RecorderLinearCombination,
        *,
        canonical: bool,
        local_columns: bool = False,
    ) -> list[list[object]]:
        if canonical:
            combined: dict[tuple[str, int], int] = {}
            for variable, coefficient in expression.terms:
                self._require_owned(variable)
                index = (
                    (variable.index.kind, variable.index.index)
                    if not local_columns
                    else ("column", self._local_column(variable))
                )
                combined[index] = (
                    combined.get(index, 0) + coefficient
                ) % SCALAR_MODULUS
            if local_columns:
                return [
                    [index, str(value)]
                    for (_, index), value in sorted(
                        combined.items(), key=lambda item: item[0][1]
                    )
                    if value
                ]
            return [
                [[kind, index], str(value)]
                for (kind, index), value in sorted(
                    combined.items(),
                    key=lambda item: (0 if item[0][0] == "input" else 1, item[0][1]),
                )
                if value
            ]
        return [
            [
                [variable.index.kind, variable.index.index],
                str(coefficient),
            ]
            for variable, coefficient in expression.terms
        ]

    def _local_column(self, variable: RecorderVariable) -> int:
        self._require_owned(variable)
        if variable.index.kind == "input":
            return variable.index.index
        return len(self._inputs) + variable.index.index

    def _alloc(
        self,
        kind: str,
        namespace: tuple[str, ...],
        annotation: Annotation,
        assignment: Assignment,
    ) -> RecorderVariable:
        self._ensure_open()
        name = self._full_name(namespace, annotation)
        value = assignment() if callable(assignment) else assignment
        if value is not None and type(value) is not int:
            raise TypeError("variable assignment must be an integer or None")
        value = None if value is None else value % SCALAR_MODULUS
        storage = self._inputs if kind == "input" else self._aux
        index = RecorderIndex(kind, len(storage))
        variable = RecorderVariable(index, name, value, self._owner)
        self._register(name)
        self._owner.variables[index] = variable
        storage.append(variable)
        return variable

    def _enforce(
        self,
        namespace: tuple[str, ...],
        annotation: Annotation,
        a: LinearCombinationBuilder,
        b: LinearCombinationBuilder,
        c: LinearCombinationBuilder,
    ) -> None:
        self._ensure_open()
        name = self._full_name(namespace, annotation)
        zero = RecorderLinearCombination((), self._owner)
        expressions = tuple(builder(zero) for builder in (a, b, c))
        for expression in expressions:
            self._require_expression(expression)
        self._register(name)
        self._constraints.append(RecordedConstraint(name, *expressions))

    def _append_constraint(
        self,
        namespace: tuple[str, ...],
        annotation: Annotation,
        a: RecorderLinearCombination | RecorderVariable | int,
        b: RecorderLinearCombination | RecorderVariable | int,
        c: RecorderLinearCombination | RecorderVariable | int,
        is_dummy: bool,
    ) -> None:
        name = self._full_name(namespace, annotation)
        expressions = tuple(self._coerce_expression(item) for item in (a, b, c))
        self._register(name)
        self._constraints.append(
            RecordedConstraint(name, *expressions, is_dummy_input_constraint=is_dummy)
        )

    def _coerce_expression(
        self, expression: RecorderLinearCombination | RecorderVariable | int
    ) -> RecorderLinearCombination:
        if isinstance(expression, RecorderLinearCombination):
            self._require_expression(expression)
            return expression
        if isinstance(expression, RecorderVariable):
            self._require_owned(expression)
            return expression.lc()
        if type(expression) is int:
            return RecorderLinearCombination((), self._owner) + expression
        raise TypeError("expected integer, recorder variable, or linear combination")

    def _require_expression(self, expression: RecorderLinearCombination) -> None:
        if (
            not isinstance(expression, RecorderLinearCombination)
            or expression._owner is not self._owner
        ):
            raise BellmanRecorderError(
                "linear combination does not belong to this recorder"
            )
        for variable, coefficient in expression.terms:
            self._require_owned(variable)
            if type(coefficient) is not int or not 0 <= coefficient < SCALAR_MODULUS:
                raise BellmanRecorderError("linear combination is not canonical")

    def _require_owned(self, variable: RecorderVariable) -> None:
        if not isinstance(variable, RecorderVariable) or variable._owner is not self._owner:
            raise BellmanRecorderError("variable does not belong to this recorder")
        variables = (
            self._inputs
            if variable.index.kind == "input"
            else self._aux
        )
        if (
            variable.index.index >= len(variables)
            or variables[variable.index.index] is not variable
        ):
            raise BellmanRecorderError("variable is not allocated in this recorder")

    def _path(self, parent: tuple[str, ...], annotation: Annotation) -> tuple[str, ...]:
        name = _resolve_annotation(annotation)
        if "/" in name:
            raise BellmanRecorderError("namespace names may not contain '/'")
        path = parent + (name,)
        return path

    def _full_name(
        self, namespace: tuple[str, ...], annotation: Annotation
    ) -> str:
        name = _resolve_annotation(annotation)
        if "/" in name:
            raise BellmanRecorderError("annotation names may not contain '/'")
        parts = namespace + (name,)
        return "/".join(part for part in parts if part)

    def _register(self, name: str) -> None:
        if name in self._named_objects:
            raise BellmanRecorderError(f"duplicate Bellman annotation path: {name}")
        self._named_objects.add(name)

    def _ensure_open(self) -> None:
        if self._dummy_inputs_added:
            raise BellmanRecorderError(
                "cannot synthesize circuit operations after setup dummy rows"
            )


class RecorderNamespace:
    """Namespace-scoped subset of Bellman's ConstraintSystem API."""

    def __init__(
        self,
        recorder: BellmanSynthesisRecorder,
        path: tuple[str, ...],
        *,
        register: bool = False,
    ) -> None:
        self._recorder = recorder
        self._path = path
        if register:
            recorder._register("/".join(path))

    def namespace(self, name: Annotation) -> RecorderNamespace:
        return RecorderNamespace(
            self._recorder,
            self._recorder._path(self._path, name),
        )

    def alloc(self, annotation: Annotation, assignment: Assignment) -> RecorderVariable:
        return self._recorder._alloc("aux", self._path, annotation, assignment)

    def alloc_input(
        self, annotation: Annotation, assignment: Assignment
    ) -> RecorderVariable:
        return self._recorder._alloc("input", self._path, annotation, assignment)

    def enforce(
        self,
        annotation: Annotation,
        a: LinearCombinationBuilder,
        b: LinearCombinationBuilder,
        c: LinearCombinationBuilder,
    ) -> None:
        self._recorder._enforce(self._path, annotation, a, b, c)


class R1CSReferenceAdapter:
    """Adapt flattened source transcriptions to the recorder's narrow API.

    The local reference files do not retain all Bellman namespace paths, so
    repeated local labels are deterministically suffixed at this test-only
    boundary. Matrix rows and variable indices are unchanged.
    """

    def __init__(self, recorder: BellmanSynthesisRecorder) -> None:
        self.recorder = recorder
        self._annotation_counts: dict[str, int] = {}

    def _annotation(self, name: str) -> str:
        count = self._annotation_counts.get(name, 0)
        self._annotation_counts[name] = count + 1
        return name if count == 0 else f"{name} [{count}]"

    def alloc_private(self, name: str, value: int | None) -> RecorderVariable:
        return self.recorder.alloc_private(self._annotation(name), value)

    def linear_combination(
        self,
        terms: Iterable[tuple[RecorderVariable, int]],
        constant: int = 0,
    ) -> RecorderLinearCombination:
        return self.recorder.linear_combination(terms, constant)

    def enforce(
        self,
        left: RecorderLinearCombination | RecorderVariable | int,
        right: RecorderLinearCombination | RecorderVariable | int,
        output: RecorderLinearCombination | RecorderVariable | int,
        label: str = "",
    ) -> None:
        self.recorder.add_constraint(
            left,
            right,
            output,
            self._annotation(label),
        )

    def _witness_value(self, variable: RecorderVariable) -> int | None:
        return self.recorder._witness_value(variable)


class RecorderSynthesisBackend:
    """Backend-neutral gadget adapter that records genuine Bellman-style rows."""

    def __init__(
        self,
        recorder: BellmanSynthesisRecorder,
        namespace: RecorderNamespace | None = None,
    ) -> None:
        self.recorder = recorder
        self._namespace = namespace

    @property
    def is_fresh(self) -> bool:
        return (
            self._namespace is None
            and len(self.recorder.inputs) == 1
            and not self.recorder.auxiliary_variables
            and self.recorder.constraint_count == 0
        )

    @property
    def one(self) -> RecorderVariable:
        return self.recorder.one()

    def namespace(self, name: str) -> RecorderSynthesisBackend:
        parent = self._namespace
        scoped = (
            self.recorder.namespace(name)
            if parent is None
            else parent.namespace(name)
        )
        return RecorderSynthesisBackend(self.recorder, scoped)

    def alloc_public(self, name: str, value: int | None) -> RecorderVariable:
        if self._namespace is None:
            return self.recorder.alloc_input(name, value)
        return self._namespace.alloc_input(name, value)

    def alloc_private(self, name: str, value: int | None) -> RecorderVariable:
        if self._namespace is None:
            return self.recorder.alloc_private(name, value)
        return self._namespace.alloc(name, value)

    def linear_combination(
        self,
        terms: Iterable[tuple[RecorderVariable, int]],
        constant: int = 0,
    ) -> RecorderLinearCombination:
        return self.recorder.linear_combination(terms, constant)

    def linear_combination_value(
        self, expression: RecorderLinearCombination
    ) -> int | None:
        return self._expression_value(expression)

    def require_owned(self, variable: RecorderVariable) -> None:
        self.recorder._require_owned(variable)

    def witness_value(self, variable: RecorderVariable) -> int | None:
        return self.recorder._witness_value(variable)

    def public_input_position(self, variable: RecorderVariable) -> int | None:
        self.recorder._require_owned(variable)
        if variable.index.kind != "input":
            return None
        return variable.index.index

    def multiply(
        self,
        left: int | RecorderVariable | RecorderLinearCombination,
        right: int | RecorderVariable | RecorderLinearCombination,
        name: str,
    ) -> RecorderVariable:
        left_value = self._expression_value(left)
        right_value = self._expression_value(right)
        product = (
            None
            if left_value is None or right_value is None
            else left_value * right_value % SCALAR_MODULUS
        )
        output = self.alloc_private(name, product)
        self.enforce(left, right, output, f"{name} multiplication")
        return output

    def enforce(
        self,
        left: int | RecorderVariable | RecorderLinearCombination,
        right: int | RecorderVariable | RecorderLinearCombination,
        output: int | RecorderVariable | RecorderLinearCombination,
        label: str = "",
    ) -> None:
        if self._namespace is None:
            self.recorder.add_constraint(left, right, output, label)
            return
        self._namespace.enforce(
            label,
            self._builder(left),
            self._builder(right),
            self._builder(output),
        )

    def enforce_equal(
        self,
        left: int | RecorderVariable | RecorderLinearCombination,
        right: int | RecorderVariable | RecorderLinearCombination,
        label: str = "",
    ) -> None:
        self.enforce(self._as_expression(left) - self._as_expression(right), 1, 0, label)

    def _as_expression(
        self, value: int | RecorderVariable | RecorderLinearCombination
    ) -> RecorderLinearCombination:
        return self.recorder._coerce_expression(value)

    def _builder(
        self, value: int | RecorderVariable | RecorderLinearCombination
    ) -> LinearCombinationBuilder:
        expression = self._as_expression(value)
        return lambda lc: lc + expression

    def _expression_value(
        self, expression: int | RecorderVariable | RecorderLinearCombination
    ) -> int | None:
        if type(expression) is int:
            return expression % SCALAR_MODULUS
        if isinstance(expression, RecorderVariable):
            self.require_owned(expression)
            return expression.value
        self.recorder._require_expression(expression)
        value = 0
        for variable, coefficient in expression.terms:
            if variable.value is None:
                return None
            value += variable.value * coefficient
        return value % SCALAR_MODULUS


def _resolve_annotation(annotation: Annotation) -> str:
    value = annotation() if callable(annotation) else annotation
    if not isinstance(value, str):
        raise TypeError("annotation must resolve to a string")
    return value


def _value_json(value: int | None) -> str | None:
    return None if value is None else str(value)


__all__ = [
    "BellmanRecorderError",
    "BellmanSynthesisRecorder",
    "R1CSReferenceAdapter",
    "RecorderIndex",
    "RecorderLinearCombination",
    "RecorderNamespace",
    "RecorderVariable",
]
