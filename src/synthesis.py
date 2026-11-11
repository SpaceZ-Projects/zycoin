"""Backend-neutral interfaces for R1CS gadget synthesis."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .r1cs import R1CS, LinearCombination, Variable


@runtime_checkable
class LinearCombinationLike(Protocol):
    def __add__(self, other: Any) -> LinearCombinationLike: ...

    def __sub__(self, other: Any) -> LinearCombinationLike: ...

    def __rsub__(self, other: Any) -> LinearCombinationLike: ...

    def __mul__(self, coefficient: int) -> LinearCombinationLike: ...


@runtime_checkable
class VariableLike(Protocol):
    def lc(self) -> LinearCombinationLike: ...


@runtime_checkable
class SynthesisBackend(Protocol):
    """Operations required by the migrated Sapling gadget slice.

    Operand types stay backend-owned; the protocol does not coerce variables
    or linear combinations between implementations.
    """

    @property
    def one(self) -> VariableLike: ...

    def namespace(self, name: str) -> SynthesisBackend: ...

    def alloc_public(self, name: str, value: int | None) -> VariableLike: ...

    def alloc_private(self, name: str, value: int | None) -> VariableLike: ...

    def linear_combination(
        self,
        terms: Iterable[tuple[Any, int]],
        constant: int = 0,
    ) -> LinearCombinationLike: ...

    def linear_combination_value(
        self, expression: LinearCombinationLike
    ) -> int | None: ...

    def require_owned(self, variable: Any) -> None: ...

    def witness_value(self, variable: Any) -> int | None: ...

    def public_input_position(self, variable: Any) -> int | None: ...

    def multiply(
        self,
        left: Any,
        right: Any,
        name: str,
    ) -> VariableLike: ...

    def enforce(
        self,
        left: Any,
        right: Any,
        output: Any,
        label: str = "",
    ) -> None: ...

    def enforce_equal(
        self,
        left: Any,
        right: Any,
        label: str = "",
    ) -> None: ...


@runtime_checkable
class FreshSynthesisBackend(SynthesisBackend, Protocol):
    @property
    def is_fresh(self) -> bool: ...


class R1CSNamespace:
    """Namespace view preserving the production R1CS labels and row order."""

    def __init__(self, system: R1CS, prefix: str) -> None:
        self._system = system
        self._prefix = prefix

    @property
    def one(self) -> Variable:
        return self._system.one

    def namespace(self, name: str) -> R1CSNamespace:
        return R1CSNamespace(self._system, f"{self._prefix} {name}")

    def alloc_public(self, name: str, value: int | None) -> Variable:
        return self._system.alloc_public(self._name(name), value)

    def alloc_private(self, name: str, value: int | None) -> Variable:
        return self._system.alloc_private(self._name(name), value)

    def linear_combination(
        self,
        terms: Iterable[tuple[Variable, int]],
        constant: int = 0,
    ) -> LinearCombination:
        return self._system.linear_combination(terms, constant)

    def linear_combination_value(
        self, expression: LinearCombination
    ) -> int | None:
        return self._system.linear_combination_value(expression)

    def require_owned(self, variable: Variable) -> None:
        self._system.require_owned(variable)

    def witness_value(self, variable: Variable) -> int | None:
        return self._system._witness_value(variable)

    def public_input_position(self, variable: Variable) -> int | None:
        self._system.require_owned(variable)
        if variable.kind != "public":
            return None
        return variable.index

    def multiply(
        self,
        left: int | Variable | LinearCombination,
        right: int | Variable | LinearCombination,
        name: str,
    ) -> Variable:
        return self._system.multiply(left, right, self._name(name))

    def enforce(
        self,
        left: int | Variable | LinearCombination,
        right: int | Variable | LinearCombination,
        output: int | Variable | LinearCombination,
        label: str = "",
    ) -> None:
        self._system.enforce(left, right, output, self._name(label))

    def enforce_equal(
        self,
        left: int | Variable | LinearCombination,
        right: int | Variable | LinearCombination,
        label: str = "",
    ) -> None:
        self._system.enforce_equal(left, right, self._name(label))

    def _name(self, name: str) -> str:
        return f"{self._prefix} {name}"
