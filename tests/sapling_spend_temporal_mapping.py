"""Test-only bridge from Bellman temporal Spend allocation to canonical R1CS."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass, replace
from typing import Any

from src.r1cs import R1CS, LinearCombination, R1CSError, Variable
from tests.sapling_spend_reference_port import SpendReferenceR1CS

SPEND_PUBLIC_INPUT_ANNOTATIONS = (
    "rk/u/input variable",
    "rk/v/input variable",
    "value commitment/commitment point/u/input variable",
    "value commitment/commitment point/v/input variable",
    "anchor/input variable",
    "pack nullifier/input 0",
    "pack nullifier/input 1",
)


@dataclass(frozen=True)
class SpendTemporalCanonicalization:
    source: SpendReferenceR1CS
    system: R1CS
    _canonical_variables_by_source_index: tuple[Variable, ...]

    @property
    def source_to_canonical_indices(self) -> tuple[int, ...]:
        return tuple(
            variable.index
            for variable in self._canonical_variables_by_source_index
        )

    def canonical_index(self, variable: Variable) -> int:
        return self.remap_variable(variable).index

    def remap_variable(self, variable: Variable) -> Variable:
        self.source.require_owned(variable)
        if (
            variable.index >= len(self._canonical_variables_by_source_index)
            or self.source.variables[variable.index] is not variable
        ):
            raise R1CSError("variable is missing from the Spend allocation map")
        return self._canonical_variables_by_source_index[variable.index]

    def remap_linear_combination(
        self, expression: LinearCombination
    ) -> LinearCombination:
        if not isinstance(expression, LinearCombination):
            raise TypeError("expression must be a LinearCombination")
        self.source._validate_linear_combination(expression)
        constant = 0
        terms: list[tuple[Variable, int]] = []
        source_variables = self.source.variables
        for source_index, coefficient in expression.terms:
            if source_index == 0:
                constant += coefficient
            else:
                terms.append(
                    (
                        self.remap_variable(source_variables[source_index]),
                        coefficient,
                    )
                )
        return self.system.linear_combination(terms, constant)

    def remap_assembly(self, assembly: Any) -> Any:
        """Return the same result shape with all variable handles remapped."""
        return _remap_value(self, assembly)


def canonicalize_spend_reference_r1cs(
    source: SpendReferenceR1CS,
) -> SpendTemporalCanonicalization:
    """Copy a valid temporal Spend R1CS into ONE/public/auxiliary order."""
    if not isinstance(source, SpendReferenceR1CS):
        raise TypeError("source must be a SpendReferenceR1CS")

    source_variables = source.variables
    public_variables, auxiliary_variables = _validate_allocations(
        source, source_variables
    )

    canonical = R1CS()
    canonical_by_source_index: list[Variable | None] = [
        None
    ] * len(source_variables)
    canonical_by_source_index[0] = canonical.one

    for variable in public_variables:
        canonical_by_source_index[variable.index] = canonical.alloc_public(
            variable.name, source.witness_value(variable)
        )
    for variable in auxiliary_variables:
        canonical_by_source_index[variable.index] = canonical.alloc_private(
            variable.name, source.witness_value(variable)
        )

    if any(variable is None for variable in canonical_by_source_index):
        raise R1CSError("Spend allocation map has an unallocated variable")
    mapped_variables = tuple(
        variable
        for variable in canonical_by_source_index
        if variable is not None
    )
    if (
        len({variable.index for variable in mapped_variables})
        != len(source_variables)
        or len(canonical.variables) != len(source_variables)
    ):
        raise R1CSError("Spend allocation map contains duplicate variables")

    mapping = SpendTemporalCanonicalization(
        source, canonical, mapped_variables
    )
    for constraint in source.iter_constraints():
        canonical.enforce(
            mapping.remap_linear_combination(constraint.left),
            mapping.remap_linear_combination(constraint.right),
            mapping.remap_linear_combination(constraint.output),
            constraint.label,
        )
    return mapping


def _validate_allocations(
    source: SpendReferenceR1CS,
    variables: tuple[Variable, ...],
) -> tuple[tuple[Variable, ...], tuple[Variable, ...]]:
    if not variables or source.one is not variables[0]:
        raise R1CSError("Spend allocation map must place ONE at index zero")
    if variables[0].index != 0 or variables[0].kind != "one":
        raise R1CSError("Spend allocation map has an invalid ONE variable")
    source.require_owned(variables[0])
    if source.witness_value(variables[0]) != 1:
        raise R1CSError("Spend allocation map has an invalid ONE assignment")

    seen: set[int] = set()
    for index, variable in enumerate(variables):
        source.require_owned(variable)
        if variable.index != index or id(variable) in seen:
            raise R1CSError("Spend allocation map has duplicate or inconsistent handles")
        seen.add(id(variable))
        if index and variable.kind not in ("public", "private"):
            raise R1CSError("Spend allocation map has an invalid variable kind")

    public_variables = tuple(
        variable for variable in variables[1:] if variable.kind == "public"
    )
    auxiliary_variables = tuple(
        variable for variable in variables[1:] if variable.kind == "private"
    )
    if len(public_variables) != source.public_input_count:
        raise R1CSError("Spend public allocation count is inconsistent")
    if tuple(source._temporal_public_variables) != public_variables:
        raise R1CSError("Spend temporal public allocation order is inconsistent")
    if tuple(variable.name for variable in public_variables) != (
        SPEND_PUBLIC_INPUT_ANNOTATIONS
    ):
        raise R1CSError("Spend public inputs are missing or incorrectly ordered")

    expected_public_positions = {
        variable.index: position
        for position, variable in enumerate(public_variables, start=1)
    }
    if source._public_positions_by_index != expected_public_positions:
        raise R1CSError("Spend public position metadata is inconsistent")
    for position, variable in enumerate(public_variables, start=1):
        if source.public_input_position(variable) != position:
            raise R1CSError("Spend public input position is inconsistent")

    expected_auxiliary_indices = {
        variable.index: index
        for index, variable in enumerate(auxiliary_variables)
    }
    if (
        source._auxiliary_count != len(auxiliary_variables)
        or source._auxiliary_indices_by_variable_index
        != expected_auxiliary_indices
    ):
        raise R1CSError("Spend auxiliary allocation metadata is inconsistent")
    for index, variable in enumerate(auxiliary_variables):
        if source.auxiliary_index(variable) != index:
            raise R1CSError("Spend auxiliary variable index is inconsistent")

    expected_columns = {
        0: 0,
        **{
            variable.index: position
            for position, variable in enumerate(public_variables, start=1)
        },
        **{
            variable.index: len(public_variables) + index + 1
            for index, variable in enumerate(auxiliary_variables)
        },
    }
    if len(expected_columns) != len(variables):
        raise R1CSError("Spend allocation map omits or duplicates a variable")
    for variable in variables:
        if source.canonical_column(variable.index) != expected_columns[variable.index]:
            raise R1CSError("Spend canonical column metadata is inconsistent")

    return public_variables, auxiliary_variables


def _remap_value(mapping: SpendTemporalCanonicalization, value: Any) -> Any:
    if isinstance(value, Variable):
        return mapping.remap_variable(value)
    if isinstance(value, LinearCombination):
        return mapping.remap_linear_combination(value)
    if isinstance(value, tuple):
        return tuple(_remap_value(mapping, item) for item in value)
    if isinstance(value, list):
        return [_remap_value(mapping, item) for item in value]
    if isinstance(value, dict):
        return {
            key: _remap_value(mapping, item)
            for key, item in value.items()
        }
    if is_dataclass(value) and not isinstance(value, type):
        return replace(
            value,
            **{
                field.name: _remap_value(mapping, getattr(value, field.name))
                for field in fields(value)
            },
        )
    return value


__all__ = [
    "SPEND_PUBLIC_INPUT_ANNOTATIONS",
    "SpendTemporalCanonicalization",
    "canonicalize_spend_reference_r1cs",
]
