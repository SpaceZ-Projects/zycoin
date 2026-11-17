"""Test-only adapter from source-faithful Spend assembly to the generic QAP API."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from typing import Any

from src.groth16_qap import QAP, QAPAssignment, QAPError
from src.r1cs import R1CS, LinearCombination, R1CSError, Variable
from tests.sapling_spend_reference_port import (
    EdwardsPointWitnessVariables,
    MerkleAuthenticationResult,
    NoteCommitmentResult,
    NullifierBlake2sResult,
    NullifierMultipackingResult,
    SourceOrderedConditionalAnchorResult,
    SpendReferenceAssembly,
    SpendReferenceR1CS,
    ValueCommitmentResult,
)
from tests.sapling_spend_temporal_mapping import (
    SPEND_PUBLIC_INPUT_ANNOTATIONS,
    SpendTemporalCanonicalization,
    canonicalize_spend_reference_r1cs,
)

_SPEND_CONSTRAINT_COUNT = 98_777
_SPEND_VARIABLE_COUNT = 98_646
_SPEND_PUBLIC_INPUT_COUNT = 7
_SPEND_MATRIX_FINGERPRINT = (
    "cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127"
)


class SpendGroth16AdapterError(ValueError):
    """Raised when a source-faithful Spend result cannot enter the generic QAP."""


@dataclass(frozen=True)
class AdaptedSpendGroth16:
    """Canonical R1CS, remapped assembly, and generic QAP witness interface."""

    canonicalization: SpendTemporalCanonicalization
    assembly: SpendReferenceAssembly
    qap: QAP
    assignment: QAPAssignment
    assignment_values: tuple[int, ...]

    @property
    def system(self) -> R1CS:
        return self.canonicalization.system

    @property
    def public_inputs(self) -> tuple[int, ...]:
        return tuple(self.assignment.public_inputs)

    @property
    def auxiliary_assignments(self) -> tuple[int, ...]:
        return tuple(self.assignment.auxiliary_assignments)


def adapt_source_faithful_spend(
    source: SpendReferenceR1CS,
    assembly: SpendReferenceAssembly,
) -> AdaptedSpendGroth16:
    """Adapt one complete, satisfied pinned Spend assembly for generic QAP use.

    This function does not load parameters, create proof material, or verify a
    Groth16 proof. It only supplies the canonical R1CS and QAP assignment
    expected by ZyCoin's generic Groth16 interfaces.
    """
    if not isinstance(source, SpendReferenceR1CS):
        raise TypeError("source must be a SpendReferenceR1CS")
    if not isinstance(assembly, SpendReferenceAssembly):
        raise TypeError("assembly must be a SpendReferenceAssembly")

    _validate_public_input_handles(source, assembly)
    _validate_assembly_contents(source, assembly)
    _validate_component_public_inputs(assembly)
    _validate_pinned_shape(source)
    try:
        if not source.is_satisfied():
            raise SpendGroth16AdapterError(
                "source Spend assignment does not satisfy its R1CS"
            )
    except R1CSError as error:
        raise SpendGroth16AdapterError(
            "source Spend assignment is incomplete or malformed"
        ) from error

    try:
        canonicalization = canonicalize_spend_reference_r1cs(source)
        canonical_assembly = canonicalization.remap_assembly(assembly)
    except (R1CSError, TypeError) as error:
        raise SpendGroth16AdapterError(
            "source Spend allocation or assembly mapping is invalid"
        ) from error
    if not isinstance(canonical_assembly, SpendReferenceAssembly):
        raise SpendGroth16AdapterError(
            "canonicalization returned an incomplete Spend assembly"
        )

    system = canonicalization.system
    if (
        len(system.variables) != _SPEND_VARIABLE_COUNT
        or system.constraint_count != _SPEND_CONSTRAINT_COUNT
        or system.public_input_count != _SPEND_PUBLIC_INPUT_COUNT
        or system.matrix_fingerprint() != _SPEND_MATRIX_FINGERPRINT
    ):
        raise SpendGroth16AdapterError(
            "canonical Spend matrix differs from the pinned source relation"
        )
    expected_public_variables = system.variables[1 : 1 + _SPEND_PUBLIC_INPUT_COUNT]
    if canonical_assembly.public_inputs != expected_public_variables:
        raise SpendGroth16AdapterError(
            "canonical Spend assembly has inconsistent public-input handles"
        )

    values = tuple(system.witness_value(variable) for variable in system.variables)
    if any(value is None for value in values):
        raise SpendGroth16AdapterError(
            "canonical Spend assignment contains an unassigned variable"
        )
    canonical_values = tuple(int(value) for value in values)
    if canonical_values[0] != 1:
        raise SpendGroth16AdapterError("canonical Spend ONE assignment is invalid")

    assignment = QAPAssignment(
        canonical_values[1 : 1 + _SPEND_PUBLIC_INPUT_COUNT],
        canonical_values[1 + _SPEND_PUBLIC_INPUT_COUNT :],
    )
    try:
        qap = QAP.from_r1cs(system)
        validated_values = qap.validate_assignment(assignment)
    except (QAPError, R1CSError) as error:
        raise SpendGroth16AdapterError(
            "canonical Spend assignment does not satisfy the generic QAP"
        ) from error

    if (
        validated_values != canonical_values
        or tuple(system.public_inputs()) != tuple(assignment.public_inputs)
    ):
        raise SpendGroth16AdapterError(
            "generic QAP assignment differs from the canonical R1CS witness"
        )
    return AdaptedSpendGroth16(
        canonicalization,
        canonical_assembly,
        qap,
        assignment,
        validated_values,
    )


def _validate_public_input_handles(
    source: SpendReferenceR1CS,
    assembly: SpendReferenceAssembly,
) -> None:
    public_inputs = assembly.public_inputs
    if not isinstance(public_inputs, tuple) or len(public_inputs) != (
        _SPEND_PUBLIC_INPUT_COUNT
    ):
        raise SpendGroth16AdapterError(
            "Spend assembly must contain exactly seven ordered public inputs"
        )
    source_public = tuple(source._temporal_public_variables)
    if (
        source.public_input_count != _SPEND_PUBLIC_INPUT_COUNT
        or len(source_public) != _SPEND_PUBLIC_INPUT_COUNT
    ):
        raise SpendGroth16AdapterError(
            "source Spend public-input allocation is incomplete"
        )

    seen: set[int] = set()
    for position, (variable, expected, annotation) in enumerate(
        zip(
            public_inputs,
            source_public,
            SPEND_PUBLIC_INPUT_ANNOTATIONS,
            strict=True,
        ),
        start=1,
    ):
        if not isinstance(variable, Variable):
            raise SpendGroth16AdapterError(
                f"Spend public input {position} is not a variable handle"
            )
        _validate_source_variable(source, variable, f"public input {position}")
        if variable.index in seen:
            raise SpendGroth16AdapterError(
                f"Spend public input {position} duplicates another handle"
            )
        seen.add(variable.index)
        if (
            variable is not expected
            or variable.kind != "public"
            or variable.name != annotation
            or source.public_input_position(variable) != position
        ):
            raise SpendGroth16AdapterError(
                f"Spend public input {position} is inconsistent or out of order"
            )


def _validate_component_public_inputs(
    assembly: SpendReferenceAssembly,
) -> None:
    public_inputs = assembly.public_inputs
    if (
        assembly.value_commitment.input_variables != public_inputs[2:4]
        or assembly.conditional_anchor.anchor_variable is not public_inputs[4]
        or assembly.nullifier_multipacking.input_variables != public_inputs[5:7]
    ):
        raise SpendGroth16AdapterError(
            "Spend assembly components disagree on public-input handles"
        )


def _validate_assembly_contents(
    source: SpendReferenceR1CS,
    assembly: SpendReferenceAssembly,
) -> None:
    point_types = {
        "randomized_key": EdwardsPointWitnessVariables,
        "nullifier_key": EdwardsPointWitnessVariables,
        "diversifier_base": EdwardsPointWitnessVariables,
        "transmission_key": EdwardsPointWitnessVariables,
        "rho": EdwardsPointWitnessVariables,
        "value_commitment": ValueCommitmentResult,
        "note_commitment": NoteCommitmentResult,
        "merkle_path": MerkleAuthenticationResult,
        "conditional_anchor": SourceOrderedConditionalAnchorResult,
        "nullifier_hash": NullifierBlake2sResult,
        "nullifier_multipacking": NullifierMultipackingResult,
    }
    for name, expected_type in point_types.items():
        if not isinstance(getattr(assembly, name), expected_type):
            raise SpendGroth16AdapterError(
                f"Spend assembly component {name} is missing or malformed"
            )

    for name in (
        "ak_repr_bits",
        "nk_repr_bits",
        "ivk_bits",
        "transmission_key_repr_bits",
        "rho_repr_bits",
    ):
        bits = getattr(assembly, name)
        if not isinstance(bits, tuple) or not bits:
            raise SpendGroth16AdapterError(
                f"Spend assembly component {name} is incomplete"
            )

    _validate_assembly_value(source, assembly, "assembly")


def _validate_assembly_value(
    source: SpendReferenceR1CS,
    value: Any,
    path: str,
) -> None:
    if value is None:
        raise SpendGroth16AdapterError(f"{path} contains a missing value")
    if isinstance(value, Variable):
        _validate_source_variable(source, value, path)
        return
    if isinstance(value, LinearCombination):
        try:
            source._validate_linear_combination(value)
        except R1CSError as error:
            raise SpendGroth16AdapterError(
                f"{path} contains a foreign or malformed expression"
            ) from error
        return
    if isinstance(value, (tuple, list)):
        if not value:
            raise SpendGroth16AdapterError(f"{path} contains an empty component")
        for index, item in enumerate(value):
            _validate_assembly_value(source, item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_assembly_value(source, key, f"{path} key")
            _validate_assembly_value(source, item, f"{path}[{key!r}]")
        return
    if is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            _validate_assembly_value(
                source,
                getattr(value, field.name),
                f"{path}.{field.name}",
            )


def _validate_source_variable(
    source: SpendReferenceR1CS,
    variable: Variable,
    path: str,
) -> None:
    try:
        source.require_owned(variable)
    except R1CSError as error:
        raise SpendGroth16AdapterError(
            f"{path} belongs to another R1CS"
        ) from error
    if (
        variable.index >= len(source.variables)
        or source.variables[variable.index] is not variable
    ):
        raise SpendGroth16AdapterError(f"{path} is not an allocated handle")


def _validate_pinned_shape(source: SpendReferenceR1CS) -> None:
    if (
        len(source.variables) != _SPEND_VARIABLE_COUNT
        or source.constraint_count != _SPEND_CONSTRAINT_COUNT
        or source.public_input_count != _SPEND_PUBLIC_INPUT_COUNT
    ):
        raise SpendGroth16AdapterError(
            "source Spend system is incomplete or has an unsupported shape"
        )


__all__ = [
    "AdaptedSpendGroth16",
    "SpendGroth16AdapterError",
    "adapt_source_faithful_spend",
]
