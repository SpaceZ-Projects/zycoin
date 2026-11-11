"""Metadata-only Groth16 parameter and Sapling circuit compatibility gate."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .groth16_parameters import ParameterManifest


class CompatibilityStatus(str, Enum):
    VERIFIED = "Verified"
    MISMATCHED = "Mismatched"
    UNVERIFIED = "Unverified"


@dataclass(frozen=True)
class CircuitMetadata:
    """Observed local circuit dimensions plus optional upstream evidence."""

    circuit_id: str
    application_public_input_order: tuple[str, ...] | None
    constraint_count: int | None
    total_column_count: int | None
    auxiliary_column_count: int | None
    has_implicit_one: bool | None
    local_matrix_fingerprint: str | None
    local_matrix_serialization_version: str | None
    trusted_upstream_metadata: bool = False
    upstream_constraint_count: int | None = None
    upstream_public_input_order: tuple[str, ...] | None = None
    upstream_total_column_count: int | None = None
    upstream_auxiliary_column_count: int | None = None
    upstream_has_implicit_one: bool | None = None
    upstream_matrix_fingerprint: str | None = None
    upstream_matrix_serialization_version: str | None = None

    def __post_init__(self) -> None:
        if not self.circuit_id:
            raise ValueError("circuit_id must be non-empty")
        for name in (
            "constraint_count",
            "total_column_count",
            "auxiliary_column_count",
            "upstream_constraint_count",
            "upstream_total_column_count",
            "upstream_auxiliary_column_count",
        ):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"{name} must be a non-negative integer or None")
        for name in (
            "application_public_input_order",
            "upstream_public_input_order",
        ):
            order = getattr(self, name)
            if order is not None and (
                any(not isinstance(item, str) or not item for item in order)
                or len(set(order)) != len(order)
            ):
                raise ValueError(f"{name} must contain unique non-empty names")
        if type(self.trusted_upstream_metadata) is not bool:
            raise TypeError("trusted_upstream_metadata must be a bool")
        for name in ("has_implicit_one", "upstream_has_implicit_one"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise TypeError(f"{name} must be a bool or None")
        for name in (
            "local_matrix_fingerprint",
            "upstream_matrix_fingerprint",
        ):
            fingerprint = getattr(self, name)
            if fingerprint is not None and (
                not isinstance(fingerprint, str)
                or len(fingerprint) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in fingerprint
                )
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
        for name in (
            "local_matrix_serialization_version",
            "upstream_matrix_serialization_version",
        ):
            version = getattr(self, name)
            if version is not None and (not isinstance(version, str) or not version):
                raise ValueError(f"{name} must be a non-empty string or None")
        if (
            self.application_public_input_order is not None
            and self.total_column_count is not None
            and self.auxiliary_column_count is not None
            and self.total_column_count
            != 1
            + len(self.application_public_input_order)
            + self.auxiliary_column_count
        ):
            raise ValueError("local column counts are inconsistent")
        if (
            self.upstream_public_input_order is not None
            and self.upstream_total_column_count is not None
            and self.upstream_auxiliary_column_count is not None
            and self.upstream_total_column_count
            != 1
            + len(self.upstream_public_input_order)
            + self.upstream_auxiliary_column_count
        ):
            raise ValueError("upstream column counts are inconsistent")
        if self.trusted_upstream_metadata and any(
            value is None
            for value in (
                self.upstream_constraint_count,
                self.upstream_public_input_order,
                self.upstream_total_column_count,
                self.upstream_auxiliary_column_count,
                self.upstream_has_implicit_one,
                self.upstream_matrix_fingerprint,
                self.upstream_matrix_serialization_version,
            )
        ):
            raise ValueError("trusted upstream metadata must be complete")

    @property
    def application_public_input_count(self) -> int | None:
        if self.application_public_input_order is None:
            return None
        return len(self.application_public_input_order)


@dataclass(frozen=True)
class CompatibilityCheck:
    property: str
    status: CompatibilityStatus
    parameter_value: object | None
    circuit_value: object | None
    detail: str


@dataclass(frozen=True)
class CompatibilityAssessment:
    circuit_id: str
    checks: tuple[CompatibilityCheck, ...]

    @property
    def compatible(self) -> bool:
        """Only all-verified assessments may pass this metadata gate."""
        return bool(self.checks) and all(
            check.status is CompatibilityStatus.VERIFIED for check in self.checks
        )

    def check(self, property_name: str) -> CompatibilityCheck:
        for item in self.checks:
            if item.property == property_name:
                return item
        raise KeyError(property_name)


SAPLING_SPEND_METADATA = CircuitMetadata(
    circuit_id="sapling-spend",
    application_public_input_order=(
        "rk.u",
        "rk.v",
        "cv.u",
        "cv.v",
        "anchor",
        "nullifier_chunk_0",
        "nullifier_chunk_1",
    ),
    constraint_count=98_777,
    total_column_count=98_646,
    auxiliary_column_count=98_638,
    has_implicit_one=True,
    local_matrix_fingerprint=(
        "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9"
    ),
    local_matrix_serialization_version="zycoin-r1cs-matrix-v1",
    upstream_constraint_count=98_777,
    upstream_public_input_order=(
        "rk.u",
        "rk.v",
        "cv.u",
        "cv.v",
        "anchor",
        "nullifier_chunk_0",
        "nullifier_chunk_1",
    ),
)

SAPLING_OUTPUT_METADATA = CircuitMetadata(
    circuit_id="sapling-output",
    application_public_input_order=("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"),
    constraint_count=7_827,
    total_column_count=7_827,
    auxiliary_column_count=7_821,
    has_implicit_one=True,
    local_matrix_fingerprint=(
        "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
    ),
    local_matrix_serialization_version="zycoin-r1cs-matrix-v1",
    upstream_constraint_count=7_827,
    upstream_public_input_order=("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"),
)


def assess_parameter_compatibility(
    manifest: ParameterManifest,
    circuit: CircuitMetadata,
) -> CompatibilityAssessment:
    """Compare recoverable parameter dimensions with circuit metadata.

    Matching dimensions are not a circuit-identity proof. Parameter streams
    contain no application input names, exact row count, or matrix fingerprint.
    """
    if not isinstance(manifest, ParameterManifest):
        raise TypeError("manifest must be a ParameterManifest")
    if not manifest.structurally_validated:
        raise ValueError("manifest must come from a completed stream validation")
    if not isinstance(circuit, CircuitMetadata):
        raise TypeError("circuit must be CircuitMetadata")

    checks: list[CompatibilityCheck] = []

    def add(
        name: str,
        status: CompatibilityStatus,
        parameter_value: object | None,
        circuit_value: object | None,
        detail: str,
    ) -> None:
        checks.append(
            CompatibilityCheck(name, status, parameter_value, circuit_value, detail)
        )

    add(
        "parameter_digest_trust",
        CompatibilityStatus.VERIFIED
        if manifest.trusted_digest_verified
        else CompatibilityStatus.UNVERIFIED,
        manifest.trusted_digest_verified,
        True,
        "A digest match is trusted only when its expected value came from an "
        "independent trusted source.",
    )
    add(
        "circuit_metadata_trust",
        CompatibilityStatus.VERIFIED
        if circuit.trusted_upstream_metadata
        else CompatibilityStatus.UNVERIFIED,
        circuit.trusted_upstream_metadata,
        True,
        "Local measurements are not an authoritative upstream circuit description.",
    )
    add(
        "parameter_circuit_binding",
        CompatibilityStatus.UNVERIFIED,
        manifest.sha256,
        circuit.circuit_id,
        "The Bellman stream has no circuit identifier or matrix fingerprint; "
        "no independently trusted digest-to-circuit binding is available.",
    )
    parameter_public_count = manifest.application_public_input_count
    circuit_public_count = circuit.application_public_input_count
    add(
        "application_public_input_count",
        _comparison_status(parameter_public_count, circuit_public_count),
        parameter_public_count,
        circuit_public_count,
        "IC contains the implicit ONE entry; subtract it to obtain application inputs.",
    )
    add(
        "application_public_input_order",
        CompatibilityStatus.UNVERIFIED,
        None,
        circuit.application_public_input_order,
        "The parameter format carries no names or application input ordering.",
    )

    domain_size = manifest.constraint_domain_size
    if circuit.constraint_count is None:
        row_status = CompatibilityStatus.UNVERIFIED
    elif circuit.constraint_count > domain_size:
        row_status = CompatibilityStatus.MISMATCHED
    else:
        row_status = CompatibilityStatus.UNVERIFIED
    add(
        "constraint_count",
        row_status,
        f"padded_domain_size={domain_size}; exact_rows=unavailable",
        circuit.constraint_count,
        "H reveals a padded QAP domain size, not the exact R1CS row count.",
    )

    parameter_aux_count = manifest.auxiliary_query_count
    add(
        "auxiliary_column_count",
        _comparison_status(parameter_aux_count, circuit.auxiliary_column_count),
        parameter_aux_count,
        circuit.auxiliary_column_count,
        "L query length records the auxiliary-variable query count.",
    )
    parameter_total_columns = manifest.total_variable_count
    add(
        "total_column_count",
        _comparison_status(parameter_total_columns, circuit.total_column_count),
        parameter_total_columns,
        circuit.total_column_count,
        "IC plus L counts include ONE, application inputs, and auxiliary variables.",
    )
    one_status = (
        CompatibilityStatus.UNVERIFIED
        if circuit.has_implicit_one is None
        else (
            CompatibilityStatus.VERIFIED
            if manifest.ic_count > 0 and circuit.has_implicit_one
            else CompatibilityStatus.MISMATCHED
        )
    )
    add(
        "implicit_one_handling",
        one_status,
        "IC[0] is the implicit ONE input",
        circuit.has_implicit_one,
        "The stream format's IC convention includes the constant ONE entry.",
    )

    if circuit.upstream_constraint_count is None or circuit.constraint_count is None:
        upstream_rows_status = CompatibilityStatus.UNVERIFIED
    else:
        upstream_rows_status = _comparison_status(
            circuit.constraint_count, circuit.upstream_constraint_count
        )
    add(
        "local_vs_upstream_constraint_count",
        upstream_rows_status,
        circuit.constraint_count,
        circuit.upstream_constraint_count,
        "A matching row count is necessary evidence only; it is not matrix equivalence.",
    )

    if circuit.upstream_public_input_order is None:
        input_order_status = CompatibilityStatus.UNVERIFIED
    else:
        input_order_status = _comparison_status(
            circuit.application_public_input_order,
            circuit.upstream_public_input_order,
        )
    add(
        "local_vs_upstream_public_input_order",
        input_order_status,
        circuit.application_public_input_order,
        circuit.upstream_public_input_order,
        "This compares circuit descriptions; the parameter stream itself names no inputs.",
    )
    add(
        "local_vs_upstream_column_counts",
        _comparison_status(
            (
                circuit.total_column_count,
                circuit.auxiliary_column_count,
                circuit.has_implicit_one,
            )
            if circuit.total_column_count is not None
            and circuit.auxiliary_column_count is not None
            and circuit.has_implicit_one is not None
            else None,
            (
                circuit.upstream_total_column_count,
                circuit.upstream_auxiliary_column_count,
                circuit.upstream_has_implicit_one,
            )
            if circuit.upstream_total_column_count is not None
            and circuit.upstream_auxiliary_column_count is not None
            and circuit.upstream_has_implicit_one is not None
            else None,
        ),
        (
            circuit.total_column_count,
            circuit.auxiliary_column_count,
            circuit.has_implicit_one,
        ),
        (
            circuit.upstream_total_column_count,
            circuit.upstream_auxiliary_column_count,
            circuit.upstream_has_implicit_one,
        ),
        "Local variable allocation must be compared with trusted upstream "
        "allocation metadata, which is currently unavailable.",
    )

    if (
        circuit.local_matrix_fingerprint is None
        or circuit.upstream_matrix_fingerprint is None
        or circuit.local_matrix_serialization_version is None
        or circuit.upstream_matrix_serialization_version is None
        or (
        circuit.local_matrix_serialization_version
        != circuit.upstream_matrix_serialization_version
        )
    ):
        matrix_status = CompatibilityStatus.UNVERIFIED
    else:
        matrix_status = _comparison_status(
            circuit.local_matrix_fingerprint,
            circuit.upstream_matrix_fingerprint,
        )
    add(
        "matrix_fingerprint",
        matrix_status,
        circuit.local_matrix_fingerprint,
        circuit.upstream_matrix_fingerprint,
        "The parameter format contains no matrix fingerprint; a comparable "
        "independent upstream matrix fingerprint is required.",
    )
    serialization_status = (
        CompatibilityStatus.UNVERIFIED
        if circuit.upstream_matrix_serialization_version is None
        else _comparison_status(
            circuit.local_matrix_serialization_version,
            circuit.upstream_matrix_serialization_version,
        )
    )
    add(
        "matrix_serialization_version",
        serialization_status,
        circuit.local_matrix_serialization_version,
        circuit.upstream_matrix_serialization_version,
        "The parameter wire format is distinct from ZyCoin's local matrix serialization.",
    )

    return CompatibilityAssessment(circuit.circuit_id, tuple(checks))


def _comparison_status(
    observed: object | None, expected: object | None
) -> CompatibilityStatus:
    if observed is None or expected is None:
        return CompatibilityStatus.UNVERIFIED
    if observed == expected:
        return CompatibilityStatus.VERIFIED
    return CompatibilityStatus.MISMATCHED


__all__ = [
    "SAPLING_OUTPUT_METADATA",
    "SAPLING_SPEND_METADATA",
    "CircuitMetadata",
    "CompatibilityAssessment",
    "CompatibilityCheck",
    "CompatibilityStatus",
    "assess_parameter_compatibility",
]
