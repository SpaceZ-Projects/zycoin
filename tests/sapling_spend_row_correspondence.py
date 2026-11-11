"""Test-only ordered-row comparison for the pinned Sapling Spend exports."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from src.bls12_381 import SCALAR_MODULUS

FIELD = SCALAR_MODULUS
FORMAT = "zycoin-bellman-sapling-spend-row-correspondence-v1"
_FINGERPRINT_DOMAIN = b"zycoin-bellman-sapling-spend-row-map-v1\0"
_ARTIFACT_DOMAIN = b"zycoin-bellman-sapling-spend-row-artifact-v1\0"


class SpendRowCorrespondenceError(ValueError):
    """Raised when row inputs or a proposed correspondence are malformed."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _coalesce(terms: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = defaultdict(int)
    for column, coefficient in terms:
        combined[column] = (combined[column] + coefficient) % FIELD
    return tuple(
        (column, coefficient)
        for column, coefficient in sorted(combined.items())
        if coefficient
    )


def _scale(
    terms: tuple[tuple[int, int], ...], coefficient: int
) -> tuple[tuple[int, int], ...]:
    return tuple(
        (column, value * coefficient % FIELD)
        for column, value in terms
        if value * coefficient % FIELD
    )


def _proportional_scale(
    expected: tuple[tuple[int, int], ...],
    actual: tuple[tuple[int, int], ...],
) -> int | None:
    if not expected or not actual:
        return 1 if expected == actual else None
    if tuple(column for column, _ in expected) != tuple(
        column for column, _ in actual
    ):
        return None
    coefficient = expected[0][1] * pow(actual[0][1], -1, FIELD) % FIELD
    return coefficient if _scale(actual, coefficient) == expected else None


def _factor_signature(
    abc: tuple[
        tuple[tuple[int, int], ...],
        tuple[tuple[int, int], ...],
        tuple[tuple[int, int], ...],
    ],
) -> tuple[Any, ...]:
    a, b, c = abc
    if a:
        scale_a = pow(a[0][1], -1, FIELD)
        normalized_a = _scale(a, scale_a)
    else:
        scale_a, normalized_a = 1, a
    if b:
        scale_b = pow(b[0][1], -1, FIELD)
        normalized_b = _scale(b, scale_b)
    else:
        scale_b, normalized_b = 1, b
    normalized_c = _scale(c, scale_a * scale_b % FIELD)
    return min(
        (normalized_a, normalized_b, normalized_c),
        (normalized_b, normalized_a, normalized_c),
    )


def _expand(
    abc: tuple[
        tuple[tuple[int, int], ...],
        tuple[tuple[int, int], ...],
        tuple[tuple[int, int], ...],
    ],
) -> tuple[tuple[tuple[int, ...], int], ...]:
    a, b, c = abc
    polynomial: dict[tuple[int, ...], int] = defaultdict(int)

    def monomial(column: int) -> tuple[int, ...]:
        return () if column == 0 else (column,)

    for left_column, left_coefficient in a:
        for right_column, right_coefficient in b:
            term = tuple(sorted(monomial(left_column) + monomial(right_column)))
            polynomial[term] = (
                polynomial[term] + left_coefficient * right_coefficient
            ) % FIELD
    for column, coefficient in c:
        term = monomial(column)
        polynomial[term] = (polynomial[term] - coefficient) % FIELD
    nonzero = {term: value for term, value in polynomial.items() if value}
    if not nonzero:
        return ()
    multiplier = pow(nonzero[min(nonzero)], -1, FIELD)
    return tuple(
        (term, value * multiplier % FIELD)
        for term, value in sorted(nonzero.items())
    )


def _polynomial_scale(
    expected: tuple[tuple[tuple[int, ...], int], ...],
    actual: tuple[tuple[tuple[int, ...], int], ...],
) -> int | None:
    if not expected or not actual:
        return 1 if expected == actual else None
    if tuple(term for term, _ in expected) != tuple(
        term for term, _ in actual
    ):
        return None
    coefficient = expected[0][1] * pow(actual[0][1], -1, FIELD) % FIELD
    if tuple(
        (term, value * coefficient % FIELD) for term, value in actual
    ) == expected:
        return coefficient
    return None


def _upstream_abc(
    row: dict[str, Any],
    identity_to_column: dict[str, int],
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    result = []
    try:
        for side in "abc":
            terms = []
            for term in row[side]:
                coefficient = int.from_bytes(
                    bytes.fromhex(term["coefficient_hex"]), "little"
                )
                if coefficient >= FIELD:
                    raise SpendRowCorrespondenceError(
                        "noncanonical upstream coefficient"
                    )
                terms.append(
                    (identity_to_column[term["identity"]], coefficient)
                )
            result.append(_coalesce(terms))
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, SpendRowCorrespondenceError):
            raise
        raise SpendRowCorrespondenceError(
            "invalid upstream constraint term"
        ) from error
    return tuple(result)  # type: ignore[return-value]


def _local_abc(
    row: dict[str, Any],
    local_to_upstream: dict[int, int],
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    result = []
    try:
        for side in "abc":
            terms = []
            for local_column, raw_coefficient in row[side]:
                coefficient = int(raw_coefficient)
                if not 0 <= coefficient < FIELD:
                    raise SpendRowCorrespondenceError(
                        "noncanonical local coefficient"
                    )
                terms.append(
                    (local_to_upstream[local_column], coefficient)
                )
            result.append(_coalesce(terms))
    except (KeyError, TypeError, ValueError) as error:
        if isinstance(error, SpendRowCorrespondenceError):
            raise
        raise SpendRowCorrespondenceError(
            "invalid local constraint term"
        ) from error
    return tuple(result)  # type: ignore[return-value]


def _assignment_decimal(variable: dict[str, Any], upstream: bool) -> str | None:
    if upstream:
        encoded = variable.get("assignment_hex")
        return (
            None
            if encoded is None
            else str(int.from_bytes(bytes.fromhex(encoded), "little"))
        )
    value = variable.get("assignment")
    return None if value is None else str(value)


def _validate_mapping(
    upstream_variables: list[dict[str, Any]],
    local_variables: list[dict[str, Any]],
    variable_correspondence: dict[str, Any],
) -> tuple[dict[int, int], dict[int, dict[str, Any]], list[str]]:
    identities = [variable["identity"] for variable in upstream_variables]
    identity_to_column = {identity: index for index, identity in enumerate(identities)}
    if len(identity_to_column) != len(identities):
        raise SpendRowCorrespondenceError("upstream variable identities are duplicated")
    local_indices = {variable["index"] for variable in local_variables}
    if local_indices != set(range(len(local_variables))):
        raise SpendRowCorrespondenceError("local variable indices are not contiguous")

    mapping: dict[int, int] = {}
    provenance: dict[int, dict[str, Any]] = {}
    mapped_upstream: set[int] = set()
    pairs = (
        variable_correspondence.get("matched_public_variables", [])
        + variable_correspondence.get("matched_auxiliary_variables", [])
    )
    for pair in pairs:
        local_index = pair["local_index"]
        upstream_index = pair["upstream_index"]
        if local_index in mapping or upstream_index in mapped_upstream:
            raise SpendRowCorrespondenceError(
                "variable correspondence is not one-to-one"
            )
        if local_index not in local_indices or not 0 <= upstream_index < len(identities):
            raise SpendRowCorrespondenceError(
                "variable correspondence references an unknown column"
            )
        mapping[local_index] = upstream_index
        mapped_upstream.add(upstream_index)
        provenance[upstream_index] = {
            "semantic_identity": pair["semantic_identity"],
            "semantic_gadget_id": pair.get("semantic_gadget_id"),
            "allocation_role": pair.get("allocation_role"),
            "gadget_invocation_context": pair.get("gadget_invocation_context"),
            "classification": pair.get("classification"),
        }
        local_assignment = _assignment_decimal(
            local_variables[local_index], False
        )
        upstream_assignment = _assignment_decimal(
            upstream_variables[upstream_index], True
        )
        if local_assignment != upstream_assignment:
            raise SpendRowCorrespondenceError(
                f"mapped variable assignment mismatch at local column {local_index}"
            )
    if not pairs:
        raise SpendRowCorrespondenceError("variable correspondence has no mapped pairs")
    return mapping, provenance, identities


def _factor_match(
    upstream: tuple[tuple[tuple[int, int], ...], ...],
    local: tuple[tuple[tuple[int, int], ...], ...],
) -> tuple[str, str, int, int] | None:
    ua, ub, uc = upstream
    la, lb, lc = local
    if upstream == local:
        return "native_a_b_c", "same", 1, 1
    if upstream == (lb, la, lc):
        return "a_b_factor_swap", "swapped", 1, 1
    candidates = []
    for orientation, local_a, local_b in (
        ("same", la, lb),
        ("swapped", lb, la),
    ):
        scale_a = _proportional_scale(ua, local_a)
        scale_b = _proportional_scale(ub, local_b)
        if scale_a is not None and scale_b is not None:
            if _scale(lc, scale_a * scale_b % FIELD) == uc:
                candidates.append((orientation, scale_a, scale_b))
    if len(candidates) > 1:
        raise SpendRowCorrespondenceError(
            "factor normalization has multiple valid orientations"
        )
    if candidates:
        orientation, scale_a, scale_b = candidates[0]
        return "valid_factor_normalization", orientation, scale_a, scale_b
    return None


def _factor_mapping(
    match: tuple[str, str, int, int],
) -> dict[str, Any]:
    _, orientation, scale_a, scale_b = match
    return {
        "orientation": orientation,
        "local_A_maps_to": "upstream_A" if orientation == "same" else "upstream_B",
        "local_B_maps_to": "upstream_B" if orientation == "same" else "upstream_A",
        "local_factor_scale_for_upstream_A_hex": scale_a.to_bytes(32, "little").hex(),
        "local_factor_scale_for_upstream_B_hex": scale_b.to_bytes(32, "little").hex(),
        "local_C_scale_hex": (scale_a * scale_b % FIELD).to_bytes(32, "little").hex(),
    }


def _terms_json(
    abc: tuple[tuple[tuple[int, int], ...], ...],
    ) -> list[list[list[Any]]]:
    return [
        [
            [column, coefficient.to_bytes(32, "little").hex()]
            for column, coefficient in terms
        ]
        for terms in abc
    ]


def _polynomial_json(
    terms: tuple[tuple[tuple[int, ...], int], ...],
) -> list[dict[str, Any]]:
    return [
        {
            "columns": list(monomial),
            "coefficient_hex": coefficient.to_bytes(32, "little").hex(),
        }
        for monomial, coefficient in terms
    ]


def _evaluate(
    abc: tuple[tuple[tuple[int, int], ...], ...],
    assignments: list[int],
) -> bool:
    values = [
        sum(coefficient * assignments[column] for column, coefficient in terms)
        % FIELD
        for terms in abc
    ]
    return values[0] * values[1] % FIELD == values[2]


def build_spend_row_correspondence(
    upstream_document: dict[str, Any],
    local_document: dict[str, Any],
    variable_correspondence: dict[str, Any],
) -> dict[str, Any]:
    """Compare every Spend row, matching only unique mapped-variable equations."""
    upstream_variables = upstream_document["inputs"] + upstream_document[
        "auxiliary_variables"
    ]
    local_variables = local_document["variables"]
    upstream_rows = upstream_document["constraints"]
    local_rows = local_document["constraints"]
    if len(upstream_rows) != len(local_rows):
        raise SpendRowCorrespondenceError("upstream and local row counts differ")

    local_to_upstream, _, identities = _validate_mapping(
        upstream_variables, local_variables, variable_correspondence
    )
    identity_to_column = {identity: index for index, identity in enumerate(identities)}
    unmapped_upstream = set(range(len(upstream_variables))) - set(
        local_to_upstream.values()
    )
    unmapped_local = set(range(len(local_variables))) - set(local_to_upstream)

    upstream_abc: dict[int, Any] = {}
    local_abc: dict[int, Any] = {}
    upstream_blocked: dict[int, list[str]] = {}
    local_blocked: dict[int, list[int]] = {}
    upstream_label_counts = Counter(row["annotation"] for row in upstream_rows)
    local_label_counts = Counter(row["label"] for row in local_rows)

    for index, row in enumerate(upstream_rows):
        abc = _upstream_abc(row, identity_to_column)
        blocked = sorted(
            {
                identities[column]
                for terms in abc
                for column, _ in terms
                if column in unmapped_upstream
            }
        )
        if blocked:
            upstream_blocked[index] = blocked
        else:
            upstream_abc[index] = abc
    for index, row in enumerate(local_rows):
        referenced = {column for side in "abc" for column, _ in row[side]}
        blocked = sorted(referenced & unmapped_local)
        if blocked:
            local_blocked[index] = blocked
        else:
            local_abc[index] = _local_abc(row, local_to_upstream)

    upstream_factor_groups: dict[Any, list[int]] = defaultdict(list)
    local_factor_groups: dict[Any, list[int]] = defaultdict(list)
    for index, abc in upstream_abc.items():
        upstream_factor_groups[_factor_signature(abc)].append(index)
    for index, abc in local_abc.items():
        local_factor_groups[_factor_signature(abc)].append(index)

    pair_indices: dict[int, int] = {}
    paired_local: set[int] = set()
    ambiguous_upstream: set[int] = set()
    ambiguous_local: set[int] = set()

    for signature in upstream_factor_groups.keys() | local_factor_groups.keys():
        upstream_matches = upstream_factor_groups.get(signature, [])
        local_matches = local_factor_groups.get(signature, [])
        if not upstream_matches or not local_matches:
            continue
        if len(upstream_matches) != 1 or len(local_matches) != 1:
            ambiguous_upstream.update(upstream_matches)
            ambiguous_local.update(local_matches)
            continue
        upstream_index = upstream_matches[0]
        local_index = local_matches[0]
        pair_indices[upstream_index] = local_index
        paired_local.add(local_index)

    upstream_residual = [
        index for index in upstream_abc if index not in pair_indices
    ]
    local_residual = [
        index for index in local_abc if index not in paired_local
    ]
    upstream_polynomials = {
        index: _expand(upstream_abc[index])
        for index in upstream_residual
        if index not in ambiguous_upstream
    }
    local_polynomials = {
        index: _expand(local_abc[index])
        for index in local_residual
        if index not in ambiguous_local
    }
    upstream_polynomial_groups: dict[Any, list[int]] = defaultdict(list)
    local_polynomial_groups: dict[Any, list[int]] = defaultdict(list)
    for index, signature in upstream_polynomials.items():
        upstream_polynomial_groups[signature].append(index)
    for index, signature in local_polynomials.items():
        local_polynomial_groups[signature].append(index)

    for signature in upstream_polynomial_groups.keys() | local_polynomial_groups.keys():
        upstream_matches = upstream_polynomial_groups.get(signature, [])
        local_matches = local_polynomial_groups.get(signature, [])
        if not upstream_matches or not local_matches:
            continue
        if len(upstream_matches) != 1 or len(local_matches) != 1:
            ambiguous_upstream.update(upstream_matches)
            ambiguous_local.update(local_matches)
            continue
        upstream_index = upstream_matches[0]
        local_index = local_matches[0]
        pair_indices[upstream_index] = local_index
        paired_local.add(local_index)

    row_pairs = []
    classifications: Counter[str] = Counter()
    moved_rows = 0
    expanded_scale_counts: Counter[str] = Counter()
    row_fingerprint = hashlib.sha256(_FINGERPRINT_DOMAIN)
    coefficient_fingerprint = hashlib.sha256(
        _FINGERPRINT_DOMAIN + b"coefficients\0"
    )
    for upstream_index, local_index in sorted(pair_indices.items()):
        upstream_row = upstream_rows[upstream_index]
        local_row = local_rows[local_index]
        ua = upstream_abc[upstream_index]
        la = local_abc[local_index]
        factor_match = _factor_match(ua, la)
        expanded = None
        if factor_match is None:
            upstream_polynomial = _expand(ua)
            local_polynomial = _expand(la)
            scale = _polynomial_scale(upstream_polynomial, local_polynomial)
            if scale is None:
                raise SpendRowCorrespondenceError(
                    f"paired rows {upstream_index}/{local_index} do not have equivalent relations"
                )
            classification = "expanded_a_times_b_minus_c_only"
            expanded = {
                "local_polynomial_scale_for_upstream_hex": scale.to_bytes(
                    32, "little"
                ).hex(),
                "upstream_terms": _polynomial_json(upstream_polynomial),
                "local_mapped_terms": _polynomial_json(local_polynomial),
            }
            expanded_scale_counts[
                "unit" if scale == 1 else "non-unit"
            ] += 1
            factor_mapping = None
        else:
            classification = factor_match[0]
            factor_mapping = _factor_mapping(factor_match)
        if upstream_index != local_index:
            moved_rows += 1
        classifications[classification] += 1
        row_pairs.append(
            {
                "upstream_row_index": upstream_index,
                "local_row_index": local_index,
                "upstream_annotation": upstream_row["annotation"],
                "local_label": local_row["label"],
                "upstream_label_unique": upstream_label_counts[
                    upstream_row["annotation"]
                ]
                == 1,
                "local_label_unique": local_label_counts[local_row["label"]] == 1,
                "classification": classification,
                "factor_mapping": factor_mapping,
                "upstream_abc": _terms_json(ua),
                "local_mapped_abc": _terms_json(la),
                "referenced_upstream_columns": sorted(
                    {column for terms in ua for column, _ in terms}
                ),
                "expanded_relation": expanded,
            }
        )
        row_fingerprint.update(
            _canonical_json([upstream_index, local_index, classification])
        )
        coefficient_fingerprint.update(
            _canonical_json(
                [
                    upstream_index,
                    local_index,
                    [
                        [[column, coefficient] for column, coefficient in terms]
                        for terms in ua
                    ],
                    [
                        [[column, coefficient] for column, coefficient in terms]
                        for terms in la
                    ],
                ]
            )
        )

    unmatched_upstream = [
        index
        for index in range(len(upstream_rows))
        if index not in pair_indices
    ]
    unmatched_local = [
        index for index in range(len(local_rows)) if index not in paired_local
    ]
    unmatched_records = {
        "upstream": [
            {
                "row_index": index,
                "annotation": upstream_rows[index]["annotation"],
                "classification": (
                    "blocked_by_unmapped_variable"
                    if index in upstream_blocked
                    else "ambiguous"
                    if index in ambiguous_upstream
                    else "no_unique_relation_counterpart"
                ),
                "unmapped_variables": upstream_blocked.get(index, []),
            }
            for index in unmatched_upstream
        ],
        "local": [
            {
                "row_index": index,
                "label": local_rows[index]["label"],
                "classification": (
                    "blocked_by_unmapped_variable"
                    if index in local_blocked
                    else "ambiguous"
                    if index in ambiguous_local
                    else "no_unique_relation_counterpart"
                ),
                "unmapped_local_columns": local_blocked.get(index, []),
            }
            for index in unmatched_local
        ],
    }

    upstream_assignments = [
        int.from_bytes(bytes.fromhex(variable["assignment_hex"]), "little")
        for variable in upstream_variables
    ]
    local_assignments = [
        int(variable["assignment"]) for variable in local_variables
    ]
    upstream_rows_satisfied = sum(
        _evaluate(_upstream_abc(row, identity_to_column), upstream_assignments)
        for row in upstream_rows
    )
    local_rows_satisfied = sum(
        _evaluate(
            tuple(
                _coalesce([(int(column), int(coefficient)) for column, coefficient in row[side]])
                for side in "abc"
            ),
            local_assignments,
        )
        for row in local_rows
    )
    mapping_fingerprint = row_fingerprint.hexdigest()
    return {
        "format": FORMAT,
        "sources": {
            "upstream_reference_sha256": variable_correspondence.get(
                "pinned_upstream", {}
            ).get("export_sha256"),
            "variable_mapping_fingerprint_sha256": variable_correspondence[
                "mapping_fingerprint_sha256"
            ],
            "local_matrix_fingerprint": local_document.get("matrix_fingerprint"),
        },
        "counts": {
            "upstream_rows": len(upstream_rows),
            "local_rows": len(local_rows),
            "one_to_one_row_pairs": len(row_pairs),
            "native_a_b_c": classifications["native_a_b_c"],
            "a_b_factor_swap": classifications["a_b_factor_swap"],
            "valid_factor_normalization": classifications[
                "valid_factor_normalization"
            ],
            "expanded_a_times_b_minus_c_only": classifications[
                "expanded_a_times_b_minus_c_only"
            ],
            "expanded_relation_unit_scale": expanded_scale_counts["unit"],
            "expanded_relation_non_unit_scale": expanded_scale_counts["non-unit"],
            "unmatched_upstream": len(unmatched_upstream),
            "unmatched_local": len(unmatched_local),
            "ambiguous_upstream": len(ambiguous_upstream),
            "ambiguous_local": len(ambiguous_local),
            "upstream_rows_blocked_by_unmapped_variable": len(upstream_blocked),
            "local_rows_blocked_by_unmapped_variable": len(local_blocked),
            "moved_row_pairs": moved_rows,
            "same_index_row_pairs": len(row_pairs) - moved_rows,
            "upstream_labels_unique": sum(
                count == 1 for count in upstream_label_counts.values()
            ),
            "local_labels_unique": sum(
                count == 1 for count in local_label_counts.values()
            ),
        },
        "witness_validation": {
            "mapped_variable_assignments_checked": len(local_to_upstream),
            "mapped_variable_assignment_mismatches": 0,
            "upstream_satisfied_rows": upstream_rows_satisfied,
            "local_satisfied_rows": local_rows_satisfied,
            "upstream_export_claimed_satisfied": upstream_document["satisfied"],
            "local_export_claimed_satisfied": local_document["satisfied"],
        },
        "row_mapping_fingerprint_sha256": mapping_fingerprint,
        "coefficient_fingerprint_sha256": coefficient_fingerprint.hexdigest(),
        "matching_policy": {
            "row_ordinals_used_as_identity": False,
            "witness_satisfaction_used_as_identity": False,
            "candidate_identity": (
                "Unique A/B/C factor relation over the accepted v7 variable "
                "mapping; residual rows use unique expanded A*B-C relations."
            ),
            "provenance": (
                "Unique upstream annotations and local labels are retained. "
                "Referenced column indices join to the v7 semantic allocation "
                "roles using the recorded variable-mapping fingerprint."
            ),
            "ambiguous_candidates": "Reported and left unmatched; never paired by order.",
        },
        "row_pairs": row_pairs,
        "unmatched_rows": unmatched_records,
        "alignment_conclusion": {
            "complete_one_to_one_row_coverage": (
                len(row_pairs) == len(upstream_rows) == len(local_rows)
            ),
            "exact_ordered_spend_matrix_alignment": False,
            "reason": (
                "The v7 variable map intentionally leaves a local Merkle path "
                "position and an upstream conditional-anchor allocation unmapped. "
                "Rows touching those variables cannot be compared by semantic "
                "identity. In addition, at least one local constraint has no "
                "unique equivalent counterpart among rows whose variables are mapped."
            ),
        },
    }


def write_spend_row_correspondence(
    upstream_path: Path,
    local_path: Path,
    variable_correspondence_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    upstream = json.loads(upstream_path.read_text(encoding="utf-8"))
    local = json.loads(local_path.read_text(encoding="utf-8"))
    variable_correspondence = json.loads(
        variable_correspondence_path.read_text(encoding="utf-8")
    )
    result = build_spend_row_correspondence(
        upstream, local, variable_correspondence
    )
    result["sources"]["upstream_reference_path"] = str(upstream_path.resolve())
    result["sources"]["upstream_reference_file_sha256"] = hashlib.sha256(
        upstream_path.read_bytes()
    ).hexdigest()
    result["sources"]["local_matrix_export_path"] = str(local_path.resolve())
    result["sources"]["local_matrix_export_file_sha256"] = hashlib.sha256(
        local_path.read_bytes()
    ).hexdigest()
    result["sources"]["variable_correspondence_path"] = str(
        variable_correspondence_path.resolve()
    )
    result["sources"]["variable_correspondence_file_sha256"] = hashlib.sha256(
        variable_correspondence_path.read_bytes()
    ).hexdigest()
    content = _canonical_json(result)
    result["artifact_content_fingerprint_sha256"] = hashlib.sha256(
        _ARTIFACT_DOMAIN + content
    ).hexdigest()
    encoded = _canonical_json(result)
    output_path.write_bytes(encoded)
    result["artifact_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result
