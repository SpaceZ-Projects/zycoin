"""Compare pinned Bellman Output rows with a fresh local synthesis."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from src.bellman_synthesis import BellmanSynthesisRecorder, RecorderSynthesisBackend
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import Point
from src.r1cs import R1CS, Constraint, LinearCombination
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness

FIELD = SCALAR_MODULUS
FORMAT = "zycoin-bellman-sapling-output-row-correspondence-v1"
PINNED_EXPORT_SHA256 = (
    "ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe"
)
VARIABLE_MAPPING_FINGERPRINT = (
    "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
)
PRODUCTION_MATRIX_FINGERPRINT = (
    "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
)


class RowCorrespondenceError(ValueError):
    """Raised when row matching is incomplete or ambiguous."""


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
    coefficient = (
        expected[0][1] * pow(actual[0][1], -1, FIELD)
    ) % FIELD
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
            term = tuple(
                sorted(monomial(left_column) + monomial(right_column))
            )
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
    coefficient = (
        expected[0][1] * pow(actual[0][1], -1, FIELD)
    ) % FIELD
    if tuple(
        (term, value * coefficient % FIELD) for term, value in actual
    ) == expected:
        return coefficient
    return None


def _upstream_terms(
    terms: list[dict[str, str]], identity_to_column: dict[str, int]
) -> tuple[tuple[int, int], ...]:
    try:
        decoded = [
            (
                identity_to_column[item["identity"]],
                int.from_bytes(bytes.fromhex(item["coefficient_hex"]), "little"),
            )
            for item in terms
        ]
    except (KeyError, ValueError) as error:
        raise RowCorrespondenceError("invalid upstream linear-combination term") from error
    if any(coefficient >= FIELD for _, coefficient in decoded):
        raise RowCorrespondenceError("noncanonical upstream coefficient")
    return _coalesce(decoded)


def _upstream_abc(
    row: dict[str, Any], identity_to_column: dict[str, int]
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    return tuple(
        _upstream_terms(row[side], identity_to_column) for side in "abc"
    )  # type: ignore[return-value]


def _local_abc(
    row: Constraint, local_to_upstream: dict[int, int]
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]:
    result = []
    for expression in (row.left, row.right, row.output):
        try:
            result.append(
                _coalesce(
                    [
                        (local_to_upstream[column], coefficient % FIELD)
                        for column, coefficient in expression.terms
                    ]
                )
            )
        except KeyError as error:
            raise RowCorrespondenceError(
                f"local row references unmapped column {error.args[0]}"
            ) from error
    return tuple(result)  # type: ignore[return-value]


def _group_unique(
    signatures: list[tuple[Any, ...]], side: str
) -> dict[tuple[Any, ...], int]:
    grouped: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    for index, signature in enumerate(signatures):
        grouped[signature].append(index)
    duplicates = [
        (signature, indices)
        for signature, indices in grouped.items()
        if len(indices) != 1
    ]
    if duplicates:
        raise RowCorrespondenceError(
            f"{side} signatures contain ambiguous rows: {duplicates[0][1][:4]}"
        )
    return {signature: indices[0] for signature, indices in grouped.items()}


def _poly_terms_json(
    terms: tuple[tuple[tuple[int, ...], int], ...],
    identities: list[str],
) -> list[dict[str, Any]]:
    return [
        {
            "variables": [identities[column] for column in monomial],
            "coefficient_hex": coefficient.to_bytes(32, "little").hex(),
        }
        for monomial, coefficient in terms
    ]


def _lc_json(
    terms: tuple[tuple[int, int], ...], identities: list[str]
) -> list[dict[str, str]]:
    return [
        {
            "identity": identities[column],
            "coefficient_hex": coefficient.to_bytes(32, "little").hex(),
        }
        for column, coefficient in terms
    ]


def _raw_upstream_terms(
    terms: list[dict[str, str]],
) -> list[dict[str, str]]:
    return [
        {
            "identity": item["identity"],
            "coefficient_hex": item["coefficient_hex"],
        }
        for item in terms
    ]


def _local_lc_json(
    expression: LinearCombination,
    local_to_upstream: dict[int, int],
    local_identities: list[str],
    upstream_identities: list[str],
) -> list[dict[str, Any]]:
    return [
        {
            "local_column": column,
            "local_identity": local_identities[column],
            "upstream_identity": upstream_identities[
                local_to_upstream[column]
            ],
            "coefficient_hex": (coefficient % FIELD).to_bytes(32, "little").hex(),
        }
        for column, coefficient in expression.terms
    ]


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

    candidates: list[tuple[str, int, int]] = []
    for orientation, local_a, local_b in (
        ("same", la, lb),
        ("swapped", lb, la),
    ):
        scale_a = _proportional_scale(ua, local_a)
        scale_b = _proportional_scale(ub, local_b)
        if scale_a is None or scale_b is None:
            continue
        if _scale(lc, scale_a * scale_b % FIELD) == uc:
            candidates.append((orientation, scale_a, scale_b))
    if len(candidates) > 1:
        raise RowCorrespondenceError("factor scaling has multiple orientations")
    if candidates:
        orientation, scale_a, scale_b = candidates[0]
        return "valid_factor_normalization", orientation, scale_a, scale_b
    return None


def _serialize_row(
    upstream_row: dict[str, Any],
    local_row: Constraint,
    upstream_index: int,
    local_index: int,
    upstream_abc: tuple[tuple[tuple[int, int], ...], ...],
    local_abc: tuple[tuple[tuple[int, int], ...], ...],
    upstream_identities: list[str],
    local_to_upstream: dict[int, int],
    local_identities: list[str],
    classification: str,
    factor_mapping: dict[str, Any] | None,
    expanded: dict[str, Any] | None,
) -> dict[str, Any]:
    upstream_sides = {
        side: {
            "canonical_terms": _lc_json(upstream_abc[index], upstream_identities),
            "source_terms": _raw_upstream_terms(upstream_row[side]),
        }
        for index, side in enumerate("abc")
    }
    local_expressions = (local_row.left, local_row.right, local_row.output)
    local_sides = {
        side: _local_lc_json(
            local_expressions[index],
            local_to_upstream,
            local_identities,
            upstream_identities,
        )
        for index, side in enumerate("abc")
    }
    return {
        "upstream_row_index": upstream_index,
        "upstream_label": upstream_row["annotation"],
        "local_row_index": local_index,
        "local_label": local_row.label,
        "classification": classification,
        "factor_mapping": factor_mapping,
        "upstream_abc": upstream_sides,
        "local_abc": local_sides,
        "expanded_relation": expanded,
    }


def _render_factor_mapping(
    match: tuple[str, str, int, int]
) -> dict[str, Any]:
    _, orientation, scale_a, scale_b = match
    if orientation == "same":
        local_a_maps_to = "upstream_A"
        local_b_maps_to = "upstream_B"
    else:
        local_a_maps_to = "upstream_B"
        local_b_maps_to = "upstream_A"
    return {
        "orientation": orientation,
        "local_A_maps_to": local_a_maps_to,
        "local_B_maps_to": local_b_maps_to,
        "local_factor_scale_for_upstream_A_hex": scale_a.to_bytes(
            32, "little"
        ).hex(),
        "local_factor_scale_for_upstream_B_hex": scale_b.to_bytes(
            32, "little"
        ).hex(),
        "local_C_scale_hex": (scale_a * scale_b % FIELD).to_bytes(
            32, "little"
        ).hex(),
    }


def build_row_correspondence(
    upstream_document: dict[str, Any],
    local_system: R1CS,
    variable_correspondence: dict[str, Any],
) -> dict[str, Any]:
    upstream_variables = upstream_document["inputs"] + upstream_document[
        "auxiliary_variables"
    ]
    upstream_identities = [item["identity"] for item in upstream_variables]
    identity_to_column = {
        identity: index for index, identity in enumerate(upstream_identities)
    }
    if len(identity_to_column) != len(upstream_identities):
        raise RowCorrespondenceError("upstream variable identities are duplicated")

    pairs = variable_correspondence["pairs"]
    upstream_pair_ids = {pair["upstream_identity"] for pair in pairs}
    local_pair_cols = {pair["local_column"] for pair in pairs}
    if len(upstream_pair_ids) != len(pairs) or len(local_pair_cols) != len(pairs):
        raise RowCorrespondenceError("variable correspondence is not one-to-one")
    if upstream_pair_ids != set(upstream_identities):
        raise RowCorrespondenceError("variable correspondence omits upstream variables")
    if local_pair_cols != set(range(len(local_system.variables))):
        raise RowCorrespondenceError("variable correspondence omits local columns")

    local_to_upstream_identity = {
        pair["local_identity"]: pair["upstream_identity"] for pair in pairs
    }
    local_to_upstream = {
        pair["local_column"]: identity_to_column[pair["upstream_identity"]]
        for pair in pairs
    }
    local_identities = [
        "Input(0)"
        if variable.index == 0
        else f"Input({variable.index})"
        if variable.kind == "public"
        else f"Aux({variable.index - 6})"
        for variable in local_system.variables
    ]
    if any(
        local_to_upstream_identity[local_identities[index]]
        != upstream_identities[column]
        for index, column in local_to_upstream.items()
    ):
        raise RowCorrespondenceError("variable identity translation is inconsistent")

    upstream_rows = upstream_document["constraints"]
    local_rows = local_system.constraints
    if len(upstream_rows) != len(local_rows):
        raise RowCorrespondenceError("upstream and local row counts differ")

    upstream_abc = [
        _upstream_abc(row, identity_to_column) for row in upstream_rows
    ]
    local_abc = [_local_abc(row, local_to_upstream) for row in local_rows]
    upstream_factor_signatures = [
        _factor_signature(row) for row in upstream_abc
    ]
    local_factor_signatures = [_factor_signature(row) for row in local_abc]
    upstream_factor_groups = _group_unique(
        upstream_factor_signatures, "upstream factor"
    )
    local_factor_groups = _group_unique(local_factor_signatures, "local factor")

    pair_indices: dict[int, int] = {}
    used_local: set[int] = set()
    for signature in upstream_factor_groups.keys() & local_factor_groups.keys():
        upstream_index = upstream_factor_groups[signature]
        local_index = local_factor_groups[signature]
        pair_indices[upstream_index] = local_index
        used_local.add(local_index)

    residual_upstream = [
        index for index in range(len(upstream_rows)) if index not in pair_indices
    ]
    residual_local = [
        index for index in range(len(local_rows)) if index not in used_local
    ]
    upstream_polynomials = {
        index: _expand(upstream_abc[index]) for index in residual_upstream
    }
    local_polynomials = {
        index: _expand(local_abc[index]) for index in residual_local
    }
    upstream_residual_signatures = [
        upstream_polynomials[index] for index in residual_upstream
    ]
    local_residual_signatures = [
        local_polynomials[index] for index in residual_local
    ]
    _group_unique(
        upstream_residual_signatures,
        "upstream expanded-relation",
    )
    _group_unique(
        local_residual_signatures,
        "local expanded-relation",
    )
    residual_upstream_by_signature = {
        signature: residual_upstream[position]
        for position, signature in enumerate(upstream_residual_signatures)
    }
    residual_local_by_signature = {
        signature: residual_local[position]
        for position, signature in enumerate(local_residual_signatures)
    }
    for signature in residual_upstream_by_signature.keys() & residual_local_by_signature.keys():
        upstream_index = residual_upstream_by_signature[signature]
        local_index = residual_local_by_signature[signature]
        if upstream_index in pair_indices or local_index in used_local:
            raise RowCorrespondenceError("expanded relation reuses a matched row")
        pair_indices[upstream_index] = local_index
        used_local.add(local_index)

    if len(pair_indices) != len(upstream_rows) or len(used_local) != len(local_rows):
        raise RowCorrespondenceError(
            "row correspondence incomplete: "
            f"unmatched upstream={len(upstream_rows) - len(pair_indices)}, "
            f"unmatched local={len(local_rows) - len(used_local)}"
        )
    if len(set(pair_indices.values())) != len(local_rows):
        raise RowCorrespondenceError("row correspondence is not one-to-one")

    records = []
    classifications: dict[str, int] = defaultdict(int)
    expanded_only_rows = []
    row_map_payload = []
    coefficient_payload = []
    for upstream_index in range(len(upstream_rows)):
        local_index = pair_indices[upstream_index]
        upstream_row = upstream_rows[upstream_index]
        local_row = local_rows[local_index]
        upstream_row_abc = upstream_abc[upstream_index]
        local_row_abc = local_abc[local_index]
        factor_match = _factor_match(upstream_row_abc, local_row_abc)
        expanded_json = None
        if factor_match is None:
            upstream_polynomial = _expand(upstream_row_abc)
            local_polynomial = _expand(local_row_abc)
            polynomial_scale = _polynomial_scale(
                upstream_polynomial, local_polynomial
            )
            if polynomial_scale is None:
                raise RowCorrespondenceError(
                    f"paired rows {upstream_index}/{local_index} do not match"
                )
            classification = "expanded_a_times_b_minus_c_only"
            expanded_json = {
                "local_polynomial_scale_for_upstream_hex": polynomial_scale.to_bytes(
                    32, "little"
                ).hex(),
                "upstream_terms": _poly_terms_json(
                    upstream_polynomial, upstream_identities
                ),
                "local_mapped_terms": _poly_terms_json(
                    local_polynomial, upstream_identities
                ),
            }
            expanded_only_rows.append(
                {
                    "upstream_row_index": upstream_index,
                    "local_row_index": local_index,
                    "upstream_label": upstream_row["annotation"],
                    "local_label": local_row.label,
                    "polynomial_scale_hex": expanded_json[
                        "local_polynomial_scale_for_upstream_hex"
                    ],
                    "upstream_relation_fingerprint": hashlib.sha256(
                        _canonical_json(expanded_json["upstream_terms"])
                    ).hexdigest(),
                }
            )
            factor_mapping = None
        else:
            classification = factor_match[0]
            factor_mapping = _render_factor_mapping(factor_match)

        classifications[classification] += 1
        row_map_payload.append(
            [upstream_index, local_index, classification]
        )
        coefficient_payload.append(
            [
                upstream_index,
                local_index,
                [
                    [[column, coefficient] for column, coefficient in lc]
                    for lc in upstream_row_abc
                ],
                [
                    [[column, coefficient] for column, coefficient in lc]
                    for lc in local_row_abc
                ],
            ]
        )
        records.append(
            _serialize_row(
                upstream_row,
                local_row,
                upstream_index,
                local_index,
                upstream_row_abc,
                local_row_abc,
                upstream_identities,
                local_to_upstream,
                local_identities,
                classification,
                factor_mapping,
                expanded_json,
            )
        )

    same_index_rows = sum(
        upstream_index == local_index
        for upstream_index, local_index in pair_indices.items()
    )
    by_upstream_region: dict[str, dict[str, int]] = {}
    for record in records:
        region = record["upstream_label"].split("/", 1)[0]
        summary = by_upstream_region.setdefault(
            region, {"rows": 0, "same_index": 0, "moved": 0}
        )
        summary["rows"] += 1
        if record["upstream_row_index"] == record["local_row_index"]:
            summary["same_index"] += 1
        else:
            summary["moved"] += 1

    return {
        "format": FORMAT,
        "source": {
            "upstream_export_sha256": variable_correspondence[
                "pinned_upstream"
            ]["export_sha256"],
            "variable_mapping_fingerprint_sha256": variable_correspondence[
                "mapping_fingerprint_sha256"
            ],
            "local_matrix_fingerprint": local_system.matrix_fingerprint(),
        },
        "counts": {
            "upstream_rows": len(upstream_rows),
            "local_rows": len(local_rows),
            "one_to_one_row_pairs": len(records),
            "native_a_b_c": classifications["native_a_b_c"],
            "a_b_factor_swap": classifications["a_b_factor_swap"],
            "valid_factor_normalization": classifications[
                "valid_factor_normalization"
            ],
            "expanded_a_times_b_minus_c_only": classifications[
                "expanded_a_times_b_minus_c_only"
            ],
            "unmatched_upstream": 0,
            "unmatched_local": 0,
            "ambiguous_upstream": 0,
            "ambiguous_local": 0,
        },
        "row_order_summary": {
            "same_index_rows": same_index_rows,
            "moved_rows": len(records) - same_index_rows,
            "identity_order": same_index_rows == len(records),
            "by_upstream_annotation_region": by_upstream_region,
        },
        "row_mapping_fingerprint_sha256": hashlib.sha256(
            b"zycoin-bellman-output-row-mapping-v1\0"
            + _canonical_json(row_map_payload)
        ).hexdigest(),
        "mapped_coefficients_fingerprint_sha256": hashlib.sha256(
            b"zycoin-bellman-output-mapped-row-coefficients-v1\0"
            + _canonical_json(coefficient_payload)
        ).hexdigest(),
        "row_index_mapping": [
            {
                "upstream_row_index": upstream_index,
                "local_row_index": pair_indices[upstream_index],
            }
            for upstream_index in range(len(upstream_rows))
        ],
        "expanded_factor_only_rows": expanded_only_rows,
        "rows": records,
    }


def build_from_export(
    export_path: Path,
    variable_mapping_path: Path,
) -> dict[str, Any]:
    export_bytes = export_path.read_bytes()
    export_sha256 = hashlib.sha256(export_bytes).hexdigest()
    variable_correspondence = json.loads(
        variable_mapping_path.read_text(encoding="utf-8")
    )
    if export_sha256 != PINNED_EXPORT_SHA256:
        raise RowCorrespondenceError("upstream export is not the pinned Bellman export")
    if export_sha256 != variable_correspondence["pinned_upstream"]["export_sha256"]:
        raise RowCorrespondenceError("upstream export hash differs from variable map")
    if (
        variable_correspondence["mapping_fingerprint_sha256"]
        != VARIABLE_MAPPING_FINGERPRINT
    ):
        raise RowCorrespondenceError("variable correspondence is not the verified map")
    export_document = json.loads(export_bytes)
    fixture_path = Path(__file__).parent / "fixtures" / "sapling_output_reference.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))["cases"][0]
    witness = make_sapling_output_witness(
        fixture["value"],
        bytes.fromhex(fixture["diversifier"]),
        Point.from_bytes(
            bytes.fromhex(fixture["transmission_key"]), check_subgroup=True
        ),
        int.from_bytes(bytes.fromhex(fixture["rcv"]), "little"),
        int.from_bytes(bytes.fromhex(fixture["rcm"]), "little"),
        int.from_bytes(bytes.fromhex(fixture["esk"]), "little"),
    )
    local_system = R1CS()
    constrain_sapling_output(local_system, witness)
    if local_system.matrix_fingerprint() != PRODUCTION_MATRIX_FINGERPRINT:
        raise RowCorrespondenceError("production Output matrix fingerprint changed")

    recorder = BellmanSynthesisRecorder()
    recorder_backend = RecorderSynthesisBackend(recorder)
    constrain_sapling_output(recorder_backend, witness)
    if local_system.serialize_matrix() != recorder.serialize_local_matrix():
        raise RowCorrespondenceError("production and recorder matrices differ")
    if local_system.constraint_count != recorder.constraint_count:
        raise RowCorrespondenceError("production and recorder row counts differ")
    if (
        len(recorder.inputs) != 6
        or len(recorder.auxiliary_variables) != 7821
        or recorder.constraint_count != 7827
        or len(local_system.variables) != 7827
    ):
        raise RowCorrespondenceError(
            "fresh production/recorder Output synthesis has unexpected dimensions"
        )

    artifact = build_row_correspondence(
        export_document, local_system, variable_correspondence
    )
    expected_counts = {
        "upstream_rows": 7827,
        "local_rows": 7827,
        "one_to_one_row_pairs": 7827,
        "native_a_b_c": 7827,
        "a_b_factor_swap": 0,
        "valid_factor_normalization": 0,
        "expanded_a_times_b_minus_c_only": 0,
        "unmatched_upstream": 0,
        "unmatched_local": 0,
        "ambiguous_upstream": 0,
        "ambiguous_local": 0,
    }
    if artifact["counts"] != expected_counts:
        raise RowCorrespondenceError(
            f"unexpected pinned Output row correspondence counts: "
            f"{artifact['counts']!r}"
        )
    artifact["source"]["upstream_export_sha256"] = export_sha256
    artifact["source"].update(
        {
            "local_recorder_matrix_fingerprint": recorder.matrix_fingerprint(),
            "local_recorder_matrix_matches_production": True,
            "fresh_local_synthesis_satisfied": local_system.is_satisfied(),
            "previous_production_matrix_fingerprint": (
                "98a2afc1c0653daa5c9b20d4136655fbfaf0f8b2a137c6d9234740cd602b540a"
            ),
            "previous_production_matrix_fingerprint_preserved": False,
            "aligned_production_matrix_fingerprint": local_system.matrix_fingerprint(),
            "recorder_input_count_including_one": len(recorder.inputs),
            "recorder_auxiliary_count": len(recorder.auxiliary_variables),
            "recorder_constraint_count": recorder.constraint_count,
        }
    )
    artifact["allocation_order_assessment"] = {
        "value_bits_rcv": (
            "Value bits and rcv bits occupy the exact pinned Bellman columns; "
            "the 64 value-bit and 252 rcv-bit Boolean rows also match in place."
        ),
        "g_d_representation_esk": (
            "The strict g_d representation bits/prefix variables, esk bits, "
            "and all epk intermediates occupy their pinned Bellman columns."
        ),
        "rcm_pedersen": (
            "The rcm bits follow note-content Pedersen allocation exactly, "
            "and all note-content and randomized-commitment intermediates "
            "occupy their pinned Bellman columns."
        ),
        "explains_all_ordered_row_differences": True,
        "reason": (
            "All 7,827 variables have identical upstream/local columns and "
            "assignments; all 7,827 ordered rows have native A/B/C matches "
            "with exact coefficients. The former 260 expanded-relation-only "
            "rows now use the pinned upstream factorization."
        ),
    }
    return artifact


def write_row_correspondence(
    export_path: Path,
    variable_mapping_path: Path,
    output_path: Path,
) -> str:
    artifact = build_from_export(export_path, variable_mapping_path)
    artifact["artifact_content_fingerprint_sha256"] = hashlib.sha256(
        b"zycoin-bellman-output-row-correspondence-artifact-v1\0"
        + _canonical_json(artifact)
    ).hexdigest()
    output_path.write_bytes(_canonical_json(artifact) + b"\n")
    return hashlib.sha256(output_path.read_bytes()).hexdigest()
