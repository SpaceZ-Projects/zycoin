"""Test-only sparse Groth16 query-index mapping for exact Output evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence


class QueryMappingError(ValueError):
    """Raised when source evidence cannot establish a unique query mapping."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _variable_order(identity: str) -> tuple[int, int]:
    if identity.startswith("Input(") and identity.endswith(")"):
        try:
            index = int(identity[6:-1])
        except ValueError as error:
            raise QueryMappingError(f"invalid input identity {identity!r}") from error
        if index < 0:
            raise QueryMappingError(f"invalid input identity {identity!r}")
        return (0, index)
    if identity.startswith("Aux(") and identity.endswith(")"):
        try:
            index = int(identity[4:-1])
        except ValueError as error:
            raise QueryMappingError(f"invalid auxiliary identity {identity!r}") from error
        if index < 0:
            raise QueryMappingError(f"invalid auxiliary identity {identity!r}")
        return (1, index)
    raise QueryMappingError(f"unknown Bellman variable identity {identity!r}")


def _mapping_for_support(
    support: set[str],
    correspondence: Mapping[str, int],
    expected_count: int,
    section: str,
) -> list[dict[str, int | str]]:
    if len(support) != expected_count:
        raise QueryMappingError(
            f"{section} structural support has {len(support)} variables, "
            f"but the serialized query has {expected_count} points"
        )
    ordered = sorted(support, key=_variable_order)
    result: list[dict[str, int | str]] = []
    for query_index, identity in enumerate(ordered):
        if identity not in correspondence:
            raise QueryMappingError(
                f"{section} variable {identity} has no unique local correspondence"
            )
        result.append(
            {
                "query_index": query_index,
                "upstream_identity": identity,
                "local_column": correspondence[identity],
            }
        )
    return result


def _spend_mapping_for_support(
    support: set[str],
    correspondence: Mapping[str, int],
    expected_count: int,
    section: str,
) -> dict[str, list[int | str | None]]:
    if len(support) != expected_count:
        raise QueryMappingError(
            f"{section} structural support has {len(support)} variables, "
            f"but the serialized query has {expected_count} points"
        )
    ordered = sorted(support, key=_variable_order)
    identities: list[str] = []
    local_columns: list[int | None] = []
    for identity in ordered:
        identities.append(identity)
        local_columns.append(correspondence.get(identity))
    return {
        "upstream_variable_identities": identities,
        "local_columns": local_columns,
    }


def build_spend_query_index_mapping(
    reference: Mapping[str, object],
    variable_artifact: Mapping[str, object],
    observed_query_counts: Mapping[str, int],
    upstream_reference_sha256: str,
) -> dict[str, object]:
    """Map authentic compact Spend query indices using exported row support.

    The pinned Bellman export contains every upstream variable identity and
    ordered R1CS row. Bellman's setup preserves variable order while omitting
    identity A/B query points, so exact agreement between nonzero structural
    support and authentic section counts establishes compact query indices.
    """
    if (
        reference.get("format") != "bellman-sapling-spend-reference-v1"
        or reference.get("num_inputs_including_one") != 8
        or reference.get("num_auxiliary_variables") != 98638
        or reference.get("num_constraints") != 98777
        or reference.get("satisfied") is not True
    ):
        raise QueryMappingError("pinned Spend reference metadata is incomplete")
    inputs = reference.get("inputs")
    auxiliaries = reference.get("auxiliary_variables")
    rows = reference.get("constraints")
    pairs = variable_artifact.get("matched_public_variables")
    auxiliary_pairs = variable_artifact.get("matched_auxiliary_variables")
    unresolved = variable_artifact.get("unresolved_upstream_auxiliary")
    if (
        not isinstance(inputs, Sequence)
        or len(inputs) != 8
        or not isinstance(auxiliaries, Sequence)
        or len(auxiliaries) != 98638
        or not isinstance(rows, Sequence)
        or len(rows) != 98777
        or not isinstance(pairs, Sequence)
        or not isinstance(auxiliary_pairs, Sequence)
        or not isinstance(unresolved, Sequence)
    ):
        raise QueryMappingError("Spend source artifacts are malformed or incomplete")

    if len(upstream_reference_sha256) != 64:
        raise QueryMappingError("pinned Spend reference SHA-256 is invalid")
    try:
        bytes.fromhex(upstream_reference_sha256)
    except ValueError as error:
        raise QueryMappingError("pinned Spend reference SHA-256 is invalid") from error

    reference_assignments: dict[str, int] = {}
    for namespace, records in (("Input", inputs), ("Aux", auxiliaries)):
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                raise QueryMappingError("Spend reference variable is malformed")
            identity = record.get("identity")
            assignment_hex = record.get("assignment_hex")
            if (
                identity != f"{namespace}({index})"
                or not isinstance(assignment_hex, str)
            ):
                raise QueryMappingError("Spend reference variable order is invalid")
            try:
                assignment = int.from_bytes(bytes.fromhex(assignment_hex), "little")
            except ValueError as error:
                raise QueryMappingError(
                    "Spend reference assignment is malformed"
                ) from error
            reference_assignments[identity] = assignment

    correspondence: dict[str, int] = {}
    local_columns: set[int] = set()
    for pair in pairs:
        if not isinstance(pair, Mapping):
            raise QueryMappingError("Spend public variable mapping is malformed")
        identity = pair.get("upstream_identity")
        local_index = pair.get("local_index")
        if (
            not isinstance(identity, str)
            or type(local_index) is not int
            or not 0 <= local_index < 8
            or identity != f"Input({local_index})"
            or identity in correspondence
            or local_index in local_columns
        ):
            raise QueryMappingError("Spend public variable mapping is ambiguous")
        _validate_spend_assignment(pair, identity, reference_assignments)
        correspondence[identity] = local_index
        local_columns.add(local_index)
    if len(correspondence) != 8:
        raise QueryMappingError("Spend public variable mapping is incomplete")

    for pair in auxiliary_pairs:
        if not isinstance(pair, Mapping):
            raise QueryMappingError("Spend auxiliary variable mapping is malformed")
        identity = pair.get("upstream_identity")
        local_index = pair.get("local_index")
        if (
            not isinstance(identity, str)
            or type(local_index) is not int
            or not 8 <= local_index < 98646
            or identity in correspondence
            or local_index in local_columns
        ):
            raise QueryMappingError("Spend auxiliary variable mapping is ambiguous")
        _validate_spend_assignment(pair, identity, reference_assignments)
        correspondence[identity] = local_index
        local_columns.add(local_index)
    unresolved_identities: set[str] = set()
    for pair in unresolved:
        if not isinstance(pair, Mapping):
            raise QueryMappingError("unresolved Spend variable record is malformed")
        identity = pair.get("variable_identity")
        if (
            not isinstance(identity, str)
            or identity not in reference_assignments
            or identity in correspondence
        ):
            raise QueryMappingError("unresolved Spend variable mapping is ambiguous")
        unresolved_identities.add(identity)
    if len(correspondence) != 98645 or len(unresolved_identities) != 1:
        raise QueryMappingError("Spend variable correspondence coverage changed")

    support = {"a": set(), "b_g1": set()}
    for row in rows:
        if not isinstance(row, Mapping):
            raise QueryMappingError("Spend constraint row is malformed")
        for side, row_key in (("a", "a"), ("b_g1", "b")):
            terms = row.get(row_key)
            if not isinstance(terms, Sequence):
                raise QueryMappingError(f"Spend row is missing factor {side.upper()}")
            for term in terms:
                if not isinstance(term, Mapping):
                    raise QueryMappingError("Spend linear-combination term is malformed")
                identity = term.get("identity")
                coefficient = term.get("coefficient_hex")
                if not isinstance(identity, str) or not isinstance(coefficient, str):
                    raise QueryMappingError("Spend linear-combination term is incomplete")
                try:
                    coefficient_value = int.from_bytes(
                        bytes.fromhex(coefficient), "little"
                    )
                    _variable_order(identity)
                except (ValueError, QueryMappingError) as error:
                    raise QueryMappingError(
                        "Spend linear-combination term is invalid"
                    ) from error
                if coefficient_value:
                    support[side].add(identity)

    # Bellman's setup adds x*0=0 for each input, including ONE.
    support["a"].update(f"Input({index})" for index in range(8))
    for identities in support.values():
        if not identities.issubset(reference_assignments):
            raise QueryMappingError(
                "Spend row support references an unallocated variable"
            )
    counts: dict[str, int] = {}
    for section in ("a", "b_g1", "b_g2"):
        count = observed_query_counts.get(section)
        if type(count) is not int:
            raise QueryMappingError(f"observed {section} query count is missing")
        counts[section] = count
    a_mapping = _spend_mapping_for_support(
        support["a"], correspondence, counts["a"], "Spend A"
    )
    b_mapping = _spend_mapping_for_support(
        support["b_g1"], correspondence, counts["b_g1"], "Spend B_G1"
    )
    a_unmapped = {
        identity
        for identity in a_mapping["upstream_variable_identities"]
        if identity not in correspondence
    }
    b_unmapped = {
        identity
        for identity in b_mapping["upstream_variable_identities"]
        if identity not in correspondence
    }
    if a_unmapped != support["a"].intersection(unresolved_identities):
        raise QueryMappingError("Spend A unresolved identities are not explained")
    if b_unmapped or not unresolved_identities.issubset(support["a"]):
        raise QueryMappingError("Spend unresolved query mapping is inconsistent")
    if counts["b_g1"] != counts["b_g2"]:
        raise QueryMappingError("Spend B_G1 and B_G2 sparse counts differ")

    l_identities = [f"Aux({index})" for index in range(98638)]
    l_columns = [
        correspondence.get(identity) for identity in l_identities
    ]
    l_unmapped = {
        identity
        for identity, column in zip(l_identities, l_columns)
        if column is None
    }
    if l_unmapped != unresolved_identities:
        raise QueryMappingError("Spend L unresolved identities are not explained")
    payload: dict[str, object] = {
        "format": "zycoin-sapling-spend-query-index-mapping-v1",
        "upstream_reference_sha256": upstream_reference_sha256,
        "upstream_variable_mapping_fingerprint": variable_artifact.get(
            "mapping_fingerprint_sha256"
        ),
        "query_sections": {
            "ic": {
                "upstream_variable_identities": [
                    f"Input({index})" for index in range(8)
                ],
                "local_columns": list(range(8)),
            },
            "l": {
                "upstream_variable_identities": l_identities,
                "local_columns": l_columns,
            },
            "a": a_mapping,
            "b_g1": b_mapping,
            "b_g2": b_mapping,
            "h": {
                "query_index_start": 0,
                "query_index_end_exclusive": 131071,
                "semantic_role": "QAP quotient coefficient degree",
                "constraint_row_mapping": None,
            },
        },
        "counts": {
            "input_variables_including_one": 8,
            "auxiliary_variables": 98638,
            "a_query_points": counts["a"],
            "b_g1_query_points": counts["b_g1"],
            "b_g2_query_points": counts["b_g2"],
            "h_query_points": 131071,
            "l_query_points": 98638,
            "unresolved_local_columns": 1,
        },
        "mapping_basis": (
            "Pinned Bellman Spend R1CS structural supports, Bellman input-then-"
            "auxiliary query order, exact serialized sparse query counts, and "
            "the existing v7 semantic variable correspondence. The unresolved "
            "conditional-anchor auxiliary is retained as an upstream identity "
            "with no fabricated local column."
        ),
    }
    fingerprint_payload = dict(payload)
    payload["mapping_fingerprint_sha256"] = hashlib.sha256(
        b"zycoin-sapling-spend-query-index-mapping-v1\0"
        + _canonical_json(fingerprint_payload)
    ).hexdigest()
    return payload


def _validate_spend_assignment(
    pair: Mapping[str, object],
    upstream_identity: str,
    reference_assignments: Mapping[str, int],
) -> None:
    _variable_order(upstream_identity)
    if (
        upstream_identity not in reference_assignments
        or reference_assignments[upstream_identity] < 0
        or not isinstance(pair.get("upstream_assignment"), str)
        or not isinstance(pair.get("local_assignment"), str)
    ):
        raise QueryMappingError("Spend assignment evidence is incomplete")
    try:
        upstream_assignment = int(pair["upstream_assignment"])
        local_assignment = int(pair["local_assignment"])
    except ValueError as error:
        raise QueryMappingError("Spend assignment evidence is malformed") from error
    if (
        upstream_assignment != reference_assignments[upstream_identity]
        or local_assignment != upstream_assignment
    ):
        raise QueryMappingError(
            f"Spend assignment consistency check failed for {upstream_identity}"
        )


def build_output_query_index_mapping(
    row_artifact: Mapping[str, object],
    variable_artifact: Mapping[str, object],
    observed_query_counts: Mapping[str, int],
) -> dict[str, object]:
    """Map compact Output A/B query points using exact pinned row evidence.

    Bellman filters identity query points without serializing their variable
    indices. For this exact Output matrix, structural support is therefore
    compared with the authentic compact point count before assigning point
    indices in Bellman's preserved input-then-auxiliary order.
    """
    counts = row_artifact.get("counts")
    rows = row_artifact.get("rows")
    pairs = variable_artifact.get("pairs")
    if not isinstance(counts, Mapping) or not isinstance(rows, Sequence):
        raise QueryMappingError("row correspondence artifact is malformed")
    if not isinstance(pairs, Sequence):
        raise QueryMappingError("variable correspondence artifact is malformed")
    if (
        counts.get("upstream_rows") != 7827
        or counts.get("local_rows") != 7827
        or counts.get("native_a_b_c") != 7827
        or len(rows) != 7827
    ):
        raise QueryMappingError("Output ordered row correspondence is incomplete")

    correspondence: dict[str, int] = {}
    for pair in pairs:
        if not isinstance(pair, Mapping):
            raise QueryMappingError("variable correspondence pair is malformed")
        identity = pair.get("upstream_identity")
        column = pair.get("local_column")
        if (
            not isinstance(identity, str)
            or type(column) is not int
            or identity in correspondence
        ):
            raise QueryMappingError("variable correspondence is ambiguous")
        correspondence[identity] = column
    if len(correspondence) != 7827:
        raise QueryMappingError("Output variable correspondence is incomplete")

    support = {"a": set(), "b": set()}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(
            row.get("upstream_abc"), Mapping
        ):
            raise QueryMappingError("row has no canonical upstream A/B/C factors")
        factors = row["upstream_abc"]
        for side in ("a", "b"):
            factor = factors.get(side)
            if not isinstance(factor, Mapping):
                raise QueryMappingError(f"row is missing factor {side.upper()}")
            terms = factor.get("canonical_terms")
            if not isinstance(terms, Sequence):
                raise QueryMappingError(f"factor {side.upper()} terms are malformed")
            for term in terms:
                if not isinstance(term, Mapping):
                    raise QueryMappingError("linear-combination term is malformed")
                identity = term.get("identity")
                coefficient = term.get("coefficient_hex")
                if not isinstance(identity, str) or not isinstance(coefficient, str):
                    raise QueryMappingError("linear-combination term is incomplete")
                try:
                    coefficient_value = int.from_bytes(bytes.fromhex(coefficient), "little")
                except ValueError as error:
                    raise QueryMappingError("linear-combination coefficient is invalid") from error
                if coefficient_value:
                    support[side].add(identity)

    # Bellman's setup adds x*0=0 rows for every input, including ONE.
    support["a"].update(f"Input({index})" for index in range(6))

    a_count = observed_query_counts.get("a")
    b_count = observed_query_counts.get("b_g1")
    b_g2_count = observed_query_counts.get("b_g2")
    if type(a_count) is not int or type(b_count) is not int or type(b_g2_count) is not int:
        raise QueryMappingError("observed A/B query counts are missing")
    if b_count != b_g2_count:
        raise QueryMappingError("observed B_G1 and B_G2 query counts differ")
    a_mapping = _mapping_for_support(support["a"], correspondence, a_count, "A")
    b_mapping = _mapping_for_support(support["b"], correspondence, b_count, "B_G1")

    payload: dict[str, object] = {
        "format": "zycoin-sapling-output-query-index-mapping-v1",
        "upstream_matrix_fingerprint": "c26d5cdfe6ccd65c03390902c02e11393ea6bb96aae32a7f2ecb12eb9103faee",
        "upstream_variable_mapping_fingerprint": variable_artifact.get(
            "mapping_fingerprint_sha256"
        ),
        "upstream_row_mapping_fingerprint": row_artifact.get(
            "mapped_coefficients_fingerprint_sha256"
        ),
        "a_query": a_mapping,
        "b_g1_query": b_mapping,
        "b_g2_query": [dict(entry) for entry in b_mapping],
        "ic_query": [
            {
                "query_index": index,
                "upstream_identity": f"Input({index})",
                "local_column": index,
            }
            for index in range(6)
        ],
        "l_query": {
            "query_index_start": 0,
            "query_index_end_exclusive": 7821,
            "upstream_identity": "Aux(query_index)",
            "local_column": "6 + query_index",
        },
        "h_query": {
            "query_index_start": 0,
            "query_index_end_exclusive": 8191,
            "semantic_role": "QAP quotient coefficient degree",
            "constraint_row_mapping": None,
        },
        "mapping_basis": (
            "Exact ordered Output A/B/C factors and complete semantic variable "
            "correspondence; the compact A/B counts equal structural support, "
            "and Bellman preserves variable order while filtering identity points."
        ),
    }
    fingerprint_payload = {
        key: value
        for key, value in payload.items()
        if key != "mapping_fingerprint_sha256"
    }
    payload["mapping_fingerprint_sha256"] = hashlib.sha256(
        b"zycoin-sapling-output-query-index-mapping-v1\0"
        + _canonical_json(fingerprint_payload)
    ).hexdigest()
    return payload
