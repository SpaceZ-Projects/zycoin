"""Reproduce the exact restricted Spend factor-map inverse certificate.

Run with retained exports:
python tests/sapling_spend_factor_span.py --local-matrix PATH --row-map PATH
  --factor-certificate reports/sapling-spend-expanded-row-factor-identities.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIELD = importlib.import_module("src.bls12_381").SCALAR_MODULUS
SIDES = ("a", "b", "c")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scalar(value: str) -> int:
    return int.from_bytes(bytes.fromhex(value), "little") % FIELD


def _add(
    columns: list[dict[int, int]], column: int, coordinate: int, value: int
) -> None:
    value %= FIELD
    if not value:
        return
    entries = columns[column]
    updated = (entries.get(coordinate, 0) + value) % FIELD
    if updated:
        entries[coordinate] = updated
    else:
        entries.pop(coordinate, None)


def _hash_columns(tag: str, columns: list[dict[int, int]]) -> str:
    digest = hashlib.sha256(f"{tag}-v1\0".encode("ascii"))
    for column, entries in enumerate(columns):
        for coordinate, value in sorted(entries.items()):
            digest.update(f"{column},{coordinate},{value % FIELD};".encode("ascii"))
        digest.update(b"|")
    return digest.hexdigest()


def _hash_pairs(tag: str, pairs: list[tuple[int, int]]) -> str:
    digest = hashlib.sha256(f"{tag}-v1\0".encode("ascii"))
    for left, right in pairs:
        digest.update(f"{left},{right};".encode("ascii"))
    return digest.hexdigest()


def _build_factor_columns(
    local: dict[str, Any],
    row_map: dict[str, Any],
    factor_certificate: dict[str, Any],
) -> tuple[list[dict[int, int]], list[dict[int, int]]]:
    rows = local["constraints"]
    row_count = len(rows)
    variable_count = len(local["variables"])
    local_columns = [{} for _ in range(variable_count)]
    transformed_columns = [{} for _ in range(variable_count)]

    for row_index, row in enumerate(rows):
        for side_index, side in enumerate(SIDES):
            coordinate = 3 * row_index + side_index
            for variable, coefficient in row[side]:
                _add(local_columns, int(variable), coordinate, int(coefficient))

    covered_rows: set[int] = set()

    def emit(
        upstream_row: int,
        output_side: int,
        local_row: int,
        local_side: int,
        scale: int,
    ) -> None:
        coordinate = 3 * upstream_row + output_side
        for variable, coefficient in rows[local_row][SIDES[local_side]]:
            _add(
                transformed_columns,
                int(variable),
                coordinate,
                scale * int(coefficient),
            )

    for pair in row_map["row_pairs"]:
        if pair["classification"] == "expanded_a_times_b_minus_c_only":
            continue
        mapping = pair["factor_mapping"]
        alpha = _scalar(mapping["local_factor_scale_for_upstream_A_hex"])
        beta = _scalar(mapping["local_factor_scale_for_upstream_B_hex"])
        gamma = _scalar(mapping["local_C_scale_hex"])
        upstream_row = pair["upstream_row_index"]
        local_row = pair["local_row_index"]
        if mapping["orientation"] == "same":
            factor_maps = [[(0, alpha)], [(1, beta)], [(2, gamma)]]
        else:
            factor_maps = [[(1, alpha)], [(0, beta)], [(2, gamma)]]
        for output_side, terms in enumerate(factor_maps):
            for local_side, scale in terms:
                emit(upstream_row, output_side, local_row, local_side, scale)
        if upstream_row in covered_rows:
            raise ValueError(f"duplicate upstream row mapping: {upstream_row}")
        covered_rows.add(upstream_row)

    for row in factor_certificate["rows"]:
        upstream_row = row["upstream_row_index"]
        local_row = row["local_row_index"]
        kind = row["kind"]
        if kind == "pkd_affine_swap":
            factor_maps = [[(1, 1)], [(0, 1)], [(2, 1), (0, 1)]]
        elif kind == "linear_constraint_c_to_a":
            factor_maps = [[], [], [(0, -1)]]
        elif kind == "unit_b_affine_shift":
            alpha = _scalar(row["derived_identity"]["scale_alpha_hex"])
            factor_maps = [[(0, alpha)], [(1, 1)], [(2, alpha)]]
        else:
            raise ValueError(f"unknown factor class: {kind}")
        for output_side, terms in enumerate(factor_maps):
            for local_side, scale in terms:
                emit(upstream_row, output_side, local_row, local_side, scale)
        if upstream_row in covered_rows:
            raise ValueError(f"duplicate upstream row mapping: {upstream_row}")
        covered_rows.add(upstream_row)

    helper_maps = (
        (76893, [[(76894, 0, 1), (32701, 0, -1)], [(76894, 1, 1)], []]),
        (76894, [[], [], [(32701, 0, 1)]]),
    )
    for upstream_row, factor_maps in helper_maps:
        for output_side, terms in enumerate(factor_maps):
            for local_row, local_side, scale in terms:
                emit(
                    upstream_row,
                    output_side,
                    local_row,
                    local_side,
                    scale,
                )
        if upstream_row in covered_rows:
            raise ValueError(f"duplicate helper row mapping: {upstream_row}")
        covered_rows.add(upstream_row)

    if covered_rows != set(range(row_count)):
        raise ValueError("factor map does not cover every upstream row exactly once")
    return local_columns, transformed_columns


def _pivot_certificate(
    columns: list[dict[int, int]],
) -> tuple[list[int], list[int]]:
    pivots: list[int] = []
    values: list[int] = []
    for entries in columns:
        if not entries:
            raise ValueError("coefficient-family column is zero")
        pivot = min(entries)
        pivots.append(pivot)
        values.append(entries[pivot] % FIELD)
    if len(set(pivots)) != len(columns):
        raise ValueError("first-nonzero coordinates are not unique")
    return pivots, values


def _eliminate_columns(
    columns: list[dict[int, int]],
) -> tuple[
    list[int],
    list[dict[int, int]],
    list[dict[int, int]],
    int,
    tuple[int, int, int, int, int, int] | None,
]:
    basis: dict[int, dict[int, int]] = {}
    basis_coordinates: dict[int, dict[int, int]] = {}
    basis_owner: dict[int, int] = {}
    pivot_for_column: list[int | None] = [None] * len(columns)
    reductions = 0
    first_reduction = None

    for column_index, original in enumerate(columns):
        residual = original.copy()
        coordinates = {column_index: 1}
        while residual:
            pivot = min(residual)
            pivot_vector = basis.get(pivot)
            if pivot_vector is None:
                basis[pivot] = residual
                basis_coordinates[pivot] = coordinates
                basis_owner[pivot] = column_index
                pivot_for_column[column_index] = pivot
                break

            scale = (
                residual[pivot]
                * pow(pivot_vector[pivot], FIELD - 2, FIELD)
                % FIELD
            )
            reductions += 1
            if first_reduction is None:
                first_reduction = (
                    column_index,
                    pivot,
                    basis_owner[pivot],
                    scale,
                    len(residual),
                    len(pivot_vector),
                )
            for coordinate, coefficient in pivot_vector.items():
                updated = (
                    residual.get(coordinate, 0) - scale * coefficient
                ) % FIELD
                if updated:
                    residual[coordinate] = updated
                else:
                    residual.pop(coordinate, None)
            for source_column, coefficient in basis_coordinates[pivot].items():
                updated = (
                    coordinates.get(source_column, 0) - scale * coefficient
                ) % FIELD
                if updated:
                    coordinates[source_column] = updated
                else:
                    coordinates.pop(source_column, None)

        if not residual:
            raise ValueError(f"coefficient columns are dependent at {column_index}")

    if any(pivot is None for pivot in pivot_for_column):
        raise ValueError("incomplete column pivot map")
    return (
        [int(pivot) for pivot in pivot_for_column],
        [basis[int(pivot)] for pivot in pivot_for_column],
        [basis_coordinates[int(pivot)] for pivot in pivot_for_column],
        reductions,
        first_reduction,
    )


def derive_certificate(
    local: dict[str, Any],
    row_map: dict[str, Any],
    factor_certificate: dict[str, Any],
) -> dict[str, Any]:
    local_columns, transformed_columns = _build_factor_columns(
        local, row_map, factor_certificate
    )
    local_pivots, local_values = _pivot_certificate(local_columns)
    pivot_columns, transformed_basis, operations, reductions, first_reduction = (
        _eliminate_columns(transformed_columns)
    )

    variable_count = len(local_columns)
    if len(pivot_columns) != variable_count:
        raise ValueError("transformed coefficient family is rank deficient")
    column_order = sorted(
        range(variable_count), key=pivot_columns.__getitem__
    )
    sorted_pivots = [pivot_columns[column] for column in column_order]
    pivot_row = {coordinate: index for index, coordinate in enumerate(sorted_pivots)}
    triangular = [{} for _ in range(variable_count)]
    for column_position, original_column in enumerate(column_order):
        vector = transformed_basis[original_column]
        for coordinate, value in vector.items():
            row_position = pivot_row.get(coordinate)
            if row_position is not None:
                if row_position < column_position:
                    raise ValueError("selected pivot minor is not triangular")
                triangular[column_position][row_position] = value % FIELD
        if triangular[column_position].get(column_position, 0) == 0:
            raise ValueError("selected pivot minor has a zero diagonal")

    # Verify P (R Q_L) U Pi = T directly for every coefficient-family vector.
    for column_position, original_column in enumerate(column_order):
        product: dict[int, int] = {}
        for source_column, scale in operations[original_column].items():
            for coordinate, value in transformed_columns[source_column].items():
                row_position = pivot_row.get(coordinate)
                if row_position is not None:
                    updated = (
                        product.get(row_position, 0) + scale * value
                    ) % FIELD
                    if updated:
                        product[row_position] = updated
                    else:
                        product.pop(row_position, None)
        if product != triangular[column_position]:
            raise ValueError(
                f"triangular inverse certificate mismatch at column {original_column}"
            )

    for column_index, operation in enumerate(operations):
        if operation.get(column_index) != 1 or any(
            row >= column_index for row in operation if row != column_index
        ):
            raise ValueError("column operation is not unit upper triangular")
    expected_operations = [{column: 1} for column in range(variable_count)]
    expected_operations[32621] = {32621: 1, 5: FIELD - 1}
    if operations != expected_operations:
        raise ValueError("unexpected sparse column-operation matrix")

    local_rank = len(local_pivots)
    transformed_rank = len(pivot_columns)
    intersection_dimension = local_rank - transformed_rank
    if intersection_dimension < 0:
        raise ValueError("transformed rank exceeds local family rank")

    local_hash = _hash_columns("QL", local_columns)
    transformed_hash = _hash_columns("RQL", transformed_columns)
    operation_hash = _hash_columns("U-column-operations", operations)
    triangular_hash = _hash_columns("T-lower-triangular", triangular)
    pivot_rows_hash = _hash_pairs(
        "pivot-row-order",
        list(enumerate(sorted_pivots)),
    )
    column_permutation_hash = _hash_pairs(
        "pivot-column-order",
        [
            (position, column)
            for position, column in enumerate(column_order)
        ],
    )
    left_inverse_hash = hashlib.sha256(
        (
            "sapling-spend-restricted-left-inverse-v1|"
            + local_hash
            + "|"
            + operation_hash
            + "|"
            + triangular_hash
            + "|"
            + pivot_rows_hash
            + "|"
            + column_permutation_hash
        ).encode("ascii")
    ).hexdigest()
    empty_intersection_hash = hashlib.sha256(
        json.dumps(
            {"field_modulus": str(FIELD), "basis": []},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    ql_pivot_hash = hashlib.sha256(
        (
            "QL-pivots-v1\0"
            + "".join(
                f"{index},{pivot},{value};"
                for index, (pivot, value) in enumerate(
                    zip(local_pivots, local_values, strict=True)
                )
            )
        ).encode("ascii")
    ).hexdigest()
    transformed_pivot_hash = hashlib.sha256(
        (
            "B-pivots-v1\0"
            + "".join(
                f"{index},{pivot},{transformed_basis[index][pivot] % FIELD};"
                for index, pivot in enumerate(pivot_columns)
            )
        ).encode("ascii")
    ).hexdigest()

    determinant_local = 1
    for value in local_values:
        determinant_local = determinant_local * value % FIELD
    determinant_triangular = 1
    for index in range(variable_count):
        determinant_triangular = (
            determinant_triangular
            * triangular[index][index]
            % FIELD
        )

    return {
        "field_modulus": str(FIELD),
        "local_factor_family": {
            "shape": [3 * len(local["constraints"]), variable_count],
            "nnz": sum(map(len, local_columns)),
            "rank": local_rank,
            "pivot_basis_sha256": ql_pivot_hash,
            "sparse_matrix_sha256": local_hash,
            "first_pivot_minor_determinant": str(determinant_local),
        },
        "transformed_factor_family_RQL": {
            "shape": [3 * len(local["constraints"]), variable_count],
            "nnz": sum(map(len, transformed_columns)),
            "rank": transformed_rank,
            "column_reductions": reductions,
            "first_reduction": first_reduction,
            "pivot_basis_sha256": transformed_pivot_hash,
            "sparse_matrix_sha256": transformed_hash,
        },
        "intersection": {
            "dimension": intersection_dimension,
            "basis_sha256": empty_intersection_hash,
        },
        "restricted_left_inverse": {
            "equation": "K = Q_L U Pi T^-1 P",
            "dimensions": [3 * len(local["constraints"])] * 2,
            "representation": {
                "Q_L_nnz": sum(map(len, local_columns)),
                "U_nnz": sum(map(len, operations)),
                "U_form": "I - E_(5,32621); U^-1=I+E_(5,32621)",
                "Pi": "columns reordered by ascending pivot factor-coordinate",
                "T_shape": [variable_count, variable_count],
                "T_nnz": sum(map(len, triangular)),
                "T_triangular": "lower",
                "T_determinant": str(determinant_triangular),
                "P": "select the sorted 98,646 pivot factor coordinates",
            },
            "component_sha256": {
                "Q_L": local_hash,
                "U": operation_hash,
                "T": triangular_hash,
                "pivot_rows": pivot_rows_hash,
                "column_permutation": column_permutation_hash,
            },
            "factorized_operator_sha256": left_inverse_hash,
            "direct_verification": {
                "P_RQL_U_Pi_equals_T_all_columns": True,
                "T_lower_triangular_nonzero_diagonal": True,
                "coefficient_family_vectors_verified": variable_count,
                "identity": "K R Q_L = Q_L",
            },
            "affine_application": {
                "identity": "K (Q_U - S) = Q_L M",
                "subtract_S_before_inverse": True,
                "helper_offsets": "Subtract public-anchor and ONE helper shifts before applying K; they are outside im(R) modulo the helper block.",
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local-matrix", type=Path, required=True)
    parser.add_argument("--row-map", type=Path, required=True)
    parser.add_argument("--factor-certificate", type=Path, required=True)
    args = parser.parse_args()
    local = _read_json(args.local_matrix)
    row_map = _read_json(args.row_map)
    factor_certificate = _read_json(args.factor_certificate)
    unsigned_certificate = {
        key: value
        for key, value in factor_certificate.items()
        if key != "certificate_sha256"
    }
    canonical_certificate = json.dumps(
        unsigned_certificate,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    if hashlib.sha256(canonical_certificate).hexdigest() != factor_certificate.get(
        "certificate_sha256"
    ):
        raise ValueError("factor certificate digest mismatch")
    result = derive_certificate(
        local,
        row_map,
        factor_certificate,
    )
    result["source_artifacts"] = {
        "local_matrix_file_sha256": _sha256_file(args.local_matrix),
        "local_matrix_fingerprint": local.get("matrix_fingerprint"),
        "row_map_file_sha256": _sha256_file(args.row_map),
        "row_mapping_fingerprint": row_map.get(
            "row_mapping_fingerprint_sha256"
        ),
        "factor_certificate_file_sha256": _sha256_file(
            args.factor_certificate
        ),
        "factor_certificate_sha256": factor_certificate.get(
            "certificate_sha256"
        ),
    }
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
