"""Verify and benchmark Output MSMs with the externally supplied official key.

Run as:
    python tests/benchmark_sapling_output_authentic_msm.py <sapling-output.params>

The script loads no Spend parameters and creates no proof. It streams the
official Output file through ZyCoin's production parser, then retains only
the decoded Output query vectors for the requested accumulations.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import sys
import time
from collections.abc import Callable, Sequence
from ctypes import wintypes
from pathlib import Path
from typing import TypeVar

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.bls12_381 import (
    FIELD_MODULUS,
    G1_INFINITY,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    encode_g1_uncompressed,
    encode_g2_uncompressed,
    multi_scalar_multiply_g1,
    multi_scalar_multiply_g2,
)
from src.groth16_parameters import read_parameter_stream
from src.groth16_queries import (
    G1Query,
    G2Query,
    QueryError,
    QueryScalarAssignment,
    ValidatedG1Point,
    ValidatedG2Point,
    msm_g1,
    msm_g2,
)
from tests.benchmark_sapling_output_proving import (
    ASSIGNMENT_SHA256,
    MAPPING_FINGERPRINT,
    MATRIX_FINGERPRINT,
    QUERY_COUNTS,
    _witness_and_qap,
)

PARAMETER_SHA256 = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
MAPPING_FILE_SHA256 = "c447b68e9ec795304a3cd067eb25c2891cfa25490aed16f50e4de1973b0b0199"
PARAMETER_BLAKE2B512 = (
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b"
    "f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
)
BOUNDARY_SIZES = (31, 32, 33, 127, 128, 129, 511, 512, 513)
T = TypeVar("T")
PointT = TypeVar("PointT", G1Point, G2Point)


def _process_memory() -> tuple[int | None, int | None]:
    if sys.platform != "win32":
        return None, None

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemoryCounters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    if not psapi.GetProcessMemoryInfo(
        kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
    ):
        return None, None
    return counters.WorkingSetSize, counters.PeakWorkingSetSize


def _measure(function: Callable[[], T]) -> tuple[T, float]:
    started = time.perf_counter()
    result = function()
    return result, time.perf_counter() - started


def _file_digests(path: Path) -> tuple[str, str]:
    sha256 = hashlib.sha256()
    blake2b = hashlib.blake2b(digest_size=64)
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            sha256.update(chunk)
            blake2b.update(chunk)
    return sha256.hexdigest(), blake2b.hexdigest()


def _read_reference_export(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"ZYMSM001"):
        raise RuntimeError("unexpected Bellman MSM reference export header")
    offset = 8
    expected_names = ("ic", "h", "l", "a", "b_g1", "b_g2")
    point_width = {"b_g2": 192}
    results: dict[str, bytes] = {}
    for expected_name in expected_names:
        if offset >= len(data):
            raise RuntimeError("truncated Bellman MSM reference export")
        name_length = data[offset]
        offset += 1
        name = data[offset : offset + name_length].decode("ascii")
        offset += name_length
        if name != expected_name or offset + 4 > len(data):
            raise RuntimeError("unexpected Bellman MSM reference section ordering")
        count = int.from_bytes(data[offset : offset + 4], "big")
        offset += 4
        if count != 1:
            raise RuntimeError(f"Bellman reference {name} must contain one result")
        width = point_width.get(name, 96)
        if offset + width > len(data):
            raise RuntimeError(f"truncated Bellman {name} result encoding")
        results[name] = data[offset : offset + width]
        offset += width
    if offset != len(data):
        raise RuntimeError("unexpected trailing data in Bellman MSM reference export")
    return results


def _reference_multiply_g1(point: G1Point, scalar: int) -> G1Point:
    if scalar < 0:
        return _reference_multiply_g1(
            G1Point(point.x, (-point.y) % FIELD_MODULUS),
            -scalar,
        )
    result = G1_INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = add_g1(result, addend)
        addend = add_g1(addend, addend)
        scalar >>= 1
    return result


def _reference_multiply_g2(point: G2Point, scalar: int) -> G2Point:
    if scalar < 0:
        return _reference_multiply_g2(G2Point(point.x, -point.y), -scalar)
    result = G2_INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = add_g2(result, addend)
        addend = add_g2(addend, addend)
        scalar >>= 1
    return result


def _affine_msm_g1(points: Sequence[G1Point], scalars: Sequence[int]) -> G1Point:
    result = G1_INFINITY
    for point, scalar in zip(points, scalars, strict=True):
        result = add_g1(result, _reference_multiply_g1(point, scalar))
    return result


def _affine_msm_g2(points: Sequence[G2Point], scalars: Sequence[int]) -> G2Point:
    result = G2_INFINITY
    for point, scalar in zip(points, scalars, strict=True):
        result = add_g2(result, _reference_multiply_g2(point, scalar))
    return result


def _mapped_dense_query(
    compact_points: Sequence[PointT],
    mappings: Sequence[dict[str, object]],
    variable_count: int,
    identity: PointT,
) -> tuple[PointT, ...]:
    if len(compact_points) != len(mappings):
        raise RuntimeError("compact query point count does not match sparse map")
    dense = [identity] * variable_count
    seen_query_indices: set[int] = set()
    seen_columns: set[int] = set()
    for entry in mappings:
        query_index = entry["query_index"]
        local_column = entry["local_column"]
        if type(query_index) is not int or type(local_column) is not int:
            raise RuntimeError("sparse query mapping indices must be integers")
        if not 0 <= query_index < len(compact_points):
            raise RuntimeError("sparse query index is out of range")
        if not 0 <= local_column < variable_count:
            raise RuntimeError("sparse query column is out of range")
        if query_index in seen_query_indices or local_column in seen_columns:
            raise RuntimeError("sparse query mapping contains a duplicate index")
        seen_query_indices.add(query_index)
        seen_columns.add(local_column)
        dense[local_column] = compact_points[query_index]
    if seen_query_indices != set(range(len(compact_points))):
        raise RuntimeError("sparse query map does not cover every compact point")
    return tuple(dense)


def _affine_subset_checks(
    g1_queries: dict[str, G1Query],
    g2_queries: dict[str, G2Query],
    scalars: dict[str, Sequence[int]],
) -> dict[str, object]:
    outcomes: dict[str, object] = {}
    for name in ("A_G1", "B_G1", "H_G1", "L_G1"):
        query = g1_queries[name]
        # Compare both beginning and end ranges so ordering and boundary
        # indices are exercised without the impractical full affine runtime.
        index_groups = (
            tuple(range(min(12, len(query.points)))),
            tuple(range(max(0, len(query.points) - 12), len(query.points))),
        )
        comparisons = []
        for indices in index_groups:
            selected_scalars = tuple(scalars[name][index] for index in indices)
            selected_points = tuple(query.points[index].point for index in indices)
            optimized, optimized_seconds = _measure(
                lambda indices=indices, query=query, selected_scalars=selected_scalars: msm_g1(
                    G1Query(tuple(query.points[index] for index in indices)),
                    selected_scalars,
                )
            )
            affine, affine_seconds = _measure(
                lambda selected_points=selected_points, selected_scalars=selected_scalars: _affine_msm_g1(
                    selected_points, selected_scalars
                )
            )
            if optimized != affine:
                raise RuntimeError(f"{name} affine reference comparison failed")
            comparisons.append(
                {
                    "indices": [indices[0], indices[-1] + 1] if indices else [],
                    "terms": len(indices),
                    "exact_match": True,
                    "optimized_seconds": optimized_seconds,
                    "affine_reference_seconds": affine_seconds,
                }
            )
        outcomes[name] = comparisons

    query = g2_queries["B_G2"]
    indices = tuple(range(min(12, len(query.points))))
    selected_points = tuple(query.points[index].point for index in indices)
    selected_scalars = tuple(scalars["B_G2"][index] for index in indices)
    optimized, optimized_seconds = _measure(
        lambda: msm_g2(
            G2Query(tuple(query.points[index] for index in indices)),
            selected_scalars,
        )
    )
    affine, affine_seconds = _measure(
        lambda: _affine_msm_g2(selected_points, selected_scalars)
    )
    if optimized != affine:
        raise RuntimeError("B_G2 affine reference comparison failed")
    outcomes["B_G2"] = [
        {
            "indices": [0, len(indices)],
            "terms": len(indices),
            "exact_match": True,
            "optimized_seconds": optimized_seconds,
            "affine_reference_seconds": affine_seconds,
        }
    ]
    return outcomes


def _boundary_checks(g1_points: Sequence[G1Point], g2_points: Sequence[G2Point]) -> dict[str, object]:
    boundary_results: dict[str, object] = {"sizes": {}, "scalar_edges": {}}
    for size in BOUNDARY_SIZES:
        scalars = tuple((index * 7 + 1) % 16 for index in range(size))
        selected_g1 = tuple(g1_points[index % len(g1_points)] for index in range(size))
        selected_g2 = tuple(g2_points[index % len(g2_points)] for index in range(size))
        dense_g1 = G1Query(selected_g1)
        dense_g2 = G2Query(selected_g2)
        optimized_g1 = msm_g1(dense_g1, scalars)
        optimized_g2 = msm_g2(dense_g2, scalars)
        affine_g1 = _affine_msm_g1(selected_g1, scalars)
        affine_g2 = _affine_msm_g2(selected_g2, scalars)
        if optimized_g1 != affine_g1 or optimized_g2 != affine_g2:
            raise RuntimeError(f"window-boundary comparison failed at {size} terms")
        boundary_results["sizes"][str(size)] = {
            "g1_exact_match": True,
            "g2_exact_match": True,
        }

    edge_g1 = G1Query((g1_points[0], g1_points[1], G1_INFINITY))
    edge_g2 = G2Query((g2_points[0], g2_points[1], G2_INFINITY))
    edge_scalars = (0, 1, SCALAR_MODULUS - 1)
    g1_expected = _affine_msm_g1(
        tuple(point.point for point in edge_g1.points), edge_scalars
    )
    g2_expected = _affine_msm_g2(
        tuple(point.point for point in edge_g2.points), edge_scalars
    )
    if msm_g1(edge_g1, edge_scalars) != g1_expected:
        raise RuntimeError("G1 scalar-edge comparison failed")
    if msm_g2(edge_g2, edge_scalars) != g2_expected:
        raise RuntimeError("G2 scalar-edge comparison failed")

    invalid_scalar_rejected = False
    try:
        msm_g1(G1Query((g1_points[0],)), (SCALAR_MODULUS,))
    except QueryError:
        invalid_scalar_rejected = True
    if not invalid_scalar_rejected:
        raise RuntimeError("scalar equal to modulus was not rejected")
    empty_inputs_match = (
        msm_g1(G1Query(()), ()) == G1_INFINITY
        and msm_g2(G2Query(()), ()) == G2_INFINITY
    )
    identity_only_match = (
        msm_g1(G1Query((ValidatedG1Point(G1_INFINITY),)), (SCALAR_MODULUS - 1,))
        == G1_INFINITY
        and msm_g2(G2Query((ValidatedG2Point(G2_INFINITY),)), (SCALAR_MODULUS - 1,))
        == G2_INFINITY
    )
    if not empty_inputs_match or not identity_only_match:
        raise RuntimeError("empty or identity MSM edge case failed")
    boundary_results["scalar_edges"] = {
        "zero_one_modulus_minus_one_exact_match": True,
        "scalar_equal_to_modulus_rejected": invalid_scalar_rejected,
        "empty_queries_return_identity": empty_inputs_match,
        "identity_only_queries_return_identity": identity_only_match,
    }
    return boundary_results


def _chunked_result_g1(
    points: Sequence[G1Point], scalars: Sequence[int], chunk_size: int = 1024
) -> G1Point:
    result = G1_INFINITY
    for start in range(0, len(points), chunk_size):
        result = add_g1(
            result,
            multi_scalar_multiply_g1(
                list(points[start : start + chunk_size]),
                list(scalars[start : start + chunk_size]),
            ),
        )
    return result


def _chunked_result_g2(
    points: Sequence[G2Point], scalars: Sequence[int], chunk_size: int = 1024
) -> G2Point:
    result = G2_INFINITY
    for start in range(0, len(points), chunk_size):
        result = add_g2(
            result,
            multi_scalar_multiply_g2(
                list(points[start : start + chunk_size]),
                list(scalars[start : start + chunk_size]),
            ),
        )
    return result


def run(
    parameter_path: Path,
    reference_export_path: Path | None = None,
) -> dict[str, object]:
    parameter_path = parameter_path.resolve(strict=True)
    if not parameter_path.is_file():
        raise ValueError("parameter path must name a file")
    file_sha256, file_blake2b512 = _file_digests(parameter_path)
    if file_sha256 != PARAMETER_SHA256:
        raise ValueError("external Output parameter SHA-256 pin mismatch")
    if file_blake2b512 != PARAMETER_BLAKE2B512:
        raise ValueError("external Output parameter BLAKE2b-512 pin mismatch")

    total_started = time.perf_counter()
    _, initial_peak = _process_memory()
    bellman_results = (
        _read_reference_export(reference_export_path)
        if reference_export_path is not None
        else None
    )
    system, qap, assignment, _ = _witness_and_qap()
    if system.matrix_fingerprint() != MATRIX_FINGERPRINT:
        raise RuntimeError("Output matrix fingerprint changed")
    scalar_assignment = QueryScalarAssignment.from_qap(qap, assignment)
    quotient = qap.quotient(assignment)

    mapping_path = (
        ROOT / "tests" / "fixtures" / "sapling_output_parameter_query_index_mapping.json"
    )
    mapping_bytes = mapping_path.read_bytes()
    if hashlib.sha256(mapping_bytes).hexdigest() != MAPPING_FILE_SHA256:
        raise RuntimeError("Output query mapping artifact hash changed")
    mapping = json.loads(mapping_bytes)
    if mapping["mapping_fingerprint_sha256"] != MAPPING_FINGERPRINT:
        raise RuntimeError("Output query mapping fingerprint changed")

    parse_started = time.perf_counter()
    with parameter_path.open("rb") as stream:
        parser = read_parameter_stream(stream, allow_trailing_data=True)
        verification_key = parser.metadata.verification_key
        parsed_sections: dict[str, list[G1Point | G2Point]] = {}
        for section in parser.sections():
            parsed_sections[section.name] = list(section)
        manifest = parser.manifest
    parse_seconds = time.perf_counter() - parse_started
    if manifest.sha256 != PARAMETER_SHA256 or manifest.blake2b512 != PARAMETER_BLAKE2B512:
        raise RuntimeError("production parser manifest digest does not match pin")
    if manifest.trailing_bytes != 52_836:
        raise RuntimeError("unexpected official Output transcript length")
    for name, count in QUERY_COUNTS.items():
        if len(parsed_sections[name]) != count:
            raise RuntimeError(f"{name} section count differs from official metadata")

    g1_variables = qap.variable_count
    dense_a_points = _mapped_dense_query(
        parsed_sections["a"], mapping["a_query"], g1_variables, G1_INFINITY
    )
    dense_b_g1_points = _mapped_dense_query(
        parsed_sections["b_g1"],
        mapping["b_g1_query"],
        g1_variables,
        G1_INFINITY,
    )
    dense_b_g2_points = _mapped_dense_query(
        parsed_sections["b_g2"],
        mapping["b_g2_query"],
        g1_variables,
        G2_INFINITY,
    )
    if mapping["b_g1_query"] != mapping["b_g2_query"]:
        raise RuntimeError("B_G1 and B_G2 sparse mappings differ")
    if len(parsed_sections["l"]) != qap.auxiliary_variable_count:
        raise RuntimeError("L points do not align with auxiliary variable order")
    if len(parsed_sections["h"]) != len(quotient):
        raise RuntimeError("H points do not align with quotient coefficient order")

    query_construction_started = time.perf_counter()
    a_query = G1Query(tuple(dense_a_points))
    b_g1_query = G1Query(tuple(dense_b_g1_points))
    b_g2_query = G2Query(tuple(dense_b_g2_points))
    l_query = G1Query(tuple(parsed_sections["l"]))
    h_query = G1Query(tuple(parsed_sections["h"]))
    query_construction_seconds = time.perf_counter() - query_construction_started

    g1_queries = {
        "A_G1": a_query,
        "B_G1": b_g1_query,
        "H_G1": h_query,
        "L_G1": l_query,
    }
    g2_queries = {"B_G2": b_g2_query}
    scalars: dict[str, Sequence[int]] = {
        "A_G1": scalar_assignment.values,
        "B_G1": scalar_assignment.values,
        "B_G2": scalar_assignment.values,
        "H_G1": quotient,
        "L_G1": scalar_assignment.auxiliary_values,
    }
    stage_results: dict[str, dict[str, object]] = {}
    group_results: dict[str, G1Point | G2Point] = {}
    for name in ("H_G1", "L_G1", "A_G1", "B_G1", "B_G2"):
        if name == "B_G2":
            query = g2_queries[name]
            result, elapsed = _measure(
                lambda query=query, name=name: msm_g2(query, scalars[name])
            )
            raw_points = tuple(point.point for point in query.points)
            chunked, chunk_elapsed = _measure(
                lambda raw_points=raw_points, name=name: _chunked_result_g2(
                    raw_points, scalars[name]
                )
            )
        else:
            query = g1_queries[name]
            result, elapsed = _measure(
                lambda query=query, name=name: msm_g1(query, scalars[name])
            )
            raw_points = tuple(point.point for point in query.points)
            chunked, chunk_elapsed = _measure(
                lambda raw_points=raw_points, name=name: _chunked_result_g1(
                    raw_points, scalars[name]
                )
            )
        if result != chunked:
            raise RuntimeError(f"{name} full MSM differs from chunked accumulation")
        encoded = (
            encode_g2_uncompressed(result)
            if isinstance(result, G2Point)
            else encode_g1_uncompressed(result)
        )
        reference_name = {
            "A_G1": "a",
            "B_G1": "b_g1",
            "B_G2": "b_g2",
            "H_G1": "h",
            "L_G1": "l",
        }[name]
        if bellman_results is not None and bellman_results[reference_name] != encoded:
            raise RuntimeError(f"{name} full accumulation differs from Bellman 0.15")
        group_results[name] = result
        stage_results[name] = {
            "terms": len(query.points),
            "nonzero_scalars": sum(value != 0 for value in scalars[name]),
            "optimized_seconds": elapsed,
            "chunked_cross_check_seconds": chunk_elapsed,
            "chunked_exact_match": True,
            "bellman_exact_match": bellman_results is not None,
            "identity_result": result
            == (G2_INFINITY if name == "B_G2" else G1_INFINITY),
            "result_sha256": hashlib.sha256(encoded).hexdigest(),
            "process_working_set_bytes_after": _process_memory()[0],
        }

    ic_query = G1Query(tuple(verification_key.ic))
    ic_scalars = scalar_assignment.values[: len(verification_key.ic)]
    if len(ic_scalars) != 6 or ic_scalars[0] != 1:
        raise RuntimeError("Output IC scalars must be ONE followed by five public inputs")
    ic_result, ic_seconds = _measure(lambda: msm_g1(ic_query, ic_scalars))
    ic_encoded = encode_g1_uncompressed(ic_result)
    if bellman_results is not None and bellman_results["ic"] != ic_encoded:
        raise RuntimeError("IC accumulation differs from Bellman 0.15")

    affine_checks = _affine_subset_checks(g1_queries, g2_queries, scalars)
    boundary_checks = _boundary_checks(
        parsed_sections["h"], parsed_sections["b_g2"]
    )
    if len(verification_key.ic) != 6:
        raise RuntimeError("Output verification-key IC count changed")

    negative_checks: dict[str, bool] = {}
    if bellman_results is not None:
        a_query = g1_queries["A_G1"]
        a_scalars = scalars["A_G1"]
        changed_scalars = list(a_scalars)
        changed_scalars[0] = (changed_scalars[0] + 1) % SCALAR_MODULUS
        negative_checks["altered_scalar_rejected"] = (
            encode_g1_uncompressed(msm_g1(a_query, changed_scalars))
            != bellman_results["a"]
        )

        reordered_points = list(a_query.points)
        reordered_points[0], reordered_points[-1] = (
            reordered_points[-1],
            reordered_points[0],
        )
        negative_checks["reordered_query_points_rejected"] = (
            encode_g1_uncompressed(msm_g1(G1Query(tuple(reordered_points)), a_scalars))
            != bellman_results["a"]
        )

        altered_mapping = [dict(entry) for entry in mapping["a_query"]]
        altered_mapping[0]["query_index"], altered_mapping[-1]["query_index"] = (
            altered_mapping[-1]["query_index"],
            altered_mapping[0]["query_index"],
        )
        incorrect_sparse_points = _mapped_dense_query(
            parsed_sections["a"],
            altered_mapping,
            g1_variables,
            G1_INFINITY,
        )
        negative_checks["incorrect_sparse_index_rejected"] = (
            encode_g1_uncompressed(
                msm_g1(G1Query(incorrect_sparse_points), a_scalars)
            )
            != bellman_results["a"]
        )

        reordered_ic_scalars = (
            ic_scalars[0],
            ic_scalars[2],
            ic_scalars[1],
            *ic_scalars[3:],
        )
        negative_checks["changed_public_input_order_rejected"] = (
            encode_g1_uncompressed(msm_g1(ic_query, reordered_ic_scalars))
            != bellman_results["ic"]
        )
        if not all(negative_checks.values()):
            raise RuntimeError("a negative MSM compatibility mutation was accepted")

    elapsed_total = time.perf_counter() - total_started
    working_set, peak_working_set = _process_memory()
    return {
        "format": "zycoin-output-authentic-query-msm-validation-v1",
        "parameter_file": {
            "name": parameter_path.name,
            "bytes": parameter_path.stat().st_size,
            "sha256": manifest.sha256,
            "blake2b512": manifest.blake2b512,
            "trailing_transcript_bytes": manifest.trailing_bytes,
            "trusted_hash_match": True,
        },
        "output_witness": {
            "assignment_sha256": ASSIGNMENT_SHA256,
            "matrix_fingerprint": system.matrix_fingerprint(),
            "rows": system.constraint_count,
            "columns": len(system.variables),
            "qap_domain": qap.domain.size,
            "scalar_source": "QueryScalarAssignment.from_qap over deterministic Zcash Output note-encryption witness; H uses qap.quotient coefficients in ascending degree; L uses auxiliary assignment order.",
        },
        "query_mapping_fingerprint": mapping["mapping_fingerprint_sha256"],
        "section_counts": {
            "ic": len(verification_key.ic),
            **{name: len(parsed_sections[name]) for name in QUERY_COUNTS},
        },
        "sparse_and_order_checks": {
            "a_compact_indices_mapped_to_local_columns": len(mapping["a_query"]),
            "b_compact_indices_mapped_to_local_columns": len(mapping["b_g1_query"]),
            "b_g1_b_g2_mappings_equal": True,
            "l_auxiliary_count_matches": True,
            "h_quotient_degree_order_count_matches": True,
        },
        "timings_seconds": {
            "production_parser_full_stream_and_subgroup_validation": parse_seconds,
            "validated_query_object_construction": query_construction_seconds,
            "ic_msm": ic_seconds,
            "total_including_witness_reconstruction": elapsed_total,
            "total_msm": sum(
                float(stage["optimized_seconds"])
                for stage in stage_results.values()
            ),
        },
        "authentic_query_accumulations": stage_results,
        "ic_accumulation": {
            "terms": len(ic_query.points),
            "scalars": len(ic_scalars),
            "constant_one_included": ic_scalars[0] == 1,
            "public_input_count": len(ic_scalars) - 1,
            "bellman_exact_match": bellman_results is not None,
            "identity_result": ic_result == G1_INFINITY,
            "result_sha256": hashlib.sha256(ic_encoded).hexdigest(),
        },
        "affine_oracle_subset_comparisons": affine_checks,
        "window_and_scalar_boundary_checks": boundary_checks,
        "negative_mutation_checks": negative_checks,
        "memory_bytes": {
            "working_set_before_run": initial_peak,
            "working_set_after_run": working_set,
            "process_peak_working_set": peak_working_set,
        },
        "authentic_proof_generated": False,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: python tests/benchmark_sapling_output_authentic_msm.py "
            "<official-sapling-output.params>"
        )
    print(json.dumps(run(Path(sys.argv[1])), sort_keys=True, indent=2))
