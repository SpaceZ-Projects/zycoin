"""Reproducible Output proving-cost benchmark with synthetic query points.

The benchmark uses the pinned Output matrix and deterministic satisfying test
witness, together with the official parameter section counts and sparse maps.
It deliberately does not load authentic proving-query values or generate a
serialized proof from official parameters; the final stage assembles only
synthetic proof elements for timing.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import statistics
import sys
import time
import tracemalloc
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.bls12_381 import (
    FIELD_MODULUS,
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    multiply_g1,
    multiply_g2,
)
from src.groth16_proof import (
    Groth16ProvingQueries,
    assemble_proof_elements,
)
from src.groth16_qap import QAP, QAPAssignment
from src.groth16_queries import (
    G1Query,
    G2Query,
    QueryScalarAssignment,
    ValidatedG1Point,
    ValidatedG2Point,
    msm_g1,
    msm_g2,
)
from src.jubjub import Point
from src.r1cs import R1CS
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness

MATRIX_FINGERPRINT = "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
ASSIGNMENT_SHA256 = "b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea"
MAPPING_FINGERPRINT = "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2"
QUERY_COUNTS = {"a": 6298, "b_g1": 4850, "b_g2": 4850, "h": 8191, "l": 7821}
def _peak_working_set_bytes() -> int | None:
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
        return None
    return counters.PeakWorkingSetSize


def _measure(function: Callable[[], object]) -> tuple[object, float]:
    started = time.perf_counter()
    value = function()
    elapsed = time.perf_counter() - started
    return value, elapsed


def _python_heap_peak_increment(function: Callable[[], object]) -> int:
    tracemalloc.start()
    before, _ = tracemalloc.get_traced_memory()
    tracemalloc.reset_peak()
    function()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return max(0, peak - before)


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


def _reference_msm_g1(points: tuple[G1Point, ...], scalars: tuple[int, ...]) -> G1Point:
    result = G1_INFINITY
    for point, scalar in zip(points, scalars):
        result = add_g1(result, _reference_multiply_g1(point, scalar))
    return result


def _reference_msm_g2(points: tuple[G2Point, ...], scalars: tuple[int, ...]) -> G2Point:
    result = G2_INFINITY
    for point, scalar in zip(points, scalars):
        result = add_g2(result, _reference_multiply_g2(point, scalar))
    return result


def _affine_msm_operation_count(query: G1Query | G2Query, scalars: tuple[int, ...]) -> int:
    nonzero_terms = 0
    operations = 0
    for wrapped, scalar in zip(query.points, scalars):
        if scalar and not wrapped.point.is_infinity:
            nonzero_terms += 1
            operations += scalar.bit_length() + scalar.bit_count() - 1
    return operations + max(0, nonzero_terms - 1)


def _witness_and_qap() -> tuple[R1CS, QAP, QAPAssignment, dict[str, float]]:
    case = json.loads(
        (ROOT / "tests" / "fixtures" / "sapling_output_reference.json").read_text(
            encoding="ascii"
        )
    )["cases"][0]
    key = Point.from_bytes(bytes.fromhex(case["transmission_key"]), check_subgroup=True)
    witness = make_sapling_output_witness(
        case["value"],
        bytes.fromhex(case["diversifier"]),
        key,
        int.from_bytes(bytes.fromhex(case["rcv"]), "little"),
        int.from_bytes(bytes.fromhex(case["rcm"]), "little"),
        int.from_bytes(bytes.fromhex(case["esk"]), "little"),
    )
    system = R1CS()
    synthesis_started = time.perf_counter()
    constrain_sapling_output(system, witness)
    synthesis_seconds = time.perf_counter() - synthesis_started
    if system.constraint_count != 7_827 or len(system.variables) != 7_827:
        raise RuntimeError("Output circuit dimensions differ from pinned metadata")
    if system.matrix_fingerprint() != MATRIX_FINGERPRINT or not system.is_satisfied():
        raise RuntimeError("Output matrix or deterministic witness changed")
    values = tuple(system.witness_value(variable) for variable in system.variables)
    if any(value is None for value in values):
        raise RuntimeError("deterministic Output witness contains unassigned values")
    assignment_bytes = b"".join(
        int(value).to_bytes(32, "little") for value in values
    )
    if hashlib.sha256(assignment_bytes).hexdigest() != ASSIGNMENT_SHA256:
        raise RuntimeError("deterministic Output witness fingerprint changed")
    qap = QAP.from_r1cs(system)
    assignment = QAPAssignment(
        values[1 : qap.public_input_count + 1],
        values[qap.public_input_count + 1 :],
    )
    return system, qap, assignment, {"witness_synthesis_seconds": synthesis_seconds}


def _build_queries(
    qap: QAP,
) -> tuple[Groth16ProvingQueries, dict[str, int]]:
    mapping = json.loads(
        (
            ROOT
            / "tests"
            / "fixtures"
            / "sapling_output_parameter_query_index_mapping.json"
        ).read_text(encoding="ascii")
    )
    if mapping["mapping_fingerprint_sha256"] != MAPPING_FINGERPRINT:
        raise RuntimeError("Output sparse query mapping fingerprint changed")
    supports = {
        "a": {entry["local_column"] for entry in mapping["a_query"]},
        "b": {entry["local_column"] for entry in mapping["b_g1_query"]},
    }
    if len(supports["a"]) != QUERY_COUNTS["a"] or len(supports["b"]) != QUERY_COUNTS["b_g1"]:
        raise RuntimeError("Output sparse query counts differ from official metadata")

    g1_pool = tuple(
        multiply_g1(G1_GENERATOR, index * 7919 + 1) for index in range(64)
    )
    g2_pool = tuple(
        multiply_g2(G2_GENERATOR, index * 3571 + 1) for index in range(64)
    )
    g1_validated = tuple(ValidatedG1Point(point) for point in g1_pool)
    g2_validated = tuple(ValidatedG2Point(point) for point in g2_pool)
    g1_identity = ValidatedG1Point(G1_INFINITY)
    g2_identity = ValidatedG2Point(G2_INFINITY)
    a_query = G1Query(
        tuple(
            g1_validated[(index * 37 + 11) % len(g1_validated)]
            if index in supports["a"]
            else g1_identity
            for index in range(qap.variable_count)
        )
    )
    b_g1_query = G1Query(
        tuple(
            g1_validated[(index * 19 + 7) % len(g1_validated)]
            if index in supports["b"]
            else g1_identity
            for index in range(qap.variable_count)
        )
    )
    b_g2_query = G2Query(
        tuple(
            g2_validated[(index * 29 + 5) % len(g2_validated)]
            if index in supports["b"]
            else g2_identity
            for index in range(qap.variable_count)
        )
    )
    l_query = G1Query(
        tuple(g1_validated[(index * 13 + 3) % len(g1_validated)]
              for index in range(qap.auxiliary_variable_count))
    )
    h_query = G1Query(
        tuple(g1_validated[(index * 23 + 9) % len(g1_validated)]
              for index in range(qap.domain.size - 1))
    )
    return (
        Groth16ProvingQueries(
            alpha_g1=g1_validated[1],
            beta_g1=g1_validated[2],
            beta_g2=g2_validated[1],
            delta_g1=g1_validated[3],
            delta_g2=g2_validated[2],
            a_query=a_query,
            b_g1_query=b_g1_query,
            b_g2_query=b_g2_query,
            l_query=l_query,
            h_query=h_query,
        ),
        {
            "a_compact": len(supports["a"]),
            "a_dense": qap.variable_count,
            "b_compact": len(supports["b"]),
            "b_dense": qap.variable_count,
            "l": qap.auxiliary_variable_count,
            "h": qap.domain.size - 1,
        },
    )


def run_benchmark() -> dict[str, object]:
    total_started = time.perf_counter()
    system, qap, assignment, setup_times = _witness_and_qap()
    queries, query_layout = _build_queries(qap)
    scalar_assignment = QueryScalarAssignment.from_qap(qap, assignment)
    evaluations, evaluation_seconds = _measure(
        lambda: qap.evaluations(assignment)
    )
    polynomials, interpolation_seconds = _measure(
        lambda: qap.polynomials(assignment)
    )
    quotient, quotient_seconds = _measure(lambda: qap.quotient(assignment))
    satisfied, satisfaction_seconds = _measure(
        lambda: qap.validate_assignment(assignment)
    )
    if (
        len(quotient) != qap.domain.size - 1
        or len(satisfied) != qap.variable_count
        or len(evaluations.a) != qap.domain.size
        or len(polynomials.a) != qap.domain.size
    ):
        raise RuntimeError("QAP output dimensions changed")

    scalar = SCALAR_MODULUS - 1234567
    g1_samples: list[float] = []
    g2_samples: list[float] = []
    legacy_g1_samples: list[float] = []
    legacy_g2_samples: list[float] = []
    for _ in range(3):
        _, elapsed = _measure(lambda: multiply_g1(G1_GENERATOR, scalar))
        g1_samples.append(elapsed)
        _, elapsed = _measure(lambda: multiply_g2(G2_GENERATOR, scalar))
        g2_samples.append(elapsed)
        _, elapsed = _measure(lambda: _reference_multiply_g1(G1_GENERATOR, scalar))
        legacy_g1_samples.append(elapsed)
        _, elapsed = _measure(lambda: _reference_multiply_g2(G2_GENERATOR, scalar))
        legacy_g2_samples.append(elapsed)

    stages: dict[str, dict[str, float | int]] = {}
    for name, function in (
        ("A_G1", lambda: msm_g1(queries.a_query, scalar_assignment.values)),
        ("B_G1", lambda: msm_g1(queries.b_g1_query, scalar_assignment.values)),
        ("B_G2", lambda: msm_g2(queries.b_g2_query, scalar_assignment.values)),
        ("L_G1", lambda: msm_g1(queries.l_query, scalar_assignment.auxiliary_values)),
        ("H_G1", lambda: msm_g1(queries.h_query, quotient)),
    ):
        result, elapsed = _measure(function)
        if result is None:
            raise RuntimeError(f"{name} returned no group element")
        stages[name] = {"seconds": elapsed}

    sample_points_g1 = tuple(point for point in (
        queries.a_query.points[index].point for index in range(32)
    ))
    sample_points_g2 = tuple(point for point in (
        queries.b_g2_query.points[index].point for index in range(32)
    ))
    sample_scalars = scalar_assignment.values[:32]
    optimized_g1_result, optimized_g1_seconds = _measure(
        lambda: msm_g1(G1Query(tuple(
            queries.a_query.points[index] for index in range(32)
        )), sample_scalars)
    )
    legacy_g1, legacy_g1_seconds = _measure(
        lambda: _reference_msm_g1(sample_points_g1, sample_scalars)
    )
    optimized_g2_result, optimized_g2_seconds = _measure(
        lambda: msm_g2(G2Query(tuple(
            queries.b_g2_query.points[index] for index in range(32)
        )), sample_scalars)
    )
    legacy_g2, legacy_g2_seconds = _measure(
        lambda: _reference_msm_g2(sample_points_g2, sample_scalars)
    )

    proof, assembly_seconds = _measure(
        lambda: assemble_proof_elements(
            qap, assignment, queries, 123456789, 987654321
        )
    )
    if proof.a.is_infinity or proof.b.is_infinity or proof.c.is_infinity:
        raise RuntimeError("synthetic proof assembly unexpectedly returned identity")
    g1_operation_count = sum(
        (
            _affine_msm_operation_count(
                queries.a_query, scalar_assignment.values
            ),
            _affine_msm_operation_count(
                queries.b_g1_query, scalar_assignment.values
            ),
            _affine_msm_operation_count(
                queries.l_query, scalar_assignment.auxiliary_values
            ),
            _affine_msm_operation_count(queries.h_query, quotient),
        )
    )
    g2_operation_count = _affine_msm_operation_count(
        queries.b_g2_query, scalar_assignment.values
    )
    legacy_g1_unit = statistics.median(legacy_g1_samples) / (
        scalar.bit_length() + scalar.bit_count() - 1
    )
    legacy_g2_unit = statistics.median(legacy_g2_samples) / (
        scalar.bit_length() + scalar.bit_count() - 1
    )
    sample_g1_query = G1Query(tuple(queries.a_query.points[:32]))
    sample_g2_query = G2Query(tuple(queries.b_g2_query.points[:32]))
    g1_legacy_heap = _python_heap_peak_increment(
        lambda: _reference_msm_g1(sample_points_g1, sample_scalars)
    )
    g1_optimized_heap = _python_heap_peak_increment(
        lambda: msm_g1(sample_g1_query, sample_scalars)
    )
    g2_legacy_heap = _python_heap_peak_increment(
        lambda: _reference_msm_g2(sample_points_g2, sample_scalars)
    )
    g2_optimized_heap = _python_heap_peak_increment(
        lambda: msm_g2(sample_g2_query, sample_scalars)
    )
    elapsed_total = time.perf_counter() - total_started
    return {
        "format": "zycoin-output-proving-benchmark-v1",
        "parameter_source": "official Output metadata/counts and sparse mapping; synthetic deterministic subgroup query points",
        "authentic_parameter_values_loaded": False,
        "authentic_proof_generated": False,
        "serialized_proof_generated": False,
        "synthetic_proof_element_assembly": True,
        "matrix": {
            "rows": system.constraint_count,
            "columns": len(system.variables),
            "fingerprint": system.matrix_fingerprint(),
            "qap_domain": qap.domain.size,
            "assignment_sha256": ASSIGNMENT_SHA256,
        },
        "query_mapping_fingerprint": MAPPING_FINGERPRINT,
        "query_section_counts": QUERY_COUNTS,
        "query_layout_used": query_layout,
        "timings_seconds": {
            **setup_times,
            "witness_satisfaction": satisfaction_seconds,
            "qap_row_evaluations": evaluation_seconds,
            "qap_interpolation_three_polynomials": interpolation_seconds,
            "qap_fft_and_quotient": quotient_seconds,
            "G1_scalar_multiply_median": statistics.median(g1_samples),
            "G2_scalar_multiply_median": statistics.median(g2_samples),
            "G1_legacy_affine_scalar_multiply_median": statistics.median(
                legacy_g1_samples
            ),
            "G2_legacy_affine_scalar_multiply_median": statistics.median(
                legacy_g2_samples
            ),
            "final_proof_element_assembly": assembly_seconds,
            "benchmark_total": elapsed_total,
        },
        "query_accumulations": stages,
        "legacy_affine_msm_sample": {
            "terms": len(sample_scalars),
            "G1_legacy_seconds": legacy_g1_seconds,
            "G1_optimized_seconds": optimized_g1_seconds,
            "G1_exact_match": legacy_g1 == optimized_g1_result,
            "G1_speedup": legacy_g1_seconds / optimized_g1_seconds,
            "G2_legacy_seconds": legacy_g2_seconds,
            "G2_optimized_seconds": optimized_g2_seconds,
            "G2_exact_match": legacy_g2 == optimized_g2_result,
            "G2_speedup": legacy_g2_seconds / optimized_g2_seconds,
        },
        "legacy_affine_full_query_estimate": {
            "method": "Count exact nonzero scalar bit lengths/popcounts and affine accumulation operations for the pinned sparse supports; calibrate per-operation cost using three 255-bit affine scalar-multiplication samples.",
            "G1_affine_operation_count": g1_operation_count,
            "G2_affine_operation_count": g2_operation_count,
            "G1_calibrated_seconds_per_operation": legacy_g1_unit,
            "G2_calibrated_seconds_per_operation": legacy_g2_unit,
            "estimated_query_accumulation_seconds": (
                g1_operation_count * legacy_g1_unit
                + g2_operation_count * legacy_g2_unit
            ),
        },
        "memory_bytes": {
            "32_term_g1_affine_msm_python_heap_peak_increment": g1_legacy_heap,
            "32_term_g1_windowed_msm_python_heap_peak_increment": g1_optimized_heap,
            "32_term_g2_affine_msm_python_heap_peak_increment": g2_legacy_heap,
            "32_term_g2_windowed_msm_python_heap_peak_increment": g2_optimized_heap,
            "process_peak_working_set": _peak_working_set_bytes(),
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), sort_keys=True, indent=2))
