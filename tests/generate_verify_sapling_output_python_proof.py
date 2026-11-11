"""Generate and independently verify an authentic Output proof in test code.

Run as:
    python tests/generate_verify_sapling_output_python_proof.py <sapling-output.params>

The proof, public inputs, and Bellman exchange files exist only in a temporary
directory. Randomizers are fixed, test-only values and are not secure RNG.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from ctypes import wintypes
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.bls12_381 import (
    G1_GENERATOR,
    G1_INFINITY,
    G2_INFINITY,
    SCALAR_MODULUS,
    add_g1,
    decode_g1,
    decode_g2,
    encode_g1,
    encode_g2,
)
from src.groth16_parameters import read_parameter_stream
from src.groth16_proof import (
    Groth16ProvingQueries,
    assemble_proof_elements,
)
from src.groth16_queries import (
    G1Query,
    G2Query,
    QueryScalarAssignment,
    ValidatedG1Point,
    ValidatedG2Point,
    msm_g1,
    msm_g2,
)
from src.groth16_verification import (
    Groth16Proof,
    Groth16VerificationKey,
    verify_groth16_proof,
)
from tests.benchmark_sapling_output_authentic_msm import (
    MAPPING_FILE_SHA256,
    PARAMETER_BLAKE2B512,
    PARAMETER_SHA256,
    _file_digests,
    _mapped_dense_query,
    _process_memory,
)
from tests.benchmark_sapling_output_proving import (
    ASSIGNMENT_SHA256,
    MAPPING_FINGERPRINT,
    MATRIX_FINGERPRINT,
    _witness_and_qap,
)

RUNNER_MANIFEST = ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
RUNNER_BINARY = "verify_python_output_proof"
ROWS_PATH = ROOT / "tests" / "fixtures" / "sapling_output_row_correspondence.json"
MAPPING_PATH = ROOT / "tests" / "fixtures" / "sapling_output_parameter_query_index_mapping.json"
OUTPUT_PUBLIC_INPUT_ORDER = ("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u")
ROW_ARTIFACT_SHA256 = "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761"
VARIABLE_MAPPING_FINGERPRINT = "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    if not resolved.drive:
        raise RuntimeError(f"cannot map path into WSL: {resolved}")
    drive = resolved.drive[0].lower()
    return f"/mnt/{drive}/" + "/".join(resolved.parts[1:])


def _python_peak_working_set_bytes() -> int | None:
    if os.name != "nt":
        return None

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


def _timed(function: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    result = function()
    return result, time.perf_counter() - started


def _hex(data: bytes) -> str:
    return data.hex()


def _public_input_bytes(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def _build_proving_queries(
    parameter_path: Path,
    query_mapping: dict[str, Any],
    variable_count: int,
) -> tuple[Groth16ProvingQueries, dict[str, Any], float, float]:
    parser_started = time.perf_counter()
    with parameter_path.open("rb") as stream:
        parser = read_parameter_stream(stream, allow_trailing_data=True)
        vk = parser.metadata.verification_key
        sections = {section.name: list(section) for section in parser.sections()}
        manifest = parser.manifest
    parser_seconds = time.perf_counter() - parser_started
    if (
        manifest.sha256 != PARAMETER_SHA256
        or manifest.blake2b512 != PARAMETER_BLAKE2B512
        or manifest.trailing_bytes != 52_836
    ):
        raise RuntimeError("production parameter parser manifest differs from pins")

    a_points = _mapped_dense_query(
        sections["a"], query_mapping["a_query"], variable_count, G1_INFINITY
    )
    b_g1_points = _mapped_dense_query(
        sections["b_g1"], query_mapping["b_g1_query"], variable_count, G1_INFINITY
    )
    b_g2_points = _mapped_dense_query(
        sections["b_g2"], query_mapping["b_g2_query"], variable_count, G2_INFINITY
    )
    if query_mapping["b_g1_query"] != query_mapping["b_g2_query"]:
        raise RuntimeError("B_G1/B_G2 sparse maps differ")
    if len(sections["h"]) != 8_191 or len(sections["l"]) != 7_821:
        raise RuntimeError("authentic Output H/L counts differ from the pinned map")
    query_started = time.perf_counter()
    queries = Groth16ProvingQueries(
        alpha_g1=ValidatedG1Point(vk.alpha_g1),
        beta_g1=ValidatedG1Point(vk.beta_g1),
        beta_g2=ValidatedG2Point(vk.beta_g2),
        delta_g1=ValidatedG1Point(vk.delta_g1),
        delta_g2=ValidatedG2Point(vk.delta_g2),
        a_query=G1Query(a_points),
        b_g1_query=G1Query(b_g1_points),
        b_g2_query=G2Query(b_g2_points),
        l_query=G1Query(sections["l"]),
        h_query=G1Query(sections["h"]),
    )
    query_seconds = time.perf_counter() - query_started
    return queries, {
        "sha256": manifest.sha256,
        "blake2b512": manifest.blake2b512,
        "trailing_bytes": manifest.trailing_bytes,
        "section_counts": {
            "ic": len(vk.ic),
            **{name: len(points) for name, points in sections.items()},
        },
        "verification_key": vk,
    }, parser_seconds, query_seconds


def _proof_bytes(proof: Groth16Proof) -> bytes:
    return encode_g1(proof.a.point) + encode_g2(proof.b.point) + encode_g1(proof.c.point)


def _make_verification_key(vk: Any) -> Groth16VerificationKey:
    return Groth16VerificationKey(
        alpha_g1=vk.alpha_g1,
        beta_g2=vk.beta_g2,
        gamma_g2=vk.gamma_g2,
        delta_g2=vk.delta_g2,
        ic_query=vk.ic,
    )


def _mutated_proof_bytes(proof: Groth16Proof) -> bytes:
    altered_a = add_g1(proof.a.point, G1_GENERATOR)
    return encode_g1(altered_a) + encode_g2(proof.b.point) + encode_g1(proof.c.point)


def _cases(proof_bytes: bytes, public_inputs: Sequence[int]) -> list[dict[str, Any]]:
    proof = Groth16Proof(
        decode_g1(proof_bytes[:48]),
        decode_g2(proof_bytes[48:144]),
        decode_g1(proof_bytes[144:]),
    )
    changed_public = list(public_inputs)
    changed_public[0] = (changed_public[0] + 1) % SCALAR_MODULUS
    reordered_public = list(public_inputs)
    reordered_public[0], reordered_public[1] = reordered_public[1], reordered_public[0]
    malformed = bytearray(proof_bytes)
    malformed[0] &= 0x7F
    return [
        {
            "name": "valid",
            "proof_hex": proof_bytes.hex(),
            "public_inputs_hex": [_public_input_bytes(value) for value in public_inputs],
        },
        {
            "name": "altered-proof-point",
            "proof_hex": _mutated_proof_bytes(proof).hex(),
            "public_inputs_hex": [_public_input_bytes(value) for value in public_inputs],
        },
        {
            "name": "altered-public-input",
            "proof_hex": proof_bytes.hex(),
            "public_inputs_hex": [_public_input_bytes(value) for value in changed_public],
        },
        {
            "name": "reordered-public-inputs",
            "proof_hex": proof_bytes.hex(),
            "public_inputs_hex": [_public_input_bytes(value) for value in reordered_public],
        },
        {
            "name": "malformed-proof-encoding",
            "proof_hex": bytes(malformed).hex(),
            "public_inputs_hex": [_public_input_bytes(value) for value in public_inputs],
        },
    ]


def _verify_with_bellman(
    params: Path,
    assignment_path: Path,
    cases_path: Path,
    result_path: Path,
) -> tuple[dict[str, Any], float, int]:
    wsl = shutil.which("wsl")
    if wsl is None:
        raise RuntimeError("pinned WSL Rust toolchain is required for Bellman verification")
    converted = tuple(
        _wsl_path(path)
        for path in (RUNNER_MANIFEST, params, ROWS_PATH, assignment_path, cases_path, result_path)
    )
    root = _wsl_path(ROOT)
    command = (
        f"cd {shlex.quote(root)} && /usr/bin/time -f "
        f"'ZYCOIN_MAX_RSS_KIB=%M' rustup run 1.97.0 cargo run --quiet --release "
        f"--offline --manifest-path {shlex.quote(converted[0])} "
        f"--bin {RUNNER_BINARY} -- {shlex.quote(converted[1])} "
        f"{shlex.quote(converted[2])} {shlex.quote(converted[3])} "
        f"{shlex.quote(converted[4])} {shlex.quote(converted[5])}"
    )
    started = time.perf_counter()
    result = subprocess.run(
        [wsl, "--", "bash", "-lc", command],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    elapsed = time.perf_counter() - started
    match = re.search(r"ZYCOIN_MAX_RSS_KIB=(\d+)", result.stderr)
    if match is None:
        raise RuntimeError("Bellman verifier did not report peak RSS")
    output = json.loads(result_path.read_text(encoding="utf-8"))
    return output, elapsed, int(match.group(1)) * 1024


def run(parameter_path: Path) -> dict[str, Any]:
    parameter_path = parameter_path.resolve(strict=True)
    if not parameter_path.is_file():
        raise ValueError("parameter path must name a file")
    parameter_sha256, parameter_blake2b = _file_digests(parameter_path)
    if parameter_sha256 != PARAMETER_SHA256 or parameter_blake2b != PARAMETER_BLAKE2B512:
        raise RuntimeError("official Output parameter hash mismatch")
    if hashlib.sha256(MAPPING_PATH.read_bytes()).hexdigest() != MAPPING_FILE_SHA256:
        raise RuntimeError("Output query mapping artifact hash mismatch")
    mapping = json.loads(MAPPING_PATH.read_text(encoding="ascii"))
    if mapping["mapping_fingerprint_sha256"] != MAPPING_FINGERPRINT:
        raise RuntimeError("Output query map fingerprint mismatch")

    total_started = time.perf_counter()
    initial_working_set, _ = _process_memory()
    (system, qap, assignment, _), witness_synthesis_seconds = _timed(_witness_and_qap)
    if system.matrix_fingerprint() != MATRIX_FINGERPRINT or not system.is_satisfied():
        raise RuntimeError("deterministic Output matrix/witness check failed")

    queries, parsed, parameter_parse_seconds, query_validation_seconds = _build_proving_queries(
        parameter_path, mapping, qap.variable_count
    )
    verification_key = _make_verification_key(parsed["verification_key"])

    quotient, qap_seconds = _timed(lambda: qap.quotient(assignment))
    scalar_assignment = QueryScalarAssignment.from_qap(qap, assignment)
    _, h_msm_seconds = _timed(lambda: msm_g1(queries.h_query, quotient))
    _, l_msm_seconds = _timed(
        lambda: msm_g1(queries.l_query, scalar_assignment.auxiliary_values)
    )
    _, a_msm_seconds = _timed(lambda: msm_g1(queries.a_query, scalar_assignment.values))
    _, b_g1_msm_seconds = _timed(
        lambda: msm_g1(queries.b_g1_query, scalar_assignment.values)
    )
    _, b_g2_msm_seconds = _timed(
        lambda: msm_g2(queries.b_g2_query, scalar_assignment.values)
    )

    seed_r = hashlib.sha256(b"ZyCoin test-only Sapling Output proof r").digest()
    seed_s = hashlib.sha256(b"ZyCoin test-only Sapling Output proof s").digest()
    r = int.from_bytes(seed_r, "little") % SCALAR_MODULUS or 1
    s = int.from_bytes(seed_s, "little") % SCALAR_MODULUS or 1

    assembled, proof_assembly_seconds = _timed(
        lambda: assemble_proof_elements(qap, assignment, queries, r, s)
    )
    proof = Groth16Proof(assembled.a, assembled.b, assembled.c)
    proof_encoding_seconds_start = time.perf_counter()
    proof_bytes = _proof_bytes(proof)
    proof_encoding_seconds = time.perf_counter() - proof_encoding_seconds_start
    public_inputs = scalar_assignment.public_values
    if len(public_inputs) != len(OUTPUT_PUBLIC_INPUT_ORDER):
        raise RuntimeError("Output public input count/order does not match expected")

    python_verify_started = time.perf_counter()
    valid_accepted = verify_groth16_proof(verification_key, proof, public_inputs)
    python_verification_seconds = time.perf_counter() - python_verify_started
    if not valid_accepted:
        raise RuntimeError("pure-Python verifier rejected the generated Output proof")

    python_negative: dict[str, bool] = {}
    altered_proof = Groth16Proof(
        add_g1(proof.a.point, G1_GENERATOR),
        proof.b.point,
        proof.c.point,
    )
    python_negative["altered_proof_point_rejected"] = not verify_groth16_proof(
        verification_key, altered_proof, public_inputs
    )
    changed_public = list(public_inputs)
    changed_public[0] = (changed_public[0] + 1) % SCALAR_MODULUS
    python_negative["altered_public_input_rejected"] = not verify_groth16_proof(
        verification_key, proof, changed_public
    )
    reordered_public = list(public_inputs)
    reordered_public[0], reordered_public[1] = reordered_public[1], reordered_public[0]
    python_negative["reordered_public_inputs_rejected"] = not verify_groth16_proof(
        verification_key, proof, reordered_public
    )
    malformed_rejected = False
    try:
        malformed = bytearray(proof_bytes)
        malformed[0] &= 0x7F
        decode_g1(bytes(malformed[:48]))
    except ValueError:
        malformed_rejected = True
    python_negative["malformed_proof_encoding_rejected"] = malformed_rejected
    if not all(python_negative.values()):
        raise RuntimeError("a pure-Python proof negative test was accepted")

    with tempfile.TemporaryDirectory(prefix="zycoin-output-python-proof-") as directory:
        work = Path(directory)
        proof_path = work / "python-proof.bin"
        assignment_path = work / "output-assignment.json"
        public_path = work / "public-inputs.json"
        cases_path = work / "proof-cases.json"
        bellman_result_path = work / "bellman-verification.json"
        proof_path.write_bytes(proof_bytes)
        witness_values = (1, *assignment.public_inputs, *assignment.auxiliary_assignments)
        assignment_bytes = b"".join(
            value.to_bytes(32, "little") for value in witness_values
        )
        if hashlib.sha256(assignment_bytes).hexdigest() != ASSIGNMENT_SHA256:
            raise RuntimeError("constructed Output assignment hash differs from its pin")
        assignment_input = {
            "format": "zycoin-sapling-output-qap-assignment-input-v1",
            "row_artifact_sha256": ROW_ARTIFACT_SHA256,
            "variable_mapping_fingerprint_sha256": VARIABLE_MAPPING_FINGERPRINT,
            "matrix_fingerprint": MATRIX_FINGERPRINT,
            "cases": [
                {
                    "name": "zcash-note-encryption-vector-0",
                    "assignment_sha256": ASSIGNMENT_SHA256,
                    "assignment_hex": [value.to_bytes(32, "little").hex() for value in witness_values],
                }
            ],
        }
        assignment_path.write_text(
            json.dumps(assignment_input, separators=(",", ":"), sort_keys=True),
            encoding="ascii",
        )
        public_path.write_text(
            json.dumps(
                {
                    "format": "zycoin-python-output-public-inputs-v1",
                    "order": list(OUTPUT_PUBLIC_INPUT_ORDER),
                    "values_le32_hex": [_public_input_bytes(v) for v in public_inputs],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="ascii",
        )
        cases_path.write_text(
            json.dumps(
                {
                    "format": "zycoin-python-output-proof-cases-v1",
                    "public_input_order": list(OUTPUT_PUBLIC_INPUT_ORDER),
                    "cases": _cases(proof_bytes, public_inputs),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="ascii",
        )
        bellman, bellman_wall_seconds, bellman_peak_rss_bytes = _verify_with_bellman(
            parameter_path, assignment_path, cases_path, bellman_result_path
        )
        if bellman["format"] != "bellman-0.15-python-output-proof-verification-v1":
            raise RuntimeError("unexpected Bellman verification result format")
        bellman_results = {case["name"]: case for case in bellman["results"]}
        expected = {
            "valid": True,
            "altered-proof-point": False,
            "altered-public-input": False,
            "reordered-public-inputs": False,
            "malformed-proof-encoding": False,
        }
        if {name: result["accepted"] for name, result in bellman_results.items()} != expected:
            raise RuntimeError("Bellman proof verification did not match expected cases")
        if not bellman_results["valid"]["canonical_proof_encoding"]:
            raise RuntimeError("Bellman rejected canonical proof encoding")
        if not bellman["witness_validation"]["satisfied"] or (
            bellman["witness_validation"]["constraints_checked"] != 7_827
        ):
            raise RuntimeError("Bellman did not independently validate the witness")
        if not bellman["witness_validation"]["public_inputs_match_assignment"]:
            raise RuntimeError("Bellman did not independently reconstruct public inputs")

        return {
            "format": "zycoin-authentic-output-python-proof-interoperability-v1",
            "proof_generated_by": "ZyCoin pure-Python assemble_proof_elements",
            "proof_randomness": {
                "source": "fixed SHA-256 test-only derivation",
                "r_sha256": hashlib.sha256(seed_r).hexdigest(),
                "s_sha256": hashlib.sha256(seed_s).hexdigest(),
                "production_secure_randomness": False,
            },
            "parameter_file": {
                "sha256": parsed["sha256"],
                "blake2b512": parsed["blake2b512"],
                "trailing_transcript_bytes": parsed["trailing_bytes"],
            },
            "witness": {
                "assignment_sha256": ASSIGNMENT_SHA256,
                "matrix_fingerprint": MATRIX_FINGERPRINT,
                "rows": system.constraint_count,
                "columns": len(system.variables),
                "query_mapping_fingerprint": MAPPING_FINGERPRINT,
                "qap_domain": qap.domain.size,
            },
            "public_inputs": {
                "order": list(OUTPUT_PUBLIC_INPUT_ORDER),
                "count": len(public_inputs),
                "values_le32_hex": [_public_input_bytes(v) for v in public_inputs],
            },
            "proof": {
                "encoding": "Bellman compressed G1/G2/G1; 48+96+48 bytes",
                "bytes": len(proof_bytes),
                "sha256": hashlib.sha256(proof_bytes).hexdigest(),
                "canonical_hex": proof_bytes.hex(),
                "temporary_file_exported": True,
                "temporary_file_retained": False,
            },
            "python": {
                "accepted_valid_proof": valid_accepted,
                "negative_cases_rejected": python_negative,
                "timings_seconds": {
                    "witness_and_matrix_construction": witness_synthesis_seconds,
                    "qap_quotient": qap_seconds,
                    "query_accumulation": {
                        "h": h_msm_seconds,
                        "l": l_msm_seconds,
                        "a": a_msm_seconds,
                        "b_g1": b_g1_msm_seconds,
                        "b_g2": b_g2_msm_seconds,
                        "total": sum(
                            (
                                h_msm_seconds,
                                l_msm_seconds,
                                a_msm_seconds,
                                b_g1_msm_seconds,
                                b_g2_msm_seconds,
                            )
                        ),
                    },
                    "proof_construction_including_qap_and_msm": proof_assembly_seconds,
                    "proof_encoding": proof_encoding_seconds,
                    "verification": python_verification_seconds,
                    "parameter_parse_and_subgroup_validation": parameter_parse_seconds,
                    "validated_query_wrapping": query_validation_seconds,
                    "total": time.perf_counter() - total_started,
                },
                "memory_bytes": {
                    "working_set_before_run": initial_working_set,
                    "process_peak_working_set": _python_peak_working_set_bytes(),
                },
            },
            "bellman": {
                "version": "0.15.0",
                "witness_validation": bellman["witness_validation"],
                "valid_proof_accepted": bellman_results["valid"]["accepted"],
                "negative_cases_rejected": {
                    case["name"]: not case["accepted"]
                    for case in bellman["results"]
                    if case["name"] != "valid"
                },
                "timings_seconds": {
                    "all_cases_with_runner_and_parameter_loading": bellman_wall_seconds,
                },
                "peak_rss_bytes": bellman_peak_rss_bytes,
            },
            "all_expected_results": True,
            "authentic_ceremony_validity_established": False,
            "production_readiness_established": False,
            "spend_scope": "Not tested or inferred.",
        }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: python tests/generate_verify_sapling_output_python_proof.py "
            "<official-sapling-output.params>"
        )
    print(json.dumps(run(Path(sys.argv[1])), sort_keys=True, indent=2))
