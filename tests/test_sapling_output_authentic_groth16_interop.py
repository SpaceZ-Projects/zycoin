"""Opt-in authentic Sapling Output Groth16 interoperability test.

Set ZYCOIN_SAPLING_OUTPUT_PARAMS to the externally downloaded, hash-verified
official Output parameter file. The file and all generated proofs remain
outside the repository.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import runpy
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from ctypes import wintypes
from pathlib import Path

from src.bls12_381 import (
    G1_GENERATOR,
    SCALAR_MODULUS,
    add_g1,
    decode_g1,
    decode_g2,
    encode_g1,
    encode_g1_uncompressed,
    encode_g2,
    encode_g2_uncompressed,
)
from src.groth16_parameters import read_parameter_stream
from src.groth16_verification import (
    Groth16Proof,
    Groth16VerificationKey,
    verify_groth16_proof,
)
from tests.sapling_output_query_compatibility import (
    compare_parameter_queries_from_files,
    validate_query_index_mapping,
)
from tests.sapling_parameter_query_mapping import build_output_query_index_mapping

ROOT = Path(__file__).resolve().parents[1]
PARAMS_ENV = "ZYCOIN_SAPLING_OUTPUT_PARAMS"
PARAMETER_SHA256 = "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
PARAMETER_SHA512 = (
    "a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf"
    "93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152"
)
PARAMETER_BLAKE2B512 = (
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b"
    "f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
)
ASSIGNMENT_SHA256 = "b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea"
PROOF_SHA256 = "8c8823da4046dc6e88640876018ec2bfeab2682d2f0a9dbfe5e085e18443c4c1"
VERIFICATION_KEY_SHA256 = (
    "d7a655f6f58745f17bf5344682d25d15967e39b575d072335e14ace0a871bd0c"
)
ROW_ARTIFACT_SHA256 = "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761"
VARIABLE_MAPPING_FINGERPRINT = (
    "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
)
MATRIX_FINGERPRINT = "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
OUTPUT_PUBLIC_INPUT_ORDER = ("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u")
SUBGROUP_COUNTS = {
    "h": 8_191,
    "l": 7_821,
    "a": 6_298,
    "b_g1": 4_850,
    "b_g2": 4_850,
}


def _file_digest(path: Path, algorithm: str) -> str:
    with path.open("rb") as stream:
        if algorithm == "blake2b512":
            digest = hashlib.file_digest(
                stream, lambda: hashlib.blake2b(digest_size=64)
            )
        else:
            digest = hashlib.file_digest(stream, algorithm)
    return digest.hexdigest()


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    if not resolved.drive:
        raise RuntimeError(f"cannot map path into WSL: {resolved}")
    drive = resolved.drive[0].lower()
    return f"/mnt/{drive}/" + "/".join(resolved.parts[1:])


def _run_bellman_prover(
    params: Path, assignment: Path, proof: Path, query_export: Path
) -> int | None:
    manifest = ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
    binary = "authentic_output_prover"
    row_artifact = ROOT / "tests" / "fixtures" / "sapling_output_row_correspondence.json"
    wsl = shutil.which("wsl")
    if wsl:
        paths = (manifest, params, row_artifact, assignment, proof, query_export)
        converted = [_wsl_path(path) for path in paths]
        root = _wsl_path(ROOT)
        command = (
            f"cd {shlex.quote(root)} && /usr/bin/time -f "
            f"'ZYCOIN_MAX_RSS_KIB=%M' rustup run 1.97.0 cargo run "
            f"--offline --release --manifest-path {shlex.quote(converted[0])} "
            f"--bin {binary} -- {shlex.quote(converted[1])} "
            f"{shlex.quote(converted[2])} {shlex.quote(converted[3])} "
            f"{shlex.quote(converted[4])} {shlex.quote(converted[5])}"
        )
        result = subprocess.run(
            [wsl, "--", "bash", "-lc", command],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        match = re.search(r"ZYCOIN_MAX_RSS_KIB=(\d+)", result.stderr)
        if match is None:
            raise RuntimeError("Bellman runner did not report peak RSS")
        return int(match.group(1))
    subprocess.run(
        [
            "cargo",
            "run",
            "--offline",
            "--release",
            "--manifest-path",
            str(manifest),
            "--bin",
            binary,
            "--",
            str(params),
            str(row_artifact),
            str(assignment),
            str(proof),
            str(query_export),
        ],
        cwd=ROOT,
        check=True,
    )
    return None


def _peak_working_set_bytes() -> int | None:
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


@unittest.skipUnless(os.environ.get(PARAMS_ENV), f"set {PARAMS_ENV} to run")
class AuthenticOutputGroth16InteropTests(unittest.TestCase):
    def test_bellman_proof_verifies_in_pure_python(self):
        started = time.perf_counter()
        params = Path(os.environ[PARAMS_ENV]).resolve()
        self.assertTrue(params.is_file())
        self.assertEqual(_file_digest(params, "sha256"), PARAMETER_SHA256)
        self.assertEqual(_file_digest(params, "sha512"), PARAMETER_SHA512)
        self.assertEqual(
            _file_digest(params, "blake2b512"), PARAMETER_BLAKE2B512
        )

        reports = ROOT / "reports"
        subgroup_manifest = json.loads(
            (reports / "sapling-query-subgroup-validation.json").read_text(
                encoding="utf-8"
            )
        )
        subgroup = subgroup_manifest["circuits"]["sapling-output"]
        self.assertEqual(subgroup["sha256"], PARAMETER_SHA256)
        self.assertEqual(subgroup["section_counts"], SUBGROUP_COUNTS)
        self.assertEqual(subgroup["query_points_rejected"], 0)
        self.assertTrue(subgroup_manifest["all_points_accounted_once"])

        mapping = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "sapling_output_parameter_query_index_mapping.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(mapping["mapping_fingerprint_sha256"], (
            "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2"
        ))
        self.assertEqual(len(mapping["a_query"]), SUBGROUP_COUNTS["a"])
        self.assertEqual(len(mapping["b_g1_query"]), SUBGROUP_COUNTS["b_g1"])
        self.assertEqual(len(mapping["b_g2_query"]), SUBGROUP_COUNTS["b_g2"])
        row_artifact = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "sapling_output_row_correspondence.json"
            ).read_text(encoding="utf-8")
        )
        variable_artifact = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "sapling_output_variable_correspondence.json"
            ).read_text(encoding="utf-8")
        )
        regenerated_mapping = build_output_query_index_mapping(
            row_artifact,
            variable_artifact,
            {
                "a": SUBGROUP_COUNTS["a"],
                "b_g1": SUBGROUP_COUNTS["b_g1"],
                "b_g2": SUBGROUP_COUNTS["b_g2"],
            },
        )
        validate_query_index_mapping(mapping, regenerated_mapping)
        self.assertEqual(
            [entry["upstream_identity"] for entry in mapping["ic_query"]],
            [
                "Input(0)",
                "Input(1)",
                "Input(2)",
                "Input(3)",
                "Input(4)",
                "Input(5)",
            ],
        )
        self.assertEqual(mapping["l_query"]["upstream_identity"], "Aux(query_index)")
        self.assertEqual(mapping["l_query"]["query_index_start"], 0)
        self.assertEqual(mapping["l_query"]["query_index_end_exclusive"], 7_821)
        self.assertEqual(mapping["h_query"]["query_index_start"], 0)
        self.assertEqual(mapping["h_query"]["query_index_end_exclusive"], 8_191)

        qap_reference = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "sapling_output_bellman_qap_reference.json"
            ).read_text(encoding="ascii")
        )
        case = qap_reference["cases"][0]
        self.assertEqual(case["name"], "zcash-note-encryption-vector-0")
        self.assertTrue(case["satisfied"])
        self.assertEqual(qap_reference["matrix_fingerprint"], MATRIX_FINGERPRINT)
        self.assertEqual(
            qap_reference["row_artifact_sha256"], ROW_ARTIFACT_SHA256
        )
        self.assertEqual(
            qap_reference["variable_mapping_fingerprint_sha256"],
            VARIABLE_MAPPING_FINGERPRINT,
        )
        assignment_input = runpy.run_path(
            str(ROOT / "tests" / "generate_sapling_output_qap_reference.py")
        )["_assignment_input"]()
        self.assertEqual(assignment_input["row_artifact_sha256"], ROW_ARTIFACT_SHA256)
        self.assertEqual(
            assignment_input["variable_mapping_fingerprint_sha256"],
            VARIABLE_MAPPING_FINGERPRINT,
        )
        witness_case = assignment_input["cases"][0]
        self.assertEqual(witness_case["name"], case["name"])
        self.assertEqual(
            witness_case["assignment_sha256"], ASSIGNMENT_SHA256
        )
        assignment_hex = witness_case["assignment_hex"]
        self.assertEqual(len(assignment_hex), 7_827)
        assignment_bytes = b"".join(bytes.fromhex(value) for value in assignment_hex)
        self.assertEqual(hashlib.sha256(assignment_bytes).hexdigest(), ASSIGNMENT_SHA256)
        prover_assignment = dict(assignment_input)
        prover_assignment["cases"] = [witness_case]

        with tempfile.TemporaryDirectory(
            prefix="zycoin-output-groth16-interop-"
        ) as directory:
            work = Path(directory)
            assignment_path = work / "assignment.json"
            proof_path = work / "proof.bin"
            query_export_path = work / "bellman-query-points.bin"
            assignment_path.write_text(
                json.dumps(prover_assignment, separators=(",", ":"), sort_keys=True),
                encoding="ascii",
            )
            proving_started = time.perf_counter()
            bellman_peak_rss_kib = _run_bellman_prover(
                params, assignment_path, proof_path, query_export_path
            )
            proving_seconds = time.perf_counter() - proving_started
            query_comparison_started = time.perf_counter()
            query_comparison = compare_parameter_queries_from_files(
                str(params), str(query_export_path)
            )
            query_comparison_seconds = (
                time.perf_counter() - query_comparison_started
            )
            self.assertTrue(query_comparison["all_points_exact"])
            self.assertEqual(query_comparison["total_points"], 32_016)
            self.assertEqual(
                query_comparison["python_parameter_sha256"], PARAMETER_SHA256
            )
            query_export_sha256 = _file_digest(query_export_path, "sha256")
            query_export_bytes = query_export_path.stat().st_size
            proof_bytes = proof_path.read_bytes()
            self.assertEqual(hashlib.sha256(proof_bytes).hexdigest(), PROOF_SHA256)

            with params.open("rb") as stream:
                parser = read_parameter_stream(stream, allow_trailing_data=True)
                bellman_vk = parser.metadata.verification_key
            self.assertEqual(len(bellman_vk.ic), 6)
            verification_key = Groth16VerificationKey(
                alpha_g1=bellman_vk.alpha_g1,
                beta_g2=bellman_vk.beta_g2,
                gamma_g2=bellman_vk.gamma_g2,
                delta_g2=bellman_vk.delta_g2,
                ic_query=bellman_vk.ic,
            )
            self.assertEqual(verification_key.public_input_count, 5)

            self.assertEqual(len(proof_bytes), 192)
            proof = Groth16Proof(
                decode_g1(proof_bytes[:48]),
                decode_g2(proof_bytes[48:144]),
                decode_g1(proof_bytes[144:]),
            )
            self.assertEqual(encode_g1(proof.a.point), proof_bytes[:48])
            self.assertEqual(encode_g2(proof.b.point), proof_bytes[48:144])
            self.assertEqual(encode_g1(proof.c.point), proof_bytes[144:])
            public_inputs = tuple(
                int.from_bytes(bytes.fromhex(value), "little")
                for value in assignment_hex[1:6]
            )
            self.assertEqual(len(OUTPUT_PUBLIC_INPUT_ORDER), len(public_inputs))
            self.assertTrue(
                all(0 <= value < SCALAR_MODULUS for value in public_inputs)
            )

            verify_started = time.perf_counter()
            self.assertTrue(
                verify_groth16_proof(verification_key, proof, public_inputs)
            )
            valid_verify_seconds = time.perf_counter() - verify_started

            changed_inputs = (
                (public_inputs[0] + 1) % SCALAR_MODULUS,
                *public_inputs[1:],
            )
            self.assertFalse(
                verify_groth16_proof(verification_key, proof, changed_inputs)
            )
            changed_proof = Groth16Proof(
                add_g1(proof.a.point, G1_GENERATOR),
                proof.b,
                proof.c,
            )
            self.assertFalse(
                verify_groth16_proof(verification_key, changed_proof, public_inputs)
            )
            with self.assertRaises(ValueError):
                decode_g1(proof_bytes[:47])
            with self.assertRaises(ValueError):
                decode_g2(bytes(96))

            key_material = b"".join(
                (
                    encode_g1_uncompressed(bellman_vk.alpha_g1),
                    encode_g1_uncompressed(bellman_vk.beta_g1),
                    encode_g2_uncompressed(bellman_vk.beta_g2),
                    encode_g2_uncompressed(bellman_vk.gamma_g2),
                    encode_g1_uncompressed(bellman_vk.delta_g1),
                    encode_g2_uncompressed(bellman_vk.delta_g2),
                    len(bellman_vk.ic).to_bytes(4, "big"),
                    *(encode_g1_uncompressed(point) for point in bellman_vk.ic),
                )
            )
            verification_key_sha256 = hashlib.sha256(key_material).hexdigest()
            self.assertEqual(verification_key_sha256, VERIFICATION_KEY_SHA256)
            print(
                json.dumps(
                    {
                        "parameter_sha256": PARAMETER_SHA256,
                        "verification_key_sha256": verification_key_sha256,
                        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
                        "proof_bytes": len(proof_bytes),
                        "query_export_sha256": query_export_sha256,
                        "query_export_bytes": query_export_bytes,
                        "query_comparison": query_comparison,
                        "public_input_order": OUTPUT_PUBLIC_INPUT_ORDER,
                        "public_inputs": [f"{value:064x}" for value in public_inputs],
                        "query_counts": SUBGROUP_COUNTS,
                        "proving_seconds_including_runner_startup": proving_seconds,
                        "query_comparison_seconds": query_comparison_seconds,
                        "bellman_runner_peak_rss_kib": bellman_peak_rss_kib,
                        "python_valid_verification_seconds": valid_verify_seconds,
                        "total_test_seconds": time.perf_counter() - started,
                        "python_peak_working_set_bytes": _peak_working_set_bytes(),
                    },
                    sort_keys=True,
                )
            )


if __name__ == "__main__":
    unittest.main()
