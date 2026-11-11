"""Compare complete authentic Output MSMs against pinned Bellman 0.15.

Run as:
    python tests/validate_sapling_output_authentic_msm.py <sapling-output.params>

The Bellman executable is test-only. It emits accumulation points only; no
Groth16 proof is created.
"""

from __future__ import annotations

import hashlib
import json
import re
import runpy
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.benchmark_sapling_output_authentic_msm import (
    MAPPING_FILE_SHA256,
    PARAMETER_BLAKE2B512,
    PARAMETER_SHA256,
    _file_digests,
)
from tests.benchmark_sapling_output_authentic_msm import (
    run as run_python_msm,
)

RUNNER_MANIFEST = ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
RUNNER_BINARY = "authentic_output_msm_reference"
REFERENCE_NAMES = {
    "A_G1": "a",
    "B_G1": "b_g1",
    "B_G2": "b_g2",
    "H_G1": "h",
    "L_G1": "l",
}
ROWS = ROOT / "tests" / "fixtures" / "sapling_output_row_correspondence.json"
ASSIGNMENT = ROOT / "tests" / "fixtures" / "sapling_output_bellman_qap_reference.json"
MAPPING = ROOT / "tests" / "fixtures" / "sapling_output_parameter_query_index_mapping.json"


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    if not resolved.drive:
        raise RuntimeError(f"cannot map path into WSL: {resolved}")
    drive = resolved.drive[0].lower()
    return f"/mnt/{drive}/" + "/".join(resolved.parts[1:])


def _run_bellman(
    params: Path,
    assignment_path: Path,
    export_path: Path,
    metrics_path: Path,
) -> tuple[dict[str, Any], float, int | None]:
    wsl = shutil.which("wsl")
    started = time.perf_counter()
    if wsl:
        paths = (
            RUNNER_MANIFEST,
            params,
            ROWS,
            assignment_path,
            MAPPING,
            export_path,
            metrics_path,
        )
        converted = [_wsl_path(path) for path in paths]
        root = _wsl_path(ROOT)
        command = (
            f"cd {shlex.quote(root)} && /usr/bin/time -f "
            f"'ZYCOIN_MAX_RSS_KIB=%M' rustup run 1.97.0 cargo run "
            f"--offline --release --manifest-path {shlex.quote(converted[0])} "
            f"--bin {RUNNER_BINARY} -- {shlex.quote(converted[1])} "
            f"{shlex.quote(converted[2])} {shlex.quote(converted[3])} "
            f"{shlex.quote(converted[4])} {shlex.quote(converted[5])} "
            f"{shlex.quote(converted[6])}"
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
        peak_rss_bytes = int(match.group(1)) * 1024
    else:
        subprocess.run(
            [
                "cargo",
                "run",
                "--offline",
                "--release",
                "--manifest-path",
                str(RUNNER_MANIFEST),
                "--bin",
                RUNNER_BINARY,
                "--",
                str(params),
                str(ROWS),
                str(assignment_path),
                str(MAPPING),
                str(export_path),
                str(metrics_path),
            ],
            cwd=ROOT,
            check=True,
        )
        peak_rss_bytes = None
    elapsed = time.perf_counter() - started
    return json.loads(metrics_path.read_text(encoding="utf-8")), elapsed, peak_rss_bytes


def run(parameter_path: Path) -> dict[str, Any]:
    parameter_path = parameter_path.resolve(strict=True)
    if not parameter_path.is_file():
        raise ValueError("parameter path must name a file")
    sha256, blake2b512 = _file_digests(parameter_path)
    if sha256 != PARAMETER_SHA256 or blake2b512 != PARAMETER_BLAKE2B512:
        raise RuntimeError("official Output parameter hash pin mismatch")
    if hashlib.sha256(MAPPING.read_bytes()).hexdigest() != MAPPING_FILE_SHA256:
        raise RuntimeError("Output query mapping artifact hash mismatch")

    with tempfile.TemporaryDirectory(prefix="zycoin-output-msm-reference-") as directory:
        temporary = Path(directory)
        assignment_path = temporary / "output-assignment-input.json"
        assignment_input = runpy.run_path(
            str(ROOT / "tests" / "generate_sapling_output_qap_reference.py")
        )["_assignment_input"]()
        assignment_path.write_text(
            json.dumps(assignment_input, separators=(",", ":"), sort_keys=True),
            encoding="ascii",
        )
        export_path = temporary / "bellman-output-msm.bin"
        metrics_path = temporary / "bellman-output-msm.json"
        bellman, bellman_wall_seconds, bellman_peak_rss_bytes = _run_bellman(
            parameter_path,
            assignment_path,
            export_path,
            metrics_path,
        )
        if not export_path.is_file() or export_path.stat().st_size == 0:
            raise RuntimeError("Bellman runner did not produce its accumulation export")
        export_sha256 = hashlib.sha256(export_path.read_bytes()).hexdigest()
        python = run_python_msm(parameter_path, export_path)

        if bellman["format"] != "bellman-0.15-authentic-output-msm-reference-v1":
            raise RuntimeError("unexpected Bellman reference metadata")
        if bellman["parameter_sha256"] != PARAMETER_SHA256:
            raise RuntimeError("Bellman metrics have the wrong parameter hash")
        if bellman["assignment_sha256"] != python["output_witness"]["assignment_sha256"]:
            raise RuntimeError("Bellman and Python used different witness fixtures")
        if bellman["mapping_fingerprint_sha256"] != python["query_mapping_fingerprint"]:
            raise RuntimeError("Bellman and Python used different sparse query maps")
        if bellman["matrix_fingerprint"] != python["output_witness"]["matrix_fingerprint"]:
            raise RuntimeError("Bellman and Python used different matrix fixtures")
        if not all(
            section["bellman_exact_match"]
            for section in python["authentic_query_accumulations"].values()
        ) or not python["ic_accumulation"]["bellman_exact_match"]:
            raise RuntimeError("complete Bellman/Python accumulation equality failed")
        python_identity_results = {
            "ic": python["ic_accumulation"]["identity_result"],
            **{
                REFERENCE_NAMES[name]: section["identity_result"]
                for name, section in python["authentic_query_accumulations"].items()
            },
        }
        bellman_identity_results = {
            section["name"]: section["identity"]
            for section in bellman["identity_results"]
        }
        if python_identity_results != bellman_identity_results:
            raise RuntimeError("Bellman/Python accumulation identity status differs")
        if not all(python["negative_mutation_checks"].values()):
            raise RuntimeError("a negative mutation check did not reject")

        return {
            "format": "zycoin-output-authentic-msm-independent-validation-v1",
            "authentic_proof_generated": False,
            "parameter_file": {
                "name": parameter_path.name,
                "bytes": parameter_path.stat().st_size,
                "sha256": sha256,
                "blake2b512": blake2b512,
            },
            "witness": python["output_witness"],
            "query_mapping_fingerprint": python["query_mapping_fingerprint"],
            "reference": {
                "implementation": "Bellman 0.15.0, test-only Rust runner",
                "metrics": bellman,
                "export_sha256": export_sha256,
                "export_bytes": export_path.stat().st_size,
                "wall_seconds_including_runner_startup": bellman_wall_seconds,
                "peak_rss_bytes": bellman_peak_rss_bytes,
                "export_retained": False,
            },
            "python": {
                "timings_seconds": python["timings_seconds"],
                "memory_bytes": python["memory_bytes"],
                "full_accumulations": python["authentic_query_accumulations"],
                "ic_accumulation": python["ic_accumulation"],
                "affine_oracle_subset_comparisons": python[
                    "affine_oracle_subset_comparisons"
                ],
                "negative_mutation_checks": python["negative_mutation_checks"],
                "boundary_checks": python["window_and_scalar_boundary_checks"],
            },
            "all_exact_point_matches": True,
            "proof_generation_correctness_established": False,
            "ceremony_validity_established": False,
            "production_readiness_established": False,
        }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: python tests/validate_sapling_output_authentic_msm.py "
            "<official-sapling-output.params>"
        )
    print(json.dumps(run(Path(sys.argv[1])), sort_keys=True, indent=2))
