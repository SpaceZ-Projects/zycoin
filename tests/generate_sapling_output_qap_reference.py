"""Generate or check the test-only Bellman 0.15 Output QAP reference fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.jubjub import Point
from src.bls12_381 import SCALAR_MODULUS
from src.r1cs import R1CS
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness

FIXTURES = ROOT / "tests" / "fixtures"
ROW_ARTIFACT = FIXTURES / "sapling_output_row_correspondence.json"
VARIABLE_ARTIFACT = FIXTURES / "sapling_output_variable_correspondence.json"
REFERENCE_CRATE = ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
OUTPUT_FIXTURE = FIXTURES / "sapling_output_bellman_qap_reference.json"
REFERENCE_SHA256 = "0d13e5d1e073139fdb6c2e609a77acb6a296ea7582cb0d92337a3f6ec71ed571"
MATRIX_FINGERPRINT = "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
FIELD_BYTES = 32


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def synthesize_cases() -> list[tuple[str, R1CS]]:
    fixture = _read_json(FIXTURES / "sapling_output_reference.json")["cases"][0]
    key = Point.from_bytes(
        bytes.fromhex(fixture["transmission_key"]), check_subgroup=True
    )
    cases = [
        (
            "zcash-note-encryption-vector-0",
            fixture["value"],
            int.from_bytes(bytes.fromhex(fixture["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(fixture["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(fixture["esk"]), "little"),
        ),
        ("zero-value-boundary", 0, 1, 2, 3),
        ("maximum-u64-value-boundary", (1 << 64) - 1, 4, 5, 6),
    ]
    result: list[tuple[str, R1CS]] = []
    for name, value, rcv, rcm, esk in cases:
        witness = make_sapling_output_witness(
            value,
            bytes.fromhex(fixture["diversifier"]),
            key,
            rcv,
            rcm,
            esk,
        )
        system = R1CS()
        constrain_sapling_output(system, witness)
        if system.constraint_count != 7_827 or len(system.variables) != 7_827:
            raise RuntimeError(f"{name}: unexpected Output circuit dimensions")
        if system.matrix_fingerprint() != MATRIX_FINGERPRINT:
            raise RuntimeError(f"{name}: Output matrix fingerprint changed")
        if not system.is_satisfied():
            raise RuntimeError(f"{name}: Output witness is unsatisfied")
        result.append((name, system))
    return result


def _witness_cases() -> list[tuple[str, dict[str, Any]]]:
    result: list[tuple[str, dict[str, Any]]] = []
    systems = synthesize_cases()
    for name, system in systems:
        values = [system.witness_value(variable) for variable in system.variables]
        if any(value is None for value in values):
            raise RuntimeError(f"{name}: Output witness contains unassigned variables")
        assignment_hex = [
            int(value).to_bytes(FIELD_BYTES, "little").hex() for value in values
        ]
        assignment_bytes = b"".join(bytes.fromhex(value) for value in assignment_hex)
        result.append(
            (
                name,
                {
                    "assignment_sha256": hashlib.sha256(assignment_bytes).hexdigest(),
                    "assignment_hex": assignment_hex,
                },
            )
        )
    invalid_name, invalid_system = systems[1]
    invalid_values = [
        system_value
        for system_value in (
            invalid_system.witness_value(variable)
            for variable in invalid_system.variables
        )
    ]
    if any(value is None for value in invalid_values):
        raise RuntimeError(f"{invalid_name}: Output witness is unassigned")
    invalid_values[1] = (int(invalid_values[1]) + 1) % SCALAR_MODULUS
    if invalid_system.is_satisfied({1: invalid_values[1]}):
        raise RuntimeError("public-input tamper unexpectedly satisfies Output")
    invalid_assignment_hex = [
        int(value).to_bytes(FIELD_BYTES, "little").hex()
        for value in invalid_values
    ]
    invalid_assignment_bytes = b"".join(
        bytes.fromhex(value) for value in invalid_assignment_hex
    )
    result.append(
        (
            "unsatisfied-public-input-tamper",
            {
                "assignment_sha256": hashlib.sha256(
                    invalid_assignment_bytes
                ).hexdigest(),
                "assignment_hex": invalid_assignment_hex,
            },
        )
    )
    return result


def _assignment_input() -> dict[str, Any]:
    row_bytes = ROW_ARTIFACT.read_bytes()
    variable = _read_json(VARIABLE_ARTIFACT)
    if variable["mapping_fingerprint_sha256"] != (
        "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
    ):
        raise RuntimeError("Output variable mapping fingerprint changed")
    return {
        "format": "zycoin-sapling-output-qap-assignment-input-v1",
        "row_artifact_sha256": hashlib.sha256(row_bytes).hexdigest(),
        "variable_mapping_fingerprint_sha256": variable[
            "mapping_fingerprint_sha256"
        ],
        "matrix_fingerprint": MATRIX_FINGERPRINT,
        "cases": [
            {"name": name, **assignments}
            for name, assignments in _witness_cases()
        ],
    }


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    if not resolved.drive:
        raise RuntimeError(f"cannot map path into WSL: {resolved}")
    drive = resolved.drive[0].lower()
    parts = resolved.parts[1:]
    return f"/mnt/{drive}/" + "/".join(parts)


def _run_reference(output_path: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="sapling-output-qap-") as directory:
        assignment_path = Path(directory) / "assignments.json"
        reference_path = Path(directory) / "reference.json"
        assignment_path.write_text(
            json.dumps(_assignment_input(), separators=(",", ":"), sort_keys=True),
            encoding="ascii",
        )
        wsl = shutil.which("wsl")
        if wsl is not None:
            reference_paths = [
                _wsl_path(path)
                for path in (REFERENCE_CRATE, ROW_ARTIFACT, assignment_path, reference_path)
            ]
            wsl_root = _wsl_path(ROOT)
            command = (
                f"cd {shlex.quote(wsl_root)} && "
                "rustup run 1.97.0 cargo run --quiet --release "
                f"--manifest-path {shlex.quote(reference_paths[0])} -- "
                f"{shlex.quote(reference_paths[1])} "
                f"{shlex.quote(reference_paths[2])} "
                f"{shlex.quote(reference_paths[3])}"
            )
            subprocess.run([wsl, "--", "bash", "-lc", command], check=True)
        else:
            subprocess.run(
                [
                    "cargo",
                    "run",
                    "--quiet",
                    "--release",
                    "--manifest-path",
                    str(REFERENCE_CRATE),
                    "--",
                    str(ROW_ARTIFACT),
                    str(assignment_path),
                    str(reference_path),
                ],
                cwd=ROOT,
                check=True,
            )
        result = reference_path.read_bytes()
    if output_path is not None:
        output_path.write_bytes(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--write", action="store_true")
    operation.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.write:
        content = _run_reference(OUTPUT_FIXTURE)
        print(f"Wrote {OUTPUT_FIXTURE.relative_to(ROOT)} ({len(content)} bytes)")
        print(f"SHA-256: {hashlib.sha256(content).hexdigest()}")
        return

    with tempfile.TemporaryDirectory(prefix="sapling-output-qap-check-") as directory:
        regenerated = _run_reference(Path(directory) / "reference.json")
    expected = OUTPUT_FIXTURE.read_bytes()
    regenerated_hash = hashlib.sha256(regenerated).hexdigest()
    if regenerated != expected:
        raise SystemExit(
            "Bellman QAP reference fixture is not deterministic: regenerated "
            f"SHA-256 {regenerated_hash}, expected "
            f"{hashlib.sha256(expected).hexdigest()}"
        )
    if regenerated_hash != REFERENCE_SHA256:
        raise SystemExit(
            f"unexpected Bellman reference SHA-256: {regenerated_hash}"
        )
    print(f"Deterministic Bellman QAP reference SHA-256: {regenerated_hash}")


if __name__ == "__main__":
    main()
