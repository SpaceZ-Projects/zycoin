"""Alternate-witness Spend QAP comparison against pinned Bellman."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from src.groth16_qap import QAP, QAPAssignment
from src.r1cs import R1CS
from src.sapling_spend_circuit import constrain_sapling_spend
from tests.test_sapling_spend_authentic_query_accumulation import (
    _read_bellman_accumulations,
    _run_bellman_accumulation,
)
from tests.test_sapling_spend_parameter_compatibility import PARAMETER_PATH
from tests.test_sapling_spend_qap_compatibility import (
    LOCAL_MATRIX_FINGERPRINT,
    LOCAL_VECTOR_HASHES,
    QUERY_MAPPING_FINGERPRINT,
    REFERENCE_VECTOR_HASHES,
    ROOT,
    _linux_path,
    _run_bellman_qap,
    _sha256_scalar_vector,
    _validate_witness_mapping,
)

REFERENCE = ROOT / "tests" / "reference" / "sapling-output-qap"
MANIFEST = REFERENCE / "Cargo.toml"
MAPPING_PATH = (
    ROOT / "tests" / "fixtures" / "sapling_spend_parameter_query_index_mapping.json"
)


def _run_bellman_variant_synthesis(trace_path: Path, variant: str) -> None:
    wsl = shutil.which("wsl")
    if wsl:
        command = (
            f"cd {shlex.quote(_linux_path(ROOT))} && "
            f"SAPLING_SPEND_VARIANT={shlex.quote(variant)} "
            f"SAPLING_SPEND_EXPORT={shlex.quote(_linux_path(trace_path))} "
            f"rustup run 1.97.0 cargo test --offline --manifest-path "
            f"{shlex.quote(_linux_path(MANIFEST))} --test export_spend "
            "export_spend_variant_fixture -- --exact --nocapture"
        )
        subprocess.run([wsl, "--", "bash", "-lc", command], cwd=ROOT, check=True)
        return

    environment = os.environ.copy()
    environment["SAPLING_SPEND_VARIANT"] = variant
    environment["SAPLING_SPEND_EXPORT"] = str(trace_path)
    subprocess.run(
        [
            "cargo",
            "test",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
            "--test",
            "export_spend",
            "export_spend_variant_fixture",
            "--",
            "--exact",
            "--nocapture",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
    )


@unittest.skipUnless(
    PARAMETER_PATH.is_file()
    and shutil.which("cargo")
    and (shutil.which("wsl") or os.name != "nt"),
    "official Spend parameters and the pinned Bellman reference are required",
)
class SaplingSpendAlternateQAPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from tests.test_sapling_spend_production_alignment import (
            ProductionSpendAlignmentTests,
        )
        from tests.test_sapling_spend_qap_compatibility import (
            _verify_local_quotient_identity,
        )

        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="zycoin-spend-alternate-qap-"
        )
        cls.addClassCleanup(cls._temporary_directory.cleanup)
        directory = Path(cls._temporary_directory.name)
        cls.trace_path = directory / "bellman-spend-variant.json"
        cls.summary_path = directory / "bellman-spend-variant-qap.json"
        cls.local_h_path = directory / "production-h-coefficients.bin"
        cls.local_evaluations_path = directory / "production-qap-evaluations.bin"
        cls.accumulations_path = directory / "bellman-query-accumulations.bin"
        cls.local_qap_report_path = directory / "bellman-production-qap-check.json"

        started = time.perf_counter()
        _run_bellman_variant_synthesis(cls.trace_path, "zero-value-alternating")
        cls.bellman_export_seconds = time.perf_counter() - started
        cls.reference_trace = json.loads(cls.trace_path.read_text(encoding="utf-8"))
        started = time.perf_counter()
        _run_bellman_qap(cls.trace_path, cls.summary_path)
        cls.bellman_qap_seconds = time.perf_counter() - started
        cls.bellman_qap = json.loads(cls.summary_path.read_text(encoding="utf-8"))

        cls.mapping = json.loads(MAPPING_PATH.read_text(encoding="ascii"))
        cls.production_witness = ProductionSpendAlignmentTests(
            "runTest"
        )._production_witness_from_reference(cls.reference_trace)
        cls.production_system = R1CS()
        started = time.perf_counter()
        constrain_sapling_spend(cls.production_system, cls.production_witness)
        cls.production_synthesis_seconds = time.perf_counter() - started
        if not cls.production_system.is_satisfied():
            raise AssertionError("alternate production Spend witness is unsatisfied")

        auxiliary = tuple(
            cls.production_system.witness_value(variable)
            for variable in cls.production_system.variables[8:]
        )
        if any(value is None for value in auxiliary):
            raise AssertionError("alternate production assignment is incomplete")
        cls.production_qap = QAP.from_r1cs(cls.production_system)
        cls.production_assignment = QAPAssignment(
            cls.production_system.public_inputs(), auxiliary
        )
        cls.production_values = cls.production_qap.validate_assignment(
            cls.production_assignment
        )
        started = time.perf_counter()
        cls.production_evaluations = cls.production_qap.evaluations(
            cls.production_assignment
        )
        cls.production_polynomials = cls.production_qap.polynomials(
            cls.production_assignment
        )
        cls.production_h = cls.production_qap.quotient(cls.production_assignment)
        cls.production_h_evaluations = tuple(
            cls.production_qap.domain.fft_domain.fft(cls.production_h + (0,))
        )
        cls.production_qap_seconds = time.perf_counter() - started

        cls.production_vectors = {
            "a_evaluations": cls.production_evaluations.a,
            "b_evaluations": cls.production_evaluations.b,
            "c_evaluations": cls.production_evaluations.c,
            "a_polynomial_coefficients": cls.production_polynomials.a,
            "b_polynomial_coefficients": cls.production_polynomials.b,
            "c_polynomial_coefficients": cls.production_polynomials.c,
            "quotient_coefficients_h": cls.production_h,
            "quotient_evaluations_h": cls.production_h_evaluations,
        }
        cls.production_vector_hashes = {
            name: _sha256_scalar_vector(values)
            for name, values in cls.production_vectors.items()
        }
        cls.bellman_vector_hashes = {
            vector["name"]: vector["sha256_little_endian_scalars"]
            for vector in cls.bellman_qap["vectors"]
        }
        cls.upstream_values = tuple(
            int.from_bytes(bytes.fromhex(value), "little")
            for value in cls.bellman_qap["assignment_hex"]
        )
        cls.position_variable = next(
            variable
            for variable in cls.production_system.variables
            if variable.name == "Sapling Spend Merkle path position"
        )
        cls.mapped_auxiliary_count = _validate_witness_mapping(
            cls.mapping,
            cls.production_values,
            cls.upstream_values,
            cls.position_variable.index,
            cls.production_witness.anchor,
            cls.production_witness.position,
        )
        cls.local_quotient_identity_verified = _verify_local_quotient_identity(
            cls.production_qap,
            cls.production_polynomials,
            cls.production_h,
        )

        cls.local_h_path.write_bytes(
            b"".join(value.to_bytes(32, "little") for value in cls.production_h)
        )
        cls.local_evaluations_path.write_bytes(
            b"".join(
                value.to_bytes(32, "little")
                for vector in (
                    cls.production_evaluations.a,
                    cls.production_evaluations.b,
                    cls.production_evaluations.c,
                )
                for value in vector
            )
        )
        started = time.perf_counter()
        _run_bellman_accumulation(
            PARAMETER_PATH,
            cls.summary_path,
            MAPPING_PATH,
            cls.local_h_path,
            cls.local_evaluations_path,
            cls.accumulations_path,
            cls.local_qap_report_path,
        )
        cls.bellman_crosscheck_seconds = time.perf_counter() - started
        cls.local_qap_report = json.loads(
            cls.local_qap_report_path.read_text(encoding="utf-8")
        )
        cls.bellman_accumulations = _read_bellman_accumulations(
            cls.accumulations_path
        )
        cls.alternate_h_accumulation_sha256 = hashlib.sha256(
            cls.bellman_accumulations["h"]
        ).hexdigest()
        cls.production_h_accumulation_sha256 = hashlib.sha256(
            cls.bellman_accumulations["h_zycoin"]
        ).hexdigest()

    def test_alternate_qap_vectors_and_bellman_quotient_crosscheck(self) -> None:
        self.assertEqual(
            self.reference_trace["fixture"]["name"],
            "independent zero-value alternating-path Spend witness",
        )
        self.assertEqual(self.production_witness.value, 0)
        self.assertEqual(
            tuple(
                direction
                for _, direction in self.production_witness.authentication_path
            ),
            (True, False) * 16,
        )
        self.assertTrue(self.bellman_qap["satisfied"])
        self.assertTrue(self.bellman_qap["quotient_divisibility_verified"])
        self.assertTrue(self.local_quotient_identity_verified)
        self.assertEqual(self.production_system.constraint_count, 98_777)
        self.assertEqual(len(self.production_system.variables), 98_646)
        self.assertEqual(self.production_system.matrix_fingerprint(), LOCAL_MATRIX_FINGERPRINT)
        self.assertEqual(self.production_qap.domain.size, 131_072)
        self.assertEqual(self.mapped_auxiliary_count, 98_637)
        self.assertEqual(self.mapping["mapping_fingerprint_sha256"], QUERY_MAPPING_FINGERPRINT)
        self.assertTrue(
            all(
                self.bellman_vector_hashes[name] != self.production_vector_hashes[name]
                for name in REFERENCE_VECTOR_HASHES
            ),
            "an alternate-witness canonical QAP vector unexpectedly matched",
        )
        self.assertEqual(
            set(self.bellman_vector_hashes),
            set(REFERENCE_VECTOR_HASHES),
        )
        self.assertEqual(
            set(self.production_vector_hashes),
            set(LOCAL_VECTOR_HASHES),
        )
        self.assertEqual(
            self.local_qap_report["local_quotient_matches_zycoin_coefficients"],
            True,
        )
        self.assertTrue(
            self.local_qap_report["quotient_divisibility_verified"]
        )
        self.assertEqual(
            self.local_qap_report[
                "independently_computed_local_h_coefficients_sha256"
            ],
            self.production_vector_hashes["quotient_coefficients_h"],
        )
        self.assertEqual(
            self.local_qap_report[
                "independently_computed_local_h_evaluations_sha256"
            ],
            self.production_vector_hashes["quotient_evaluations_h"],
        )
        self.assertNotEqual(
            self.bellman_accumulations["h"],
            self.bellman_accumulations["h_zycoin"],
            "the direct official H-query mismatch did not persist",
        )

        baseline_comparison = {
            name: {
                "bellman_same_as_baseline": (
                    self.bellman_vector_hashes[name]
                    == REFERENCE_VECTOR_HASHES[name]
                ),
                "production_same_as_baseline": (
                    self.production_vector_hashes[name] == LOCAL_VECTOR_HASHES[name]
                ),
                "bellman_vs_production_still_different": (
                    self.bellman_vector_hashes[name]
                    != self.production_vector_hashes[name]
                ),
            }
            for name in REFERENCE_VECTOR_HASHES
        }
        print(
            json.dumps(
                {
                    "fixture": "zero-value-alternating",
                    "matrix_dimensions": {
                        "rows": self.production_system.constraint_count,
                        "columns": len(self.production_system.variables),
                    },
                    "domain_size": self.production_qap.domain.size,
                    "bellman_assignment_sha256": self.bellman_qap[
                        "assignment_sha256"
                    ],
                    "production_assignment_sha256": _sha256_scalar_vector(
                        self.production_values
                    ),
                    "mapped_auxiliaries": self.mapped_auxiliary_count,
                    "bellman_vector_hashes": self.bellman_vector_hashes,
                    "production_vector_hashes": self.production_vector_hashes,
                    "baseline_comparison": baseline_comparison,
                    "bellman_quotient_verified": self.bellman_qap[
                        "quotient_divisibility_verified"
                    ],
                    "production_quotient_identity_verified": (
                        self.local_quotient_identity_verified
                    ),
                    "bellman_recomputed_production_h": self.local_qap_report[
                        "local_quotient_matches_zycoin_coefficients"
                    ],
                    "bellman_recomputed_production_h_sha256": self.local_qap_report[
                        "independently_computed_local_h_coefficients_sha256"
                    ],
                    "h_query_accumulation_sha256": {
                        "bellman_coefficients": self.alternate_h_accumulation_sha256,
                        "production_coefficients": self.production_h_accumulation_sha256,
                    },
                    "h_query_mismatch_persists": (
                        self.alternate_h_accumulation_sha256
                        != self.production_h_accumulation_sha256
                    ),
                    "timings_seconds": {
                        "bellman_variant_export": self.bellman_export_seconds,
                        "bellman_qap": self.bellman_qap_seconds,
                        "production_synthesis": self.production_synthesis_seconds,
                        "production_qap": self.production_qap_seconds,
                        "bellman_local_h_crosscheck_and_query_accumulation": (
                            self.bellman_crosscheck_seconds
                        ),
                    },
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
