"""Compare ZyCoin's Output QAP with pinned Bellman 0.15 reference data."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_qap import (
    QAP,
    QAPAssignment,
    UnsatisfiedAssignmentError,
)
from tests.generate_sapling_output_qap_reference import synthesize_cases

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
REFERENCE_FIXTURE = FIXTURES / "sapling_output_bellman_qap_reference.json"
EXPECTED_REFERENCE_SHA256 = (
    "0d13e5d1e073139fdb6c2e609a77acb6a296ea7582cb0d92337a3f6ec71ed571"
)


def _decode_values(values: list[str]) -> tuple[int, ...]:
    decoded = tuple(int.from_bytes(bytes.fromhex(value), "little") for value in values)
    if any(value >= SCALAR_MODULUS for value in decoded):
        raise AssertionError("Bellman reference contains a noncanonical field value")
    return decoded


def _assignment(system) -> QAPAssignment:
    auxiliary = tuple(
        system.witness_value(variable) for variable in system.variables[6:]
    )
    if any(value is None for value in auxiliary):
        raise AssertionError("Output witness contains an unassigned auxiliary")
    return QAPAssignment(system.public_inputs(), auxiliary)


class SaplingOutputIndependentQAPReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_bytes = REFERENCE_FIXTURE.read_bytes()
        cls.fixture = json.loads(cls.fixture_bytes)
        cls.systems = synthesize_cases()

    def test_reference_provenance_domain_and_deterministic_artifact(self):
        reference = self.fixture
        self.assertEqual(
            hashlib.sha256(self.fixture_bytes).hexdigest(),
            EXPECTED_REFERENCE_SHA256,
        )
        self.assertEqual(reference["format"], "bellman-sapling-output-qap-reference-v1")
        self.assertEqual(reference["bellman_crate_version"], "0.15.0")
        self.assertEqual(
            reference["bellman_revision"],
            "b726862a4ece8a627e7fea486d77b502a6edbb0b",
        )
        self.assertEqual(
            reference["sapling_revision"],
            "88a7946b4a3066787776e11f0a502654167e022d",
        )
        self.assertEqual(reference["constraint_count"], 7_827)
        self.assertEqual(reference["input_count_including_one"], 6)
        self.assertEqual(reference["auxiliary_variable_count"], 7_821)
        self.assertEqual(reference["row_count_with_dummy_inputs"], 7_833)
        self.assertEqual(reference["padding_count"], 359)
        self.assertEqual(reference["domain_size"], 8_192)
        self.assertEqual(
            int.from_bytes(bytes.fromhex(reference["omega_hex"]), "little"),
            32731401973776920074999878620293785439674386180695720638377027142500196583783,
        )
        self.assertEqual(
            int.from_bytes(bytes.fromhex(reference["coset_generator_hex"]), "little"),
            7,
        )
        self.assertEqual(
            [case[0] for case in self.systems],
            [
                "zcash-note-encryption-vector-0",
                "zero-value-boundary",
                "maximum-u64-value-boundary",
            ],
        )
        self.assertEqual(len(reference["cases"]), len(self.systems) + 1)

    def test_bellman_evaluations_polynomials_and_quotients_match_exactly(self):
        for (name, system), expected in zip(
            self.systems, self.fixture["cases"][: len(self.systems)], strict=True
        ):
            with self.subTest(case=name):
                qap = QAP.from_r1cs(system)
                assignment = _assignment(system)
                self.assertTrue(system.is_satisfied())
                self.assertTrue(expected["satisfied"])
                self.assertEqual(expected["failed_constraints"], [])
                self.assertTrue(expected["quotient_divisibility_verified"])

                evaluations = qap.evaluations(assignment)
                self.assertEqual(
                    evaluations.a, _decode_values(expected["a_evaluations_hex"])
                )
                self.assertEqual(
                    evaluations.b, _decode_values(expected["b_evaluations_hex"])
                )
                self.assertEqual(
                    evaluations.c, _decode_values(expected["c_evaluations_hex"])
                )

                polynomials = qap.polynomials(assignment)
                self.assertEqual(
                    polynomials.a,
                    _decode_values(expected["a_polynomial_coefficients_hex"]),
                )
                self.assertEqual(
                    polynomials.b,
                    _decode_values(expected["b_polynomial_coefficients_hex"]),
                )
                self.assertEqual(
                    polynomials.c,
                    _decode_values(expected["c_polynomial_coefficients_hex"]),
                )
                quotient = qap.quotient(assignment)
                self.assertEqual(
                    quotient, _decode_values(expected["quotient_coefficients_hex"])
                )
                self.assertEqual(len(quotient), qap.domain.size - 1)

                observed_degrees = [
                    next(
                        (
                            index
                            for index in range(len(coefficients) - 1, -1, -1)
                            if coefficients[index]
                        ),
                        None,
                    )
                    for coefficients in (
                        polynomials.a,
                        polynomials.b,
                        polynomials.c,
                        quotient,
                    )
                ]
                self.assertEqual(observed_degrees, expected["highest_nonzero_degree"])

    def test_dummy_input_rows_one_convention_and_zero_padding(self):
        dummy_start = self.fixture["constraint_count"]
        row_count = self.fixture["row_count_with_dummy_inputs"]
        for (name, system), expected in zip(
            self.systems, self.fixture["cases"][: len(self.systems)], strict=True
        ):
            with self.subTest(case=name):
                qap = QAP.from_r1cs(system)
                assignments = qap.assignment_values(_assignment(system))
                evaluations = qap.evaluations(_assignment(system))
                for input_index, input_value in enumerate(assignments[:6]):
                    row = dummy_start + input_index
                    self.assertEqual(evaluations.a[row], input_value)
                    self.assertEqual(evaluations.b[row], 0)
                    self.assertEqual(evaluations.c[row], 0)
                self.assertEqual(
                    evaluations.a[row_count:],
                    (0,) * self.fixture["padding_count"],
                )
                self.assertEqual(
                    evaluations.b[row_count:],
                    (0,) * self.fixture["padding_count"],
                )
                self.assertEqual(
                    evaluations.c[row_count:],
                    (0,) * self.fixture["padding_count"],
                )
                self.assertEqual(
                    _decode_values(expected["a_evaluations_hex"])[row_count:],
                    (0,) * self.fixture["padding_count"],
                )

    def test_unsatisfied_output_assignment_has_no_reference_quotient(self):
        expected = self.fixture["cases"][-1]
        self.assertEqual(expected["name"], "unsatisfied-public-input-tamper")
        self.assertFalse(expected["satisfied"])
        self.assertTrue(expected["failed_constraints"])
        self.assertIsNone(expected["quotient_coefficients_hex"])
        self.assertFalse(expected["quotient_divisibility_verified"])

        _, system = self.systems[1]
        qap = QAP.from_r1cs(system)
        valid = _assignment(system)
        changed_public = list(valid.public_inputs)
        changed_public[0] = (changed_public[0] + 1) % SCALAR_MODULUS
        invalid = QAPAssignment(changed_public, valid.auxiliary_assignments)
        assignment_bytes = b"".join(
            value.to_bytes(32, "little")
            for value in qap.assignment_values(invalid)
        )
        self.assertEqual(
            hashlib.sha256(assignment_bytes).hexdigest(),
            expected["assignment_sha256"],
        )
        evaluations = qap.evaluations(invalid)
        self.assertEqual(
            evaluations.a, _decode_values(expected["a_evaluations_hex"])
        )
        self.assertEqual(
            evaluations.b, _decode_values(expected["b_evaluations_hex"])
        )
        self.assertEqual(
            evaluations.c, _decode_values(expected["c_evaluations_hex"])
        )
        polynomials = qap.polynomials(invalid)
        self.assertEqual(
            polynomials.a,
            _decode_values(expected["a_polynomial_coefficients_hex"]),
        )
        self.assertEqual(
            polynomials.b,
            _decode_values(expected["b_polynomial_coefficients_hex"]),
        )
        self.assertEqual(
            polynomials.c,
            _decode_values(expected["c_polynomial_coefficients_hex"]),
        )
        with self.assertRaises(UnsatisfiedAssignmentError):
            qap.quotient(invalid)

    def test_invalid_assignments_and_malformed_field_values_are_rejected(self):
        _, system = self.systems[1]
        qap = QAP.from_r1cs(system)
        valid = _assignment(system)
        changed_public = list(valid.public_inputs)
        changed_public[0] = (changed_public[0] + 1) % SCALAR_MODULUS
        invalid = QAPAssignment(changed_public, valid.auxiliary_assignments)
        with self.assertRaises(UnsatisfiedAssignmentError):
            qap.validate_assignment(invalid)
        with self.assertRaises(UnsatisfiedAssignmentError):
            qap.quotient(invalid)

        with self.assertRaises(ValueError):
            QAPAssignment((SCALAR_MODULUS,), ())
        with self.assertRaises(ValueError):
            QAPAssignment((True,), ())


if __name__ == "__main__":
    unittest.main()
