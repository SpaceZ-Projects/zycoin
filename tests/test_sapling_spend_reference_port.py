from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from sapling_spend_reference_port import constrain_spend_edwards_point_witness

from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import CURVE_D, IDENTITY, Point
from src.r1cs import R1CS, R1CSError

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_MANIFEST = (
    ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
)


def _reference_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_index(identity: str) -> int:
    if identity == "Input(0)":
        return 0
    if identity.startswith("Aux(") and identity.endswith(")"):
        return int(identity[4:-1]) + 1
    raise AssertionError(f"unexpected isolated reference variable {identity!r}")


def _canonical_terms(terms: list[dict]) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = {}
    for term in terms:
        index = _reference_index(term["identity"])
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        combined[index] = (combined.get(index, 0) + coefficient) % SCALAR_MODULUS
    return tuple(
        (index, coefficient)
        for index, coefficient in sorted(combined.items())
        if coefficient
    )


class SpendEdwardsPointReferencePortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = _reference_cases()
        if cls.reference["format"] != "bellman-sapling-edwards-point-reference-v1":
            raise AssertionError("unexpected Bellman Edwards point export format")
        if cls.reference["sapling_crypto_revision"] != (
            "88a7946b4a3066787776e11f0a502654167e022d"
        ):
            raise AssertionError("unexpected pinned Sapling source revision")
        if cls.reference["bellman_crate_version"] != "0.15.0":
            raise AssertionError("unexpected Bellman crate version")
        cls.cases = {case["name"]: case for case in cls.reference["cases"]}

    def assert_case_matches(
        self, name: str, point: Point, *, expected_satisfied: bool = True
    ) -> None:
        reference = self.cases[name]
        self.assertEqual(int(reference["u"]), point.u)
        self.assertEqual(int(reference["v"]), point.v)
        self.assertEqual(
            int.from_bytes(
                bytes.fromhex(self.reference["curve_d"]), "little"
            ),
            CURVE_D,
        )

        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, point)
        self.assertEqual(system.public_input_count, 0)
        self.assertEqual(
            [(variable.name, variable.index) for variable in system.variables[1:]],
            [
                (record["annotation"], _reference_index(record["identity"]))
                for record in reference["variables"]
            ],
        )
        self.assertEqual(
            [system._witness_value(variable) for variable in system.variables[1:]],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["variables"]
            ],
        )
        self.assertEqual(system.constraint_count, len(reference["constraints"]))

        for local_row, reference_row in zip(
            system.constraints, reference["constraints"], strict=True
        ):
            with self.subTest(case=name, row=reference_row["index"]):
                self.assertEqual(local_row.label, reference_row["annotation"])
                self.assertEqual(local_row.left.terms, _canonical_terms(reference_row["a"]))
                self.assertEqual(local_row.right.terms, _canonical_terms(reference_row["b"]))
                self.assertEqual(local_row.output.terms, _canonical_terms(reference_row["c"]))

        self.assertEqual(system.is_satisfied(), expected_satisfied)
        self.assertEqual(reference["satisfied"], expected_satisfied)
        self.assertEqual((variables.u.index, variables.v.index), (1, 2))

    def test_exact_parity_for_identity_and_generator_points(self) -> None:
        self.assert_case_matches("identity", IDENTITY)
        self.assert_case_matches("generator", Point(*self._generator_coordinates()))
        self.assert_case_matches(
            "negative_generator",
            Point(*self._negative_generator_coordinates()),
        )

    def test_invalid_assignment_is_unsatisfied_like_bellman(self) -> None:
        point = IDENTITY
        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, point)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({variables.u.index: 1}))
        off_curve_system = R1CS()
        off_curve_point = Point(1, 1)
        constrain_spend_edwards_point_witness(off_curve_system, off_curve_point)
        self.assertFalse(off_curve_system.is_satisfied())
        self.assert_case_matches(
            "off_curve", off_curve_point, expected_satisfied=False
        )

    def test_unassigned_or_malformed_witness_is_rejected_before_mutation(self) -> None:
        for invalid in (None, object()):
            system = R1CS()
            with self.subTest(witness=type(invalid).__name__):
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_witness(system, invalid)  # type: ignore[arg-type]
                self.assertEqual(len(system.variables), 1)
                self.assertEqual(system.constraint_count, 0)

    def _generator_coordinates(self) -> tuple[int, int]:
        case = self.cases["generator"]
        return int(case["u"]), int(case["v"])

    def _negative_generator_coordinates(self) -> tuple[int, int]:
        case = self.cases["negative_generator"]
        return int(case["u"]), int(case["v"])


if __name__ == "__main__":
    unittest.main()
