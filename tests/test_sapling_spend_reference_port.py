from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from sapling_spend_reference_port import (
    constrain_spend_edwards_point_add,
    constrain_spend_edwards_point_double,
    constrain_spend_edwards_point_not_small_order,
    constrain_spend_edwards_point_witness,
)

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


def _reference_failed_rows(
    reference: dict, variable_index: int, replacement: int
) -> tuple[int, ...]:
    assignments = [1] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["variables"]
    ]
    assignments[variable_index] = replacement % SCALAR_MODULUS

    def evaluate(terms: list[dict]) -> int:
        return sum(
            int.from_bytes(
                bytes.fromhex(term["coefficient_hex"]), "little"
            )
            * assignments[_reference_index(term["identity"])]
            for term in terms
        ) % SCALAR_MODULUS

    return tuple(
        row["index"]
        for row in reference["constraints"]
        if evaluate(row["a"]) * evaluate(row["b"]) % SCALAR_MODULUS
        != evaluate(row["c"])
    )


def _local_failed_rows(
    system: R1CS, variable_index: int, replacement: int
) -> tuple[int, ...]:
    assignments = list(system._values)
    assignments[variable_index] = replacement % SCALAR_MODULUS
    return tuple(
        index
        for index, row in enumerate(system.constraints)
        if system._evaluate(row.left, assignments)
        * system._evaluate(row.right, assignments)
        % SCALAR_MODULUS
        != system._evaluate(row.output, assignments)
    )


class SpendEdwardsPointReferencePortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = _reference_cases()
        if cls.reference["format"] != "bellman-sapling-edwards-point-reference-v2":
            raise AssertionError("unexpected Bellman Edwards point export format")
        if cls.reference["sapling_crypto_revision"] != (
            "88a7946b4a3066787776e11f0a502654167e022d"
        ):
            raise AssertionError("unexpected pinned Sapling source revision")
        if cls.reference["bellman_revision"] != (
            "b726862a4ece8a627e7fea486d77b502a6edbb0b"
        ):
            raise AssertionError("unexpected Bellman source revision")
        if cls.reference["bellman_crate_version"] != "0.15.0":
            raise AssertionError("unexpected Bellman crate version")
        cls.cases = {case["name"]: case for case in cls.reference["cases"]}
        cls.non_small_order_cases = {
            case["name"]: case
            for case in cls.reference["non_small_order_cases"]
        }

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
        self.assert_system_matches_reference(
            name, system, reference, expected_satisfied
        )
        self.assertEqual((variables.u.index, variables.v.index), (1, 2))

    def assert_system_matches_reference(
        self,
        name: str,
        system: R1CS,
        reference: dict,
        expected_satisfied: bool = True,
    ) -> None:
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

    def test_exact_addition_and_doubling_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        negative = Point(*self._negative_generator_coordinates())
        identity = IDENTITY
        twice_generator = generator + generator
        cases = (
            (
                "identity_add_generator",
                "add",
                identity,
                generator,
            ),
            (
                "generator_add_identity",
                "add",
                generator,
                identity,
            ),
            (
                "negative_generator_add_generator",
                "add",
                negative,
                generator,
            ),
            (
                "generator_add_negative_generator",
                "add",
                generator,
                negative,
            ),
            (
                "equal_point_addition",
                "add",
                generator,
                generator,
            ),
            (
                "nontrivial_point_addition",
                "add",
                generator,
                twice_generator,
            ),
            ("identity_double", "double", identity, None),
            ("generator_double", "double", generator, None),
            ("negative_generator_double", "double", negative, None),
        )
        for name, operation, left, right in cases:
            with self.subTest(case=name):
                system = R1CS()
                left_variables = constrain_spend_edwards_point_witness(
                    system, left, "left" if right is not None else "point"
                )
                if operation == "add":
                    assert right is not None
                    right_variables = constrain_spend_edwards_point_witness(
                        system, right, "right"
                    )
                    result_variables = constrain_spend_edwards_point_add(
                        system,
                        left_variables,
                        left,
                        right_variables,
                        right,
                    )
                    expected = left + right
                else:
                    result_variables = constrain_spend_edwards_point_double(
                        system, left_variables, left
                    )
                    expected = left + left
                reference = self.cases[name]
                self.assertEqual(int(reference["u"]), expected.u)
                self.assertEqual(int(reference["v"]), expected.v)
                self.assertEqual(
                    len(system.variables) - 1,
                    16 if operation == "add" else 10,
                )
                self.assertEqual(
                    system.constraint_count,
                    14 if operation == "add" else 9,
                )
                self.assertEqual(
                    system.witness_value(result_variables.u), expected.u
                )
                self.assertEqual(
                    system.witness_value(result_variables.v), expected.v
                )
                self.assert_system_matches_reference(name, system, reference)

    def test_invalid_operation_input_and_inconsistent_intermediate(self) -> None:
        generator = Point(*self._generator_coordinates())
        invalid = Point(1, 1)
        system = R1CS()
        invalid_variables = constrain_spend_edwards_point_witness(
            system, invalid, "left"
        )
        generator_variables = constrain_spend_edwards_point_witness(
            system, generator, "right"
        )
        constrain_spend_edwards_point_add(
            system,
            invalid_variables,
            invalid,
            generator_variables,
            generator,
        )
        self.assert_system_matches_reference(
            "off_curve_addition", system, self.cases["off_curve_addition"], False
        )

        valid_system = R1CS()
        point_variables = constrain_spend_edwards_point_witness(
            valid_system, generator
        )
        result = constrain_spend_edwards_point_double(
            valid_system, point_variables, generator
        )
        self.assertTrue(valid_system.is_satisfied())
        reference = self.cases["generator_double"]
        self.assert_system_matches_reference(
            "generator_double", valid_system, reference
        )
        changed_variable = next(
            variable for variable in valid_system.variables
            if variable.name == "doubling/C/num"
        )
        changed_assignment = (
            valid_system.witness_value(changed_variable) + 1
        ) % SCALAR_MODULUS
        self.assertFalse(
            valid_system.is_satisfied(
                {changed_variable.index: changed_assignment}
            )
        )
        self.assertEqual(
            _local_failed_rows(
                valid_system, changed_variable.index, changed_assignment
            ),
            _reference_failed_rows(
                reference, changed_variable.index, changed_assignment
            ),
        )
        self.assertEqual(
            (result.u.index, result.v.index),
            (changed_variable.index + 1, changed_variable.index + 2),
        )

    def test_exact_non_small_order_check_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        cases = (
            ("generator", generator),
            (
                "negative_generator",
                Point(*self._negative_generator_coordinates()),
            ),
            ("twice_generator", generator + generator),
            ("identity", IDENTITY),
            ("order_two", Point(0, SCALAR_MODULUS - 1)),
            ("off_curve", Point(1, 1)),
        )
        for name, point in cases:
            with self.subTest(case=name):
                reference = self.non_small_order_cases[name]
                system = R1CS()
                point_variables = constrain_spend_edwards_point_witness(
                    system, point
                )
                if reference["synthesis_succeeded"]:
                    result_variables = constrain_spend_edwards_point_not_small_order(
                        system, point_variables, point
                    )
                    expected = point
                    for _ in range(3):
                        expected = expected + expected
                    self.assertEqual(
                        system.witness_value(result_variables.u), expected.u
                    )
                    self.assertEqual(
                        system.witness_value(result_variables.v), expected.v
                    )
                    self.assertEqual(len(system.variables) - 1, 21)
                    self.assertEqual(system.constraint_count, 20)
                else:
                    with self.assertRaises(R1CSError):
                        constrain_spend_edwards_point_not_small_order(
                            system, point_variables, point
                        )
                    self.assertEqual(len(system.variables) - 1, 20)
                    self.assertEqual(system.constraint_count, 19)
                    self.assertEqual(
                        reference["synthesis_error"], "DivisionByZero"
                    )
                self.assertEqual(
                    reference["synthesis_succeeded"],
                    any(
                        variable.name
                        == "non-small-order/check u != 0/ephemeral inverse"
                        for variable in system.variables
                    ),
                )
                self.assert_system_matches_reference(
                    name, system, reference, reference["satisfied"]
                )

    def test_non_small_order_input_validation_and_intermediate_failures(self) -> None:
        generator = Point(*self._generator_coordinates())
        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, generator)
        foreign = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            foreign, generator
        )
        for point_variables, point_witness in (
            (foreign_variables, generator),
            (variables, Point(generator.u + 1, generator.v)),
            (variables, None),
            (variables, object()),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                constrain_spend_edwards_point_not_small_order(
                    system, point_variables, point_witness  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        reference = self.non_small_order_cases["generator"]
        result = constrain_spend_edwards_point_not_small_order(
            system, variables, generator
        )
        changed = next(
            variable for variable in system.variables
            if variable.name == "non-small-order/second doubling/C/num"
        )
        replacement = (
            system.witness_value(changed) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, changed.index, replacement),
            _reference_failed_rows(reference, changed.index, replacement),
        )

        inverse = next(
            variable for variable in system.variables
            if variable.name
            == "non-small-order/check u != 0/ephemeral inverse"
        )
        inverse_replacement = (
            system.witness_value(inverse) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, inverse.index, inverse_replacement),
            _reference_failed_rows(reference, inverse.index, inverse_replacement),
        )
        self.assertEqual(result.v.index + 1, inverse.index)

    def test_missing_foreign_and_inconsistent_point_witnesses_reject_before_mutation(
        self,
    ) -> None:
        generator = Point(*self._generator_coordinates())
        system = R1CS()
        point_variables = constrain_spend_edwards_point_witness(system, generator)
        other_system = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            other_system, generator
        )
        for witness, variables, target in (
            (None, point_variables, system),
            (object(), point_variables, system),
            (generator, foreign_variables, system),
            (Point(generator.u + 1, generator.v), point_variables, system),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.subTest(witness=type(witness).__name__):
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_double(
                        target, variables, witness  # type: ignore[arg-type]
                    )
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

        valid_variables = constrain_spend_edwards_point_witness(
            system, generator, "valid"
        )
        before_variables = len(system.variables)
        before_rows = system.constraint_count
        with self.assertRaises(R1CSError):
            constrain_spend_edwards_point_add(
                system,
                valid_variables,
                Point(generator.u + 1, generator.v),
                valid_variables,
                generator,
            )
        self.assertEqual(len(system.variables), before_variables)
        self.assertEqual(system.constraint_count, before_rows)

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
