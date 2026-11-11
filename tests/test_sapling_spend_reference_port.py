from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from sapling_spend_reference_port import (
    EdwardsPointWitnessVariables,
    allocate_spend_fixed_base_scalar_bits,
    allocate_spend_montgomery_point,
    constrain_spend_conditional_anchor,
    constrain_spend_edwards_point_add,
    constrain_spend_edwards_point_double,
    constrain_spend_edwards_point_mul,
    constrain_spend_edwards_point_not_small_order,
    constrain_spend_edwards_point_repr,
    constrain_spend_edwards_point_witness,
    constrain_spend_fixed_base_mul,
    constrain_spend_merkle_authentication_path,
    constrain_spend_montgomery_add,
    constrain_spend_montgomery_into_edwards,
    constrain_spend_note_commitment,
    constrain_spend_pedersen_hash,
    constrain_spend_signed_montgomery_lookup,
    spend_edwards_to_montgomery_coordinates,
    spend_fixed_base_tables,
    spend_pedersen_montgomery_tables,
)

from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import (
    CURVE_D,
    IDENTITY,
    Point,
)
from src.jubjub import SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS
from src.r1cs import R1CS, R1CSError, Variable
from src.sapling_gadgets import (
    _pedersen_montgomery_tables,
    sapling_fixed_base_generator,
)

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
    return _reference_failed_rows_with_assignments(
        reference, {variable_index: replacement}
    )


def _reference_failed_rows_with_assignments(
    reference: dict, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = [1] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["variables"]
    ]
    for variable_index, replacement in replacements.items():
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
    return _local_failed_rows_with_assignments(
        system, {variable_index: replacement}
    )


def _local_failed_rows_with_assignments(
    system: R1CS, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = list(system._values)
    for variable_index, replacement in replacements.items():
        assignments[variable_index] = replacement % SCALAR_MODULUS
    return tuple(
        index
        for index, row in enumerate(system.constraints)
        if system._evaluate(row.left, assignments)
        * system._evaluate(row.right, assignments)
        % SCALAR_MODULUS
        != system._evaluate(row.output, assignments)
    )


def _conditional_anchor_reference_index(identity: str, input_count: int) -> int:
    if identity.startswith("Input(") and identity.endswith(")"):
        return int(identity[6:-1])
    if identity.startswith("Aux(") and identity.endswith(")"):
        return input_count + int(identity[4:-1])
    raise AssertionError(f"unexpected anchor reference variable {identity!r}")


def _conditional_anchor_terms(
    terms: list[dict], input_count: int
) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = {}
    for term in terms:
        index = _conditional_anchor_reference_index(
            term["identity"], input_count
        )
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        combined[index] = (combined.get(index, 0) + coefficient) % SCALAR_MODULUS
    return tuple(
        (index, coefficient)
        for index, coefficient in sorted(combined.items())
        if coefficient
    )


def _conditional_anchor_failed_rows(
    reference: dict, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = [1] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["inputs"]
    ] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["variables"]
    ]
    for variable_index, replacement in replacements.items():
        assignments[variable_index] = replacement % SCALAR_MODULUS

    def evaluate(terms: list[dict]) -> int:
        return sum(
            int.from_bytes(bytes.fromhex(term["coefficient_hex"]), "little")
            * assignments[
                _conditional_anchor_reference_index(
                    term["identity"], len(reference["inputs"]) + 1
                )
            ]
            for term in terms
        ) % SCALAR_MODULUS

    return tuple(
        row["index"]
        for row in reference["constraints"]
        if evaluate(row["a"]) * evaluate(row["b"]) % SCALAR_MODULUS
        != evaluate(row["c"])
    )


def _allocate_boolean_bits(
    system: R1CS, values: list[bool], label: str = "scalar bits"
) -> tuple:
    bits = []
    for index, value in enumerate(values):
        bit = system.alloc_private(f"{label}/bit {index}/boolean", int(value))
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{label}/bit {index}/boolean constraint",
        )
        bits.append(bit)
    return tuple(bits)


class SpendEdwardsPointReferencePortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = _reference_cases()
        if cls.reference["format"] != "bellman-sapling-edwards-point-reference-v11":
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
        cls.representation_cases = {
            case["name"]: case for case in cls.reference["representations"]
        }
        cls.fixed_base = cls.reference["fixed_base"]
        cls.fixed_base_cases = {
            case["name"]: case for case in cls.fixed_base["cases"]
        }
        cls.variable_base_cases = {
            case["name"]: case
            for case in cls.reference["variable_base"]["cases"]
        }
        cls.montgomery_cases = {
            case["name"]: case for case in cls.reference["montgomery_cases"]
        }
        cls.signed_lookup = cls.reference["signed_lookup"]
        cls.signed_lookup_cases = {
            case["name"]: case for case in cls.signed_lookup["cases"]
        }
        cls.pedersen = cls.reference["pedersen"]
        cls.pedersen_cases = {case["name"]: case for case in cls.pedersen["cases"]}
        cls.note_commitment = cls.reference["note_commitment"]
        cls.note_commitment_cases = {
            case["name"]: case for case in cls.note_commitment["cases"]
        }
        cls.merkle_authentication = cls.reference["merkle_authentication"]
        cls.merkle_authentication_cases = {
            case["name"]: case
            for case in cls.merkle_authentication["cases"]
        }
        cls.conditional_anchor_cases = {
            case["name"]: case
            for case in cls.reference["conditional_anchor"]["cases"]
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

    def test_exact_strict_point_representation_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        cases = (
            ("generator", generator),
            (
                "negative_generator",
                Point(*self._negative_generator_coordinates()),
            ),
            ("identity", IDENTITY),
            ("order_two", Point(0, SCALAR_MODULUS - 1)),
            ("twice_generator", generator + generator),
            ("off_curve", Point(1, 1)),
        )
        for name, point in cases:
            with self.subTest(case=name):
                reference = self.representation_cases[name]
                system = R1CS()
                point_variables = constrain_spend_edwards_point_witness(
                    system, point
                )
                bits = constrain_spend_edwards_point_repr(
                    system, point_variables, point
                )
                expected_bits = tuple(
                    (point.v >> index) & 1
                    for index in range(SCALAR_MODULUS.bit_length())
                ) + (point.u & 1,)
                self.assertEqual(len(bits), 256)
                self.assertEqual(
                    tuple(system.witness_value(bit) for bit in bits),
                    expected_bits,
                )
                self.assertTrue(all(value < 2 for value in expected_bits))
                self.assertEqual(
                    len(system.variables) - 1,
                    len(reference["variables"]),
                )
                self.assert_system_matches_reference(
                    name, system, reference, reference["satisfied"]
                )
                self.assertEqual(
                    [bit.index for bit in bits],
                    [
                        _reference_index(bit["identity"])
                        for bit in reference["bits"]
                    ],
                )
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["bits"]],
                )
                self.assertEqual(len(reference["bits"]), 256)

    def test_strict_representation_rejects_bad_inputs_and_detects_bit_changes(
        self,
    ) -> None:
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
                constrain_spend_edwards_point_repr(
                    system,
                    point_variables,
                    point_witness,  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        reference = self.representation_cases["generator"]
        bits = constrain_spend_edwards_point_repr(system, variables, generator)
        changed_bit = bits[0]
        changed_value = 1 - system.witness_value(changed_bit)
        self.assertEqual(
            _local_failed_rows(system, changed_bit.index, changed_value),
            _reference_failed_rows(reference, changed_bit.index, changed_value),
        )
        field_coordinate = variables.u
        replacement = (system.witness_value(field_coordinate) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, field_coordinate.index, replacement),
            _reference_failed_rows(reference, field_coordinate.index, replacement),
        )
        noncanonical_alias = Point(
            generator.u + SCALAR_MODULUS, generator.v
        )
        self.assertEqual(noncanonical_alias, generator)
        alias_system = R1CS()
        alias_variables = constrain_spend_edwards_point_witness(
            alias_system, noncanonical_alias
        )
        alias_bits = constrain_spend_edwards_point_repr(
            alias_system, alias_variables, noncanonical_alias
        )
        self.assertEqual(
            [alias_system.witness_value(bit) for bit in alias_bits],
            [int(bit["value"]) for bit in reference["bits"]],
        )
        self.assert_system_matches_reference(
            "generator",
            alias_system,
            reference,
        )

        noncanonical_field_bits = {
            bit.index: (SCALAR_MODULUS >> index) & 1
            for index, bit in enumerate(bits[: SCALAR_MODULUS.bit_length()])
        }
        self.assertFalse(system.is_satisfied(noncanonical_field_bits))
        self.assertEqual(
            _local_failed_rows_with_assignments(system, noncanonical_field_bits),
            _reference_failed_rows_with_assignments(
                reference, noncanonical_field_bits
            ),
        )
        self.assertEqual(len(bits), 256)

    def test_fixed_base_tables_and_all_lookup_selectors_match_bellman(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        tables = spend_fixed_base_tables(base)
        reference_tables = self.fixed_base["windows"]
        self.assertEqual(len(tables), 84)
        self.assertEqual(len(reference_tables), 84)
        for window_index, (table, reference_table) in enumerate(
            zip(tables, reference_tables, strict=True)
        ):
            with self.subTest(window=window_index):
                self.assertEqual(len(table), 8)
                self.assertEqual(len(reference_table), 8)
                self.assertEqual(
                    [(point.u, point.v) for point in table],
                    [
                        (int(point["u"]), int(point["v"]))
                        for point in reference_table
                    ],
                )

        for selector in range(8):
            name = f"selector_{selector}"
            reference = self.fixed_base_cases[name]
            system = R1CS()
            bits = allocate_spend_fixed_base_scalar_bits(
                system, selector, 3
            )
            point = constrain_spend_fixed_base_mul(
                system, bits, base
            )
            self.assertEqual(
                (system.witness_value(point.u), system.witness_value(point.v)),
                (int(reference["output_u"]), int(reference["output_v"])),
            )
            self.assert_system_matches_reference(name, system, reference)
            self.assertEqual(
                [system.witness_value(bit) for bit in bits],
                [int(bit["value"]) for bit in reference["selectors"]],
            )

    def test_fixed_base_scalar_boundaries_and_full_window_parity(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        case_scalars = {
            "scalar_0": 0,
            "scalar_1": 1,
            "scalar_7": 7,
            "scalar_8": 8,
            "scalar_9": 9,
            "scalar_63": 63,
            "scalar_64": 64,
            "scalar_65": 65,
            "scalar_511": 511,
            "scalar_512": 512,
            "scalar_513": 513,
            "u64_max": (1 << 64) - 1,
            "maximum_scalar": JUBJUB_SCALAR_MODULUS - 1,
            "all_windows_all_selectors": sum(
                ((window % 8) << (3 * window))
                for window in range(84)
            ),
        }
        for name, scalar in case_scalars.items():
            with self.subTest(case=name):
                reference = self.fixed_base_cases[name]
                bit_length = (
                    64 if name == "u64_max"
                    else 3 if name.startswith("selector_")
                    else 252
                )
                system = R1CS()
                bits = allocate_spend_fixed_base_scalar_bits(
                    system, scalar, bit_length
                )
                point = constrain_spend_fixed_base_mul(system, bits, base)
                expected = base.multiply(scalar)
                self.assertEqual(
                    (system.witness_value(point.u), system.witness_value(point.v)),
                    (expected.u, expected.v),
                )
                self.assertEqual(
                    (expected.u, expected.v),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(len(bits), len(reference["selectors"]))
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["selectors"]],
                )

    def test_fixed_base_invalid_selector_lookup_witness_and_rejection(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        reference = self.fixed_base_cases["selector_5"]
        system = R1CS()
        bits = allocate_spend_fixed_base_scalar_bits(system, 5, 3)
        point = constrain_spend_fixed_base_mul(system, bits, base)
        self.assertEqual(
            _local_failed_rows(system, bits[0].index, 2),
            _reference_failed_rows(
                reference, bits[0].index, 2
            ),
        )
        lookup_x = next(
            variable for variable in system.variables
            if variable.name
            == "fixed base multiplication/window table lookup 0/x/num"
        )
        altered_x = (system.witness_value(lookup_x) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, lookup_x.index, altered_x),
            _reference_failed_rows(reference, lookup_x.index, altered_x),
        )
        self.assertEqual(point.u.index, lookup_x.index)

        foreign = R1CS()
        foreign_bit = allocate_spend_fixed_base_scalar_bits(foreign, 1, 1)[0]
        for bad_bits, bad_base in (
            ([foreign_bit], base),
            ([None], base),
            ([object()], base),
            ([True], object()),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                constrain_spend_fixed_base_mul(
                    system,
                    bad_bits,  # type: ignore[arg-type]
                    bad_base,  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        unassigned_system = R1CS()
        unassigned = unassigned_system.alloc_private("unassigned bit", None)
        with self.assertRaises(R1CSError):
            constrain_spend_fixed_base_mul(
                unassigned_system, [unassigned], base
            )
        self.assertEqual(len(unassigned_system.variables), 2)
        self.assertEqual(unassigned_system.constraint_count, 0)

        for scalar, bit_length in (
            (None, 252),
            (-1, 252),
            (JUBJUB_SCALAR_MODULUS, 252),
            (1, 0),
        ):
            target = R1CS()
            with self.subTest(scalar=scalar, bit_length=bit_length):
                with self.assertRaises(R1CSError):
                    allocate_spend_fixed_base_scalar_bits(
                        target, scalar, bit_length  # type: ignore[arg-type]
                    )
                self.assertEqual(len(target.variables), 1)
                self.assertEqual(target.constraint_count, 0)

    def test_variable_base_multiplication_matches_bellman_ordered_traces(self) -> None:
        expected_scalars = {
            "generator_zero": 0,
            "generator_one": 1,
            "generator_small": 13,
            "generator_boundary_31": 31,
            "generator_boundary_32": 32,
            "generator_boundary_63": 63,
            "generator_boundary_64": 64,
            "generator_maximum_scalar": JUBJUB_SCALAR_MODULUS - 1,
            "identity_mixed": 13,
            "negative_generator_mixed": 11,
            "generator_all_zero_252": 0,
            "generator_all_one_252": (1 << 252) - 1,
        }
        for name, scalar in expected_scalars.items():
            with self.subTest(case=name):
                reference = self.variable_base_cases[name]
                base = Point(int(reference["base_u"]), int(reference["base_v"]))
                bits_values = [bool(bit["value"]) for bit in reference["scalar_bits"]]
                system = R1CS()
                base_variables = constrain_spend_edwards_point_witness(
                    system, base, "base"
                )
                bits = _allocate_boolean_bits(system, bits_values)
                result = constrain_spend_edwards_point_mul(
                    system, base_variables, base, bits
                )
                expected = base.multiply(scalar)
                self.assertEqual(
                    (system.witness_value(result.u), system.witness_value(result.v)),
                    (expected.u, expected.v),
                )
                self.assertEqual(
                    (expected.u, expected.v),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["scalar_bits"]],
                )

    def test_variable_base_invalid_bits_and_altered_witnesses_match_bellman(self) -> None:
        name = "generator_small"
        reference = self.variable_base_cases[name]
        base = Point(int(reference["base_u"]), int(reference["base_v"]))
        system = R1CS()
        base_variables = constrain_spend_edwards_point_witness(
            system, base, "base"
        )
        bits = _allocate_boolean_bits(
            system, [bool(bit["value"]) for bit in reference["scalar_bits"]]
        )
        constrain_spend_edwards_point_mul(system, base_variables, base, bits)
        self.assertEqual(
            _local_failed_rows(system, bits[0].index, 2),
            _reference_failed_rows(reference, bits[0].index, 2),
        )
        altered_selection = next(
            variable for variable in system.variables
            if variable.name
            == "variable base multiplication/selection 1/u'/num"
        )
        changed_value = (
            system.witness_value(altered_selection) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered_selection.index, changed_value),
            _reference_failed_rows(
                reference, altered_selection.index, changed_value
            ),
        )

    def test_variable_base_rejects_bad_inputs_before_mutation(self) -> None:
        base = Point(*self._generator_coordinates())
        system = R1CS()
        base_variables = constrain_spend_edwards_point_witness(system, base, "base")
        foreign = R1CS()
        foreign_bit = _allocate_boolean_bits(foreign, [True])[0]
        unassigned = system.alloc_private("unassigned bit", None)
        out_of_range = system.alloc_private("out of range bit", 2)

        invalid_inputs = (
            ([], base_variables, base),
            ([foreign_bit], base_variables, base),
            ([None], base_variables, base),
            ([object()], base_variables, base),
            ([unassigned], base_variables, base),
            ([out_of_range], base_variables, base),
            ([True], object(), base),
            ([True], base_variables, IDENTITY),
        )
        for bad_bits, bad_point, witness in invalid_inputs:
            with self.subTest(bad_bits=bad_bits, bad_point=bad_point):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_mul(
                        system,
                        bad_point,  # type: ignore[arg-type]
                        witness,
                        bad_bits,  # type: ignore[arg-type]
                    )
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    def test_signed_lookup_matches_bellman_for_all_digits_and_signs(self) -> None:
        table = tuple(
            (int(point["u"]), int(point["v"]))
            for point in self.signed_lookup["table"]
        )
        self.assertEqual(len(table), 4)
        self.assertEqual(table, _pedersen_montgomery_tables()[0][0][:4])
        for selector in range(8):
            name = f"selector_{selector}"
            reference = self.signed_lookup_cases[name]
            with self.subTest(selector=selector):
                system = R1CS()
                bits = _allocate_boolean_bits(
                    system,
                    [
                        bool(selector & 1),
                        bool(selector & 2),
                        bool(selector & 4),
                    ],
                    "selector bits",
                )
                result = constrain_spend_signed_montgomery_lookup(
                    system, bits, table, "signed lookup"
                )
                self.assertEqual(result.selected_index, selector & 3)
                self.assertEqual(result.negative, bool(selector & 4))
                self.assertEqual(
                    result.x.value, table[selector & 3][0]
                )
                expected_y = table[selector & 3][1]
                if selector & 4:
                    expected_y = -expected_y % SCALAR_MODULUS
                self.assertEqual(result.y.value, expected_y)
                self.assertEqual(
                    (
                        system._evaluate(result.x.expression, system._values),
                        system.witness_value(result.y.expression),
                    ),
                    (int(reference["output_x"]), int(reference["output_y"])),
                )
                self.assert_system_matches_reference(name, system, reference)

    def test_signed_lookup_invalid_selectors_witnesses_and_mutations(self) -> None:
        table = tuple(
            (int(point["u"]), int(point["v"]))
            for point in self.signed_lookup["table"]
        )
        reference = self.signed_lookup_cases["selector_7"]
        system = R1CS()
        bits = _allocate_boolean_bits(
            system, [True, True, True], "selector bits"
        )
        result = constrain_spend_signed_montgomery_lookup(
            system, bits, table, "signed lookup"
        )
        self.assert_system_matches_reference("selector_7", system, reference)

        self.assertEqual(
            _local_failed_rows(system, bits[2].index, 2),
            _reference_failed_rows(reference, bits[2].index, 2),
        )
        y_variable = result.y.expression
        assert isinstance(y_variable, Variable)
        replacement = (system.witness_value(y_variable) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, y_variable.index, replacement),
            _reference_failed_rows(reference, y_variable.index, replacement),
        )
        precomp = next(
            variable for variable in system.variables
            if variable.name == "signed lookup/precomp/and result"
        )
        replacement_precomp = 1 - int(system.witness_value(precomp))
        self.assertEqual(
            _local_failed_rows(system, precomp.index, replacement_precomp),
            _reference_failed_rows(reference, precomp.index, replacement_precomp),
        )

        foreign = R1CS()
        foreign_bit = _allocate_boolean_bits(foreign, [True], "foreign")[0]
        unassigned = system.alloc_private("unassigned selector", None)
        out_of_range = system.alloc_private("non-boolean selector", 2)
        invalid_calls = (
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, True], table[:3]
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, foreign_bit], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, unassigned], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, out_of_range], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, None], table  # type: ignore[list-item]
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, True], [(SCALAR_MODULUS, 0), *table[1:]]
            ),
        )
        for call in invalid_calls:
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                call()
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

    def test_edwards_to_montgomery_coordinate_mapping(self) -> None:
        mappings = {
            case["name"]: case
            for case in self.reference["montgomery_mappings"]
        }
        for name, expected in mappings.items():
            point = Point(int(expected["edwards_u"]), int(expected["edwards_v"]))
            with self.subTest(point=name):
                mapped = spend_edwards_to_montgomery_coordinates(point)
                if expected["x"] is None:
                    self.assertIsNone(mapped)
                else:
                    self.assertEqual(
                        mapped, (int(expected["x"]), int(expected["y"]))
                    )
        with self.assertRaises(R1CSError):
            spend_edwards_to_montgomery_coordinates(Point(1, 1))

    def test_montgomery_operations_match_bellman_ordered_traces(self) -> None:
        for name, reference in self.montgomery_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                synthesis_succeeded = True
                synthesis_error = None
                converted = None
                try:
                    point = allocate_spend_montgomery_point(
                        system,
                        int(reference["input_x"]),
                        int(reference["input_y"]),
                        "montgomery point",
                    )
                    if reference["other_x"] is not None:
                        other = allocate_spend_montgomery_point(
                            system,
                            int(reference["other_x"]),
                            int(reference["other_y"]),
                            "other point",
                        )
                        point = constrain_spend_montgomery_add(
                            system, point, other, "montgomery addition"
                        )
                    if name != "add_boundary_coordinates":
                        converted = constrain_spend_montgomery_into_edwards(
                            system, point, "conversion"
                        )
                except R1CSError as error:
                    synthesis_succeeded = False
                    synthesis_error = str(error)
                self.assertEqual(
                    synthesis_succeeded, reference["synthesis_succeeded"]
                )
                expected_errors = {
                    "convert_zero_y": "u conversion",
                    "convert_x_minus_one": "v conversion",
                    "add_equal_x_opposites": "equal x coordinates",
                }
                if name in expected_errors:
                    self.assertEqual(reference["synthesis_error"], "DivisionByZero")
                    self.assertIn(expected_errors[name], synthesis_error)
                else:
                    self.assertIsNone(synthesis_error)
                self.assert_system_matches_reference(
                    name,
                    system,
                    reference,
                    expected_satisfied=reference["satisfied"],
                )
                if reference["synthesis_succeeded"]:
                    if reference["montgomery_x"] is not None:
                        self.assertEqual(
                            system.witness_value(point.x.expression)
                            if isinstance(point.x.expression, Variable)
                            else system._evaluate(point.x.expression, system._values),
                            int(reference["montgomery_x"]),
                        )
                        self.assertEqual(
                            system.witness_value(point.y.expression)
                            if isinstance(point.y.expression, Variable)
                            else system._evaluate(point.y.expression, system._values),
                            int(reference["montgomery_y"]),
                        )
                    if converted is not None:
                        self.assertEqual(
                            (system.witness_value(converted.u), system.witness_value(converted.v)),
                            (int(reference["edwards_u"]), int(reference["edwards_v"])),
                        )

    def test_montgomery_altered_witnesses_and_invalid_inputs(self) -> None:
        reference = self.montgomery_cases["add_generator_twice_generator"]
        system = R1CS()
        left = allocate_spend_montgomery_point(
            system,
            int(reference["input_x"]),
            int(reference["input_y"]),
            "montgomery point",
        )
        right = allocate_spend_montgomery_point(
            system,
            int(reference["other_x"]),
            int(reference["other_y"]),
            "other point",
        )
        result = constrain_spend_montgomery_add(
            system, left, right, "montgomery addition"
        )
        converted = constrain_spend_montgomery_into_edwards(
            system, result, "conversion"
        )
        self.assert_system_matches_reference(
            "add_generator_twice_generator", system, reference
        )
        altered = result.x.expression
        assert isinstance(altered, Variable)
        replacement = (system.witness_value(altered) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered.index, replacement),
            _reference_failed_rows(reference, altered.index, replacement),
        )
        altered_u = converted.u
        replacement_u = (system.witness_value(altered_u) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered_u.index, replacement_u),
            _reference_failed_rows(reference, altered_u.index, replacement_u),
        )

        foreign = R1CS()
        foreign_point = allocate_spend_montgomery_point(foreign, 1, 2)
        unassigned = system.alloc_private("unassigned Montgomery x", None)
        unassigned_point = type(left)(
            type(left.x)(unassigned, 1), left.y
        )
        mismatched_point = type(left)(
            type(left.x)(left.x.expression, (left.x.value + 1) % SCALAR_MODULUS),
            left.y,
        )
        invalid_calls = (
            lambda: constrain_spend_montgomery_add(
                system, left, foreign_point
            ),
            lambda: constrain_spend_montgomery_into_edwards(
                system, unassigned_point
            ),
            lambda: constrain_spend_montgomery_add(
                system, mismatched_point, left
            ),
            lambda: allocate_spend_montgomery_point(
                system, SCALAR_MODULUS, 1
            ),
            lambda: allocate_spend_montgomery_point(system, None, 1),
            lambda: constrain_spend_montgomery_add(
                system, object(), left  # type: ignore[arg-type]
            ),
        )
        for call in invalid_calls:
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                call()
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

    def test_pedersen_generator_windows_match_pinned_bellman_tables(self) -> None:
        local_tables = spend_pedersen_montgomery_tables()
        self.assertEqual(len(local_tables), len(self.pedersen["tables"]))
        for segment_index, (local_segment, reference_segment) in enumerate(
            zip(local_tables, self.pedersen["tables"], strict=True)
        ):
            self.assertEqual(len(local_segment), 63)
            self.assertEqual(len(reference_segment), 63)
            for window_index, (local_window, reference_window) in enumerate(
                zip(local_segment, reference_segment, strict=True)
            ):
                with self.subTest(segment=segment_index, window=window_index):
                    self.assertEqual(len(local_window), 4)
                    self.assertEqual(
                        local_window,
                        tuple(
                            (int(point["u"]), int(point["v"]))
                            for point in reference_window
                        ),
                    )

    def test_pedersen_hash_matches_complete_bellman_traces(self) -> None:
        for name, reference in self.pedersen_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                message_bits = _allocate_boolean_bits(
                    system, reference["message_bits"], "input bits"
                )
                result = constrain_spend_pedersen_hash(system, message_bits)
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(
                    (
                        system.witness_value(result.variables.u),
                        system.witness_value(result.variables.v),
                    ),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assertEqual(
                    result.witness,
                    Point(int(reference["output_u"]), int(reference["output_v"])),
                )

    def test_pedersen_altered_witnesses_fail_on_identical_rows(self) -> None:
        reference = self.pedersen_cases["alternating_multi_segment"]
        system = R1CS()
        message_bits = _allocate_boolean_bits(
            system, reference["message_bits"], "input bits"
        )
        result = constrain_spend_pedersen_hash(system, message_bits)
        self.assert_system_matches_reference(
            "alternating_multi_segment", system, reference
        )

        message_bit_index = message_bits[0].index
        invalid_boolean_value = 2
        self.assertEqual(
            _local_failed_rows(system, message_bit_index, invalid_boolean_value),
            _reference_failed_rows(reference, message_bit_index, invalid_boolean_value),
        )

        sign_bit = message_bits[2]
        sign_value = system.witness_value(sign_bit)
        self.assertIn(sign_value, (0, 1))
        self.assertEqual(
            _local_failed_rows(system, sign_bit.index, 1 - sign_value),
            _reference_failed_rows(reference, sign_bit.index, 1 - sign_value),
        )

        y_record = next(
            record
            for record in reference["variables"]
            if record["annotation"] == "pedersen hash/segment 0, window 0/y/num"
        )
        y_index = _reference_index(y_record["identity"])
        y_value = int.from_bytes(bytes.fromhex(y_record["assignment"]), "little")
        self.assertEqual(
            _local_failed_rows(system, y_index, y_value + 1),
            _reference_failed_rows(reference, y_index, y_value + 1),
        )

        lambda_record = next(
            record
            for record in reference["variables"]
            if record["annotation"]
            == "pedersen hash/addition of segment 0, window 1/lambda/num"
        )
        lambda_index = _reference_index(lambda_record["identity"])
        lambda_value = int.from_bytes(
            bytes.fromhex(lambda_record["assignment"]), "little"
        )
        self.assertEqual(
            _local_failed_rows(system, lambda_index, lambda_value + 1),
            _reference_failed_rows(reference, lambda_index, lambda_value + 1),
        )

        output_u = result.variables.u
        output_u_value = system.witness_value(output_u)
        self.assertIsNotNone(output_u_value)
        self.assertEqual(
            _local_failed_rows(system, output_u.index, output_u_value + 1),
            _reference_failed_rows(reference, output_u.index, output_u_value + 1),
        )

    def test_pedersen_invalid_bits_reject_before_mutation(self) -> None:
        system = R1CS()
        valid = system.alloc_private("valid bit", 1)
        unassigned = system.alloc_private("unassigned bit", None)
        out_of_range = system.alloc_private("out of range bit", 2)
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign bit", 0)
        invalid_arguments = (
            lambda: constrain_spend_pedersen_hash(system, (unassigned,)),
            lambda: constrain_spend_pedersen_hash(system, (out_of_range,)),
            lambda: constrain_spend_pedersen_hash(system, (foreign,)),
            lambda: constrain_spend_pedersen_hash(
                system, (valid,), personalization_bits=(True,)
            ),
            lambda: constrain_spend_pedersen_hash(system, (valid, False, 1)),  # type: ignore[arg-type]
            lambda: constrain_spend_pedersen_hash(system, (valid,) * (1128 + 1)),
        )
        for call in invalid_arguments:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    def test_note_commitment_matches_complete_bellman_traces(self) -> None:
        diversifiers = [
            tuple(case["diversifier"])
            for case in self.note_commitment_cases.values()
        ]
        self.assertTrue(all(len(diversifier) == 11 for diversifier in diversifiers))
        self.assertEqual(len(set(diversifiers)), len(diversifiers))
        randomness_base = sapling_fixed_base_generator(
            "note_commitment_randomness"
        )
        self.assertEqual(
            (randomness_base.u, randomness_base.v),
            (
                int(self.note_commitment["randomness_base"]["u"]),
                int(self.note_commitment["randomness_base"]["v"]),
            ),
        )
        for name, reference in self.note_commitment_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                g_d_witness = Point(int(reference["g_d_u"]), int(reference["g_d_v"]))
                pk_d_witness = Point(
                    int(reference["pk_d_u"]), int(reference["pk_d_v"])
                )
                g_d_variables = constrain_spend_edwards_point_witness(
                    system, g_d_witness, "input g_d"
                )
                pk_d_variables = constrain_spend_edwards_point_witness(
                    system, pk_d_witness, "input pk_d"
                )
                rcm = sum(
                    int(bit) << index
                    for index, bit in enumerate(reference["rcm_bits"])
                )
                result = constrain_spend_note_commitment(
                    system,
                    reference["value"],
                    g_d_variables,
                    g_d_witness,
                    pk_d_variables,
                    pk_d_witness,
                    rcm,
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(reference["note_bit_count"], 576)
                self.assertEqual(len(result.note_contents), 576)
                self.assertEqual(
                    (
                        system.witness_value(result.note_hash.variables.u),
                        system.witness_value(result.note_hash.variables.v),
                    ),
                    (int(reference["hash_u"]), int(reference["hash_v"])),
                )
                self.assertEqual(
                    (
                        system.witness_value(result.commitment_variables.u),
                        system.witness_value(result.commitment_variables.v),
                    ),
                    (
                        int(reference["commitment_u"]),
                        int(reference["commitment_v"]),
                    ),
                )
                self.assertEqual(
                    result.commitment_witness,
                    Point(
                        int(reference["commitment_u"]),
                        int(reference["commitment_v"]),
                    ),
                )
                self.assertEqual(
                    [system.witness_value(bit) for bit in result.value_bits],
                    [(reference["value"] >> index) & 1 for index in range(64)],
                )

    def test_note_commitment_altered_inputs_and_witnesses_match_bellman_rows(
        self,
    ) -> None:
        reference = self.note_commitment_cases["maximum_value_maximum_rcm"]
        system = R1CS()
        g_d_witness = Point(int(reference["g_d_u"]), int(reference["g_d_v"]))
        pk_d_witness = Point(int(reference["pk_d_u"]), int(reference["pk_d_v"]))
        g_d_variables = constrain_spend_edwards_point_witness(
            system, g_d_witness, "input g_d"
        )
        pk_d_variables = constrain_spend_edwards_point_witness(
            system, pk_d_witness, "input pk_d"
        )
        rcm = sum(
            int(bit) << index for index, bit in enumerate(reference["rcm_bits"])
        )
        result = constrain_spend_note_commitment(
            system,
            reference["value"],
            g_d_variables,
            g_d_witness,
            pk_d_variables,
            pk_d_witness,
            rcm,
        )
        self.assert_system_matches_reference(
            "maximum_value_maximum_rcm", system, reference
        )

        mutation_annotations = (
            "value commitment/value/bit 63/boolean",
            "representation of g_d/unpack u/bit 0/boolean",
            "note content hash/segment 0, window 0/y/num",
            "rcm/bit 0/boolean",
            "computation of commitment randomness/window table lookup 0/x/num",
            "randomization of note commitment/u3/num",
        )
        for annotation in mutation_annotations:
            variable = next(
                item for item in system.variables if item.name == annotation
            )
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (
                1 - assigned
                if assigned in (0, 1)
                else (assigned + 1) % SCALAR_MODULUS
            )
            with self.subTest(variable=annotation):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _reference_failed_rows(
                        reference, variable.index, replacement
                    ),
                )

        commitment_v = result.commitment_variables.v
        commitment_v_value = system.witness_value(commitment_v)
        self.assertIsNotNone(commitment_v_value)
        self.assertEqual(
            _local_failed_rows(
                system, commitment_v.index, commitment_v_value + 1
            ),
            _reference_failed_rows(
                reference, commitment_v.index, commitment_v_value + 1
            ),
        )

    def test_note_commitment_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        point = Point(
            int(self.cases["generator"]["u"]),
            int(self.cases["generator"]["v"]),
        )
        variables = constrain_spend_edwards_point_witness(
            system, point, "valid point"
        )
        foreign_system = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            foreign_system, point, "foreign point"
        )
        unassigned_u = system.alloc_private("unassigned u", None)
        unassigned_v = system.alloc_private("unassigned v", None)
        unassigned_variables = EdwardsPointWitnessVariables(
            unassigned_u, unassigned_v
        )
        invalid_calls = (
            lambda: constrain_spend_note_commitment(
                system, -1, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1 << 64, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, True, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point, None
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, None, variables, point, 0  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point, -1
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point,
                JUBJUB_SCALAR_MODULUS,
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, foreign_variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, foreign_variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, unassigned_variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, Point(point.u + 1, point.v), variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, object(), point, variables, point, 0  # type: ignore[arg-type]
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    def test_merkle_authentication_matches_bellman_ordered_traces(self) -> None:
        for name, reference in self.merkle_authentication_cases.items():
            path = list(
                zip(reference["siblings"], reference["directions"], strict=True)
            )
            path = [(int(sibling), direction) for sibling, direction in path]
            with self.subTest(case=name, depth=len(path)):
                system = R1CS()
                leaf_value = int(reference["leaf"])
                leaf_variable = system.alloc_private("leaf/num", leaf_value)
                result = constrain_spend_merkle_authentication_path(
                    system, leaf_variable, leaf_value, path
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(len(result.position_bits), len(path))
                self.assertEqual(len(result.path_nodes), len(path))
                self.assertEqual(
                    [system.witness_value(bit) for bit in result.position_bits],
                    [int(direction) for direction in reference["directions"]],
                )
                self.assertEqual(
                    [system.witness_value(node) for node in result.path_nodes],
                    [int(sibling) for sibling in reference["siblings"]],
                )
                self.assertEqual(result.root_value, int(reference["root"]))
                self.assertEqual(
                    system.witness_value(result.root_variable),
                    int(reference["root"]),
                )

    def test_merkle_direction_sibling_intermediate_and_root_mutations_match(
        self,
    ) -> None:
        reference = self.merkle_authentication_cases["mixed_directions"]
        path = [
            (int(sibling), direction)
            for sibling, direction in zip(
                reference["siblings"], reference["directions"], strict=True
            )
        ]
        system = R1CS()
        leaf_value = int(reference["leaf"])
        leaf_variable = system.alloc_private("leaf/num", leaf_value)
        result = constrain_spend_merkle_authentication_path(
            system, leaf_variable, leaf_value, path
        )
        self.assert_system_matches_reference("mixed_directions", system, reference)

        mutation_annotations = (
            "merkle tree hash 0/position bit/boolean",
            "merkle tree hash 0/path element/num",
            (
                "merkle tree hash 0/conditional reversal of preimage/"
                "conditional reversal result 1/num"
            ),
            (
                "merkle tree hash 0/computation of pedersen hash/"
                "segment 0, window 0/y/num"
            ),
        )
        for annotation in mutation_annotations:
            variable = next(
                item for item in system.variables if item.name == annotation
            )
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (
                1 - assigned
                if assigned in (0, 1)
                else (assigned + 1) % SCALAR_MODULUS
            )
            with self.subTest(variable=annotation):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _reference_failed_rows(
                        reference, variable.index, replacement
                    ),
                )

        root_value = system.witness_value(result.root_variable)
        self.assertIsNotNone(root_value)
        self.assertEqual(
            _local_failed_rows(
                system, result.root_variable.index, root_value + 1
            ),
            _reference_failed_rows(
                reference, result.root_variable.index, root_value + 1
            ),
        )

    def test_merkle_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        system.alloc_private("existing", 0)
        leaf_variable = system.alloc_private("leaf/num", 1)
        unassigned_leaf = system.alloc_private("unassigned leaf", None)
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign sibling", 1)
        invalid_calls = (
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, -1, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, SCALAR_MODULUS, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, True, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, None  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, None, 1, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, foreign, 1, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, unassigned_leaf, 1, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 2, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(None, False)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(SCALAR_MODULUS, False)]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(foreign, False)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, 0)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, None)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, False)] * 33
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, False, 2)]  # type: ignore[list-item]
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

        empty_leaf = system.alloc_private("empty leaf/num", 5)
        empty_path = constrain_spend_merkle_authentication_path(
            system, empty_leaf, 5, []
        )
        self.assertEqual(empty_path.root_value, 5)
        self.assertEqual(system.witness_value(empty_path.root_variable), 5)

    def _anchor_fixture(self, reference: dict) -> tuple[R1CS, Variable, Variable, Variable]:
        system = R1CS()
        for name in ("rk.u", "rk.v", "cv.u", "cv.v"):
            system.alloc_public(name, 1)
        anchor = system.alloc_public("anchor/input variable", int(reference["anchor"]))
        value = system.alloc_private("note value/num", int(reference["value"]))
        root = system.alloc_private("merkle root/num", int(reference["root"]))
        return system, root, value, anchor

    def test_conditional_anchor_matches_bellman_ordered_traces(self) -> None:
        for name, reference in self.conditional_anchor_cases.items():
            with self.subTest(case=name):
                system, root, value, anchor = self._anchor_fixture(reference)
                result = constrain_spend_conditional_anchor(
                    system,
                    root,
                    int(reference["root"]),
                    value,
                    int(reference["value"]),
                    anchor,
                    int(reference["anchor"]),
                )
                input_count = len(reference["inputs"]) + 1
                expected_variables = reference["inputs"] + reference["variables"]
                self.assertEqual(
                    [
                        (variable.name, variable.index)
                        for variable in system.variables[1:]
                    ],
                    [
                        (
                            record["annotation"],
                            _conditional_anchor_reference_index(
                                record["identity"], input_count
                            ),
                        )
                        for record in expected_variables
                    ],
                )
                self.assertEqual(
                    [
                        system.witness_value(variable)
                        for variable in system.variables[1:]
                    ],
                    [
                        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                        for record in expected_variables
                    ],
                )
                self.assertEqual(
                    system.public_input_position(anchor),
                    reference["anchor_position"],
                )
                self.assertEqual(
                    system.public_inputs(),
                    tuple(
                        int.from_bytes(
                            bytes.fromhex(record["assignment"]), "little"
                        )
                        for record in reference["inputs"]
                    ),
                )
                self.assertEqual(system.constraint_count, len(reference["constraints"]))
                for local_row, reference_row in zip(
                    system.constraints, reference["constraints"], strict=True
                ):
                    with self.subTest(case=name, row=reference_row["index"]):
                        self.assertEqual(
                            local_row.label, reference_row["annotation"]
                        )
                        self.assertEqual(
                            local_row.left.terms,
                            _conditional_anchor_terms(
                                reference_row["a"], input_count
                            ),
                        )
                        self.assertEqual(
                            local_row.right.terms,
                            _conditional_anchor_terms(
                                reference_row["b"], input_count
                            ),
                        )
                        self.assertEqual(
                            local_row.output.terms,
                            _conditional_anchor_terms(
                                reference_row["c"], input_count
                            ),
                        )
                self.assertEqual(system.is_satisfied(), reference["satisfied"])
                self.assertEqual(result.conditional_anchor_variable.name, "conditional anchor/num")
                self.assertEqual(
                    system.witness_value(result.conditional_anchor_variable),
                    int(reference["anchor"]),
                )

    def test_conditional_anchor_witness_mutations_match_bellman(self) -> None:
        reference = self.conditional_anchor_cases["nonzero_mismatching_anchor"]
        system, root, value, anchor = self._anchor_fixture(reference)
        result = constrain_spend_conditional_anchor(
            system,
            root,
            int(reference["root"]),
            value,
            int(reference["value"]),
            anchor,
            int(reference["anchor"]),
        )
        for variable in (
            root,
            value,
            anchor,
            result.conditional_anchor_variable,
        ):
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (assigned + 1) % SCALAR_MODULUS
            with self.subTest(variable=variable.name):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _conditional_anchor_failed_rows(
                        reference, {variable.index: replacement}
                    ),
                )

    def test_conditional_anchor_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        prior_inputs = [
            system.alloc_public(f"prior/{index}", 1) for index in range(4)
        ]
        anchor = system.alloc_public("anchor", 7)
        value = system.alloc_private("value", 3)
        root = system.alloc_private("root", 5)
        unassigned_root = system.alloc_private("unassigned root", None)
        unassigned_value = system.alloc_private("unassigned value", None)
        unassigned_anchor_system = R1CS()
        for index in range(4):
            unassigned_anchor_system.alloc_public(f"prior/{index}", 1)
        unassigned_anchor = unassigned_anchor_system.alloc_public("anchor", None)
        unassigned_anchor_value = unassigned_anchor_system.alloc_private("value", 3)
        unassigned_anchor_root = unassigned_anchor_system.alloc_private("root", 5)
        foreign_system = R1CS()
        for index in range(6):
            foreign_system.alloc_public(f"foreign prior/{index}", 1)
        foreign_anchor = foreign_system.variables[-1]
        foreign_root = foreign_system.alloc_private("foreign root", 5)
        foreign_value = foreign_system.alloc_private("foreign value", 3)
        calls = (
            lambda: constrain_spend_conditional_anchor(
                system, None, 5, value, 3, anchor, 7  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_conditional_anchor(
                system, foreign_root, 5, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, foreign_value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, foreign_anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, unassigned_root, 5, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, unassigned_value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, SCALAR_MODULUS, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, -1, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, anchor, SCALAR_MODULUS
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 6, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 4, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, anchor, 8
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, root, 5
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, True, value, 3, anchor, 7  # type: ignore[arg-type]
            ),
        )
        for call in calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)
        before_variables = len(unassigned_anchor_system.variables)
        before_rows = unassigned_anchor_system.constraint_count
        with self.assertRaises(R1CSError):
            constrain_spend_conditional_anchor(
                unassigned_anchor_system,
                unassigned_anchor_root,
                5,
                unassigned_anchor_value,
                3,
                unassigned_anchor,
                7,
            )
        self.assertEqual(len(unassigned_anchor_system.variables), before_variables)
        self.assertEqual(
            unassigned_anchor_system.constraint_count, before_rows
        )
        self.assertEqual(prior_inputs[-1].kind, "public")

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
