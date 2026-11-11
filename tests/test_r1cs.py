import hashlib
import json
import unittest

from src.bls12_381 import SCALAR_MODULUS
from src.r1cs import LinearCombination, R1CS, R1CSError, Variable


class R1CSTests(unittest.TestCase):
    def test_public_private_order_and_constraint_satisfaction(self):
        system = R1CS()
        public = system.alloc_public("public_value", 7)
        private = system.alloc_private("private_value", 9)
        product = system.multiply(public, private, "product")
        system.enforce_equal(product, 63, "expected product")

        self.assertEqual(system.public_inputs(), (7,))
        self.assertEqual(system.constraint_count, 2)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({private.index: 8}))
        with self.assertRaises(R1CSError):
            system.alloc_public("late_public", 1)

    def test_field_arithmetic_and_boolean_constraint(self):
        system = R1CS()
        variable = system.alloc_private("field_value", SCALAR_MODULUS + 1)
        self.assertTrue(system.is_satisfied())
        self.assertEqual(system.variables[1].index, variable.index)

        boolean_system = R1CS()
        bit = boolean_system.alloc_private("bit", 1)
        boolean_system.boolean(bit)
        self.assertTrue(boolean_system.is_satisfied())
        self.assertFalse(boolean_system.is_satisfied({bit.index: 2}))

    def test_range_check_and_invalid_range(self):
        system = R1CS()
        value = system.alloc_public("value", 5)
        bits = system.range_check(value, 3, "value_bit")
        self.assertEqual(len(bits), 3)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({bits[0].index: 0}))

        out_of_range = R1CS()
        too_large = out_of_range.alloc_public("too_large", 8)
        with self.assertRaises(R1CSError):
            out_of_range.range_check(too_large, 3, "bit")

    def test_unassigned_values_are_not_silently_accepted(self):
        system = R1CS()
        value = system.alloc_private("value", None)
        system.enforce_equal(value, 3)
        with self.assertRaises(R1CSError):
            system.is_satisfied()
        self.assertTrue(system.is_satisfied({value.index: 3}))
        self.assertFalse(system.is_satisfied({value.index: 4}))

    def test_serialization_is_deterministic_and_excludes_witness_values(self):
        def build(secret):
            system = R1CS()
            public = system.alloc_public("message", 2)
            private = system.alloc_private("secret", secret)
            system.multiply(public, private, "product")
            return system

        first = build(11)
        second = build(999)
        encoded = first.serialize()
        self.assertEqual(encoded, second.serialize())
        self.assertTrue(first.is_satisfied())
        self.assertTrue(second.is_satisfied())
        document = json.loads(encoded)
        self.assertEqual(document["format"], "zycoin-r1cs-v1")
        self.assertEqual(document["public_input_count"], 1)
        self.assertEqual(
            [entry["kind"] for entry in document["variables"]],
            ["one", "public", "private", "private"],
        )
        self.assertTrue(all("value" not in entry for entry in document["variables"]))

    def test_matrix_empty_shape_and_fingerprint_version(self):
        system = R1CS()
        matrix = system.serialize_matrix()
        document = json.loads(matrix)

        self.assertEqual(document["format"], "zycoin-r1cs-matrix-v1")
        self.assertEqual(document["column_count"], 1)
        self.assertEqual(document["one_column"], 0)
        self.assertEqual(document["public_input_count"], 0)
        self.assertEqual(document["auxiliary_variable_count"], 0)
        self.assertEqual(document["variable_kinds"], ["one"])
        self.assertEqual(document["constraints"], [])
        self.assertEqual(
            system.matrix_fingerprint(),
            hashlib.sha256(
                b"zycoin-r1cs-matrix-fingerprint-v1\0" + matrix
            ).hexdigest(),
        )
        self.assertEqual(system.serialize_matrix(), R1CS().serialize_matrix())

    def test_matrix_serialization_tracks_ordered_rows_columns_and_coefficients(self):
        def build(
            reverse_rows=False,
            reverse_columns=False,
            coefficient=1,
            metadata="first",
        ):
            system = R1CS()
            if reverse_columns:
                second = system.alloc_public(f"second {metadata}", 5)
                first = system.alloc_public(f"first {metadata}", 3)
            else:
                first = system.alloc_public(f"first {metadata}", 3)
                second = system.alloc_public(f"second {metadata}", 5)
            private = system.alloc_private(f"private {metadata}", 7)
            rows = (
                (first, second, private),
                (second, first, private),
            )
            if reverse_rows:
                rows = tuple(reversed(rows))
            for left, right, output in rows:
                system.enforce(
                    left.lc() * coefficient,
                    right,
                    output,
                    f"metadata {metadata}",
                )
            return system

        first = build()
        same_matrix = build(metadata="different")
        reordered_rows = build(reverse_rows=True)
        reordered_columns = build(reverse_columns=True)
        changed_coefficient = build(coefficient=2)

        self.assertEqual(
            first.serialize_matrix(), same_matrix.serialize_matrix()
        )
        self.assertEqual(
            first.matrix_fingerprint(), same_matrix.matrix_fingerprint()
        )
        self.assertNotEqual(
            first.serialize_matrix(), reordered_rows.serialize_matrix()
        )
        self.assertNotEqual(
            first.matrix_fingerprint(), reordered_rows.matrix_fingerprint()
        )
        self.assertNotEqual(
            first.serialize_matrix(), reordered_columns.serialize_matrix()
        )
        self.assertNotEqual(
            first.matrix_fingerprint(), reordered_columns.matrix_fingerprint()
        )
        self.assertNotEqual(
            first.serialize_matrix(), changed_coefficient.serialize_matrix()
        )
        self.assertNotEqual(
            first.matrix_fingerprint(), changed_coefficient.matrix_fingerprint()
        )
        document = json.loads(first.serialize_matrix())
        self.assertEqual(document["format"], "zycoin-r1cs-matrix-v1")
        self.assertEqual(document["column_count"], 4)
        self.assertEqual(document["one_column"], 0)
        self.assertEqual(
            document["variable_kinds"],
            ["one", "public", "public", "private"],
        )
        self.assertEqual(document["public_input_count"], 2)
        self.assertEqual(document["auxiliary_variable_count"], 1)
        self.assertNotIn("metadata", first.serialize_matrix().decode())

    def test_matrix_terms_are_canonical_across_insertion_orders(self):
        def build(terms, constant, value, name):
            system = R1CS()
            x = system.alloc_public("x", value)
            y = system.alloc_public("y", 11)
            system.alloc_private(name, 13)
            left = system.linear_combination(terms(x, y), constant)
            system.enforce(left, 1, 0)
            return system

        first = build(
            lambda x, y: ((x, 1), (y, 3), (x, 1)),
            -2,
            7,
            "first witness",
        )
        reordered = build(
            lambda x, y: ((x, 2), (y, 3)),
            SCALAR_MODULUS - 2,
            999,
            "different witness",
        )

        self.assertEqual(first.serialize_matrix(), reordered.serialize_matrix())
        self.assertEqual(first.matrix_fingerprint(), reordered.matrix_fingerprint())

    def test_matrix_coefficients_normalize_zero_duplicates_negatives_and_modulus(self):
        system = R1CS()
        public = system.alloc_public("public", 0)
        auxiliary = system.alloc_private("auxiliary", 1)
        expression = system.linear_combination(
            (
                (public, 0),
                (public, SCALAR_MODULUS),
                (public, -1),
                (auxiliary, SCALAR_MODULUS + 1),
                (auxiliary, SCALAR_MODULUS - 1),
                (auxiliary, 1),
            ),
            SCALAR_MODULUS,
        )
        system.enforce(expression, 1, 1)

        terms = json.loads(system.serialize_matrix())["constraints"][0][0]
        self.assertEqual(
            terms,
            [
                [1, str(SCALAR_MODULUS - 1)],
                [2, "1"],
            ],
        )
        self.assertTrue(system.is_satisfied())
        self.assertEqual(
            LinearCombination(
                ((public.index, -1), (public.index, SCALAR_MODULUS)),
                system._owner,
            ).terms,
            ((public.index, SCALAR_MODULUS - 1),),
        )
        self.assertEqual(
            LinearCombination(
                ((public.index, 1), (public.index, -1)),
                system._owner,
            ).terms,
            (),
        )

    def test_matrix_rejects_invalid_column_indices(self):
        system = R1CS()
        system.alloc_private("private", 1)
        invalid = LinearCombination(((2, 1),), system._owner)
        with self.assertRaisesRegex(R1CSError, "index is out of range"):
            system.enforce(invalid, 1, 0)
        with self.assertRaisesRegex(R1CSError, "non-negative"):
            LinearCombination(((-1, 1),), system._owner)

        with self.assertRaises(R1CSError):
            system.linear_combination(
                ((Variable(9, "private", "bad", system._owner), 1),)
            )

    def test_matrix_excludes_secret_assignments_and_variable_names(self):
        secret_name = "sentinel-private-key-do-not-serialize"
        secret_value = 918273645546372819
        first = R1CS()
        first_private = first.alloc_private(secret_name, secret_value)
        first.enforce(first_private, 1, 0, secret_name)
        second = R1CS()
        second_private = second.alloc_private("other private name", 7)
        second.enforce(second_private, 1, 0, "other label")

        encoded = first.serialize_matrix()
        self.assertEqual(encoded, second.serialize_matrix())
        self.assertEqual(first.matrix_fingerprint(), second.matrix_fingerprint())
        self.assertNotIn(secret_name.encode(), encoded)
        self.assertNotIn(str(secret_value).encode(), encoded)
        self.assertNotIn(str(secret_value).encode(), first.matrix_fingerprint().encode())

    def test_each_matrix_structure_dimension_changes_serialization_and_fingerprint(self):
        def build(
            *,
            extra_column=False,
            extra_row=False,
            coefficient=1,
            public=False,
            changed_side=None,
        ):
            system = R1CS()
            value = (
                system.alloc_public("value", 1)
                if public
                else system.alloc_private("value", 1)
            )
            if extra_column:
                system.alloc_private("extra", 0)
            if changed_side == "b":
                system.enforce(1, value.lc() * coefficient, 0)
            elif changed_side == "c":
                system.enforce(1, 1, value.lc() * coefficient)
            else:
                system.enforce(value.lc() * coefficient, 1, 0)
            if extra_row:
                system.enforce(value, 1, 1)
            return system

        baseline = build()
        variants = (
            build(extra_column=True),
            build(extra_row=True),
            build(coefficient=2),
            build(public=True),
            build(changed_side="b"),
            build(changed_side="c"),
        )
        for variant in variants:
            with self.subTest(fingerprint=variant.matrix_fingerprint()):
                self.assertNotEqual(
                    baseline.serialize_matrix(), variant.serialize_matrix()
                )
                self.assertNotEqual(
                    baseline.matrix_fingerprint(), variant.matrix_fingerprint()
                )

    def test_rejects_foreign_variables_and_invalid_assignments(self):
        first, second = R1CS(), R1CS()
        variable = first.alloc_private("value", 1)
        foreign = second.alloc_private("foreign", 1)
        with self.assertRaises(R1CSError):
            first.enforce_equal(variable, foreign)
        with self.assertRaises(R1CSError):
            first.is_satisfied({0: 1})
        with self.assertRaises(TypeError):
            first.is_satisfied({variable.index: True})


if __name__ == "__main__":
    unittest.main()
