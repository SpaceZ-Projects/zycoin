import hashlib
import json
import unittest

from src.bls12_381 import SCALAR_MODULUS
from src.r1cs import R1CS, R1CSError
from src.sapling_gadgets import constrain_sapling_conditional_anchor
from tests.sapling_spend_semantic_equivalence import (
    local_anchor_satisfied,
    local_position_bits,
    local_position_reconstruction_satisfied,
    semantic_probe_results,
    upstream_anchor_satisfied,
    upstream_position_from_directions,
)


class SaplingSpendSemanticEquivalenceTests(unittest.TestCase):
    def _local_anchor_system(self, note_value, root, anchor):
        system = R1CS()
        anchor_variable = system.alloc_public("public anchor", anchor)
        root_variable = system.alloc_private("computed root", root)
        value_bits = tuple(
            system.alloc_private(
                f"note value bit[{index}]", (note_value >> index) & 1
            )
            for index in range(64)
        )
        for index, bit in enumerate(value_bits):
            system.boolean(bit, f"note value bit[{index}] boolean")
        note_value_expression = system.linear_combination(
            tuple((bit, 1 << index) for index, bit in enumerate(value_bits))
        )
        constrain_sapling_conditional_anchor(
            system,
            root_variable,
            anchor_variable,
            note_value_expression,
            "conditional anchor",
        )
        return system, root_variable, anchor_variable, value_bits

    def test_anchor_substitution_matches_at_zero_and_nonzero_value_boundaries(self):
        field_max = SCALAR_MODULUS - 1
        for note_value in (0, 1, (1 << 64) - 1):
            with self.subTest(note_value=note_value):
                bits = tuple((note_value >> index) & 1 for index in range(64))
                upstream = upstream_anchor_satisfied(
                    bits, field_max, field_max, field_max
                )
                local = local_anchor_satisfied(bits, field_max, field_max)
                self.assertTrue(upstream)
                self.assertEqual(local, upstream)

                system, _, _, _ = self._local_anchor_system(
                    note_value, field_max, field_max
                )
                self.assertTrue(system.is_satisfied())

    def test_zero_value_allows_root_difference_but_nonzero_value_rejects_it(self):
        anchor = 7
        other_root = 9
        for note_value, expected in ((0, True), (1, False), ((1 << 64) - 1, False)):
            with self.subTest(note_value=note_value):
                bits = tuple((note_value >> index) & 1 for index in range(64))
                upstream = upstream_anchor_satisfied(
                    bits, other_root, anchor, anchor
                )
                local = local_anchor_satisfied(bits, other_root, anchor)
                self.assertEqual(upstream, expected)
                self.assertEqual(local, expected)

                system, root, _, _ = self._local_anchor_system(
                    note_value, other_root, anchor
                )
                self.assertEqual(system.is_satisfied(), expected)
                if note_value:
                    self.assertFalse(system.is_satisfied({root.index: anchor + 2}))

    def test_upstream_anchor_auxiliary_must_be_bound_even_at_zero_value(self):
        bits = (0,) * 64
        self.assertFalse(
            upstream_anchor_satisfied(
                bits,
                root=9,
                anchor_auxiliary=7,
                public_anchor=8,
            )
        )
        self.assertTrue(local_anchor_satisfied(bits, root=9, public_anchor=8))

    def test_local_anchor_rejects_non_boolean_note_value_assignment(self):
        system, _, _, bits = self._local_anchor_system(1, 5, 5)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({bits[0].index: 2}))

    def test_merkle_position_is_the_little_endian_path_direction_integer(self):
        for position in (0, 1, 1 << 31, (1 << 32) - 1):
            with self.subTest(position=position):
                bits = local_position_bits(position)
                directions = tuple(bool(bit) for bit in bits)
                self.assertEqual(
                    upstream_position_from_directions(directions), position
                )
                self.assertTrue(
                    local_position_reconstruction_satisfied(position, bits)
                )
                self.assertEqual(bits[0], position & 1)
                self.assertEqual(bits[31], (position >> 31) & 1)

    def test_local_range_check_accepts_position_boundaries_and_rejects_overflow(self):
        for value in (0, 1, 1 << 31, (1 << 32) - 1):
            with self.subTest(position=value):
                system = R1CS()
                position = system.alloc_private("position", value)
                bits = system.range_check(position, 32, "position bit")
                self.assertEqual(
                    tuple(system._witness_value(bit) for bit in bits),
                    local_position_bits(value),
                )
                self.assertTrue(system.is_satisfied())
                self.assertFalse(
                    system.is_satisfied({position.index: value ^ 1})
                )

        system = R1CS()
        position = system.alloc_private("position", 1 << 32)
        variable_count_before = len(system.variables)
        with self.assertRaises(R1CSError):
            system.range_check(position, 32, "position bit")
        self.assertEqual(len(system.variables), variable_count_before)

    def test_merkle_position_invalid_or_inconsistent_assignments_are_rejected(self):
        for position in (-1, 1 << 32, True):
            with self.subTest(position=position), self.assertRaises(ValueError):
                local_position_bits(position)

        with self.assertRaises(ValueError):
            upstream_position_from_directions((False,) * 31)
        with self.assertRaises(ValueError):
            upstream_position_from_directions((False,) * 31 + (1,))

        position = 1 << 31
        bits = local_position_bits(position)
        changed_bits = bits[:-1] + (0,)
        self.assertFalse(local_position_reconstruction_satisfied(position, changed_bits))
        self.assertEqual(
            upstream_position_from_directions(tuple(bool(bit) for bit in changed_bits)),
            0,
        )

    def test_boundary_probe_results_are_deterministic(self):
        first = semantic_probe_results()
        second = semantic_probe_results()
        encoded = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(first, second)
        self.assertEqual(
            hashlib.sha256(encoded).hexdigest(),
            "94d29c70b4f5ce62e37ffa0083300fa7025699b90fbc81c7c16a6b1e278964cd",
        )
        self.assertTrue(
            all(
                case["upstream"] == case["local"]
                for case in first["anchor_boundary_cases"]
            )
        )
        self.assertTrue(
            first["anchor_root_mismatch_cases"][0]["upstream"]
        )
        self.assertTrue(first["anchor_root_mismatch_cases"][0]["local"])
        self.assertFalse(
            first["anchor_root_mismatch_cases"][1]["upstream"]
        )
        self.assertFalse(first["anchor_root_mismatch_cases"][1]["local"])
        self.assertFalse(first["invalid_auxiliary_binding_case"]["upstream"])
        self.assertTrue(first["invalid_auxiliary_binding_case"]["local"])
        self.assertTrue(
            all(case["local_reconstruction"] for case in first["position_boundary_cases"])
        )


if __name__ == "__main__":
    unittest.main()
