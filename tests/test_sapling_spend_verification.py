import unittest
from dataclasses import replace

from src.jubjub import FIELD_MODULUS, Point
from src.sapling_spend_reference import generate_pinned_test_witness
from src.sapling_spend_verification import (
    SPEND_PUBLIC_INPUT_ORDER,
    verify_spend_reference_witness,
)


class SpendWitnessVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.witness = generate_pinned_test_witness()

    def test_seeded_witness_relations_are_consistent(self):
        result = verify_spend_reference_witness(self.witness)
        self.assertTrue(result.valid, result.mismatches)
        self.assertEqual(result.mismatches, ())
        self.assertIn("public_inputs", result.checked_fields)
        self.assertEqual(
            SPEND_PUBLIC_INPUT_ORDER,
            (
                "rk.u",
                "rk.v",
                "cv.u",
                "cv.v",
                "anchor",
                "nullifier_chunk_0",
                "nullifier_chunk_1",
            ),
        )

    def test_individual_witness_field_mutations_are_rejected(self):
        witness = self.witness

        def point_change(point):
            return Point((point.u + 1) % FIELD_MODULUS, point.v)

        first_sibling, first_direction = witness.authentication_path[0]
        changed_path = (
            (first_sibling + 1, first_direction),
            *witness.authentication_path[1:],
        )
        changed_inputs = (
            witness.public_inputs[0] + 1,
            *witness.public_inputs[1:],
        )
        mutations = {
            "value": witness.value + 1,
            "rcv": witness.rcv + 1,
            "ak": point_change(witness.ak),
            "nsk": witness.nsk + 1,
            "nk": point_change(witness.nk),
            "ivk": witness.ivk + 1,
            "diversifier": bytes((witness.diversifier[0] ^ 1,))
            + witness.diversifier[1:],
            "diversifier_base": point_change(witness.diversifier_base),
            "transmission_key": point_change(witness.transmission_key),
            "rcm": witness.rcm + 1,
            "note_commitment": point_change(witness.note_commitment),
            "ar": witness.ar + 1,
            "randomized_key": point_change(witness.randomized_key),
            "value_commitment": point_change(witness.value_commitment),
            "authentication_path": changed_path,
            "position": (witness.position + 1) % (1 << 32),
            "anchor": (witness.anchor + 1) % FIELD_MODULUS,
            "nullifier": bytes((witness.nullifier[0] ^ 1,))
            + witness.nullifier[1:],
            "public_inputs": changed_inputs,
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                result = verify_spend_reference_witness(
                    replace(witness, **{field: replacement})
                )
                self.assertFalse(result.valid)
                self.assertTrue(result.mismatches)

    def test_public_input_slot_mutations_are_rejected(self):
        for index in range(len(self.witness.public_inputs)):
            with self.subTest(public_input=index):
                inputs = list(self.witness.public_inputs)
                inputs[index] += 1
                result = verify_spend_reference_witness(
                    replace(self.witness, public_inputs=tuple(inputs))
                )
                self.assertIn("public_inputs", result.mismatches)


if __name__ == "__main__":
    unittest.main()
