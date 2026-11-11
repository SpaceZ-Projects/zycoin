import unittest
from unittest.mock import patch

import src.groth16_verification as verification
from src.bls12_381 import (
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    multiply_g1,
    multiply_g2,
)
from src.groth16_verification import (
    SAPLING_SPEND_PUBLIC_INPUT_ORDER,
    Groth16Proof,
    Groth16VerificationError,
    Groth16VerificationKey,
    public_input_accumulator,
    verify_groth16_proof,
    verify_sapling_spend_proof,
)
from src.sapling_spend_circuit import SPEND_PUBLIC_INPUT_ORDER


def _synthetic_valid_case():
    public_inputs = (3, 5)
    ic_scalars = (13, 17, 19)
    alpha_scalar, beta_scalar = 23, 29
    gamma_scalar, delta_scalar = 31, 37
    a_scalar, b_scalar = 41, 43
    accumulator_scalar = (
        ic_scalars[0]
        + sum(value * coefficient for value, coefficient in zip(public_inputs, ic_scalars[1:]))
    ) % SCALAR_MODULUS
    c_scalar = (
        (
            a_scalar * b_scalar
            - alpha_scalar * beta_scalar
            - accumulator_scalar * gamma_scalar
        )
        * pow(delta_scalar, -1, SCALAR_MODULUS)
    ) % SCALAR_MODULUS

    verification_key = Groth16VerificationKey(
        alpha_g1=multiply_g1(G1_GENERATOR, alpha_scalar),
        beta_g2=multiply_g2(G2_GENERATOR, beta_scalar),
        gamma_g2=multiply_g2(G2_GENERATOR, gamma_scalar),
        delta_g2=multiply_g2(G2_GENERATOR, delta_scalar),
        ic_query=tuple(multiply_g1(G1_GENERATOR, value) for value in ic_scalars),
    )
    proof = Groth16Proof(
        multiply_g1(G1_GENERATOR, a_scalar),
        multiply_g2(G2_GENERATOR, b_scalar),
        multiply_g1(G1_GENERATOR, c_scalar),
    )
    return verification_key, proof, public_inputs, accumulator_scalar


class PublicInputAccumulatorTests(unittest.TestCase):
    def test_accumulator_includes_one_then_preserves_input_order(self):
        key, _, inputs, expected_scalar = _synthetic_valid_case()
        accumulator = public_input_accumulator(key, inputs)
        self.assertEqual(accumulator, multiply_g1(G1_GENERATOR, expected_scalar))
        self.assertNotEqual(
            accumulator,
            public_input_accumulator(key, tuple(reversed(inputs))),
        )

    def test_sapling_input_order_matches_circuit_contract(self):
        self.assertEqual(SAPLING_SPEND_PUBLIC_INPUT_ORDER, SPEND_PUBLIC_INPUT_ORDER)
        inputs = tuple(range(1, 8))
        key = Groth16VerificationKey(
            G1_GENERATOR,
            G2_GENERATOR,
            G2_INFINITY,
            G2_INFINITY,
            tuple(multiply_g1(G1_GENERATOR, index + 2) for index in range(8)),
        )
        accumulator_scalar = 2 + sum(
            value * (index + 3) for index, value in enumerate(inputs)
        )
        self.assertEqual(
            public_input_accumulator(key, inputs),
            multiply_g1(G1_GENERATOR, accumulator_scalar),
        )


class Groth16VerificationTests(unittest.TestCase):
    def test_valid_synthetic_proof_and_single_final_exponentiation(self):
        key, proof, inputs, _ = _synthetic_valid_case()
        with patch(
            "src.groth16_verification.miller_loop",
            wraps=verification.miller_loop,
        ) as miller, patch(
            "src.groth16_verification.final_exponentiate",
            wraps=verification.final_exponentiate,
        ) as final_exp:
            self.assertTrue(verify_groth16_proof(key, proof, inputs))
            self.assertEqual(miller.call_count, 4)
            self.assertEqual(final_exp.call_count, 1)

    def test_altered_public_input_and_proof_points_return_false(self):
        key, proof, inputs, _ = _synthetic_valid_case()
        self.assertFalse(verify_groth16_proof(key, proof, (inputs[0] + 1, inputs[1])))
        altered_proofs = (
            Groth16Proof(multiply_g1(G1_GENERATOR, 42), proof.b, proof.c),
            Groth16Proof(
                proof.a,
                multiply_g2(G2_GENERATOR, 44),
                proof.c,
            ),
            Groth16Proof(
                proof.a,
                proof.b,
                multiply_g1(G1_GENERATOR, 1),
            ),
        )
        for changed_proof in altered_proofs:
            with self.subTest(proof=changed_proof):
                self.assertFalse(verify_groth16_proof(key, changed_proof, inputs))

    def test_wrong_ic_length_and_malformed_public_values_raise(self):
        key, proof, inputs, _ = _synthetic_valid_case()
        with self.assertRaisesRegex(Groth16VerificationError, "expected 2"):
            verify_groth16_proof(key, proof, inputs[:1])
        for invalid in (-1, SCALAR_MODULUS, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                Groth16VerificationError, "canonical"
            ):
                verify_groth16_proof(key, proof, (invalid, inputs[1]))
        with self.assertRaisesRegex(Groth16VerificationError, "exactly seven"):
            verify_sapling_spend_proof(key, proof, inputs)

    def test_identity_points_are_valid_and_verify_identity_equation(self):
        identity_key = Groth16VerificationKey(
            G1_INFINITY,
            G2_INFINITY,
            G2_INFINITY,
            G2_INFINITY,
            (G1_INFINITY,),
        )
        identity_proof = Groth16Proof(G1_INFINITY, G2_INFINITY, G1_INFINITY)
        self.assertEqual(
            public_input_accumulator(identity_key, ()),
            G1_INFINITY,
        )
        self.assertTrue(verify_groth16_proof(identity_key, identity_proof, ()))

    def test_wrong_group_and_non_subgroup_points_fail_explicitly(self):
        with self.assertRaisesRegex(TypeError, "alpha_g1"):
            Groth16VerificationKey(
                G2_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                (G1_GENERATOR,),
            )
        with self.assertRaisesRegex(ValueError, "not on the curve"):
            Groth16Proof(G1Point(0, 0), G2_GENERATOR, G1_GENERATOR)
        non_subgroup = G1Point(0, 2)
        self.assertTrue(non_subgroup.is_on_curve())
        self.assertFalse(non_subgroup.is_in_subgroup())
        with self.assertRaisesRegex(ValueError, "prime-order subgroup"):
            Groth16Proof(non_subgroup, G2_GENERATOR, G1_GENERATOR)
        with self.assertRaisesRegex(ValueError, "prime-order subgroup"):
            Groth16VerificationKey(
                G1_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                (non_subgroup,),
            )
        with self.assertRaisesRegex(Groth16VerificationError, "implicit ONE"):
            Groth16VerificationKey(
                G1_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                G2_GENERATOR,
                (),
            )

    def test_sapling_helper_requires_seven_inputs_and_key_slots(self):
        valid_key, proof, _, _ = _synthetic_valid_case()
        seven_input_key = Groth16VerificationKey(
            G1_GENERATOR,
            G2_GENERATOR,
            G2_INFINITY,
            G2_INFINITY,
            (G1_GENERATOR,) * 8,
        )
        self.assertTrue(
            verify_sapling_spend_proof(
                seven_input_key,
                Groth16Proof(G1_GENERATOR, G2_GENERATOR, G1_INFINITY),
                (0, 1, 2, 3, 4, 5, 6),
            )
        )
        with self.assertRaisesRegex(Groth16VerificationError, "seven"):
            verify_sapling_spend_proof(valid_key, proof, (1, 2, 3, 4, 5, 6, 7))


if __name__ == "__main__":
    unittest.main()
