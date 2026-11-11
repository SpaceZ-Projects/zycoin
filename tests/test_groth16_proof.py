import unittest
from dataclasses import replace
from unittest.mock import patch

from src.bls12_381 import (
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    multiply_g1,
    multiply_g2,
)
from src.groth16_proof import (
    Groth16ProvingQueries,
    ProofAssemblyError,
    assemble_proof_elements,
)
from src.groth16_qap import QAP, QAPAssignment
from src.groth16_queries import G1Query, G2Query, ValidatedG1Point, ValidatedG2Point
from src.r1cs import R1CS


def _system_and_assignment():
    system = R1CS()
    public = system.alloc_public("public", 2)
    private = system.alloc_private("private", 3)
    product = system.multiply(public, private, "product")
    system.enforce_equal(product, 6, "product binding")
    return QAP.from_r1cs(system), QAPAssignment((2,), (3, 6))


def _queries(
    a,
    b1,
    b2,
    l,
    h,
    alpha=17,
    beta1=19,
    beta2=23,
    delta1=29,
    delta2=31,
):
    return Groth16ProvingQueries(
        ValidatedG1Point(multiply_g1(G1_GENERATOR, alpha)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, beta1)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, beta2)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, delta1)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, delta2)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, n) for n in a)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, n) for n in b1)),
        G2Query(tuple(multiply_g2(G2_GENERATOR, n) for n in b2)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, n) for n in l)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, n) for n in h)),
    )


class ProofAssemblyTests(unittest.TestCase):
    def test_bellman_equations_match_independent_hand_computation(self):
        qap, assignment = _system_and_assignment()
        h_weights = (11, 12, 13)
        queries = _queries(
            a=(1, 2, 3, 4),
            b1=(5, 6, 7, 8),
            b2=(13, 14, 15, 16),
            l=(9, 10),
            h=h_weights,
        )

        # Witness order is ONE, public, auxiliary: (1, 2, 3, 6).
        a_query = 1 + 4 + 9 + 24
        b1_query = 5 + 12 + 21 + 48
        b2_query = 13 + 28 + 45 + 96
        l_query = 9 * 3 + 10 * 6
        quotient = qap.quotient(assignment)
        h_query = sum(value * weight for value, weight in zip(quotient, h_weights))
        r, s = 2, 3

        result = assemble_proof_elements(qap, assignment, queries, r, s)
        expected_a = 17 + r * 29 + a_query
        expected_b = 23 + s * 31 + b2_query
        expected_c = (
            r * s * 29
            + s * 17
            + r * 19
            + s * a_query
            + r * b1_query
            + h_query
            + l_query
        )
        self.assertEqual(result.a, multiply_g1(G1_GENERATOR, expected_a))
        self.assertEqual(result.b, multiply_g2(G2_GENERATOR, expected_b))
        self.assertEqual(result.c, multiply_g1(G1_GENERATOR, expected_c))

    def test_zero_randomizers_and_identity_points(self):
        qap, assignment = _system_and_assignment()
        queries = _queries(
            a=(1, 2, 3, 4),
            b1=(5, 6, 7, 8),
            b2=(13, 14, 15, 16),
            l=(9, 10),
            h=(11, 12, 13),
        )
        result = assemble_proof_elements(qap, assignment, queries, 0, 0)
        self.assertEqual(result.a, multiply_g1(G1_GENERATOR, 38 + 17))
        self.assertEqual(result.b, multiply_g2(G2_GENERATOR, 182 + 23))

        identity = ValidatedG1Point(G1_INFINITY)
        identity_g2 = ValidatedG2Point(G2_INFINITY)
        nonidentity = ValidatedG1Point(G1_GENERATOR)
        nonidentity_g2 = ValidatedG2Point(G2_GENERATOR)
        identity_queries = Groth16ProvingQueries(
            identity,
            identity,
            identity_g2,
            nonidentity,
            nonidentity_g2,
            G1Query((identity,) * qap.variable_count),
            G1Query((identity,) * qap.variable_count),
            G2Query((identity_g2,) * qap.variable_count),
            G1Query((identity,) * qap.auxiliary_variable_count),
            G1Query((identity,) * (qap.domain.size - 1)),
        )
        identity_result = assemble_proof_elements(
            qap, assignment, identity_queries, 0, 0
        )
        self.assertEqual(identity_result.a, G1_INFINITY)
        self.assertEqual(identity_result.b, G2_INFINITY)
        self.assertEqual(identity_result.c, G1_INFINITY)

    def test_wrong_group_types_and_query_lengths_reject(self):
        qap, assignment = _system_and_assignment()
        with self.assertRaisesRegex(TypeError, "alpha_g1"):
            Groth16ProvingQueries(
                G1_GENERATOR,
                ValidatedG1Point(G1_GENERATOR),
                ValidatedG2Point(G2_GENERATOR),
                ValidatedG1Point(G1_GENERATOR),
                ValidatedG2Point(G2_GENERATOR),
                G1Query((G1_GENERATOR,) * qap.variable_count),
                G1Query((G1_GENERATOR,) * qap.variable_count),
                G2Query((G2_GENERATOR,) * qap.variable_count),
                G1Query((G1_GENERATOR,) * qap.auxiliary_variable_count),
                G1Query((G1_GENERATOR,) * (qap.domain.size - 1)),
            )

        valid = _queries(
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2),
            (1, 2, 3),
        )
        malformed = Groth16ProvingQueries(
            valid.alpha_g1,
            valid.beta_g1,
            valid.beta_g2,
            valid.delta_g1,
            valid.delta_g2,
            G1Query(()),
            valid.b_g1_query,
            valid.b_g2_query,
            valid.l_query,
            valid.h_query,
        )
        with patch("src.groth16_qap.QAP.validate_assignment") as validate:
            with self.assertRaisesRegex(ProofAssemblyError, "A-query length"):
                assemble_proof_elements(qap, assignment, malformed, 1, 1)
            validate.assert_not_called()

    def test_identity_delta_elements_are_rejected_before_witness_evaluation(self):
        qap, assignment = _system_and_assignment()
        valid = _queries(
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2),
            (1, 2, 3),
        )
        malformed = replace(valid, delta_g1=ValidatedG1Point(G1_INFINITY))
        with patch("src.groth16_qap.QAP.validate_assignment") as validate:
            with self.assertRaisesRegex(ProofAssemblyError, "identity delta"):
                assemble_proof_elements(qap, assignment, malformed, 1, 1)
            validate.assert_not_called()

    def test_invalid_randomizers_and_unsatisfied_assignment_reject(self):
        qap, assignment = _system_and_assignment()
        queries = _queries(
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2, 3, 4),
            (1, 2),
            (1, 2, 3),
        )
        with self.assertRaisesRegex(ProofAssemblyError, "canonical"):
            assemble_proof_elements(qap, assignment, queries, SCALAR_MODULUS, 0)
        with self.assertRaisesRegex(ProofAssemblyError, "does not satisfy"):
            assemble_proof_elements(
                qap, QAPAssignment((2,), (4, 6)), queries, 1, 1
            )


if __name__ == "__main__":
    unittest.main()
