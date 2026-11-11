import unittest
from unittest.mock import patch

from src.bls12_381 import (
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    Fp2,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    multiply_g1,
    multiply_g2,
)
from src.groth16_qap import QAP, QAPAssignment
from src.groth16_queries import (
    G1Query,
    G2Query,
    QueryError,
    QueryScalarAssignment,
    ValidatedG1Point,
    ValidatedG2Point,
    evaluate_a_query,
    evaluate_b_g1_query,
    evaluate_b_g2_query,
    evaluate_h_query,
    evaluate_l_query,
    msm_g1,
    msm_g2,
)
from src.r1cs import R1CS


def _system_and_assignment():
    system = R1CS()
    public = system.alloc_public("public", 2)
    private = system.alloc_private("private", 3)
    product = system.multiply(public, private, "product")
    system.enforce_equal(product, 6, "product binding")
    qap = QAP.from_r1cs(system)
    assignment = QAPAssignment((2,), (3, 6))
    return system, qap, assignment


class ValidatedQueryTests(unittest.TestCase):
    def test_validated_point_wrappers_accept_generators_and_identity(self):
        self.assertEqual(ValidatedG1Point(G1_GENERATOR).point, G1_GENERATOR)
        self.assertEqual(ValidatedG1Point(G1_INFINITY).point, G1_INFINITY)
        self.assertEqual(ValidatedG2Point(G2_GENERATOR).point, G2_GENERATOR)
        self.assertEqual(ValidatedG2Point(G2_INFINITY).point, G2_INFINITY)

    def test_validated_point_wrappers_reject_invalid_curve_points(self):
        with self.assertRaisesRegex(QueryError, "not on the curve"):
            ValidatedG1Point(G1Point(0, 0))
        with self.assertRaisesRegex(QueryError, "not on the curve"):
            ValidatedG2Point(G2Point(Fp2(), Fp2()))

    def test_scalar_assignment_is_immutable_canonical_and_has_one_prefix(self):
        system, qap, assignment = _system_and_assignment()
        values = QueryScalarAssignment.from_qap(qap, assignment)
        self.assertEqual(values.values, (1, 2, 3, 6))
        self.assertEqual(values.public_values, (2,))
        self.assertEqual(values.auxiliary_values, (3, 6))
        with self.assertRaises((AttributeError, TypeError)):
            values.values = (1, 2, 3, 6)
        with self.assertRaises(TypeError):
            QueryScalarAssignment((1, 2, 3, 6), 1, 2)
        self.assertTrue(system.is_satisfied())

    def test_from_qap_rejects_unsatisfied_witness(self):
        _, qap, _ = _system_and_assignment()
        with self.assertRaisesRegex(QueryError, "does not satisfy"):
            QueryScalarAssignment.from_qap(qap, QAPAssignment((2,), (4, 6)))


class MSMTests(unittest.TestCase):
    def test_g1_single_term_zero_and_multiple_terms(self):
        query = G1Query((G1_GENERATOR, G1_INFINITY, G1_GENERATOR, G1_GENERATOR))
        self.assertEqual(msm_g1(query, (5, 9, 0, 0)), multiply_g1(G1_GENERATOR, 5))
        self.assertEqual(msm_g1(query, (0, 1, 0, 0)), G1_INFINITY)
        # 2G + 3G is independently assembled as successive additions.
        expected = add_g1(
            add_g1(G1_GENERATOR, G1_GENERATOR),
            add_g1(add_g1(G1_GENERATOR, G1_GENERATOR), G1_GENERATOR),
        )
        self.assertEqual(msm_g1(G1Query((G1_GENERATOR, G1_GENERATOR)), (2, 3)), expected)

    def test_g2_single_term_zero_identity_and_multiple_terms(self):
        query = G2Query((G2_GENERATOR, G2_INFINITY, G2_GENERATOR))
        self.assertEqual(msm_g2(query, (4, 8, 0)), multiply_g2(G2_GENERATOR, 4))
        self.assertEqual(msm_g2(query, (0, 1, 0)), G2_INFINITY)
        expected = add_g2(multiply_g2(G2_GENERATOR, 2), multiply_g2(G2_GENERATOR, 3))
        self.assertEqual(msm_g2(G2Query((G2_GENERATOR, G2_GENERATOR)), (2, 3)), expected)

    def test_malformed_lengths_and_scalars_reject_before_group_operations(self):
        g1_query = G1Query((G1_GENERATOR,))
        with patch("src.groth16_queries.multiply_g1") as multiply:
            with self.assertRaisesRegex(QueryError, "does not match scalar length"):
                msm_g1(g1_query, ())
            multiply.assert_not_called()
        with self.assertRaisesRegex(QueryError, "not canonical"):
            msm_g1(g1_query, (SCALAR_MODULUS,))
        with self.assertRaisesRegex(QueryError, "does not match scalar length"):
            msm_g2(G2Query((G2_GENERATOR,)), ())


class QueryEvaluationTests(unittest.TestCase):
    def test_a_and_b_queries_use_one_public_then_auxiliary_order(self):
        _, qap, witness_assignment = _system_and_assignment()
        assignment = QueryScalarAssignment.from_qap(qap, witness_assignment)
        g1_points = (G1_GENERATOR, *(multiply_g1(G1_GENERATOR, k) for k in (2, 3, 4)))
        g2_points = (G2_GENERATOR, *(multiply_g2(G2_GENERATOR, k) for k in (2, 3, 4)))
        g1_query = G1Query(g1_points)
        g2_query = G2Query(g2_points)

        # ONE*G + public*(2G) + private*(3G) + output*(4G) = 38G.
        expected_g1 = multiply_g1(G1_GENERATOR, 38)
        expected_g2 = multiply_g2(G2_GENERATOR, 38)
        self.assertEqual(evaluate_a_query(g1_query, qap, assignment), expected_g1)
        self.assertEqual(evaluate_b_g1_query(g1_query, qap, assignment), expected_g1)
        self.assertEqual(evaluate_b_g2_query(g2_query, qap, assignment), expected_g2)

    def test_l_query_uses_only_auxiliary_values(self):
        _, qap, witness_assignment = _system_and_assignment()
        assignment = QueryScalarAssignment.from_qap(qap, witness_assignment)
        query = G1Query(
            (multiply_g1(G1_GENERATOR, 2), multiply_g1(G1_GENERATOR, 4))
        )
        # The public scalar 2 and implicit ONE are intentionally absent.
        self.assertEqual(
            evaluate_l_query(query, qap, assignment),
            multiply_g1(G1_GENERATOR, 30),
        )

    def test_h_query_uses_qap_domain_coefficients_in_order(self):
        _, qap, witness_assignment = _system_and_assignment()
        quotient = qap.quotient(witness_assignment)
        query = G1Query(
            tuple(multiply_g1(G1_GENERATOR, index + 1) for index in range(len(quotient)))
        )
        expected_scalar = sum(
            coefficient * (index + 1)
            for index, coefficient in enumerate(quotient)
        ) % SCALAR_MODULUS
        self.assertEqual(
            evaluate_h_query(query, qap, quotient),
            multiply_g1(G1_GENERATOR, expected_scalar),
        )

    def test_query_and_h_lengths_are_rejected_before_scalar_multiplication(self):
        _, qap, witness_assignment = _system_and_assignment()
        assignment = QueryScalarAssignment.from_qap(qap, witness_assignment)
        with patch("src.groth16_queries.multiply_g1") as multiply:
            with self.assertRaisesRegex(QueryError, "A-query length"):
                evaluate_a_query(G1Query(()), qap, assignment)
            with self.assertRaisesRegex(QueryError, "L-query length"):
                evaluate_l_query(G1Query(()), qap, assignment)
            with self.assertRaisesRegex(QueryError, "H-query length"):
                evaluate_h_query(G1Query(()), qap, ())
            multiply.assert_not_called()

    def test_b_query_rejects_unsatisfied_scalar_assignment(self):
        _, qap, assignment = _system_and_assignment()
        with self.assertRaisesRegex(QueryError, "does not satisfy"):
            QueryScalarAssignment.from_qap(
                qap, QAPAssignment(assignment.public_inputs, (4, 6))
            )

    def test_assignment_is_bound_to_the_qap_that_validated_it(self):
        _, qap, _ = _system_and_assignment()
        other_system, other_qap, other_assignment = _system_and_assignment()
        self.assertIsNot(other_system, qap.system)
        validated = QueryScalarAssignment.from_qap(other_qap, other_assignment)
        query = G1Query((G1_GENERATOR,) * qap.variable_count)
        with self.assertRaisesRegex(QueryError, "dimensions do not match"):
            evaluate_a_query(query, qap, validated)


if __name__ == "__main__":
    unittest.main()
