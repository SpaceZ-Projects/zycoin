import unittest
from unittest.mock import patch

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_fft import MAX_DOMAIN_SIZE, FFTDomain
from src.groth16_qap import (
    QAP,
    QAPAssignment,
    QAPDomain,
    QAPError,
    UnsatisfiedAssignmentError,
)
from src.r1cs import R1CS


def _evaluate_polynomial(coefficients, point):
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * point + coefficient) % SCALAR_MODULUS
    return value


def _divide_by_vanishing(product, domain_size):
    remainder = list(product)
    quotient = [0] * max(0, domain_size - 1)
    for degree in range(len(remainder) - 1, domain_size - 1, -1):
        coefficient = remainder[degree]
        quotient[degree - domain_size] = coefficient
        remainder[degree] = 0
        remainder[degree - domain_size] = (
            remainder[degree - domain_size] + coefficient
        ) % SCALAR_MODULUS
    return quotient, remainder[:domain_size]


def _direct_quotient(polynomials, domain_size):
    product = [0] * (2 * domain_size - 1)
    for left_index, left in enumerate(polynomials.a):
        for right_index, right in enumerate(polynomials.b):
            product[left_index + right_index] = (
                product[left_index + right_index] + left * right
            ) % SCALAR_MODULUS
    for index, coefficient in enumerate(polynomials.c):
        product[index] = (product[index] - coefficient) % SCALAR_MODULUS
    quotient, remainder = _divide_by_vanishing(product, domain_size)
    return quotient, remainder


def _satisfied_system():
    system = R1CS()
    first_public = system.alloc_public("first public", 3)
    second_public = system.alloc_public("second public", 4)
    private = system.alloc_private("private", 5)
    product = system.multiply(first_public, private, "product")
    system.enforce_equal(product, 15, "product constant")
    system.enforce_equal(second_public, 4, "second public binding")
    return system, QAPAssignment((3, 4), (5, 15))


class QAPDomainTests(unittest.TestCase):
    def test_domain_includes_dummy_inputs_and_pads_to_next_power_of_two(self):
        domain = QAPDomain.create(constraint_count=3, input_count=4)
        self.assertEqual(domain.row_count, 7)
        self.assertEqual(domain.padding_count, 1)
        self.assertEqual(domain.size, 8)

    def test_domain_boundary_and_invalid_shapes(self):
        maximum = QAPDomain.create(MAX_DOMAIN_SIZE - 1, 1)
        self.assertEqual(maximum.size, MAX_DOMAIN_SIZE)
        with self.assertRaisesRegex(QAPError, "Bellman limit"):
            QAPDomain.create(MAX_DOMAIN_SIZE, 1)
        for constraints, inputs in ((-1, 1), (True, 1), (0, 0), (0, False)):
            with self.subTest(constraints=constraints, inputs=inputs), self.assertRaises(
                QAPError
            ):
                QAPDomain.create(constraints, inputs)

    def test_inconsistent_explicit_domain_metadata_is_rejected(self):
        domain = QAPDomain.create(1, 1)
        with self.assertRaisesRegex(QAPError, "inconsistent"):
            QAPDomain(
                constraint_count=1,
                input_count=1,
                row_count=2,
                padding_count=domain.padding_count + 1,
                fft_domain=domain.fft_domain,
            )


class QAPConstructionTests(unittest.TestCase):
    def test_assignment_separates_public_auxiliary_and_implicit_one(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        evaluations = qap.evaluations(assignment)

        self.assertTrue(system.is_satisfied())
        self.assertEqual(system.public_inputs(), (3, 4))
        self.assertEqual(qap.domain.row_count, 6)
        self.assertEqual(qap.domain.size, 8)
        self.assertEqual(evaluations.a[:3], (3, 0, 0))
        self.assertEqual(evaluations.b[:3], (5, 1, 1))
        self.assertEqual(evaluations.c[:3], (15, 0, 0))
        # Bellman's appended rows are ONE, first public, second public.
        self.assertEqual(evaluations.a[3:6], (1, 3, 4))
        self.assertEqual(evaluations.b[3:6], (0, 0, 0))
        self.assertEqual(evaluations.c[3:6], (0, 0, 0))
        self.assertEqual(evaluations.a[6:], (0, 0))
        self.assertEqual(len(assignment.auxiliary_assignments), 2)

    def test_polynomials_match_direct_evaluation_at_every_domain_point(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        evaluations = qap.evaluations(assignment)
        polynomials = qap.polynomials(assignment)
        point = 1
        for index in range(qap.domain.size):
            with self.subTest(index=index):
                self.assertEqual(
                    _evaluate_polynomial(polynomials.a, point),
                    evaluations.a[index],
                )
                self.assertEqual(
                    _evaluate_polynomial(polynomials.b, point),
                    evaluations.b[index],
                )
                self.assertEqual(
                    _evaluate_polynomial(polynomials.c, point),
                    evaluations.c[index],
                )
            point = point * qap.domain.fft_domain.omega % SCALAR_MODULUS

    def test_quotient_matches_independent_polynomial_division(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        polynomials = qap.polynomials(assignment)
        expected, remainder = _direct_quotient(polynomials, qap.domain.size)

        self.assertEqual(remainder, [0] * qap.domain.size)
        self.assertEqual(qap.quotient(assignment), tuple(expected))

    def test_zero_and_constant_constraint_polynomials(self):
        zero_system = R1CS()
        zero_system.enforce(0, 1, 0, "zero relation")
        zero_qap = QAP.from_r1cs(zero_system)
        zero_assignment = QAPAssignment((), ())
        zero_polynomials = zero_qap.polynomials(zero_assignment)
        self.assertEqual(zero_polynomials.c, (0, 0))
        self.assertEqual(
            zero_qap.quotient(zero_assignment),
            ((-pow(4, -1, SCALAR_MODULUS)) % SCALAR_MODULUS,),
        )

        constant_system = R1CS()
        constant_system.enforce(1, 1, 1, "constant relation")
        constant_qap = QAP.from_r1cs(constant_system)
        constant_assignment = QAPAssignment((), ())
        constant_polynomials = constant_qap.polynomials(constant_assignment)
        self.assertEqual(constant_polynomials.a, (1, 0))
        half = pow(2, -1, SCALAR_MODULUS)
        self.assertEqual(constant_polynomials.b, (half, half))
        self.assertEqual(constant_polynomials.c, (half, half))
        self.assertEqual(constant_qap.quotient(constant_assignment), (0,))

    def test_unsatisfied_and_nondivisible_assignment_is_rejected(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        invalid = QAPAssignment(assignment.public_inputs, (6, 15))
        with self.assertRaisesRegex(UnsatisfiedAssignmentError, "constraint 0"):
            qap.quotient(invalid)

        impossible = R1CS()
        impossible.enforce(1, 1, 0, "nonzero remainder")
        with self.assertRaises(UnsatisfiedAssignmentError):
            QAP.from_r1cs(impossible).quotient(QAPAssignment((), ()))

    def test_nonzero_highest_quotient_coefficient_is_not_truncated(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        invalid_coefficients = [0] * qap.domain.size
        invalid_coefficients[-1] = 1
        with patch.object(
            FFTDomain, "icoset_fft", return_value=invalid_coefficients
        ), self.assertRaisesRegex(QAPError, "degree-\\(n-1\\)"):
            qap.quotient(assignment)

    def test_invalid_assignments_and_mutated_r1cs_shape_are_rejected(self):
        system, assignment = _satisfied_system()
        qap = QAP.from_r1cs(system)
        with self.assertRaisesRegex(QAPError, "public inputs"):
            qap.evaluations(QAPAssignment((3,), (5, 15)))
        with self.assertRaisesRegex(QAPError, "auxiliary assignments"):
            qap.evaluations(QAPAssignment((3, 4), (5,)))
        with self.assertRaises(QAPError):
            QAPAssignment((True,), ())

        system.enforce_equal(1, 1, "post-QAP mutation")
        with self.assertRaisesRegex(QAPError, "shape changed"):
            qap.evaluations(assignment)

    def test_zero_constraint_system_has_zero_quotient(self):
        qap = QAP.from_r1cs(R1CS())
        self.assertEqual(qap.domain.size, 1)
        self.assertEqual(qap.quotient(QAPAssignment((), ())), ())


if __name__ == "__main__":
    unittest.main()
