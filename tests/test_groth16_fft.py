import unittest

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_fft import (
    MAX_DOMAIN_SIZE,
    MULTIPLICATIVE_GENERATOR,
    TWO_ADICITY,
    FFTDomain,
    FFTError,
)


def _evaluate_polynomial(coefficients, point):
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * point + coefficient) % SCALAR_MODULUS
    return value


def _direct_domain_evaluations(coefficients, domain):
    point = 1
    results = []
    for _ in range(domain.size):
        results.append(_evaluate_polynomial(coefficients, point))
        point = point * domain.omega % SCALAR_MODULUS
    return results


class FFTDomainTests(unittest.TestCase):
    def test_domain_uses_bellman_scalar_field_and_root_conventions(self):
        self.assertEqual(TWO_ADICITY, 32)
        self.assertEqual(MULTIPLICATIVE_GENERATOR, 7)
        for size in (1, 2, 4, 8, 1024):
            with self.subTest(size=size):
                domain = FFTDomain.create(size)
                self.assertEqual(pow(domain.omega, size, SCALAR_MODULUS), 1)
                if size > 1:
                    self.assertNotEqual(
                        pow(domain.omega, size // 2, SCALAR_MODULUS),
                        1,
                    )
                self.assertEqual(domain.omega * domain.omega_inverse % SCALAR_MODULUS, 1)
                self.assertEqual(size * domain.size_inverse % SCALAR_MODULUS, 1)
                self.assertNotEqual(
                    pow(domain.coset_generator, size, SCALAR_MODULUS), 1
                )

    def test_maximum_bellman_domain_boundary_without_allocating_coefficients(self):
        maximum = FFTDomain.create(MAX_DOMAIN_SIZE)
        self.assertEqual(maximum.size, 1 << 31)
        self.assertEqual(pow(maximum.omega, maximum.size, SCALAR_MODULUS), 1)
        self.assertNotEqual(
            pow(maximum.omega, maximum.size // 2, SCALAR_MODULUS), 1
        )
        with self.assertRaisesRegex(FFTError, "Bellman limit"):
            FFTDomain.create(MAX_DOMAIN_SIZE * 2)

    def test_rejects_invalid_sizes_and_unsupported_roots(self):
        for invalid_size in (0, -1, 3, 6, True, 1.0):
            with self.subTest(size=invalid_size), self.assertRaises(FFTError):
                FFTDomain.create(invalid_size)
        with self.assertRaisesRegex(FFTError, "canonical"):
            FFTDomain.create(4, SCALAR_MODULUS)
        with self.assertRaisesRegex(FFTError, "primitive"):
            FFTDomain.create(4, 1)
        with self.assertRaisesRegex(FFTError, "order dividing"):
            FFTDomain.create(4, 2)

    def test_accepts_an_explicit_primitive_root(self):
        canonical = FFTDomain.create(8)
        alternate_root = pow(canonical.omega, 3, SCALAR_MODULUS)
        alternate = FFTDomain.create(8, alternate_root)
        coefficients = [1, 2, 3, 4, 0, 0, 0, 0]
        self.assertEqual(
            alternate.fft(coefficients),
            _direct_domain_evaluations(coefficients, alternate),
        )

    def test_rejects_inconsistent_direct_domain_metadata(self):
        domain = FFTDomain.create(8)
        with self.assertRaisesRegex(FFTError, "normalization factor"):
            FFTDomain(
                size=domain.size,
                omega=domain.omega,
                omega_inverse=domain.omega_inverse,
                size_inverse=(domain.size_inverse + 1) % SCALAR_MODULUS,
                coset_generator=domain.coset_generator,
                coset_generator_inverse=domain.coset_generator_inverse,
            )


class Radix2FFTTests(unittest.TestCase):
    def test_small_polynomial_evaluations_match_independent_horner_reference(self):
        domain = FFTDomain.create(4)
        coefficients = [3, 2, 1, 0]
        self.assertEqual(
            domain.fft(coefficients),
            _direct_domain_evaluations(coefficients, domain),
        )

    def test_transform_order_is_natural_not_bit_reversed(self):
        domain = FFTDomain.create(8)
        evaluations = domain.fft([0, 1, 0, 0, 0, 0, 0, 0])
        expected = [pow(domain.omega, index, SCALAR_MODULUS) for index in range(8)]
        self.assertEqual(evaluations, expected)

    def test_forward_inverse_round_trips_constant_zero_sparse_and_dense(self):
        for size in (1, 2, 4, 16, 64):
            domain = FFTDomain.create(size)
            cases = (
                [0] * size,
                [123] + [0] * (size - 1),
                ([0] * size if size < 3 else [0, 0, 77] + [0] * (size - 3)),
                [(index * index + 9) % SCALAR_MODULUS for index in range(size)],
            )
            for coefficients in cases:
                with self.subTest(size=size, coefficients=coefficients[:4]):
                    evaluations = domain.fft(coefficients)
                    self.assertEqual(domain.ifft(evaluations), coefficients)

    def test_invalid_vector_lengths_and_noncanonical_field_elements_are_rejected(self):
        domain = FFTDomain.create(4)
        with self.assertRaisesRegex(FFTError, "does not match"):
            domain.fft([1, 2])
        for invalid in (-1, SCALAR_MODULUS, True, 1.0):
            with self.subTest(value=invalid), self.assertRaises(FFTError):
                domain.fft([invalid, 0, 0, 0])
        with self.assertRaises(TypeError):
            domain.fft(iter((1, 2, 3, 4)))

    def test_coset_fft_matches_direct_evaluation_and_inverse(self):
        for size in (1, 2, 4, 16):
            domain = FFTDomain.create(size)
            coefficients = [(index * 7 + 2) % SCALAR_MODULUS for index in range(size)]
            evaluations = domain.coset_fft(coefficients)
            point = domain.coset_generator
            expected = []
            for _ in range(size):
                expected.append(_evaluate_polynomial(coefficients, point))
                point = point * domain.omega % SCALAR_MODULUS
            with self.subTest(size=size):
                self.assertEqual(evaluations, expected)
                self.assertEqual(domain.icoset_fft(evaluations), coefficients)

    def test_coset_transform_does_not_mutate_input(self):
        domain = FFTDomain.create(8)
        coefficients = tuple(range(8))
        original = tuple(coefficients)
        domain.coset_fft(coefficients)
        self.assertEqual(coefficients, original)


if __name__ == "__main__":
    unittest.main()
