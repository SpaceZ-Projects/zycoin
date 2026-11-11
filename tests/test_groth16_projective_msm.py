import unittest

from src.bls12_381 import (
    FIELD_MODULUS,
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    add_g1,
    add_g2,
    multi_scalar_multiply_g1,
    multi_scalar_multiply_g2,
    multiply_g1,
    multiply_g2,
)
from src.groth16_queries import G1Query, G2Query, msm_g1, msm_g2


def _reference_multiply_g1(point, scalar):
    if scalar < 0:
        return _reference_multiply_g1(
            G1Point(point.x, (-point.y) % FIELD_MODULUS), -scalar
        )
    result = G1_INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = add_g1(result, addend)
        addend = add_g1(addend, addend)
        scalar >>= 1
    return result


def _reference_multiply_g2(point, scalar):
    if scalar < 0:
        return _reference_multiply_g2(G2Point(point.x, -point.y), -scalar)
    result = G2_INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = add_g2(result, addend)
        addend = add_g2(addend, addend)
        scalar >>= 1
    return result


class ProjectiveScalarMultiplicationTests(unittest.TestCase):
    def test_projective_scalar_multiplication_matches_affine_reference(self):
        scalars = (
            0,
            1,
            2,
            17,
            (1 << 127) + 0x12345,
            SCALAR_MODULUS - 1,
            SCALAR_MODULUS + 3,
        )
        for scalar in scalars:
            with self.subTest(group="G1", scalar=scalar):
                self.assertEqual(
                    multiply_g1(G1_GENERATOR, scalar),
                    _reference_multiply_g1(G1_GENERATOR, scalar),
                )
            with self.subTest(group="G2", scalar=scalar):
                self.assertEqual(
                    multiply_g2(G2_GENERATOR, scalar),
                    _reference_multiply_g2(G2_GENERATOR, scalar),
                )

    def test_projective_scalar_multiplication_preserves_negative_and_identity(self):
        self.assertEqual(
            multiply_g1(G1_GENERATOR, -123),
            _reference_multiply_g1(G1_GENERATOR, -123),
        )
        self.assertEqual(
            multiply_g2(G2_GENERATOR, -123),
            _reference_multiply_g2(G2_GENERATOR, -123),
        )
        self.assertEqual(multiply_g1(G1_INFINITY, 999), G1_INFINITY)
        self.assertEqual(multiply_g2(G2_INFINITY, 999), G2_INFINITY)


class ProjectiveMsmTests(unittest.TestCase):
    def test_groth16_query_dispatch_uses_windowed_msm_without_reordering(self):
        scalars = tuple((index * 7919) % 4096 for index in range(40))
        g1_points = tuple(
            multiply_g1(G1_GENERATOR, index + 1) for index in range(len(scalars))
        )
        g2_points = tuple(
            multiply_g2(G2_GENERATOR, index + 1) for index in range(len(scalars))
        )
        expected_g1 = G1_INFINITY
        expected_g2 = G2_INFINITY
        for point, scalar in zip(g1_points, scalars):
            expected_g1 = add_g1(
                expected_g1, _reference_multiply_g1(point, scalar)
            )
        for point, scalar in zip(g2_points, scalars):
            expected_g2 = add_g2(
                expected_g2, _reference_multiply_g2(point, scalar)
            )
        self.assertEqual(msm_g1(G1Query(g1_points), scalars), expected_g1)
        self.assertEqual(msm_g2(G2Query(g2_points), scalars), expected_g2)

    def test_windowed_g1_msm_matches_independent_affine_accumulation(self):
        scalars = tuple((index * 7919) % 4096 for index in range(40))
        points = tuple(
            multiply_g1(G1_GENERATOR, index + 1) for index in range(len(scalars))
        )
        expected = G1_INFINITY
        for point, scalar in zip(points, scalars):
            expected = add_g1(expected, _reference_multiply_g1(point, scalar))
        self.assertEqual(multi_scalar_multiply_g1(points, scalars), expected)

    def test_windowed_g2_msm_matches_independent_affine_accumulation(self):
        scalars = tuple((index * 3571) % 2048 for index in range(40))
        points = tuple(
            multiply_g2(G2_GENERATOR, index + 1) for index in range(len(scalars))
        )
        expected = G2_INFINITY
        for point, scalar in zip(points, scalars):
            expected = add_g2(expected, _reference_multiply_g2(point, scalar))
        self.assertEqual(multi_scalar_multiply_g2(points, scalars), expected)

    def test_windowed_msm_accepts_zero_and_rejects_bad_dimensions_or_scalars(self):
        self.assertEqual(multi_scalar_multiply_g1((), ()), G1_INFINITY)
        self.assertEqual(multi_scalar_multiply_g2((), ()), G2_INFINITY)
        with self.assertRaisesRegex(ValueError, "counts do not match"):
            multi_scalar_multiply_g1((G1_GENERATOR,), ())
        with self.assertRaisesRegex(ValueError, "non-negative"):
            multi_scalar_multiply_g1((G1_GENERATOR,), (-1,))
        with self.assertRaisesRegex(ValueError, "non-negative"):
            multi_scalar_multiply_g2((G2_GENERATOR,), (-SCALAR_MODULUS,))
        self.assertEqual(
            multi_scalar_multiply_g1((G1_GENERATOR,) * 40, (0,) * 40),
            G1_INFINITY,
        )
        self.assertEqual(
            multi_scalar_multiply_g2((G2_GENERATOR,) * 40, (0,) * 40),
            G2_INFINITY,
        )


if __name__ == "__main__":
    unittest.main()
