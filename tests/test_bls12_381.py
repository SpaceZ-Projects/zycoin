import json
import unittest
from pathlib import Path

from src.bls12_381 import (
    FIELD_MODULUS,
    SCALAR_MODULUS,
    Fp,
    Fp2,
    Fp6,
    Fp12,
    Scalar,
    G1_GENERATOR,
    G1_INFINITY,
    G1Point,
    G2_GENERATOR,
    G2_INFINITY,
    G2Point,
    add_g1,
    add_g2,
    decode_g1,
    decode_g2,
    decode_g1_uncompressed,
    decode_g2_uncompressed,
    encode_g1,
    encode_g2,
    encode_g1_uncompressed,
    encode_g2_uncompressed,
    final_exponentiate,
    multiply_g1,
    multiply_g2,
    pairing,
)
from tests.sapling_parameter_subgroup_audit import validate_subgroup_batch


ROOT = Path(__file__).resolve().parent
REFERENCE = json.loads(
    (ROOT / "fixtures" / "bls12_381_reference.json").read_text(
        encoding="utf-8"
    )
)
SUBGROUP_FIXTURE = json.loads(
    (ROOT / "fixtures" / "bls12_381_subgroup_points.json").read_text(
        encoding="utf-8"
    )
)


def _embed_fp6(value):
    coefficients = [0] * 12
    for index, coefficient in enumerate((value.c0, value.c1, value.c2)):
        base = 2 * index
        coefficients[base] = coefficient.c0 - coefficient.c1
        coefficients[base + 6] = coefficient.c1
    return tuple(value % FIELD_MODULUS for value in coefficients)


class BLS12381FieldTests(unittest.TestCase):
    def test_moduli_and_fp2_reference_vector(self):
        self.assertEqual(FIELD_MODULUS, int(REFERENCE["field_modulus"]))
        self.assertEqual(SCALAR_MODULUS, int(REFERENCE["scalar_modulus"]))
        for field_type, name, modulus in (
            (Fp, "base_field_arithmetic", FIELD_MODULUS),
            (Scalar, "scalar_field_arithmetic", SCALAR_MODULUS),
        ):
            vector = REFERENCE[name]
            left, right = field_type(int(vector["left"])), field_type(
                int(vector["right"])
            )
            self.assertEqual(str((left * right).value), vector["product"])
            self.assertEqual(str((field_type(modulus - 1) + 2).value), vector["wraparound"])
            self.assertEqual((left / left).value, 1)
        vector = REFERENCE["fp2_multiplication"]
        left, right = Fp2(*(int(value) for value in vector["left"])), Fp2(
            *(int(value) for value in vector["right"])
        )
        result = left * right
        self.assertEqual(
            [str(result.c0), str(result.c1)], vector["result"]
        )
        self.assertEqual(Fp2(3, 4).sqrt() ** 2, Fp2(3, 4))

    def test_fp6_reference_vector_and_inverse(self):
        vector = REFERENCE["fp6_multiplication"]
        left = Fp6(*(Fp2(*(int(c) for c in pair)) for pair in vector["left"]))
        right = Fp6(*(Fp2(*(int(c) for c in pair)) for pair in vector["right"]))
        self.assertEqual(
            [str(value) for value in _embed_fp6(left * right)],
            vector["embedded_result"],
        )
        self.assertEqual(left * left.inverse(), Fp6(Fp2(1)))

    def test_fp12_reference_vector_and_inverse(self):
        vector = REFERENCE["fp12_multiplication"]
        left = Fp12(tuple(int(value) for value in vector["left"]))
        right = Fp12(tuple(int(value) for value in vector["right"]))
        self.assertEqual(
            [str(value) for value in (left * right).coefficients],
            vector["result"],
        )
        self.assertEqual(left * left.inverse(), Fp12.one())
        with self.assertRaises(ValueError):
            final_exponentiate(Fp12.zero())


class BLS12381CurveTests(unittest.TestCase):
    def test_generators_and_compressed_encodings_match_reference(self):
        g1_encoded = bytes.fromhex(REFERENCE["g1_generator_compressed"])
        g2_encoded = bytes.fromhex(REFERENCE["g2_generator_compressed"])
        self.assertTrue(G1_GENERATOR.is_on_curve())
        self.assertTrue(G2_GENERATOR.is_on_curve())
        self.assertTrue(G1_GENERATOR.is_in_subgroup())
        self.assertTrue(G2_GENERATOR.is_in_subgroup())
        self.assertEqual(encode_g1(G1_GENERATOR), g1_encoded)
        self.assertEqual(encode_g2(G2_GENERATOR), g2_encoded)
        self.assertEqual(decode_g1(g1_encoded), G1_GENERATOR)
        self.assertEqual(decode_g2(g2_encoded), G2_GENERATOR)

    def test_group_law_and_scalar_order(self):
        self.assertEqual(add_g1(G1_GENERATOR, G1_GENERATOR), multiply_g1(G1_GENERATOR, 2))
        self.assertEqual(add_g2(G2_GENERATOR, G2_GENERATOR), multiply_g2(G2_GENERATOR, 2))
        self.assertEqual(multiply_g1(G1_GENERATOR, SCALAR_MODULUS), G1_INFINITY)
        self.assertEqual(multiply_g2(G2_GENERATOR, SCALAR_MODULUS), G2_INFINITY)
        self.assertEqual(decode_g1(encode_g1(G1_INFINITY)), G1_INFINITY)
        self.assertEqual(decode_g2(encode_g2(G2_INFINITY)), G2_INFINITY)

    def test_exact_fast_subgroup_checks_match_order_multiplication(self):
        non_subgroup_g1 = decode_g1_uncompressed(
            bytes.fromhex(
                SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g1_uncompressed"]
            ),
            check_subgroup=False,
        )
        non_subgroup_g2 = decode_g2_uncompressed(
            bytes.fromhex(
                SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g2_uncompressed"]
            ),
            check_subgroup=False,
        )
        points = (
            (G1_GENERATOR, multiply_g1),
            (multiply_g1(G1_GENERATOR, 17), multiply_g1),
            (non_subgroup_g1, multiply_g1),
            (G2_GENERATOR, multiply_g2),
            (multiply_g2(G2_GENERATOR, 19), multiply_g2),
            (non_subgroup_g2, multiply_g2),
        )
        for point, multiply in points:
            with self.subTest(point_type=type(point).__name__, point=point):
                self.assertTrue(point.is_on_curve())
                expected = multiply(point, SCALAR_MODULUS).is_infinity
                self.assertEqual(point.is_in_subgroup(), expected)

    def test_uncompressed_decoders_reject_on_curve_non_subgroup_points(self):
        non_subgroup_g1_encoding = bytes.fromhex(
            SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g1_uncompressed"]
        )
        non_subgroup_g2_encoding = bytes.fromhex(
            SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g2_uncompressed"]
        )
        non_subgroup_g1 = decode_g1_uncompressed(
            non_subgroup_g1_encoding, check_subgroup=False
        )
        non_subgroup_g2 = decode_g2_uncompressed(
            non_subgroup_g2_encoding, check_subgroup=False
        )
        self.assertTrue(non_subgroup_g1.is_on_curve())
        self.assertTrue(non_subgroup_g2.is_on_curve())
        self.assertFalse(non_subgroup_g1.is_in_subgroup())
        self.assertFalse(non_subgroup_g2.is_in_subgroup())
        with self.assertRaisesRegex(ValueError, "prime-order subgroup"):
            decode_g1_uncompressed(
                non_subgroup_g1_encoding,
                check_subgroup=True,
            )
        with self.assertRaisesRegex(ValueError, "prime-order subgroup"):
            decode_g2_uncompressed(
                non_subgroup_g2_encoding,
                check_subgroup=True,
            )
        self.assertEqual(
            decode_g1_uncompressed(
                non_subgroup_g1_encoding,
                check_subgroup=False,
            ),
            non_subgroup_g1,
        )
        self.assertEqual(
            decode_g2_uncompressed(
                non_subgroup_g2_encoding,
                check_subgroup=False,
            ),
            non_subgroup_g2,
        )

    def test_subgroup_identity_and_invalid_curve_handling(self):
        self.assertTrue(G1_INFINITY.is_in_subgroup())
        self.assertTrue(G2_INFINITY.is_in_subgroup())
        self.assertEqual(
            decode_g1_uncompressed(encode_g1_uncompressed(G1_INFINITY)),
            G1_INFINITY,
        )
        self.assertEqual(
            decode_g2_uncompressed(encode_g2_uncompressed(G2_INFINITY)),
            G2_INFINITY,
        )
        with self.assertRaisesRegex(ValueError, "exactly 96 bytes"):
            decode_g1_uncompressed(bytes(95))
        with self.assertRaisesRegex(ValueError, "exactly 192 bytes"):
            decode_g2_uncompressed(bytes(191))
        malformed_g1 = bytearray(encode_g1_uncompressed(G1_GENERATOR))
        malformed_g1[0] |= 0x80
        with self.assertRaisesRegex(ValueError, "compressed flag"):
            decode_g1_uncompressed(bytes(malformed_g1))
        malformed_g2 = bytearray(encode_g2_uncompressed(G2_GENERATOR))
        malformed_g2[0] |= 0x80
        with self.assertRaisesRegex(ValueError, "compressed flag"):
            decode_g2_uncompressed(bytes(malformed_g2))
        with self.assertRaisesRegex(ValueError, "invalid G1"):
            G1Point(0, 0).is_in_subgroup()
        with self.assertRaisesRegex(ValueError, "invalid G2"):
            G2Point(Fp2(), Fp2()).is_in_subgroup()

    def test_exact_batch_results_match_individual_order_checks(self):
        non_subgroup_g1 = decode_g1_uncompressed(
            bytes.fromhex(
                SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g1_uncompressed"]
            ),
            check_subgroup=False,
        )
        non_subgroup_g2 = decode_g2_uncompressed(
            bytes.fromhex(
                SUBGROUP_FIXTURE["on_curve_non_subgroup_points"]["g2_uncompressed"]
            ),
            check_subgroup=False,
        )
        points = (
            G1_INFINITY,
            G1_GENERATOR,
            multiply_g1(G1_GENERATOR, 37),
            non_subgroup_g1,
            G2_INFINITY,
            G2_GENERATOR,
            multiply_g2(G2_GENERATOR, 41),
            non_subgroup_g2,
        )
        actual = validate_subgroup_batch(points)
        expected = tuple(
            multiply_g1(point, SCALAR_MODULUS).is_infinity
            if isinstance(point, G1Point)
            else multiply_g2(point, SCALAR_MODULUS).is_infinity
            for point in points
        )
        self.assertEqual(actual, expected)

    def test_rejects_malformed_and_noncanonical_encodings(self):
        with self.assertRaises(ValueError):
            decode_g1(bytes(48))
        with self.assertRaises(ValueError):
            decode_g2(bytes(96))
        with self.assertRaises(ValueError):
            decode_g1(bytes((0xE0,)) + bytes(47))
        with self.assertRaises(ValueError):
            decode_g2(bytes((0xE0,)) + bytes(95))
        noncanonical_g1 = bytearray(FIELD_MODULUS.to_bytes(48, "big"))
        noncanonical_g1[0] |= 0x80
        with self.assertRaises(ValueError):
            decode_g1(bytes(noncanonical_g1))
        noncanonical_g2 = bytearray(96)
        noncanonical_g2[0] = 0x80
        noncanonical_g2[:48] = FIELD_MODULUS.to_bytes(48, "big")
        noncanonical_g2[0] |= 0x80
        with self.assertRaises(ValueError):
            decode_g2(bytes(noncanonical_g2))
        with self.assertRaises(ValueError):
            encode_g1(G1Point(0, 0))
        with self.assertRaises(ValueError):
            encode_g2(G2Point(Fp2(), Fp2()))


class BLS12381PairingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.generator_pairing = pairing(G2_GENERATOR, G1_GENERATOR)

    def test_generator_pairing_matches_independent_reference(self):
        self.assertEqual(
            [str(value) for value in self.generator_pairing.coefficients],
            REFERENCE["pairing_generator_coefficients"],
        )
        self.assertEqual(
            self.generator_pairing**SCALAR_MODULUS, Fp12.one()
        )

    def test_pairing_bilinearity_and_infinity(self):
        doubled = pairing(multiply_g2(G2_GENERATOR, 2), G1_GENERATOR)
        self.assertEqual(doubled, self.generator_pairing * self.generator_pairing)
        self.assertEqual(pairing(G2_INFINITY, G1_GENERATOR), Fp12.one())
        self.assertEqual(pairing(G2_GENERATOR, G1_INFINITY), Fp12.one())

    def test_pairing_rejects_invalid_and_non_subgroup_inputs(self):
        with self.assertRaises(ValueError):
            pairing(G2_GENERATOR, G1Point(0, 0))
        with self.assertRaises(ValueError):
            pairing(G2_GENERATOR, G1Point(0, 2))


if __name__ == "__main__":
    unittest.main()
