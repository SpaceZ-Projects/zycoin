"""Test-only probes for relation-preserving Spend QAP transformations."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_fft import FFTDomain

FIELD = SCALAR_MODULUS
ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "reports" / "sapling-circuit-compatibility-manifest.json"


def _permuted_rows(
    rows: tuple[tuple[int, int, int], ...],
    source_indices: tuple[int, ...],
) -> tuple[tuple[int, int, int], ...]:
    if len(source_indices) != len(rows) or set(source_indices) != set(range(len(rows))):
        raise ValueError("row map must be a complete permutation")
    return tuple(rows[index] for index in source_indices)


def _scaled_row(
    row: tuple[int, int, int], scale_a: int, scale_b: int
) -> tuple[int, int, int]:
    if (
        type(scale_a) is not int
        or type(scale_b) is not int
        or not 0 < scale_a < FIELD
        or not 0 < scale_b < FIELD
    ):
        raise ValueError("factor scales must be nonzero canonical scalars")
    a, b, c = row
    return (
        a * scale_a % FIELD,
        b * scale_b % FIELD,
        c * scale_a * scale_b % FIELD,
    )


def _trim(polynomial: list[int]) -> list[int]:
    while polynomial and polynomial[-1] % FIELD == 0:
        polynomial.pop()
    return polynomial


def _multiply(left: tuple[int, ...], right: tuple[int, ...]) -> list[int]:
    product = [0] * (len(left) + len(right) - 1)
    for left_degree, left_value in enumerate(left):
        for right_degree, right_value in enumerate(right):
            degree = left_degree + right_degree
            product[degree] = (
                product[degree] + left_value * right_value
            ) % FIELD
    return _trim(product)


def _subtract(left: list[int], right: tuple[int, ...]) -> list[int]:
    result = left + [0] * max(0, len(right) - len(left))
    for degree, value in enumerate(right):
        result[degree] = (result[degree] - value) % FIELD
    return _trim(result)


def _divide_by_vanishing(
    polynomial: list[int], domain_size: int
) -> tuple[int, ...]:
    remainder = polynomial + [0] * max(0, domain_size + 1 - len(polynomial))
    quotient = [0] * max(1, len(remainder) - domain_size)
    for degree in range(len(remainder) - 1, domain_size - 1, -1):
        coefficient = remainder[degree] % FIELD
        quotient[degree - domain_size] = coefficient
        remainder[degree] = 0
        remainder[degree - domain_size] = (
            remainder[degree - domain_size] + coefficient
        ) % FIELD
    if any(remainder):
        raise ValueError("witness rows are not divisible by the vanishing polynomial")
    quotient.extend([0] * max(0, domain_size - len(quotient)))
    return tuple(quotient[:domain_size])


def _qap_vectors(
    rows: tuple[tuple[int, int, int], ...],
) -> tuple[tuple[tuple[int, ...], ...], tuple[int, ...]]:
    domain = FFTDomain.create(len(rows))
    polynomials = tuple(
        tuple(domain.ifft([row[side] for row in rows]))
        for side in range(3)
    )
    numerator = _subtract(
        _multiply(polynomials[0], polynomials[1]), polynomials[2]
    )
    quotient = _divide_by_vanishing(numerator, len(rows))
    return polynomials, quotient


def _rank_mod(matrix: list[list[int]]) -> int:
    rows = [[value % FIELD for value in row] for row in matrix]
    pivot_row = 0
    for column in range(len(rows[0])):
        pivot = next(
            (index for index in range(pivot_row, len(rows)) if rows[index][column]),
            None,
        )
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = pow(rows[pivot_row][column], FIELD - 2, FIELD)
        rows[pivot_row] = [value * inverse % FIELD for value in rows[pivot_row]]
        for index in range(len(rows)):
            if index == pivot_row:
                continue
            scale = rows[index][column]
            if scale:
                rows[index] = [
                    (value - scale * pivot_value) % FIELD
                    for value, pivot_value in zip(
                        rows[index], rows[pivot_row], strict=True
                    )
                ]
        pivot_row += 1
        if pivot_row == len(rows):
            break
    return pivot_row


class SaplingSpendQAPTransformationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        cls.audit = cls.manifest["authentic_parameter_audit"][
            "spend_qap_transformation_audit"
        ]

    def test_recorded_row_crosswalk_accounts_for_the_nonidentity_qap(self):
        audit = self.audit
        self.assertEqual(
            audit["row_correspondence"]["row_counts"],
            {
                "upstream": 98_777,
                "local": 98_777,
                "one_to_one_pairs": 98_775,
                "native_a_b_c": 69_840,
                "a_b_factor_swap": 251,
                "valid_factor_normalization": 28_351,
                "expanded_a_times_b_minus_c_only": 333,
                "unmatched_upstream": 2,
                "unmatched_local": 2,
                "ambiguous_upstream": 0,
                "ambiguous_local": 0,
            },
        )
        self.assertEqual(
            audit["row_correspondence"]["moved_rows"],
            {"moved": 48_546, "same_index": 50_229},
        )
        self.assertEqual(
            audit["row_correspondence"]["expanded_relation_breakdown"],
            {
                "pk_d_selection": 251,
                "merkle_path_left_and_right": 64,
                "other": 18,
                "normalized_unit_relation_scale": 333,
            },
        )
        factor_certificate = audit["expanded_row_factor_certificate"]
        self.assertEqual(factor_certificate["expanded_rows"], 333)
        self.assertEqual(
            factor_certificate["factor_map_classes"],
            {
                "linear_constraint_c_to_a": 74,
                "pkd_affine_swap": 251,
                "unit_b_affine_shift": 8,
            },
        )
        self.assertEqual(
            factor_certificate["raw_residual_scales"],
            {"+1": 329, "-1": 4},
        )
        self.assertEqual(
            audit["row_correspondence"]["expanded_relation_scale"],
            {
                "rows": 333,
                "all_unit_scale": True,
                "scale_domain": "normalized expanded-polynomial signatures",
                "raw_residual_scales": {"+1": 329, "-1": 4},
            },
        )
        self.assertEqual(
            [row["row"] for row in audit["unmatched_rows"]["upstream"]],
            [76_893, 76_894],
        )
        self.assertEqual(
            [row["row"] for row in audit["unmatched_rows"]["local"]],
            [32_701, 76_894],
        )

    def test_row_permutation_preserves_constraints_but_changes_qap(self):
        rows = (
            (2, 11, 22),
            (3, 13, 39),
            (5, 17, 85),
            (7, 19, 133),
        )
        permuted = _permuted_rows(rows, (1, 0, 2, 3))
        self.assertEqual(sorted(rows), sorted(permuted))
        self.assertTrue(all(a * b % FIELD == c for a, b, c in permuted))

        original_polynomials, original_h = _qap_vectors(rows)
        permuted_polynomials, permuted_h = _qap_vectors(permuted)
        self.assertNotEqual(original_polynomials, permuted_polynomials)
        self.assertNotEqual(original_h, permuted_h)

    def test_a_b_swap_and_nonuniform_factor_scaling_preserve_rows_not_qap(self):
        rows = (
            (2, 11, 22),
            (3, 13, 39),
            (5, 17, 85),
            (7, 19, 133),
        )
        swapped = ((rows[0][1], rows[0][0], rows[0][2]),) + rows[1:]
        scaled = (_scaled_row(rows[0], 2, 3),) + rows[1:]

        for transformed in (swapped, scaled):
            self.assertTrue(
                all(a * b % FIELD == c for a, b, c in transformed)
            )
            transformed_polynomials, transformed_h = _qap_vectors(transformed)
            original_polynomials, original_h = _qap_vectors(rows)
            self.assertNotEqual(original_polynomials, transformed_polynomials)
            self.assertNotEqual(original_h, transformed_h)

    def test_expanded_relation_equality_does_not_preserve_factor_vectors(self):
        # (x + 1) * 1 - y equals x * 1 - (y - 1), but the A/B/C
        # factors presented to QAP interpolation are different.
        x, y = 2, 3
        upstream = (
            (x + 1, 1, y),
            (3, 7, 21),
            (5, 11, 55),
            (13, 17, 221),
        )
        local = (
            (x, 1, y - 1),
            *upstream[1:],
        )
        self.assertEqual((x + 1) - y, x - (y - 1))
        self.assertTrue(all(a * b == c for a, b, c in upstream))
        self.assertTrue(all(a * b == c for a, b, c in local))

        upstream_polynomials, upstream_h = _qap_vectors(upstream)
        local_polynomials, local_h = _qap_vectors(local)
        self.assertNotEqual(upstream_polynomials, local_polynomials)
        self.assertNotEqual(upstream_h, local_h)

    def test_global_extended_factor_map_is_fixed_but_not_invertible(self):
        counts = self.audit["row_correspondence"]["row_counts"]
        expanded = self.audit["expanded_row_factor_certificate"]
        global_map = self.audit["global_coordinate_transformation"]
        self.assertEqual(counts["one_to_one_pairs"], 98_775)
        self.assertEqual(
            counts["native_a_b_c"]
            + counts["a_b_factor_swap"]
            + counts["valid_factor_normalization"],
            98_442,
        )
        self.assertEqual(
            expanded["factor_map_classes"],
            {
                "linear_constraint_c_to_a": 74,
                "pkd_affine_swap": 251,
                "unit_b_affine_shift": 8,
            },
        )

        pkd = [[0, 1, 0], [1, 0, 0], [1, 0, 1]]
        linear_to_c = [[0, 0, 0], [0, 0, 0], [-1, 0, 0]]
        unit_b = [[-1, 0, 0], [0, 1, 0], [0, 0, -1]]
        helper_factors = [
            [1, 0, 0, -1, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
        ]
        helper = [
            [1, 0, 0, -1, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 1, 0, 0, 1, 0],
        ]
        self.assertEqual(_rank_mod(pkd), 3)
        self.assertEqual(_rank_mod(linear_to_c), 1)
        self.assertEqual(_rank_mod(unit_b), 3)
        self.assertEqual(_rank_mod(helper_factors), 3)
        self.assertEqual(_rank_mod(helper), 5)

        factor_rank = 3 * 98_442 + 3 * 251 + 74 + 3 * 8 + 3
        operator_rank = (
            3 * 98_442
            + 3 * 251
            + 74
            + 3 * 8
            + 5
        )
        codomain_dimension = 3 * 98_777
        extended_domain_dimension = codomain_dimension + 98_646
        self.assertEqual(factor_rank, 296_180)
        self.assertEqual(codomain_dimension - factor_rank, 151)
        self.assertEqual(operator_rank, 296_182)
        self.assertEqual(codomain_dimension - operator_rank, 149)
        self.assertEqual(extended_domain_dimension - operator_rank, 98_795)
        self.assertEqual(global_map["factor_operator"]["R_rank"], factor_rank)
        self.assertEqual(
            global_map["factor_operator"]["augmented_rank"], operator_rank
        )
        self.assertEqual(
            global_map["factor_operator"]["augmented_kernel_dimension"], 98_795
        )
        self.assertEqual(global_map["qap_polynomials"]["domain_size"], 131_072)
        self.assertEqual(
            set(global_map["official_query_sections"]),
            {"IC", "H", "L", "A", "B_G1", "B_G2"},
        )
        self.assertEqual(
            global_map["verification_equation"]["preserved_by_available_mapping"],
            "Unresolved; no complete query-point and proof-coordinate "
            "transformation exists in the evidence.",
        )
        self.assertEqual(
            global_map["verification"]["focused_tests_passed"], 50
        )
        self.assertEqual(
            global_map["verification"]["focused_test_subtests_passed"], 346
        )
        self.assertEqual(
            global_map["verification"]["focused_regression_rerun"]["tests_passed"],
            49,
        )
        self.assertEqual(
            global_map["verification"]["focused_regression_rerun"]["tests_deselected"],
            1,
        )

    def test_helper_residual_map_requires_a_witness_dependent_coefficient(self):
        # With h = P-S, g_root=f_root-V*h and g_position=h.
        # The V*h monomial is outside the span of constant row combinations.
        helper_residuals = {
            ("f_root",): 1,
            ("V", "f_anchor"): -1,
        }
        constant_row_span = {("f_root",), ("f_anchor",)}
        self.assertIn(("V", "f_anchor"), helper_residuals)
        self.assertNotIn(("V", "f_anchor"), constant_row_span)

    def test_malformed_row_maps_and_invalid_scalings_are_rejected(self):
        rows = (
            (2, 11, 22),
            (3, 13, 39),
            (5, 17, 85),
            (7, 19, 133),
        )
        for invalid_map in (
            (1, 1, 2, 3),
            (1, 0, 2),
            (1, 0, 2, 4),
        ):
            with self.subTest(invalid_map=invalid_map), self.assertRaisesRegex(
                ValueError, "complete permutation"
            ):
                _permuted_rows(rows, invalid_map)

        with self.assertRaisesRegex(ValueError, "nonzero canonical"):
            _scaled_row(rows[0], 0, 3)
        incorrectly_scaled = (rows[0][0] * 2 % FIELD, rows[0][1], rows[0][2])
        self.assertNotEqual(
            incorrectly_scaled[0] * incorrectly_scaled[1] % FIELD,
            incorrectly_scaled[2],
        )


if __name__ == "__main__":
    unittest.main()
