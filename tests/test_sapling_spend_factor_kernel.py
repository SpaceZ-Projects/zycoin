"""Exact sparse kernel certificates for the retained Spend factor map."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS

FIELD = SCALAR_MODULUS
ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE = ROOT / "reports" / "sapling-spend-expanded-row-factor-identities.json"
MANIFEST = ROOT / "reports" / "sapling-circuit-compatibility-manifest.json"
ROWS = 98_777
VARIABLES = 98_646
FACTOR_COORDINATES = 3 * ROWS
HELPER_ROOT_UP = 76_893
HELPER_ANCHOR_UP = 76_894
HELPER_POSITION_LOCAL = 32_701
HELPER_ROOT_LOCAL = 76_894


def _scalar(value: str) -> int:
    return int.from_bytes(bytes.fromhex(value), "little") % FIELD


def _row_vector(row: int, side: int) -> int:
    return 3 * row + side


def _sparse_fingerprint(
    shape: tuple[int, int], basis: list[dict[int, int]]
) -> str:
    encoded = json.dumps(
        {
            "coordinate_order": "row-major A,B,C; augmented variables follow factors",
            "field_modulus": str(FIELD),
            "shape": list(shape),
            "basis": [
                [[index, str(value % FIELD)] for index, value in sorted(vector.items()) if value % FIELD]
                for vector in basis
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


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
    return pivot_row


class SaplingSpendFactorKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate = json.loads(CERTIFICATE.read_text(encoding="ascii"))
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.audit = cls.manifest["authentic_parameter_audit"][
            "spend_qap_transformation_audit"
        ]["global_coordinate_transformation"]
        rows = cls.certificate["rows"]
        cls.by_kind = {
            kind: [row for row in rows if row["kind"] == kind]
            for kind in (
                "linear_constraint_c_to_a",
                "pkd_affine_swap",
                "unit_b_affine_shift",
            )
        }

    def _right_and_left_bases(self) -> tuple[list[dict[int, int]], ...]:
        ker_r: list[dict[int, int]] = []
        ker_rt: list[dict[int, int]] = []
        ker_augmented: list[dict[int, int]] = []
        ker_augmented_t: list[dict[int, int]] = []

        for row in self.by_kind["linear_constraint_c_to_a"]:
            local = row["local_row_index"]
            upstream = row["upstream_row_index"]
            ker_r.extend(
                [
                    {_row_vector(local, 1): 1},
                    {_row_vector(local, 2): 1},
                ]
            )
            ker_rt.extend(
                [
                    {_row_vector(upstream, 0): 1},
                    {_row_vector(upstream, 1): 1},
                ]
            )

        # The helper block has columns (root A/B/C, position A/B/C) and
        # rows (root A/B/C, anchor A/B/C).
        ker_r.extend(
            [
                {_row_vector(HELPER_ROOT_LOCAL, 2): 1},
                {_row_vector(HELPER_POSITION_LOCAL, 1): 1},
                {_row_vector(HELPER_POSITION_LOCAL, 2): 1},
            ]
        )
        ker_rt.extend(
            [
                {_row_vector(HELPER_ROOT_UP, 2): 1},
                {_row_vector(HELPER_ANCHOR_UP, 0): 1},
                {_row_vector(HELPER_ANCHOR_UP, 1): 1},
            ]
        )
        ker_augmented.extend(ker_r)
        ker_augmented_t.extend(ker_rt[:149])

        # The helper shifts constrain the ONE and public anchor coordinates.
        # Every other variable basis vector has a factor-space preimage under R.
        variable_basis = []
        for variable in range(VARIABLES):
            if variable in (0, 5):
                continue
            vector = {FACTOR_COORDINATES + variable: 1}
            for row in self.by_kind["unit_b_affine_shift"]:
                shift = row["derived_identity"]["shift_u_terms"]
                coefficient = sum(
                    _scalar(term[1])
                    for term in shift
                    if int(term[0]) == variable
                ) % FIELD
                if coefficient:
                    alpha = _scalar(row["derived_identity"]["scale_alpha_hex"])
                    inverse_alpha = pow(alpha, FIELD - 2, FIELD)
                    cancellation = -coefficient * inverse_alpha % FIELD
                    local = row["local_row_index"]
                    vector[_row_vector(local, 0)] = cancellation
                    vector[_row_vector(local, 2)] = cancellation
            variable_basis.append(vector)
        ker_augmented.extend(variable_basis)

        return ker_r, ker_rt, ker_augmented, ker_augmented_t

    def _verify_factor_kernel_vector(self, vector: dict[int, int]) -> None:
        # The rank-deficient ordinary blocks are exactly U_C=-L_A.
        for row in self.by_kind["linear_constraint_c_to_a"]:
            local = row["local_row_index"]
            a = vector.get(_row_vector(local, 0), 0)
            output = (0, 0, -a % FIELD)
            self.assertEqual(output, (0, 0, 0))

        # Directly multiply the six-by-six helper block.
        source = [
            vector.get(_row_vector(HELPER_ROOT_LOCAL, side), 0)
            for side in range(3)
        ] + [
            vector.get(_row_vector(HELPER_POSITION_LOCAL, side), 0)
            for side in range(3)
        ]
        helper_output = [
            source[0] - source[3],
            source[1],
            0,
            0,
            0,
            source[3],
        ]
        expected = [0] * 6
        self.assertEqual([value % FIELD for value in helper_output], expected)

    def _verify_augmented_variable_vector(self, vector: dict[int, int]) -> None:
        variable_terms = {
            index - FACTOR_COORDINATES: value
            for index, value in vector.items()
            if index >= FACTOR_COORDINATES
        }
        self.assertFalse(set(variable_terms).intersection({0, 5}))
        for row in self.by_kind["unit_b_affine_shift"]:
            local = row["local_row_index"]
            alpha = _scalar(row["derived_identity"]["scale_alpha_hex"])
            shift = sum(
                _scalar(term[1]) * variable_terms.get(int(term[0]), 0)
                for term in row["derived_identity"]["shift_u_terms"]
            ) % FIELD
            a = vector.get(_row_vector(local, 0), 0)
            c = vector.get(_row_vector(local, 2), 0)
            self.assertEqual((alpha * a + shift) % FIELD, 0)
            self.assertEqual((alpha * c + shift) % FIELD, 0)
        self.assertEqual(vector.get(FACTOR_COORDINATES, 0), 0)
        self.assertEqual(vector.get(FACTOR_COORDINATES + 5, 0), 0)

    def _verify_left_kernel_vector(
        self, vector: dict[int, int], *, augmented: bool
    ) -> None:
        for row in self.by_kind["linear_constraint_c_to_a"]:
            upstream = row["upstream_row_index"]
            values = [
                vector.get(_row_vector(upstream, side), 0)
                for side in range(3)
            ]
            # R has only the local-A coefficient in its C output.
            self.assertEqual(values[2], 0)

        helper = [
            vector.get(_row_vector(HELPER_ROOT_UP, side), 0)
            for side in range(3)
        ] + [
            vector.get(_row_vector(HELPER_ANCHOR_UP, side), 0)
            for side in range(3)
        ]
        self.assertEqual(helper[0] - helper[5], 0)
        self.assertEqual(helper[1], 0)
        self.assertEqual(helper[5], 0)
        if augmented:
            # S has independent ONE and anchor shifts in anchor A/B.
            self.assertEqual(helper[3], 0)
            self.assertEqual(helper[4], 0)

    def test_exact_kernel_bases_and_augmented_operator(self) -> None:
        ker_r, ker_rt, ker_augmented, ker_augmented_t = (
            self._right_and_left_bases()
        )
        self.assertEqual((len(ker_r), len(ker_rt)), (151, 151))
        self.assertEqual((len(ker_augmented), len(ker_augmented_t)), (98_795, 149))
        self.assertEqual(
            len({next(iter(vector)) for vector in ker_r}), len(ker_r)
        )
        self.assertEqual(
            len({next(iter(vector)) for vector in ker_rt}), len(ker_rt)
        )
        self.assertEqual(
            {
                next(index - FACTOR_COORDINATES for index in vector if index >= FACTOR_COORDINATES)
                for vector in ker_augmented[len(ker_r) :]
            },
            set(range(VARIABLES)) - {0, 5},
        )
        self.assertEqual(
            self.audit["factor_operator"]["R_rank"]
            + len(ker_r),
            FACTOR_COORDINATES,
        )
        self.assertEqual(
            self.audit["factor_operator"]["augmented_rank"]
            + len(ker_augmented),
            FACTOR_COORDINATES + VARIABLES,
        )
        self.assertEqual(
            self.audit["factor_operator"]["augmented_rank"]
            + len(ker_augmented_t),
            FACTOR_COORDINATES,
        )

        for vector in ker_r:
            self._verify_factor_kernel_vector(vector)
        for vector in ker_augmented[: len(ker_r)]:
            self._verify_factor_kernel_vector(vector)
        for vector in ker_augmented[len(ker_r) :]:
            self._verify_augmented_variable_vector(vector)
        for vector in ker_rt:
            self._verify_left_kernel_vector(vector, augmented=False)
        for vector in ker_augmented_t:
            self._verify_left_kernel_vector(vector, augmented=True)

        self.assertEqual(self.audit["factor_operator"]["R_rank"], 296_180)
        self.assertEqual(
            self.audit["factor_operator"]["augmented_rank"], 296_182
        )
        self.assertEqual(
            self.audit["factor_operator"]["augmented_kernel_dimension"],
            len(ker_augmented),
        )
        self.assertEqual(
            self.audit["factor_operator"]["augmented_left_nullity"],
            len(ker_augmented_t),
        )
        helper = [
            [1, 0, 0, -1, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
        ]
        augmented_helper = [
            [1, 0, 0, -1, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1],
            [0, 0, 0, 1, 0, 0, 1, 0],
        ]
        self.assertEqual(_rank_mod(helper), 3)
        self.assertEqual(_rank_mod(augmented_helper), 5)
        self.assertEqual(
            3 * 98_442 + 3 * 251 + 74 + 3 * 8 + _rank_mod(helper),
            296_180,
        )
        self.assertEqual(
            3 * 98_442 + 3 * 251 + 74 + 3 * 8 + _rank_mod(augmented_helper),
            296_182,
        )

        fingerprints = {
            "ker_R": _sparse_fingerprint(
                (FACTOR_COORDINATES, FACTOR_COORDINATES), ker_r
            ),
            "ker_R_transpose": _sparse_fingerprint(
                (FACTOR_COORDINATES, FACTOR_COORDINATES), ker_rt
            ),
            "ker_augmented": _sparse_fingerprint(
                (FACTOR_COORDINATES, FACTOR_COORDINATES + VARIABLES),
                ker_augmented,
            ),
            "ker_augmented_transpose": _sparse_fingerprint(
                (FACTOR_COORDINATES, FACTOR_COORDINATES + VARIABLES),
                ker_augmented_t,
            ),
        }
        recorded = self.audit["factor_operator"]["kernel_certificates"]
        self.assertEqual(
            recorded["helper_row_coordinates"],
            {
                "local_root": HELPER_ROOT_LOCAL,
                "local_position": HELPER_POSITION_LOCAL,
                "upstream_root": HELPER_ROOT_UP,
                "upstream_anchor": HELPER_ANCHOR_UP,
                "one_variable": 0,
                "public_anchor_variable": 5,
            },
        )
        self.assertEqual(
            {name: data["basis_sha256"] for name, data in recorded.items()
             if isinstance(data, dict) and "basis_sha256" in data},
            fingerprints,
        )

    def test_restricted_inverse_certificate_is_recorded(self) -> None:
        restricted = self.audit["factor_operator"]["restricted_left_inverse"]
        span = restricted["coefficient_family_span"]
        for key, expected in {
            "dimension": 98_646,
            "local_matrix_nnz": 564_245,
            "transformed_matrix_nnz": 564_324,
            "rank_Q_L": 98_646,
            "rank_R_Q_L": 98_646,
            "Q_L_sha256": "28f61fae36f26c92e5bdd0be365db771a232ca9e6a32d0a9aac90e5dfd168d7c",
            "R_Q_L_sha256": "5f0d1f2527be2ec5423093d5ee46569f72fa28a513aaffa6616f3cb4e7c63b4e",
        }.items():
            self.assertEqual(span[key], expected)
        self.assertEqual(
            restricted["intersection"]["ker_R_intersection_col_Q_L_dimension"],
            0,
        )
        self.assertEqual(
            restricted["intersection"]["basis_sha256"],
            "5ca8a26614342463c1a25680db98966b1fb6e8a70fcef19cbeb485e2865a0318",
        )
        self.assertEqual(
            restricted["factorized_operator"]["factorized_operator_sha256"],
            "105b77e87dc07bccdbbd0ccfbf36fc4e094957d4ddc712a1f3e6f3718d9be87e",
        )
        self.assertEqual(
            restricted["direct_verification"]["coefficient_family_vectors_verified"],
            98_646,
        )
        self.assertTrue(
            restricted["direct_verification"][
                "P_RQL_U_Pi_equals_T_all_columns"
            ]
        )
        self.assertTrue(
            restricted["affine_offset"]["subtract_before_inverse"]
        )


if __name__ == "__main__":
    unittest.main()
