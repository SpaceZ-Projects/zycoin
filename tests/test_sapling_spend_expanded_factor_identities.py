"""Verify exact row-factor identities from the retained Spend correspondence."""

from __future__ import annotations

import hashlib
import json
import unittest
from collections import defaultdict
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS

ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE = ROOT / "reports" / "sapling-spend-expanded-row-factor-identities.json"


def _read_terms(terms: list[list[int | str]]) -> dict[int, int]:
    return {
        int(column): int.from_bytes(bytes.fromhex(coefficient), "little")
        for column, coefficient in terms
    }


def _add(*scaled_terms: tuple[int, dict[int, int]]) -> dict[int, int]:
    result: dict[int, int] = defaultdict(int)
    for scale, terms in scaled_terms:
        for column, coefficient in terms.items():
            result[column] = (
                result[column] + scale * coefficient
            ) % SCALAR_MODULUS
    return {column: value for column, value in result.items() if value}


def _expand(abc: tuple[dict[int, int], dict[int, int], dict[int, int]]) -> dict:
    a, b, c = abc
    result: dict[tuple[int, ...], int] = defaultdict(int)

    def monomial(column: int) -> tuple[int, ...]:
        return () if column == 0 else (column,)

    for left_column, left_coefficient in a.items():
        for right_column, right_coefficient in b.items():
            key = tuple(
                sorted(monomial(left_column) + monomial(right_column))
            )
            result[key] = (
                result[key] + left_coefficient * right_coefficient
            ) % SCALAR_MODULUS
    for column, coefficient in c.items():
        key = monomial(column)
        result[key] = (result[key] - coefficient) % SCALAR_MODULUS
    return {key: value for key, value in result.items() if value}


class SaplingSpendExpandedFactorIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.certificate = json.loads(CERTIFICATE.read_text(encoding="ascii"))
        digest = cls.certificate["certificate_sha256"]
        unsigned = {
            key: value
            for key, value in cls.certificate.items()
            if key != "certificate_sha256"
        }
        encoded = json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        if hashlib.sha256(encoded).hexdigest() != digest:
            raise AssertionError("expanded-row factor certificate digest mismatch")

    def test_all_333_exact_residual_and_factor_identities(self) -> None:
        rows = self.certificate["rows"]
        counts = self.certificate["counts"]
        self.assertEqual(len(rows), 333)
        self.assertEqual(
            counts["factor_map_classes"],
            {
                "linear_constraint_c_to_a": 74,
                "pkd_affine_swap": 251,
                "unit_b_affine_shift": 8,
            },
        )
        self.assertEqual(
            counts["raw_residual_scales"], {"+1": 329, "-1": 4}
        )

        observed: dict[str, int] = defaultdict(int)
        for row in rows:
            with self.subTest(
                upstream=row["upstream_row_index"],
                local=row["local_row_index"],
            ):
                upstream = tuple(
                    _read_terms(row["upstream_abc"][side]) for side in "abc"
                )
                local = tuple(
                    _read_terms(row["local_mapped_abc"][side])
                    for side in "abc"
                )
                scale = int.from_bytes(
                    bytes.fromhex(row["raw_residual_scale_hex"]), "little"
                )
                self.assertEqual(
                    _expand(upstream),
                    {
                        monomial: coefficient * scale % SCALAR_MODULUS
                        for monomial, coefficient in _expand(local).items()
                        if coefficient * scale % SCALAR_MODULUS
                    },
                )
                observed[row["kind"]] += 1

                if row["kind"] == "pkd_affine_swap":
                    self.assertEqual(scale, 1)
                    self.assertEqual(
                        upstream[0], _add((1, local[1]), (1, {0: 1}))
                    )
                    self.assertEqual(upstream[1], local[0])
                    self.assertEqual(
                        upstream[2], _add((1, local[2]), (1, local[0]))
                    )
                elif row["kind"] == "linear_constraint_c_to_a":
                    self.assertEqual(scale, 1)
                    self.assertEqual(upstream[0], {})
                    self.assertEqual(upstream[1], {})
                    self.assertEqual(upstream[2], _add((-1, local[0])))
                    self.assertEqual(local[1], {0: 1})
                    self.assertEqual(local[2], {})
                else:
                    self.assertEqual(row["kind"], "unit_b_affine_shift")
                    shift = _read_terms(
                        row["derived_identity"]["shift_u_terms"]
                    )
                    self.assertEqual(upstream[0], _add((scale, local[0]), (1, shift)))
                    self.assertEqual(upstream[1], {0: 1})
                    self.assertEqual(local[1], {0: 1})
                    self.assertEqual(local[2], {})
                    self.assertEqual(upstream[2], shift)

        self.assertEqual(dict(observed), counts["factor_map_classes"])


if __name__ == "__main__":
    unittest.main()
