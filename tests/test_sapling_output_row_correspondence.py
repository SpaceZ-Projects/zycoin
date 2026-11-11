import hashlib
import json
import unittest
from pathlib import Path

from src.r1cs import R1CS
from tests.sapling_output_row_correspondence import (
    RowCorrespondenceError,
    _canonical_json,
    build_row_correspondence,
)

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = (
    ROOT / "tests" / "fixtures" / "sapling_output_row_correspondence.json"
)

def _term(identity, coefficient=1):
    return {
        "identity": identity,
        "coefficient_hex": coefficient.to_bytes(32, "little").hex(),
    }


def _synthetic_correspondence(upstream_abc, local_abc):
    system = R1CS()
    public_inputs = [
        system.alloc_public(f"input-{index}", 1) for index in range(1, 6)
    ]
    y = system.alloc_private("y", 1)
    identities = [f"Input({index})" for index in range(6)] + ["Aux(0)"]
    variables = {"Input(0)": system.one, "Aux(0)": y}
    variables.update(
        {
            f"Input({index})": variable
            for index, variable in enumerate(public_inputs, start=1)
        }
    )

    def local_lc(terms):
        return system.linear_combination(
            [
                (variables[identity], coefficient)
                for identity, coefficient in terms
            ]
        )

    local_row = tuple(local_lc(terms) for terms in local_abc)
    system.enforce(*local_row, label="synthetic row")
    upstream = {
        "inputs": [{"identity": identity} for identity in identities[:6]],
        "auxiliary_variables": [{"identity": identities[6]}],
        "constraints": [
            {
                "annotation": "synthetic/row",
                **{
                    side: [_term(identity, coefficient) for identity, coefficient in terms]
                    for side, terms in zip("abc", upstream_abc)
                },
            }
        ],
    }
    correspondence = {
        "pinned_upstream": {"export_sha256": "synthetic"},
        "mapping_fingerprint_sha256": "synthetic-map",
        "pairs": [
            {
                "upstream_identity": identity,
                "local_identity": identity,
                "local_column": index,
            }
            for index, identity in enumerate(identities)
        ],
    }
    return build_row_correspondence(upstream, system, correspondence)


class SaplingOutputRowCorrespondenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))

    def test_artifact_covers_every_row_once_and_fails_no_rows_ambiguous(self):
        artifact = self.artifact
        self.assertEqual(
            artifact["counts"],
            {
                "upstream_rows": 7827,
                "local_rows": 7827,
                "one_to_one_row_pairs": 7827,
                "native_a_b_c": 7827,
                "a_b_factor_swap": 0,
                "valid_factor_normalization": 0,
                "expanded_a_times_b_minus_c_only": 0,
                "unmatched_upstream": 0,
                "unmatched_local": 0,
                "ambiguous_upstream": 0,
                "ambiguous_local": 0,
            },
        )
        pairs = artifact["row_index_mapping"]
        self.assertEqual(len(pairs), 7827)
        self.assertEqual(
            {pair["upstream_row_index"] for pair in pairs}, set(range(7827))
        )
        self.assertEqual(
            {pair["local_row_index"] for pair in pairs}, set(range(7827))
        )
        self.assertEqual(
            artifact["row_order_summary"]["same_index_rows"], 7827
        )
        self.assertEqual(artifact["row_order_summary"]["moved_rows"], 0)
        self.assertTrue(artifact["row_order_summary"]["identity_order"])

    def test_artifact_contains_exact_coefficients_and_expanded_rows(self):
        artifact = self.artifact
        self.assertEqual(len(artifact["rows"]), 7827)
        for row in artifact["rows"]:
            self.assertEqual(row["classification"], "native_a_b_c")
            self.assertEqual(row["upstream_row_index"], row["local_row_index"])
            self.assertEqual(
                set(row["upstream_abc"]), {"a", "b", "c"}
            )
            self.assertEqual(set(row["local_abc"]), {"a", "b", "c"})
            for side in "abc":
                for term in row["upstream_abc"][side]["canonical_terms"]:
                    self.assertEqual(len(bytes.fromhex(term["coefficient_hex"])), 32)
                for term in row["local_abc"][side]:
                    self.assertEqual(
                        len(bytes.fromhex(term["coefficient_hex"])), 32
                    )
                self.assertEqual(
                    row["upstream_abc"][side]["canonical_terms"],
                    [
                        {
                            "identity": term["upstream_identity"],
                            "coefficient_hex": term["coefficient_hex"],
                        }
                        for term in row["local_abc"][side]
                    ],
                )

        expanded = artifact["expanded_factor_only_rows"]
        self.assertEqual(len(expanded), 0)
        self.assertEqual(
            {
                (row["upstream_row_index"], row["local_row_index"])
                for row in expanded
            },
            {
                (row["upstream_row_index"], row["local_row_index"])
                for row in artifact["rows"]
                if row["classification"] == "expanded_a_times_b_minus_c_only"
            },
        )
        for row in artifact["rows"]:
            if row["classification"] == "expanded_a_times_b_minus_c_only":
                self.assertIsNotNone(row["expanded_relation"])
                self.assertIsNone(row["factor_mapping"])
            else:
                self.assertIsNotNone(row["factor_mapping"])

    def test_factor_coefficient_preservation(self):
        artifact = _synthetic_correspondence(
            (
                [("Input(1)", 2), ("Input(1)", 3)],
                [("Aux(0)", 7)],
                [("Input(0)", 35)],
            ),
            (
                [("Input(1)", 5)],
                [("Aux(0)", 7)],
                [("Input(0)", 35)],
            ),
        )
        row = artifact["rows"][0]
        self.assertEqual(row["classification"], "native_a_b_c")
        self.assertEqual(
            row["upstream_abc"]["a"]["canonical_terms"],
            [
                {
                    "identity": "Input(1)",
                    "coefficient_hex": (5).to_bytes(32, "little").hex(),
                }
            ],
        )
        self.assertEqual(row["local_abc"]["b"][0]["coefficient_hex"],
                         (7).to_bytes(32, "little").hex())

    def test_a_b_factor_swap_is_classified_separately(self):
        artifact = _synthetic_correspondence(
            (
                [("Input(1)", 2)],
                [("Aux(0)", 3)],
                [("Input(0)", 6)],
            ),
            (
                [("Aux(0)", 3)],
                [("Input(1)", 2)],
                [("Input(0)", 6)],
            ),
        )
        row = artifact["rows"][0]
        self.assertEqual(row["classification"], "a_b_factor_swap")
        self.assertEqual(row["factor_mapping"]["orientation"], "swapped")
        self.assertEqual(row["factor_mapping"]["local_C_scale_hex"],
                         (1).to_bytes(32, "little").hex())

    def test_nonzero_factor_normalization_is_checked_with_product_scale(self):
        artifact = _synthetic_correspondence(
            (
                [("Input(1)", 10)],
                [("Aux(0)", 21)],
                [("Input(0)", 210)],
            ),
            (
                [("Input(1)", 2)],
                [("Aux(0)", 3)],
                [("Input(0)", 6)],
            ),
        )
        row = artifact["rows"][0]
        self.assertEqual(row["classification"], "valid_factor_normalization")
        self.assertEqual(
            row["factor_mapping"]["local_factor_scale_for_upstream_A_hex"],
            (5).to_bytes(32, "little").hex(),
        )
        self.assertEqual(
            row["factor_mapping"]["local_factor_scale_for_upstream_B_hex"],
            (7).to_bytes(32, "little").hex(),
        )
        self.assertEqual(
            row["factor_mapping"]["local_C_scale_hex"],
            (35).to_bytes(32, "little").hex(),
        )

    def test_expanded_polynomial_only_relation_is_not_factor_match(self):
        artifact = _synthetic_correspondence(
            (
                [("Input(1)", 1), ("Input(0)", 1)],
                [("Input(0)", 1)],
                [("Aux(0)", 1)],
            ),
            (
                [("Input(1)", 1)],
                [("Input(0)", 1)],
                [("Aux(0)", 1), ("Input(0)", -1)],
            ),
        )
        row = artifact["rows"][0]
        self.assertEqual(
            row["classification"], "expanded_a_times_b_minus_c_only"
        )
        self.assertIsNone(row["factor_mapping"])
        self.assertEqual(
            row["expanded_relation"]["upstream_terms"],
            row["expanded_relation"]["local_mapped_terms"],
        )

    def test_synthetic_generation_is_deterministic(self):
        upstream = (
            [("Input(1)", 2), ("Input(1)", 3)],
            [("Aux(0)", 7)],
            [("Input(0)", 35)],
        )
        local = (
            [("Input(1)", 5)],
            [("Aux(0)", 7)],
            [("Input(0)", 35)],
        )
        first = _synthetic_correspondence(upstream, local)
        second = _synthetic_correspondence(upstream, local)
        self.assertEqual(_canonical_json(first), _canonical_json(second))
        self.assertEqual(
            hashlib.sha256(_canonical_json(first)).digest(),
            hashlib.sha256(_canonical_json(second)).digest(),
        )

    def test_ambiguous_rows_fail_closed(self):
        system = R1CS()
        for index in range(1, 6):
            system.alloc_public(f"input-{index}", 1)
        y = system.alloc_private("y", 1)
        x = system.variables[1]
        system.enforce(x, y, 0, "row 1")
        system.enforce(x, y, 0, "row 2")
        identities = [f"Input({index})" for index in range(6)] + ["Aux(0)"]
        upstream = {
            "inputs": [{"identity": identity} for identity in identities[:6]],
            "auxiliary_variables": [{"identity": identities[6]}],
            "constraints": [
                {
                    "annotation": f"synthetic/row {index}",
                    "a": [_term("Input(1)")],
                    "b": [_term("Aux(0)")],
                    "c": [],
                }
                for index in range(2)
            ],
        }
        correspondence = {
            "pinned_upstream": {"export_sha256": "synthetic"},
            "mapping_fingerprint_sha256": "synthetic-map",
            "pairs": [
                {
                    "upstream_identity": identity,
                    "local_identity": identity,
                    "local_column": index,
                }
                for index, identity in enumerate(identities)
            ],
        }
        with self.assertRaises(RowCorrespondenceError):
            build_row_correspondence(upstream, system, correspondence)

    def test_artifact_fingerprints_are_deterministic(self):
        artifact = self.artifact
        self.assertEqual(
            hashlib.sha256(ARTIFACT_PATH.read_bytes()).hexdigest(),
            "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761",
        )
        content = dict(artifact)
        expected = content.pop("artifact_content_fingerprint_sha256")
        self.assertEqual(
            expected,
            hashlib.sha256(
                b"zycoin-bellman-output-row-correspondence-artifact-v1\0"
                + _canonical_json(content)
            ).hexdigest(),
        )
        self.assertEqual(
            artifact["source"]["local_matrix_fingerprint"],
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertEqual(
            artifact["source"]["local_recorder_matrix_fingerprint"],
            "a38185ca3e1f8b5f788430faa44be8f3fe208e9a311b6758137d42667c3198af",
        )
        self.assertEqual(
            artifact["row_mapping_fingerprint_sha256"],
            "69f6498dbc3d2504bcc7beb6285d3312dd68c790f41dff9b21d3c1e162de8537",
        )
        self.assertTrue(
            artifact["source"]["local_recorder_matrix_matches_production"]
        )


if __name__ == "__main__":
    unittest.main()
