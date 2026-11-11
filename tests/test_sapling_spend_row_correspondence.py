import hashlib
import unittest

from tests.sapling_spend_row_correspondence import (
    FIELD,
    SpendRowCorrespondenceError,
    _canonical_json,
    build_spend_row_correspondence,
)


def _term(identity, coefficient=1):
    return {
        "identity": identity,
        "coefficient_hex": coefficient.to_bytes(32, "little").hex(),
    }


def _fixture(upstream_rows, local_rows, *, map_aux=True, mismatch_assignment=False):
    assignments = [1] * 8 + [3]
    assignments[1] = 2
    inputs = [
        {
            "identity": f"Input({index})",
            "assignment_hex": assignments[index].to_bytes(32, "little").hex(),
        }
        for index in range(8)
    ]
    auxiliary = [
        {
            "identity": "Aux(0)",
            "assignment_hex": assignments[8].to_bytes(32, "little").hex(),
        }
    ]
    upstream = {
        "inputs": inputs,
        "auxiliary_variables": auxiliary,
        "constraints": upstream_rows,
        "satisfied": True,
    }
    local_variables = [
        {
            "index": index,
            "assignment": str(
                assignments[index] + (1 if mismatch_assignment and index == 1 else 0)
            ),
        }
        for index in range(9)
    ]
    local = {
        "variables": local_variables,
        "constraints": local_rows,
        "satisfied": True,
        "matrix_fingerprint": "synthetic-local-matrix",
    }
    pairs = [
        {
            "local_index": index,
            "upstream_index": index,
            "semantic_identity": (
                "sapling:implicit-one"
                if index == 0
                else f"sapling:public:{index}"
            ),
            "semantic_gadget_id": "synthetic.gadget",
            "allocation_role": f"variable-{index}",
            "gadget_invocation_context": ["synthetic.gadget", "invocation:0"],
        }
        for index in range(8)
    ]
    if map_aux:
        pairs.append(
            {
                "local_index": 8,
                "upstream_index": 8,
                "semantic_identity": "synthetic.gadget|invocation:0|aux",
                "semantic_gadget_id": "synthetic.gadget",
                "allocation_role": "aux",
                "gadget_invocation_context": ["synthetic.gadget", "invocation:0"],
            }
        )
    correspondence = {
        "matched_public_variables": pairs[:8],
        "matched_auxiliary_variables": pairs[8:],
        "mapping_fingerprint_sha256": "synthetic-variable-map",
    }
    return upstream, local, correspondence


def _row(label, abc):
    return {
        "index": 0,
        "annotation": f"synthetic/{label}",
        **{
            side: [_term(identity, coefficient) for identity, coefficient in terms]
            for side, terms in zip("abc", abc)
        },
    }


def _local_row(label, abc):
    index = {
        "Input(0)": 0,
        "Input(1)": 1,
        "Input(2)": 2,
        "Input(3)": 3,
        "Input(4)": 4,
        "Input(5)": 5,
        "Input(6)": 6,
        "Input(7)": 7,
        "Aux(0)": 8,
    }
    return {
        "index": 0,
        "label": f"synthetic {label}",
        **{
            side: [
                [index[identity], str(coefficient % FIELD)]
                for identity, coefficient in terms
            ]
            for side, terms in zip("abc", abc)
        },
    }


def _compare(upstream_abc, local_abc, labels=("upstream", "local")):
    upstream, local, correspondence = _fixture(
        [_row(labels[0], upstream_abc)],
        [_local_row(labels[1], local_abc)],
    )
    return build_spend_row_correspondence(
        upstream, local, correspondence
    )


class SaplingSpendRowCorrespondenceTests(unittest.TestCase):
    def test_native_match_preserves_variable_references_coefficients_and_witness(self):
        abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        result = _compare(abc, abc)
        self.assertEqual(result["counts"]["native_a_b_c"], 1)
        self.assertEqual(result["counts"]["one_to_one_row_pairs"], 1)
        self.assertEqual(
            result["row_pairs"][0]["upstream_abc"],
            result["row_pairs"][0]["local_mapped_abc"],
        )
        self.assertEqual(
            result["row_pairs"][0]["local_label"], "synthetic local"
        )
        self.assertTrue(result["row_pairs"][0]["upstream_label_unique"])
        self.assertTrue(result["row_pairs"][0]["local_label_unique"])
        self.assertEqual(
            result["witness_validation"]["mapped_variable_assignment_mismatches"],
            0,
        )
        self.assertEqual(result["witness_validation"]["upstream_satisfied_rows"], 1)
        self.assertEqual(result["witness_validation"]["local_satisfied_rows"], 1)

    def test_a_b_swap_is_not_reported_as_native(self):
        upstream = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        local = (
            [("Aux(0)", 1)],
            [("Input(1)", 1)],
            [("Input(0)", 6)],
        )
        result = _compare(upstream, local)
        self.assertEqual(result["counts"]["a_b_factor_swap"], 1)
        self.assertEqual(
            result["row_pairs"][0]["factor_mapping"]["orientation"],
            "swapped",
        )

    def test_factor_normalization_checks_product_scale_and_coefficients(self):
        upstream = (
            [("Input(1)", 10)],
            [("Aux(0)", 21)],
            [("Input(0)", 1260)],
        )
        local = (
            [("Input(1)", 2)],
            [("Aux(0)", 3)],
            [("Input(0)", 36)],
        )
        result = _compare(upstream, local)
        row = result["row_pairs"][0]
        self.assertEqual(
            row["classification"], "valid_factor_normalization"
        )
        self.assertEqual(
            int.from_bytes(
                bytes.fromhex(
                    row["factor_mapping"][
                        "local_factor_scale_for_upstream_A_hex"
                    ]
                ),
                "little",
            ),
            5,
        )
        self.assertEqual(
            int.from_bytes(
                bytes.fromhex(
                    row["factor_mapping"][
                        "local_factor_scale_for_upstream_B_hex"
                    ]
                ),
                "little",
            ),
            7,
        )
        self.assertEqual(
            int.from_bytes(
                bytes.fromhex(row["factor_mapping"]["local_C_scale_hex"]),
                "little",
            ),
            35,
        )

    def test_incorrect_factor_coefficient_scale_is_not_equivalent(self):
        upstream = (
            [("Input(1)", 10)],
            [("Aux(0)", 21)],
            [("Input(0)", 1260)],
        )
        local = (
            [("Input(1)", 2)],
            [("Aux(0)", 3)],
            [("Input(0)", 37)],
        )
        result = _compare(upstream, local)
        self.assertEqual(result["counts"]["one_to_one_row_pairs"], 0)
        self.assertEqual(
            result["unmatched_rows"]["upstream"][0]["classification"],
            "no_unique_relation_counterpart",
        )
        self.assertEqual(
            result["unmatched_rows"]["local"][0]["classification"],
            "no_unique_relation_counterpart",
        )

    def test_expanded_relation_match_is_not_claimed_as_factor_match(self):
        upstream = (
            [("Input(1)", 1), ("Input(0)", 1)],
            [("Input(0)", 1)],
            [("Aux(0)", 1)],
        )
        local = (
            [("Input(1)", 1)],
            [("Input(0)", 1)],
            [("Aux(0)", 1), ("Input(0)", -1)],
        )
        result = _compare(upstream, local)
        row = result["row_pairs"][0]
        self.assertEqual(
            row["classification"], "expanded_a_times_b_minus_c_only"
        )
        self.assertIsNone(row["factor_mapping"])
        self.assertEqual(
            row["expanded_relation"]["local_polynomial_scale_for_upstream_hex"],
            (1).to_bytes(32, "little").hex(),
        )
        self.assertEqual(
            row["expanded_relation"]["upstream_terms"],
            row["expanded_relation"]["local_mapped_terms"],
        )

    def test_duplicate_row_relations_are_reported_ambiguous_and_not_paired(self):
        abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        upstream, local, correspondence = _fixture(
            [_row("u0", abc), _row("u1", abc)],
            [_local_row("l0", abc), _local_row("l1", abc)],
        )
        local["constraints"][1]["index"] = 1
        upstream["constraints"][1]["index"] = 1
        result = build_spend_row_correspondence(
            upstream, local, correspondence
        )
        self.assertEqual(result["counts"]["ambiguous_upstream"], 2)
        self.assertEqual(result["counts"]["ambiguous_local"], 2)
        self.assertEqual(result["counts"]["one_to_one_row_pairs"], 0)

    def test_unmapped_variable_blocks_rows_instead_of_inventing_a_pair(self):
        upstream, local, correspondence = _fixture([], [], map_aux=False)
        upstream["auxiliary_variables"].append(
            {
                "identity": "Aux(1)",
                "assignment_hex": (4).to_bytes(32, "little").hex(),
            }
        )
        local["variables"].append({"index": 9, "assignment": "4"})
        upstream["constraints"] = [
            _row(
                "unmapped",
                (
                    [("Input(1)", 1)],
                    [("Aux(1)", 1)],
                    [("Input(0)", 8)],
                ),
            )
        ]
        local["constraints"] = [
            {
                "index": 0,
                "label": "unmapped local",
                "a": [[1, "1"]],
                "b": [[9, "1"]],
                "c": [[0, "8"]],
            }
        ]
        result = build_spend_row_correspondence(
            upstream, local, correspondence
        )
        self.assertEqual(result["counts"]["upstream_rows_blocked_by_unmapped_variable"], 1)
        self.assertEqual(result["counts"]["local_rows_blocked_by_unmapped_variable"], 1)
        self.assertEqual(
            result["unmatched_rows"]["upstream"][0]["classification"],
            "blocked_by_unmapped_variable",
        )
        self.assertEqual(result["counts"]["one_to_one_row_pairs"], 0)

    def test_mapping_witness_mismatch_is_rejected(self):
        abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        upstream, local, correspondence = _fixture(
            [_row("u", abc)],
            [_local_row("l", abc)],
            mismatch_assignment=True,
        )
        with self.assertRaisesRegex(
            SpendRowCorrespondenceError, "assignment mismatch"
        ):
            build_spend_row_correspondence(
                upstream, local, correspondence
            )

    def test_unmatched_rows_are_not_paired_by_index(self):
        upstream_abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        different_local_abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 7)],
        )
        result = _compare(upstream_abc, different_local_abc)
        self.assertEqual(result["counts"]["one_to_one_row_pairs"], 0)
        self.assertEqual(
            result["unmatched_rows"]["upstream"][0]["classification"],
            "no_unique_relation_counterpart",
        )
        self.assertEqual(
            result["unmatched_rows"]["local"][0]["classification"],
            "no_unique_relation_counterpart",
        )

    def test_row_mapping_and_coefficient_fingerprints_are_deterministic(self):
        abc = (
            [("Input(1)", 1)],
            [("Aux(0)", 1)],
            [("Input(0)", 6)],
        )
        first = _compare(abc, abc)
        second = _compare(abc, abc)
        self.assertEqual(
            first["row_mapping_fingerprint_sha256"],
            second["row_mapping_fingerprint_sha256"],
        )
        self.assertEqual(
            first["coefficient_fingerprint_sha256"],
            second["coefficient_fingerprint_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(_canonical_json(first)).digest(),
            hashlib.sha256(_canonical_json(second)).digest(),
        )


if __name__ == "__main__":
    unittest.main()
