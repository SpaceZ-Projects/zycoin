import hashlib
import json
import unittest

from tests.sapling_spend_variable_correspondence import (
    _semantic_role_translation,
    _upstream_semantic_allocation_id,
    build_gadget_crosswalk,
    build_correspondence_result,
    match_allocation_provenance,
    validate_complete_mapping,
)


def _local(index, name, assignment, kind="private", semantic_identity=None):
    return {
        "index": index,
        "kind": kind,
        "name": name,
        "assignment": assignment,
        "semantic_identity": semantic_identity,
    }


def _upstream(index, label, assignment, semantic_identity=None, namespace=None):
    return {
        "identity": f"Input({index})" if index < 8 else f"Aux({index - 8})",
        "annotation": label,
        "allocation_namespace": namespace or [],
        "allocation_label": label,
        "assignment_hex": int(assignment).to_bytes(32, "little").hex()
        if assignment is not None
        else None,
        "index": index,
        "semantic_identity": semantic_identity,
        "assignment": assignment,
    }


def _minimal_exports(aux_local, aux_upstream):
    public_local = [
        _local(0, "ONE", "1", "one"),
        _local(1, "Sapling Spend public rk.u", "11", "public"),
        _local(2, "Sapling Spend public rk.v", "12", "public"),
        _local(3, "Sapling Spend public cv.u", "13", "public"),
        _local(4, "Sapling Spend public cv.v", "14", "public"),
        _local(5, "Sapling Spend public anchor", "15", "public"),
        _local(6, "Sapling Spend public nullifier_chunk_0", "16", "public"),
        _local(7, "Sapling Spend public nullifier_chunk_1", "17", "public"),
    ]
    public_upstream = [
        _upstream(0, "ONE", 1),
        _upstream(1, "rk/u/input variable", 11),
        _upstream(2, "rk/v/input variable", 12),
        _upstream(3, "value commitment/commitment point/u/input variable", 13),
        _upstream(4, "value commitment/commitment point/v/input variable", 14),
        _upstream(5, "anchor/input variable", 15),
        _upstream(6, "pack nullifier/input 0", 16),
        _upstream(7, "pack nullifier/input 1", 17),
    ]
    return public_local + aux_local, public_upstream + aux_upstream


class SaplingSpendVariableCorrespondenceTests(unittest.TestCase):
    def test_scalar_multiplication_pairs_record_source_role_translation(self):
        for gadget_id in (
            "sapling.spend.pk-d.scalar-multiplication",
            "sapling.spend.nk.fixed-base-multiplication",
            "sapling.spend.randomized-authorization-key",
        ):
            translation = _semantic_role_translation(gadget_id, "addition/1/u")
            self.assertIsNotNone(translation)
            self.assertIn("scalar-multiplication", translation["rule"])

    def test_unlabeled_g_position_namespace_gets_role_identity_not_ordinal_identity(self):
        variable = {
            "allocation_namespace": [
                "g^position",
                "addition 4",
                "A computation",
            ],
            "allocation_label": "product num",
        }
        self.assertEqual(
            _upstream_semantic_allocation_id(variable),
            "sapling.spend.nullifier-rho|mul:rho-position|"
            "addition/4/a/computation",
        )
        self.assertIsNone(
            _upstream_semantic_allocation_id(
                {
                    "allocation_namespace": ["g^position", "addition 4", "A computation"],
                    "allocation_label": "num",
                }
            )
        )

    def test_upstream_small_order_and_witness_namespaces_require_valid_labels(self):
        cases = [
            (
                ["ak not small order", "second doubling", "A computation"],
                "product num",
                "sapling.spend.randomized-authorization-key|"
                "non-small-order:ak|second/doubling/a/computation",
            ),
            (
                ["g_d not small order", "check u != 0"],
                "ephemeral inverse",
                "sapling.spend.diversifier-base|non-small-order:g-d|"
                "check/u/0/ephemeral/inverse",
            ),
            (
                ["witness g_d", "point interpretation", "u^2 v^2"],
                "product num",
                "sapling.spend.diversifier-base|witness:g-d|"
                "point/interpretation/u/2/v/2",
            ),
            (
                ["witness g_d", "point interpretation", "u^2"],
                "squared num",
                "sapling.spend.diversifier-base|witness:g-d|"
                "point/interpretation/u/2",
            ),
            (
                ["randomization of note commitment", "B computation"],
                "product num",
                "sapling.spend.note-commitment|"
                "randomization:note-commitment|b/computation",
            ),
            (
                ["faerie gold prevention", "u3"],
                "num",
                "sapling.spend.nullifier-rho|faerie-gold-prevention|u3",
            ),
        ]
        for namespace, label, expected in cases:
            with self.subTest(namespace=namespace):
                self.assertEqual(
                    _upstream_semantic_allocation_id(
                        {
                            "allocation_namespace": namespace,
                            "allocation_label": label,
                        }
                    ),
                    expected,
                )

    def test_complete_one_to_one_mapping_requires_every_variable(self):
        local = [
            {"index": 0, "semantic_identity": "one", "assignment": "1"},
            {"index": 1, "semantic_identity": "aux:a", "assignment": "7"},
        ]
        upstream = [
            {"index": 0, "semantic_identity": "one", "assignment": "1"},
            {"index": 1, "semantic_identity": "aux:a", "assignment": "7"},
        ]
        pairs = [
            {"local_index": 0, "upstream_index": 0, "semantic_identity": "one"},
            {"local_index": 1, "upstream_index": 1, "semantic_identity": "aux:a"},
        ]
        validate_complete_mapping(local, upstream, pairs)
        with self.assertRaisesRegex(ValueError, "does not cover"):
            validate_complete_mapping(local, upstream, pairs[:1])

    def test_duplicate_labels_are_not_silently_paired(self):
        aux_local = [
            _local(8, "shared", "5", semantic_identity="local:a"),
            _local(9, "shared", "6", semantic_identity="local:b"),
        ]
        aux_upstream = [
            _upstream(8, "upstream:a", 5, namespace=["scope"]),
            _upstream(9, "upstream:b", 6, namespace=["scope"]),
        ]
        local, upstream = _minimal_exports(aux_local, aux_upstream)
        with self.assertRaisesRegex(ValueError, "local auxiliary semantic identities are ambiguous"):
            build_correspondence_result(local, upstream)

    def test_repeated_upstream_labels_are_reported_with_namespace_context(self):
        aux_local = [
            _local(8, "local first", "5", semantic_identity="local:a"),
            _local(9, "local second", "6", semantic_identity="local:b"),
        ]
        aux_upstream = [
            _upstream(8, "repeated", 5, namespace=["scope-a"]),
            _upstream(9, "repeated", 6, namespace=["scope-b"]),
        ]
        local, upstream = _minimal_exports(aux_local, aux_upstream)
        result = build_correspondence_result(local, upstream)
        self.assertEqual(result["counts"]["repeated_upstream_allocation_labels"], 1)
        self.assertEqual(result["counts"]["auxiliary_variables_mapped"], 0)

    def test_ambiguous_semantic_identity_is_rejected(self):
        local = [
            {"index": 0, "semantic_identity": "aux:same", "assignment": "3"},
            {"index": 1, "semantic_identity": "aux:same", "assignment": "4"},
        ]
        upstream = [
            {"index": 0, "semantic_identity": "aux:same", "assignment": "3"},
            {"index": 1, "semantic_identity": "aux:same", "assignment": "4"},
        ]
        pairs = [
            {"local_index": 0, "upstream_index": 0, "semantic_identity": "aux:same"},
            {"local_index": 1, "upstream_index": 1, "semantic_identity": "aux:same"},
        ]
        with self.assertRaisesRegex(ValueError, "ambiguous semantic identity"):
            validate_complete_mapping(local, upstream, pairs)

    def test_repeated_witness_values_do_not_establish_identity(self):
        aux_local = [
            _local(8, "local first", "9", semantic_identity="local:first"),
            _local(9, "local second", "9", semantic_identity="local:second"),
        ]
        aux_upstream = [
            _upstream(8, "upstream first", 9, namespace=["first"]),
            _upstream(9, "upstream second", 9, namespace=["second"]),
        ]
        local, upstream = _minimal_exports(aux_local, aux_upstream)
        result = build_correspondence_result(local, upstream)
        self.assertEqual(
            result["assignment_diagnostics"]["same_value_candidate_pairs_if_values_were_used"],
            4,
        )
        self.assertEqual(result["counts"]["auxiliary_variables_mapped"], 0)

    def test_public_mapping_checks_assignment_after_semantic_match(self):
        local, upstream = _minimal_exports([], [])
        result = build_correspondence_result(local, upstream)
        self.assertEqual(result["counts"]["public_variables_mapped"], 8)
        self.assertTrue(
            all(
                pair["classification"] == "matched-public-semantic-identity"
                for pair in result["matched_public_variables"]
            )
        )
        upstream[1]["assignment_hex"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "public assignment mismatch"):
            build_correspondence_result(local, upstream)

    def test_generation_is_deterministic(self):
        local, upstream = _minimal_exports(
            [_local(8, "local aux", "4", semantic_identity="local:aux")],
            [_upstream(8, "upstream aux", 4, namespace=["aux"])],
        )
        first = build_correspondence_result(local, upstream)
        second = build_correspondence_result(local, upstream)
        first_bytes = json.dumps(first, sort_keys=True, separators=(",", ":")).encode()
        second_bytes = json.dumps(second, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(
            first["mapping_fingerprint_sha256"],
            hashlib.sha256(
                b"zycoin-sapling-spend-variable-mapping-v2\0"
                + json.dumps(
                    {
                        "public": first["matched_public_variables"],
                        "auxiliary": first["matched_auxiliary_variables"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("ascii")
            ).hexdigest(),
        )

    def test_variable_identity_does_not_depend_on_constraint_coefficients(self):
        local, upstream = _minimal_exports(
            [_local(8, "local aux", "4", semantic_identity="local:aux")],
            [_upstream(8, "upstream aux", 4, namespace=["aux"])],
        )
        result_before = build_correspondence_result(local, upstream)
        local[8]["constraint_coefficients"] = ["1", "3"]
        upstream[8]["constraint_coefficients"] = ["17", "29", "493"]
        result_after = build_correspondence_result(local, upstream)
        self.assertEqual(
            result_before["mapping_fingerprint_sha256"],
            result_after["mapping_fingerprint_sha256"],
        )

    def test_actual_sized_counts_are_not_assumed_from_ordinal_alignment(self):
        local, upstream = _minimal_exports(
            [_local(8, "local aux", "4", semantic_identity="local:aux")],
            [_upstream(8, "upstream aux", 4, namespace=["aux"])],
        )
        result = build_correspondence_result(local, upstream)
        self.assertEqual(result["counts"]["local_auxiliary_unresolved"], 1)
        self.assertEqual(result["counts"]["upstream_auxiliary_unresolved"], 1)
        self.assertEqual(result["matching_policy"]["witness_values_used_as_identity"], False)

    def test_namespace_provenance_maps_unique_semantic_paths_not_ordinals(self):
        local = [
            {
                **_local(41, "Sapling Spend ar bit[0]", "1"),
                "allocation_context_frames": [
                    {"file": "src/sapling_spend_circuit.py", "function": "constrain_sapling_spend", "line": 1}
                ],
                "allocation_event_index": 41,
                "gadget_scope": "src/sapling_spend_circuit.py:constrain_sapling_spend",
            }
        ]
        upstream = [
            {
                **_upstream(93, "boolean", 1, namespace=["ar", "bit 0"]),
                "allocation_event_index": 93,
                "namespace_hierarchy": ["ar", "bit 0"],
                "gadget_scope": "ar/bit 0",
            }
        ]
        result = match_allocation_provenance(local, upstream)
        self.assertEqual(result["counts"]["matched_after_assignment_check"], 1)
        pair = result["matched_auxiliary_variables"][0]
        self.assertEqual(pair["local_index"], 41)
        self.assertEqual(pair["upstream_index"], 93)
        self.assertEqual(
            pair["semantic_identity"], "sapling-spend:allocation-path:ar/bit/0"
        )
        self.assertFalse(
            result["matching_policy"]["ordinal_positions_used_as_identity"]
        )

    def test_duplicate_provenance_paths_remain_ambiguous(self):
        local = [
            {
                **_local(8, "Sapling Spend repeated", "4"),
                "allocation_context_frames": [{"function": "first"}],
            },
            {
                **_local(9, "Sapling Spend repeated", "5"),
                "allocation_context_frames": [{"function": "second"}],
            },
        ]
        upstream = [
            _upstream(8, "value", 4, namespace=["repeated"]),
        ]
        result = match_allocation_provenance(local, upstream)
        self.assertEqual(result["counts"]["matched_after_assignment_check"], 0)
        self.assertEqual(
            result["counts"]["ambiguous_local_auxiliary_variables"], 2
        )
        self.assertEqual(result["counts"]["many_to_one_candidate_paths"], 1)
        self.assertEqual(result["counts"]["one_to_many_candidate_paths"], 0)

    def test_provenance_candidate_assignment_mismatch_is_not_accepted(self):
        local = [
            {
                **_local(8, "Sapling Spend ar bit[0]", "0"),
                "allocation_context_frames": [{"function": "constrain_sapling_spend"}],
            }
        ]
        upstream = [
            _upstream(8, "boolean", 1, namespace=["ar", "bit 0"]),
        ]
        result = match_allocation_provenance(local, upstream)
        self.assertEqual(result["counts"]["candidate_assignment_mismatches"], 1)
        self.assertEqual(result["matched_auxiliary_variables"], [])

    def test_gadget_ids_disambiguate_repeated_merkle_invocations(self):
        local = []
        upstream = []
        for level in (0, 1):
            local_variable = {
                **_local(41 + level, f"Sapling Spend Merkle path position bit[{level}]", "1"),
                "allocation_context_frames": [
                    {"file": "src/sapling_gadgets.py", "function": "constrain_merkle_authentication_path"}
                ],
                "allocation_event_index": 41 + level,
                "gadget_scope": "src/sapling_gadgets.py:constrain_merkle_authentication_path",
                "semantic_gadget_id": "sapling.spend.merkle-authentication-path",
                "parent_gadget_context": [
                    "sapling.spend",
                    "sapling.spend.merkle-authentication-path",
                ],
                "gadget_invocation_context": [
                    "sapling.spend",
                    "sapling.spend.merkle-authentication-path",
                    f"level:{level}",
                ],
                "allocation_role": "position/bit",
                "semantic_allocation_id": (
                    "sapling.spend.merkle-authentication-path"
                    f"|level:{level}|position/bit"
                ),
            }
            upstream_variable = {
                **_upstream(
                    90 + level,
                    "boolean",
                    1,
                    namespace=[
                        f"merkle tree hash {level}",
                        "position bit",
                    ],
                ),
                "allocation_event_index": 90 + level,
                "gadget_scope": f"merkle tree hash {level}/position bit",
                "semantic_gadget_id": "sapling.spend.merkle-authentication-path",
                "parent_gadget_context": [
                    "sapling.spend",
                    "sapling.spend.merkle-authentication-path",
                ],
                "gadget_invocation_context": [
                    "sapling.spend",
                    "sapling.spend.merkle-authentication-path",
                    f"level:{level}",
                ],
                "allocation_role": "position bit",
                "semantic_allocation_id": (
                    "sapling.spend.merkle-authentication-path"
                    f"|level:{level}|position/bit"
                ),
            }
            local.append(local_variable)
            upstream.append(upstream_variable)

        result = match_allocation_provenance(local, upstream)
        self.assertEqual(result["counts"]["matched_after_assignment_check"], 2)
        self.assertEqual(result["counts"]["ambiguous_local_auxiliary_variables"], 0)
        self.assertEqual(
            {
                pair["gadget_invocation_context"][-1]
                for pair in result["matched_auxiliary_variables"]
            },
            {"level:0", "level:1"},
        )
        correspondence = {
            "matched_auxiliary_variables": result["matched_auxiliary_variables"],
            "counts": {
                "public_variables_mapped": 8,
                "auxiliary_variables_mapped": 2,
                "previously_mapped_auxiliary_variables": 0,
                "newly_mapped_auxiliary_variables": 2,
                "local_auxiliary_unresolved": 0,
            },
            "allocation_provenance_analysis": result["counts"],
            "complete_one_to_one_coverage": False,
        }
        first_crosswalk = build_gadget_crosswalk(correspondence)
        second_crosswalk = build_gadget_crosswalk(correspondence)
        self.assertEqual(first_crosswalk, second_crosswalk)
        self.assertEqual(first_crosswalk["counts"]["gadget_invocation_groups"], 2)

    def test_duplicate_gadget_semantic_id_is_not_accepted(self):
        identity = "sapling.spend.merkle-authentication-path|level:0|position/bit"
        local = [
            {
                **_local(8, "Sapling Spend Merkle path position bit[0]", "1"),
                "allocation_context_frames": [{"function": "constrain_merkle_authentication_path"}],
                "semantic_allocation_id": identity,
                "semantic_gadget_id": "sapling.spend.merkle-authentication-path",
            },
            {
                **_local(9, "Sapling Spend duplicate Merkle path position bit[0]", "1"),
                "allocation_context_frames": [{"function": "constrain_merkle_authentication_path"}],
                "semantic_allocation_id": identity,
                "semantic_gadget_id": "sapling.spend.merkle-authentication-path",
            },
        ]
        upstream = [
            {
                **_upstream(8, "boolean", 1, namespace=["merkle tree hash 0", "position bit"]),
                "semantic_allocation_id": identity,
                "semantic_gadget_id": "sapling.spend.merkle-authentication-path",
            }
        ]
        result = match_allocation_provenance(local, upstream)
        self.assertEqual(result["matched_auxiliary_variables"], [])
        self.assertEqual(result["counts"]["many_to_one_candidate_paths"], 1)
        self.assertEqual(result["counts"]["ambiguous_local_auxiliary_variables"], 2)

    def test_unmatched_duplicate_semantic_ids_are_still_reported_ambiguous(self):
        identity = "sapling.spend.ivk.blake2s|block:0|state/word/0"
        local = [
            {
                **_local(8, "Sapling Spend IVK duplicate A", "1"),
                "allocation_context_frames": [{"function": "constrain_ivk"}],
                "semantic_allocation_id": identity,
            },
            {
                **_local(9, "Sapling Spend IVK duplicate B", "1"),
                "allocation_context_frames": [{"function": "constrain_ivk"}],
                "semantic_allocation_id": identity,
            },
        ]
        result = match_allocation_provenance(local, [])
        self.assertEqual(result["matched_auxiliary_variables"], [])
        self.assertEqual(result["counts"]["ambiguous_local_auxiliary_variables"], 2)
        self.assertEqual(result["counts"]["ambiguous_upstream_auxiliary_variables"], 0)

    def test_previous_semantic_pair_is_retained_only_after_identity_and_assignment_check(self):
        identity = "sapling.spend.authorization-randomizer|invocation:ar|bit/0"
        local = [
            {
                **_local(41, "Sapling Spend ar bit[0]", "1"),
                "allocation_context_frames": [{"function": "constrain_sapling_spend"}],
                "semantic_allocation_id": identity,
                "semantic_gadget_id": "sapling.spend.authorization-randomizer",
                "allocation_role": "bit/0",
                "gadget_invocation_context": ["invocation:ar"],
                "parent_gadget_context": ["sapling.spend"],
            }
        ]
        upstream = [
            {
                **_upstream(93, "boolean", 1, namespace=["ar", "bit 0"]),
                "semantic_allocation_id": identity,
                "semantic_gadget_id": "sapling.spend.authorization-randomizer",
                "allocation_role": "bit 0",
                "gadget_invocation_context": ["invocation:ar"],
                "parent_gadget_context": ["sapling.spend"],
            }
        ]
        prior = [{"local_index": 41, "upstream_index": 93}]
        result = match_allocation_provenance(local, upstream, prior)
        self.assertEqual(result["counts"]["previously_mapped_and_cross_checked"], 1)
        self.assertEqual(result["counts"]["newly_mapped"], 0)
        self.assertEqual(
            result["matched_auxiliary_variables"][0]["classification"],
            "cross-checked-previous-semantic-mapping",
        )


if __name__ == "__main__":
    unittest.main()
