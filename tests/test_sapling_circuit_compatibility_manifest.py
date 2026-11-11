import hashlib
import json
import unittest
from pathlib import Path

from tests.sapling_parameter_subgroup_audit import build_validation_manifest
from src.groth16_compatibility import (
    SAPLING_OUTPUT_METADATA,
    SAPLING_SPEND_METADATA,
)

MANIFEST_PATH = (
    Path(__file__).resolve().parents[1]
    / "reports"
    / "sapling-circuit-compatibility-manifest.json"
)
SUBGROUP_REPORT_PATH = (
    Path(__file__).resolve().parents[1]
    / "reports"
    / "sapling-query-subgroup-validation.json"
)
ALLOWED_STATUSES = {
    "Verified",
    "Partially Verified",
    "Unverified",
    "Unsupported",
    "Blocked",
    "Verified at the relation level; exact matrices differ",
    "Partially Verified; complete relation multiset matched after row and equation normalization",
    "Verified by complete semantic correspondence; allocation order differs",
    "Partial row correspondence; exact ordered A/B/C equality is Unverified",
}


class SaplingCircuitCompatibilityManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_bytes = MANIFEST_PATH.read_bytes()
        cls.manifest = json.loads(cls.manifest_bytes)

    def test_manifest_has_complete_local_and_upstream_evidence_sections(self):
        manifest = self.manifest
        self.assertEqual(manifest["schema_version"], "1.0")
        self.assertEqual(manifest["phase"], "9.21.36")
        self.assertEqual(
            set(manifest["circuits"]),
            {"sapling-spend", "sapling-output"},
        )
        self.assertIn("provenance", manifest)
        self.assertIn("evidence_model", manifest)
        self.assertIn("reconstruction_assessment", manifest)
        self.assertIn("authentic_parameter_audit", manifest)

        for circuit_id, circuit in manifest["circuits"].items():
            with self.subTest(circuit=circuit_id):
                local = circuit["local"]
                upstream = circuit["upstream_source_reconstruction"]
                self.assertEqual(local["evidence_status"], "Verified")
                self.assertEqual(
                    local["total_columns_including_one"],
                    1
                    + len(local["application_public_inputs"])
                    + local["auxiliary_columns"],
                )
                self.assertEqual(
                    local["implicit_one"]["local_column"],
                    0,
                )
                self.assertEqual(
                    len(upstream["public_inputs"]["order"]),
                    len(upstream["public_inputs"]["input_identities"]),
                )
                self.assertEqual(
                    upstream["public_inputs"]["status"],
                    "Verified",
                )
                self.assertEqual(
                    [item["name"] for item in local["application_public_inputs"]],
                    upstream["public_inputs"]["order"],
                )
                if circuit_id == "sapling-output":
                    self.assertEqual(
                        upstream["complete_typed_auxiliary_identity_order"]["status"],
                        "Verified",
                    )
                    self.assertTrue(
                        upstream["complete_typed_auxiliary_identity_order"]["available"]
                    )
                    self.assertEqual(
                        upstream["complete_typed_auxiliary_identity_order"]["count"],
                        7821,
                    )
                    self.assertEqual(
                        upstream["constraint_row_order_and_abc_terms"]["status"],
                        "Verified",
                    )
                    self.assertTrue(
                        upstream["constraint_row_order_and_abc_terms"][
                            "ordered_rows_available"
                        ]
                    )
                else:
                    self.assertEqual(
                        upstream["complete_typed_auxiliary_identity_order"]["status"],
                        "Verified",
                    )
                    self.assertTrue(
                        upstream["complete_typed_auxiliary_identity_order"]["available"]
                    )
                    self.assertEqual(
                        upstream["complete_typed_auxiliary_identity_order"]["count"],
                        98638,
                    )
                    self.assertEqual(
                        upstream["constraint_row_order_and_abc_terms"]["status"],
                        "Verified",
                    )
                    self.assertTrue(
                        upstream["constraint_row_order_and_abc_terms"][
                            "ordered_rows_available"
                        ]
                    )
                    self.assertEqual(
                        upstream["constraint_row_order_and_abc_terms"]["count"],
                        98777,
                    )
                    self.assertEqual(
                        upstream["pinned_reference_export"]["sha256"],
                        "b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046",
                    )
                    self.assertEqual(
                        upstream["local_order_diagnostic"][
                            "same_index_assignment_mismatches"
                        ],
                        43658,
                    )
                    self.assertEqual(
                        upstream["local_order_diagnostic"][
                            "same_index_public_input_assignment_matches"
                        ],
                        8,
                    )
                    self.assertEqual(
                        upstream["local_order_diagnostic"][
                            "same_row_index_exact_abc_mismatches"
                        ],
                        66135,
                    )
                    self.assertEqual(
                        upstream["local_order_diagnostic"][
                            "semantic_variable_correspondence"
                        ],
                        "Partial; 8 public and 98,637 auxiliary identities established by gadget-level semantic allocation provenance; one distinct allocation remains unmatched on each side",
                    )
                    self.assertEqual(
                        upstream["local_order_diagnostic"][
                            "semantic_row_correspondence"
                        ],
                        "Partial; 98,775 unique row pairs are established, with two unmatched rows per side and no ambiguities",
                    )
                    correspondence = upstream["variable_correspondence"]
                    self.assertEqual(
                        correspondence["status"],
                        "Partial semantic correspondence; one distinct allocation remains unmatched per side",
                    )
                    self.assertFalse(correspondence["complete_one_to_one_coverage"])
                    self.assertEqual(correspondence["public_variables_mapped"], 8)
                    self.assertEqual(correspondence["auxiliary_variables_mapped"], 98637)
                    self.assertEqual(correspondence["previously_mapped_auxiliary_variables"], 98573)
                    self.assertEqual(correspondence["newly_mapped_auxiliary_variables"], 64)
                    self.assertEqual(correspondence["local_auxiliary_unresolved"], 1)
                    self.assertEqual(correspondence["upstream_auxiliary_unresolved"], 1)
                    self.assertEqual(correspondence["artifact_sha256"], "efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f")
                    self.assertEqual(correspondence["mapping_fingerprint_sha256"], "26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656")
                    provenance = correspondence["allocation_provenance"]
                    self.assertEqual(provenance["shared_semantic_paths"], 98637)
                    self.assertEqual(provenance["crosswalk_path"], "C:\\Users\\EzzyG\\.copilot\\session-state\\dedf634b-2027-4458-b86d-28e6f44497f6\\files\\sapling-spend-gadget-allocation-crosswalk-v7.json")
                    self.assertEqual(provenance["crosswalk_sha256"], "0b2b37a5ada665f4d1a640618275c02cea320555b5d58e0a8580b87f25573356")
                    self.assertEqual(provenance["crosswalk_fingerprint_sha256"], "a54e423b92a0fc7649b7d4ad75e369fe957069c151c229b26f0075bb60f38a5b")
                    self.assertEqual(provenance["candidate_assignment_mismatches"], 0)
                    self.assertEqual(provenance["ambiguous_local_auxiliary_variables"], 0)
                    self.assertEqual(provenance["ambiguous_upstream_auxiliary_variables"], 0)
                    self.assertEqual(
                        provenance["local_auxiliary_variables_without_namespace_hierarchy"],
                        98638,
                    )
                    self.assertEqual(
                        provenance["analysis_report_sha256"],
                        "4fea9950d68756db8bf4a0137df6bc9a1319234eae70c2bb87c14997c9ad14f8",
                    )
                    self.assertEqual(
                        provenance["new_mapping_families"],
                        {
                            "authorization-key point interpretation": 3,
                            "authorization-key small-order check": 16,
                            "g_d point interpretation": 5,
                            "g_d small-order check": 16,
                            "randomized authorization-key addition": 6,
                            "value-commitment output relation": 6,
                            "note-commitment randomization": 6,
                            "faerie-gold prevention": 6,
                        },
                    )
                    self.assertIn(
                        "Sapling Spend Merkle path position",
                        correspondence["unresolved_reason"],
                    )
                    self.assertIn(
                        "conditional anchor/num",
                        correspondence["unresolved_reason"],
                    )
                    self.assertEqual(
                        correspondence["validation"][
                            "spend_output_bellman_qap_groth16_compatibility_tests"
                        ],
                        {"passed": 216, "subtests_passed": 280},
                    )
                    self.assertFalse(
                        correspondence["validation"][
                            "production_spend_or_output_code_modified"
                        ]
                    )
                    self.assertEqual(provenance["one_to_many_candidate_paths"], 0)
                    self.assertEqual(provenance["many_to_one_candidate_paths"], 0)
                    self.assertEqual(provenance["many_to_many_candidate_paths"], 0)
                    incidence = correspondence["coefficient_independent_incidence_probe"]
                    self.assertEqual(incidence["round_1_shared_auxiliary_colors"], 33)
                    self.assertEqual(incidence["round_1_unique_cross_system_auxiliary_pairs"], 1)
                    self.assertEqual(incidence["round_2_shared_auxiliary_colors"], 0)
                    self.assertEqual(incidence["round_2_unique_cross_system_auxiliary_pairs"], 0)
                    rows = correspondence["row_correspondence"]
                    self.assertFalse(rows["exact_ordered_matrix_alignment"])
                    self.assertEqual(
                        upstream["upstream_to_local_comparison"][
                            "constraint_row_order_and_abc_terms"
                        ],
                        "Partial row correspondence; exact ordered A/B/C equality is Unverified",
                    )
                    self.assertEqual(
                        rows["row_counts"],
                        {
                            "upstream": 98777,
                            "local": 98777,
                            "one_to_one_pairs": 98775,
                            "native_a_b_c": 69840,
                            "a_b_factor_swap": 251,
                            "valid_factor_normalization": 28351,
                            "expanded_a_times_b_minus_c_only": 333,
                            "unmatched_upstream": 2,
                            "unmatched_local": 2,
                            "ambiguous_upstream": 0,
                            "ambiguous_local": 0,
                        },
                    )
                    self.assertEqual(rows["row_positions"], {"same_index": 50229, "moved": 48546})
                    self.assertTrue(rows["expanded_relation_scale"]["all_unit_scale"])
                    self.assertEqual(
                        rows["artifact_sha256"],
                        "44a14939955a9a82a24f4013bb0b9144a1810b648d6e4d9d3643117330b58ecc",
                    )
                    self.assertEqual(
                        rows["row_mapping_fingerprint_sha256"],
                        "f502b0f22dece3829d6e2e1e198ca8d98d82e233e9eb1a4dcded3a399f6ae17d",
                    )
                    investigation = rows["unmatched_row_investigation"]
                    self.assertEqual(
                        investigation["anchor_relation"]["correspondence_class"],
                        "Two upstream rows to one local row; not a one-to-one row match.",
                    )
                    self.assertFalse(
                        investigation["anchor_relation"]["new_variable_mapping"]
                    )
                    self.assertEqual(
                        investigation["rows"][0]["constraint"],
                        "(Aux(76803) - Aux(76805)) * V = 0",
                    )
                    self.assertEqual(
                        investigation["rows"][1]["constraint"],
                        "Input(5) * Input(0) = Aux(76805)",
                    )
                    self.assertEqual(
                        investigation["rows"][2]["constraint"],
                        "(position - sum(2^i * position_bit[i], i=0..31)) * ONE = 0",
                    )
                    self.assertEqual(
                        investigation["transformed_match_audit"][
                            "position_bit_boolean_rows"
                        ]["count"],
                        32,
                    )
                    self.assertEqual(
                        investigation["conclusion"]["new_variable_pairs"],
                        0,
                    )
                    self.assertEqual(
                        investigation["preserved_artifacts"][
                            "variable_mapping_sha256"
                        ],
                        "efa67820fdbaf0410cc1fad7380f2468173fedc5fa25ae8366ed0e067124046f",
                    )
                    semantic = rows["semantic_equivalence_audit"]
                    self.assertEqual(
                        semantic["anchor_projection"]["upstream_root_relation"],
                        "(R - T) * V = 0",
                    )
                    self.assertEqual(
                        semantic["anchor_projection"]["upstream_public_anchor_binding"],
                        "A * ONE = T",
                    )
                    self.assertFalse(
                        semantic["anchor_projection"]["variable_mapping_added"]
                    )
                    self.assertEqual(
                        semantic["merkle_position_projection"][
                            "boundary_positions"
                        ],
                        [0, 1, 2147483648, 4294967295],
                    )
                    self.assertEqual(
                        semantic["witness_probes"]["focused_tests"],
                        {"passed": 8, "subtests_passed": 17},
                    )
                    self.assertEqual(
                        semantic["witness_probes"]["targeted_regression_tests"][
                            "passed"
                        ],
                        276,
                    )
                    self.assertEqual(
                        semantic["witness_probes"]["targeted_regression_tests"][
                            "subtests_passed"
                        ],
                        570,
                    )
                    self.assertFalse(
                        semantic["witness_probes"][
                            "whole_relation_formal_proof"
                        ]
                    )
                    self.assertEqual(
                        semantic["whole_export_assessment"][
                            "exact_ordered_matrix_alignment"
                        ],
                        "Unverified",
                    )
                self.assertEqual(
                    upstream["whole_circuit_matrix_fingerprint"],
                    (
                        {
                            "status": "Verified for exact local comparison to the pinned ordered export",
                            "value": "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
                        }
                        if circuit_id == "sapling-output"
                        else {
                            "status": "Verified for the pinned reference export; not a local equivalence result",
                            "value": "cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127",
                        }
                    ),
                )
                self.assertEqual(
                    upstream["total_columns"],
                    (
                        {"status": "Verified", "value": 7827}
                        if circuit_id == "sapling-output"
                        else {"status": "Verified", "value": 98646}
                    ),
                )

    def test_authentic_parameter_audit_preserves_unverified_compatibility(self):
        audit = self.manifest["authentic_parameter_audit"]
        self.assertEqual(audit["phase"], "9.21.25")
        self.assertEqual(
            audit["official_parameters"]["sapling-spend"][
                "published_digest_algorithm"
            ],
            "BLAKE2b-512",
        )
        self.assertEqual(
            audit["official_parameters"]["sapling-output"]["bytes"],
            3_592_860,
        )
        self.assertTrue(
            audit["zcash_trailing_transcript"]["included_in_official_whole_file_digest"]
        )
        self.assertTrue(
            audit["parser_changes"]["sparse_query_positions_reconstructed"]
        )
        self.assertTrue(
            audit["parser_changes"]["authentic_whole_file_digests_verified"]
        )
        self.assertTrue(
            audit["parser_changes"]["authentic_section_layout_scanned"]
        )
        self.assertTrue(
            audit["parser_changes"]["authentic_query_points_fully_decoded"]
        )
        self.assertTrue(
            audit["parser_changes"]["authentic_query_points_subgroup_checked"]
        )
        self.assertTrue(
            audit["authentic_query_point_scan"]["query_subgroup_membership_checked"]
        )
        self.assertEqual(
            audit["authentic_query_point_scan"]["spend"]["query_points_checked"],
            437_699,
        )
        self.assertEqual(
            audit["authentic_query_point_scan"]["output"]["query_points_checked"],
            32_010,
        )
        self.assertEqual(
            audit["query_index_mapping_artifacts"]["sapling-spend"][
                "mapping_fingerprint_sha256"
            ],
            "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08",
        )
        self.assertEqual(
            audit["query_index_mapping_artifacts"]["sapling-output"][
                "mapping_fingerprint_sha256"
            ],
            "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2",
        )
        self.assertEqual(
            audit["authentic_vk_and_ic_points_checked"]["sapling-spend"],
            14,
        )
        self.assertEqual(
            audit["observed_authentic_sections"]["sapling-spend"]["a"],
            85_390,
        )
        status = audit["proof_and_key_status"]
        self.assertTrue(
            status["verification_key_compatibility"].startswith(
                "Partially Verified"
            )
        )
        self.assertTrue(
            status["proving_key_compatibility"].startswith("Partially Verified")
        )
        self.assertEqual(status["spend_query_compatibility"], "Unverified")
        self.assertEqual(
            status["output_query_compatibility"],
            "Exact Python-parser/Bellman point decoding and ordering verified; authentic query-to-circuit and ceremony binding remain Unverified",
        )
        self.assertEqual(
            status["output_parameter_parser_to_bellman_query_compatibility"],
            "Verified for all 32,016 Output proving-query and IC points",
        )
        self.assertEqual(status["production_proof_generation"], "Unverified")
        self.assertTrue(
            status["authentic_proof_vector_available_in_inspected_tests"]
        )
        security_audit = audit["production_api_security_audit"]
        self.assertEqual(security_audit["phase"], "9.21.31")
        self.assertEqual(
            security_audit["findings"][0]["classification"],
            "Fixed",
        )
        self.assertEqual(security_audit["unresolved_findings"], [])
        self.assertEqual(
            security_audit["validation"]["focused_suite_passed"],
            165,
        )
        trust_audit = audit["parameter_to_circuit_trust_audit"]
        self.assertEqual(trust_audit["phase"], "9.21.32")
        self.assertIn(
            "no circuit ID",
            trust_audit["findings"]["parameter_format_circuit_identifier"],
        )
        self.assertTrue(
            trust_audit["findings"]["circuit_binding"].startswith("Unverified.")
        )
        self.assertTrue(
            trust_audit["findings"]["ceremony_validity"].startswith("Unverified.")
        )
        self.assertTrue(
            trust_audit["negative_tests"]["same_length_modified_pinned_file_rejected"]
        )
        self.assertTrue(
            trust_audit["negative_tests"][
                "different_digest_rejected_even_when_format_and_counts_match"
            ]
        )

    def test_ceremony_transcript_audit_does_not_claim_cryptographic_validation(self):
        audit = self.manifest["authentic_parameter_audit"]["zcash_trailing_transcript"][
            "audit"
        ]
        self.assertEqual(
            audit["status"],
            "Format identified and trailer boundaries cross-checked; cryptographic ceremony verification not performed.",
        )
        self.assertEqual(audit["reference_format"]["version"], "0.2.2")
        self.assertEqual(
            audit["reference_format"]["revision"],
            "0c2b25fe8879deeb46530e91a5654d353a9bf94c",
        )
        for circuit in ("sapling-spend", "sapling-output"):
            record = audit["files"][circuit]
            self.assertEqual(record["transcript_bytes"], 52_836)
            self.assertEqual(record["contribution_count_field"], 97)
            self.assertEqual(
                record["format_length_check"], "68 + 97 * 544 = 52836 bytes"
            )
        self.assertTrue(
            any(
                "phase1radix2m17" in item
                for item in audit["verification_prerequisites_missing"]
            )
        )
        self.assertTrue(
            any(
                "phase1radix2m13" in item
                for item in audit["verification_prerequisites_missing"]
            )
        )
        self.assertEqual(audit["ceremony_validity"], "Unverified")

    def test_authentic_output_full_msm_matches_bellman_without_readiness_claim(self):
        audit = self.manifest["authentic_parameter_audit"][
            "authentic_output_msm_accumulation"
        ]
        self.assertEqual(audit["phase"], "9.21.28")
        self.assertIn("Verified exact Bellman 0.15", audit["status"])
        self.assertFalse(audit["proof_generated"])
        self.assertEqual(
            audit["section_counts"],
            {
                "h": 8191,
                "l": 7821,
                "a": 6298,
                "b_g1": 4850,
                "b_g2": 4850,
                "ic": 6,
            },
        )
        self.assertTrue(all(audit["exact_point_equality"].values()))
        self.assertTrue(all(audit["negative_mutations_rejected"].values()))
        self.assertTrue(
            audit["bellman_reference_export"]["sha256"]
            == "af22fb8571fefc1c3929e1e8949b098442042c2ad26e2d797747a3cab5e5b72e"
        )
        self.assertTrue(
            all(
                audit["peak_memory_bytes"][name] > 0
                for name in ("bellman_rss", "python_process_working_set")
            )
        )

    def test_authentic_output_query_layout_and_qap_do_not_claim_value_compatibility(self):
        audit = self.manifest["authentic_parameter_audit"][
            "authentic_output_query_to_circuit_compatibility"
        ]
        self.assertEqual(
            audit["authentic_query_value_compatibility"], "Unverified"
        )
        self.assertEqual(
            audit["proof_interoperability"]["status"],
            "Test-only deterministic Python-to-Bellman proof interoperability for one pinned Output witness; production API behavior is tracked separately.",
        )
        proof_interop = audit["proof_interoperability"]
        self.assertEqual(proof_interop["phase"], "9.21.29")
        self.assertEqual(
            proof_interop["reference_runner"],
            "tests/reference/sapling-output-qap/src/bin/verify_python_output_proof.rs",
        )
        point_comparison = audit["parameter_parser_to_bellman_query_compatibility"]
        self.assertEqual(
            point_comparison["status"],
            "Verified exact canonical point equality and ordering for every parsed Output proving-query point and IC entry.",
        )
        self.assertEqual(
            point_comparison["export"]["sha256"],
            "b56a9951fb00b54fee097a382fd78ebe19d98c6936461c14bd601d0414cf2bc1",
        )
        self.assertEqual(point_comparison["point_totals"]["total"], 32_016)
        self.assertEqual(point_comparison["point_totals"]["exact_matches"], 32_016)
        self.assertEqual(point_comparison["point_totals"]["mismatches"], 0)
        self.assertEqual(
            point_comparison["index_semantics"]["mapping_fingerprint_sha256"],
            "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2",
        )
        self.assertTrue(
            point_comparison["negative_tests"]["incorrect_sparse_indices_rejected"]
        )
        self.assertEqual(
            proof_interop["proof"]["sha256"],
            "22b06dcd01c54e8329cc04ac4270a72de0919642452c478a64c783c4780bb6ef",
        )
        self.assertEqual(
            proof_interop["query_sections_consumed"],
            {
                "ic_including_one": 6,
                "h": 8191,
                "l": 7821,
                "a": 6298,
                "b_g1": 4850,
                "b_g2": 4850,
            },
        )
        self.assertEqual(
            proof_interop["public_input_order"],
            ["cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"],
        )
        self.assertTrue(
            proof_interop["proof"]["bellman_verification"] == "Verified"
        )
        self.assertTrue(
            proof_interop["proof"]["pure_python_verification"] == "Verified"
        )
        self.assertTrue(
            proof_interop["proof"]["altered_proof_rejected"]
        )
        self.assertTrue(proof_interop["proof"]["altered_public_input_rejected"])
        self.assertTrue(proof_interop["proof"]["reordered_public_inputs_rejected"])
        self.assertTrue(proof_interop["proof"]["truncated_encoding_rejected"])
        self.assertTrue(proof_interop["proof"]["malformed_point_encoding_rejected"])
        self.assertEqual(
            proof_interop["performance"]["python_qap_quotient_seconds"], 0.7
        )
        self.assertEqual(
            proof_interop["performance"]["python_peak_working_set_bytes"],
            61_693_952,
        )
        self.assertEqual(
            proof_interop["performance"]["bellman_peak_rss_bytes"],
            197_558_272,
        )
        self.assertFalse(proof_interop["parameter_and_proof_files_retained"])
        self.assertIn("Verified", proof_interop["python_to_bellman"])
        production_api = audit["production_output_proving_api"]
        self.assertEqual(production_api["phase"], "9.21.30")
        self.assertTrue(
            production_api["randomness"]["repeated_proofs_for_same_witness_differed"]
        )
        self.assertTrue(
            production_api["proof_and_verification"][
                "bellman_0_15_independently_accepted_both_generated_proofs"
            ]
        )
        self.assertTrue(
            production_api["proof_and_verification"][
                "invalid_or_unsatisfied_witness_rejected_before_random_draw"
            ]
        )
        self.assertEqual(
            production_api["parameter_source"]["ceremony_validity"], "Unverified"
        )
        self.assertFalse(
            production_api["secret_lifetime"]["guaranteed_python_memory_zeroization"]
        )
        self.assertIn("Unverified", production_api["circuit_and_mapping_checks"][
            "parameter_to_circuit_binding"
        ])
        self.assertIn("zycoin.sapling_output_proof.py", production_api["validation"][
            "package_build"
        ])
        self.assertEqual(audit["parameter_identity_and_provenance"]["bytes"], 3_592_860)
        self.assertEqual(
            audit["pinned_output_circuit_evidence"]["ordered_rows"], 7827
        )
        self.assertEqual(
            audit["query_index_mapping"]["mapping_fingerprint_sha256"],
            "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2",
        )
        test_hash = self.manifest["circuits"]["sapling-output"][
            "upstream_source_reconstruction"
        ]["upstream_test_assertions"]["test_constraint_system_hash"]
        self.assertFalse(test_hash["is_matrix_fingerprint"])
        self.assertIn(
            test_hash["digest_hex"],
            audit["query_index_mapping"]["legacy_map_metadata_note"],
        )
        self.assertEqual(
            audit["pinned_output_circuit_evidence"]["matrix_fingerprint_sha256"],
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertEqual(
            audit["query_index_mapping"]["h"]["constraint_row_mapping"], None
        )
        self.assertEqual(
            audit["subgroup_coverage"]["query_points_checked"], 32_010
        )
        self.assertEqual(
            audit["qap_comparison"]["comparison_result"]["quotient_coefficient_count"],
            8191,
        )
        reference = audit["qap_comparison"]["independent_bellman_reference"]
        self.assertEqual(reference["status"], "Verified")
        self.assertEqual(reference["bellman_crate_version"], "0.15.0")
        self.assertEqual(len(reference["witnesses"]), 3)
        self.assertTrue(reference["exact_comparisons"]["bellman_python_exact_field_values_equal"])
        self.assertTrue(reference["exact_comparisons"]["all_quotients_divisible"])
        self.assertEqual(
            reference["fixture_sha256"],
            "0d13e5d1e073139fdb6c2e609a77acb6a296ea7582cb0d92337a3f6ec71ed571",
        )
        self.assertEqual(reference["fixture_bytes"], 14_821_991)
        self.assertTrue(
            reference["negative_cases"][
                "full_output_unsatisfied_public_input_tamper_recorded"
            ]
        )
        self.assertTrue(
            reference["negative_cases"][
                "unsatisfied_assignment_rejected_before_quotient"
            ]
        )
        self.assertEqual(
            reference["validation"]["targeted_sapling_bellman_qap_groth16_compatibility_tests_passed"],
            301,
        )
        self.assertTrue(reference["validation"]["fixture_regeneration_byte_for_byte"])
        self.assertIn(
            "does not establish every query point's expected value",
            audit["qap_comparison"]["independence_limit"],
        )
        self.assertIn("Spend", audit["spend_scope"])

    def test_authentic_query_subgroup_validation_manifest_is_deterministic(self):
        manifest_bytes = SUBGROUP_REPORT_PATH.read_bytes()
        report = json.loads(manifest_bytes)
        fingerprint = report["validation_fingerprint_sha256"]
        fingerprint_payload = dict(report)
        del fingerprint_payload["validation_fingerprint_sha256"]
        canonical = json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(
                b"zycoin-sapling-query-subgroup-validation-v1\0" + canonical
            ).hexdigest(),
            fingerprint,
        )
        regenerated = build_validation_manifest(report["circuits"])
        self.assertEqual(
            json.dumps(regenerated, sort_keys=True, separators=(",", ":")) + "\n",
            manifest_bytes.decode("utf-8"),
        )
        self.assertTrue(report["all_points_accounted_once"])
        expected = {
            "sapling-spend": {
                "query_points_checked": 437_699,
                "section_counts": {
                    "h": 131_071,
                    "l": 98_638,
                    "a": 85_390,
                    "b_g1": 61_300,
                    "b_g2": 61_300,
                },
            },
            "sapling-output": {
                "query_points_checked": 32_010,
                "section_counts": {
                    "h": 8_191,
                    "l": 7_821,
                    "a": 6_298,
                    "b_g1": 4_850,
                    "b_g2": 4_850,
                },
            },
        }
        for circuit, expected_result in expected.items():
            result = report["circuits"][circuit]
            self.assertEqual(
                result["query_points_checked"],
                expected_result["query_points_checked"],
            )
            self.assertEqual(
                result["section_counts"],
                expected_result["section_counts"],
            )
            self.assertEqual(result["query_points_rejected"], 0)
            self.assertEqual(
                sum(
                    section["checked"]
                    for section in result["section_results"].values()
                ),
                result["query_points_checked"],
            )
            self.assertTrue(
                all(
                    section["rejected"] == 0
                    for section in result["section_results"].values()
                )
            )

    def test_manifest_records_backend_neutral_affine_addition_evidence(self):
        addition = self.manifest["circuits"]["sapling-output"][
            "recorder_reconstruction"
        ]["backend_neutral_affine_addition"]
        self.assertEqual(addition["status"], "Partially Verified")
        self.assertTrue(addition["shared_operation_on_both_backends"])
        self.assertEqual(addition["production_rows"], 6)
        self.assertEqual(addition["recorder_rows"], 6)
        self.assertEqual(addition["production_columns_including_one"], 11)
        self.assertEqual(
            addition["production_matrix_fingerprint"],
            "b9c3cfc17d0b5201e6f4c69a10138911190b747f9c09ffcc6ee56a0fbadce39c",
        )
        self.assertTrue(
            addition["foreign_backend_variables_and_linear_combinations_rejected_before_mutation"]
        )
        self.assertFalse(addition["upstream_bellman_matrix_export"])

    def test_manifest_records_scalar_bit_decomposition_without_range_claim(self):
        decomposition = self.manifest["circuits"]["sapling-output"][
            "recorder_reconstruction"
        ]["backend_neutral_scalar_bit_decomposition"]
        self.assertEqual(decomposition["status"], "Partially Verified")
        self.assertEqual(decomposition["bit_width"], 252)
        self.assertEqual(decomposition["bit_order"], "Least-significant bit first: bits_le[index] = (esk >> index) & 1.")
        self.assertIn("None in the R1CS", decomposition["reconstruction_equation"])
        self.assertIn("No circuit less-than", decomposition["canonicality_or_range"])
        self.assertEqual(decomposition["production_rows"], 252)
        self.assertEqual(decomposition["recorder_rows"], 252)
        self.assertEqual(decomposition["production_columns_including_one"], 253)
        self.assertTrue(decomposition["unassigned_values_preserved"])
        self.assertFalse(decomposition["upstream_bellman_matrix_export"])

    def test_manifest_records_backend_neutral_scalar_accumulation(self):
        accumulation = self.manifest["circuits"]["sapling-output"][
            "recorder_reconstruction"
        ]["backend_neutral_scalar_mul_accumulation"]
        self.assertEqual(accumulation["status"], "Partially Verified")
        self.assertEqual(accumulation["production_rows"], 18)
        self.assertEqual(accumulation["recorder_rows"], 18)
        self.assertEqual(accumulation["production_columns_including_one"], 27)
        self.assertEqual(
            accumulation["production_matrix_fingerprint"],
            "2a095999443d2a45416b2e06c6003fcb83f736d1401f38e3dd1334867cda33a0",
        )
        self.assertIn("first selected point", accumulation["initial_accumulator"])
        self.assertTrue(
            accumulation["foreign_backend_variables_and_linear_combinations_rejected_before_mutation"]
        )
        self.assertFalse(accumulation["upstream_bellman_matrix_export"])

    def test_manifest_records_complete_scalar_multiplication_slice(self):
        multiplication = self.manifest["circuits"]["sapling-output"][
            "recorder_reconstruction"
        ]["backend_neutral_variable_base_scalar_multiplication"]
        self.assertEqual(multiplication["status"], "Partially Verified")
        self.assertTrue(multiplication["shared_operation_on_both_backends"])
        self.assertEqual(multiplication["production_rows"], 3521)
        self.assertEqual(multiplication["recorder_rows"], 3521)
        self.assertEqual(multiplication["production_columns_including_one"], 3523)
        self.assertEqual(
            multiplication["production_matrix_fingerprint"],
            "1e53bdeacde8d6565d678691dc5a47723f9bcdf781aced9a50cf8dee94c8216f",
        )
        self.assertFalse(multiplication["production_output_entrypoint_guard_changed"])
        self.assertEqual(multiplication["whole_output_recorder_synthesis"], "Not performed")
        self.assertFalse(multiplication["upstream_bellman_matrix_export"])

    def test_local_allocation_ranges_are_complete_and_consistent(self):
        for circuit_id, circuit in self.manifest["circuits"].items():
            local = circuit["local"]
            ranges = local["allocation_ranges"]
            expected_first = 1 + len(local["application_public_inputs"])
            covered = []
            for entry in ranges:
                self.assertEqual(
                    entry["count"],
                    entry["last"] - entry["first"] + 1,
                )
                self.assertEqual(entry["first"], expected_first)
                expected_first = entry["last"] + 1
                covered.extend(range(entry["first"], entry["last"] + 1))
            self.assertEqual(
                len(covered),
                local["auxiliary_columns"],
                circuit_id,
            )
            self.assertEqual(
                expected_first,
                local["total_columns_including_one"],
                circuit_id,
            )
            self.assertEqual(
                len(local["ordered_allocation_manifest_sha256"]),
                64,
            )
            self.assertTrue(
                all(
                    character in "0123456789abcdef"
                    for character in local["ordered_allocation_manifest_sha256"]
                )
            )

    def test_provenance_distinguishes_source_assertions_from_transcriptions(self):
        provenance = self.manifest["provenance"]
        self.assertEqual(
            provenance["sapling_crypto_revision"],
            "88a7946b4a3066787776e11f0a502654167e022d",
        )
        self.assertEqual(
            provenance["bellman_revision"],
            "b726862a4ece8a627e7fea486d77b502a6edbb0b",
        )
        self.assertTrue(provenance["execution"]["pinned_output_synthesis_executed"])
        self.assertTrue(provenance["execution"]["pinned_spend_synthesis_executed"])
        self.assertTrue(provenance["execution"]["rust_or_native_tooling_used"])
        self.assertIn("WSL", provenance["execution"]["meaning"])
        for source in provenance["sources"]:
            self.assertIn(source["path"], source["url"] or source["path"])
        for circuit_id, circuit in self.manifest["circuits"].items():
            upstream_test = circuit["upstream_source_reconstruction"][
                "upstream_test_assertions"
            ]
            self.assertFalse(
                upstream_test["test_constraint_system_hash"]["is_matrix_fingerprint"]
            )
            if circuit_id == "sapling-output":
                self.assertIn(
                    "test passed",
                    upstream_test["assertion_provenance"].lower(),
                )
                execution = circuit["upstream_source_reconstruction"][
                    "pinned_upstream_test_execution"
                ]
                self.assertEqual(execution["status"], "Verified")
                self.assertTrue(
                    execution["ordered_matrix_or_assignment_export_produced"]
                )
                self.assertEqual(
                    execution["source_integrity"]["src/circuit.rs"],
                    "769132963e46597aa2170b7adf453ca6a53b524667bec34bb564d09ad726037b",
                )
            else:
                self.assertIn(
                    "iteration 0 executed",
                    upstream_test["assertion_provenance"].lower(),
                )
            for component in circuit["upstream_source_reconstruction"][
                "component_matrix_fingerprints"
            ]:
                self.assertIn(component["status"], ALLOWED_STATUSES)
                if component["sha256"] is not None:
                    self.assertIn("not an upstream export", component["provenance"])
                else:
                    self.assertEqual(component["status"], "Unverified")

    def test_output_bellman_equivalence_and_source_order_effects(self):
        upstream = self.manifest["circuits"]["sapling-output"][
            "upstream_source_reconstruction"
        ]
        audit = upstream["allocation_order_differences"]
        self.assertEqual(
            audit["status"],
            "Previously identified allocation-order differences are resolved; exact variable correspondence verified.",
        )
        differences = {
            entry["id"]: entry for entry in audit["differences"]
        }
        self.assertEqual(
            set(differences),
            {"rcv-after-value-base", "g-d-representation-before-esk", "rcm-after-pedersen"},
        )
        for entry in differences.values():
            with self.subTest(difference=entry["id"]):
                self.assertIn("variable_index_effect", entry)
                self.assertIn("assignment_effect", entry)
                self.assertIn("constraint_order_effect", entry)
                self.assertIn("query_mapping_effect", entry)
                self.assertTrue(entry["upstream_order"])
                self.assertTrue(entry["zycoin_order"])
        self.assertEqual(audit["current_resolution"]["index_mismatches"], 0)
        self.assertIn(
            "pinned upstream column",
            audit["current_resolution"]["rcv_after_value_base"],
        )
        self.assertIn(
            "pinned upstream columns",
            audit["current_resolution"]["g_d_representation_before_esk"],
        )
        self.assertIn(
            "pinned upstream columns",
            audit["current_resolution"]["rcm_after_pedersen"],
        )
        export = upstream["reference_export"]
        self.assertEqual(export["status"], "Verified")
        self.assertEqual(export["format"], "bellman-sapling-output-reference-v1")
        self.assertEqual(export["artifact_size_bytes"], 6271047)
        self.assertEqual(
            export["artifact_sha256"],
            "ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe",
        )
        self.assertEqual(export["typed_allocations"]["auxiliary_variables"], 7821)
        self.assertEqual(export["ordered_rows"]["count"], 7827)
        self.assertTrue(export["ordered_rows"]["satisfied"])
        self.assertTrue(export["export_hash_cross_check"]["matches_pinned_test_assertion"])
        self.assertFalse(export["export_hash_cross_check"]["is_matrix_fingerprint"])
        self.assertEqual(
            upstream["total_columns"],
            {"status": "Verified", "value": 7827},
        )
        self.assertEqual(
            upstream["upstream_to_local_comparison"][
                "overall_bellman_matrix_equivalence"
            ],
            "Verified",
        )
        self.assertEqual(
            upstream["whole_circuit_matrix_fingerprint"],
            {
                "status": "Verified for exact local comparison to the pinned ordered export",
                "value": "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
            },
        )
        self.assertEqual(
            upstream["pinned_upstream_test_execution"]["status"],
            "Verified",
        )

    def test_output_semantic_comparison_accounts_for_complete_relation(self):
        upstream = self.manifest["circuits"]["sapling-output"][
            "upstream_source_reconstruction"
        ]
        comparison = upstream["semantic_matrix_comparison"]
        self.assertEqual(
            comparison["status"],
            "Exact ordered Bellman Output R1CS alignment verified for the pinned fixture; Groth16 parameter compatibility remains unverified.",
        )
        self.assertFalse(comparison["production_unchanged"])
        self.assertEqual(
            comparison["local_production"]["matrix_fingerprint"],
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        mapping = comparison["variable_correspondence"]
        self.assertEqual(mapping["public_inputs_including_one"], 6)
        self.assertTrue(mapping["public_input_positions_match"])
        self.assertEqual(
            mapping["previously_established_named_scalar_bits"][
                "total_auxiliary_mappings"
            ],
            820,
        )
        self.assertEqual(mapping["local_auxiliaries_accounted_for"], 7821)
        self.assertEqual(mapping["upstream_auxiliaries_accounted_for"], 7821)
        self.assertTrue(mapping["complete_auxiliary_accounting"])
        self.assertEqual(mapping["semantic_key_collisions"], 0)
        self.assertEqual(mapping["unmatched_variables"], 0)
        self.assertEqual(mapping["assignment_mismatches"], 0)
        self.assertIn("alone cannot establish identity", mapping["witness_value_collision_evidence"]["conclusion"])
        structural = mapping["structural_refinement"]
        self.assertEqual(
            structural["status"],
            "Complete semantic correspondence",
        )
        self.assertEqual(structural["additional_auxiliary_mappings_accepted"], 7001)
        self.assertEqual(structural["unaccounted_auxiliaries"], 0)
        self.assertEqual(structural["ambiguous_candidates"], 0)
        artifact = mapping["materialized_mapping_artifact"]
        self.assertEqual(artifact["status"], "Verified")
        self.assertEqual(artifact["counts"]["one_to_one_pairs"], 7827)
        self.assertEqual(artifact["counts"]["unmatched_upstream"], 0)
        self.assertEqual(artifact["counts"]["unmatched_local"], 0)
        self.assertEqual(artifact["counts"]["ambiguous_upstream_keys"], 0)
        self.assertEqual(artifact["counts"]["ambiguous_local_keys"], 0)
        self.assertEqual(artifact["counts"]["assignment_mismatches"], 0)
        self.assertEqual(
            artifact["mapping_fingerprint_sha256"],
            "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc",
        )
        self.assertEqual(artifact["position_mismatches"], 0)

        matrix = comparison["constraint_multiset_comparison"]
        self.assertEqual(matrix["local_rows"], 7827)
        self.assertEqual(matrix["upstream_rows"], 7827)
        self.assertEqual(matrix["exact_same_index_abc_rows"], 7827)
        self.assertEqual(matrix["exact_mapped_abc_row_multiset"], 7827)
        self.assertEqual(matrix["factor_swap_and_nonzero_scaling_relation_matches"], 0)
        self.assertEqual(matrix["additional_exact_expanded_polynomial_matches"], 0)
        self.assertEqual(matrix["additional_nonzero_scalar_polynomial_matches"], 0)
        self.assertEqual(matrix["unmatched_local_rows_after_relation_normalization"], 0)
        self.assertEqual(matrix["unmatched_upstream_rows_after_relation_normalization"], 0)
        self.assertTrue(matrix["relation_row_permutation_exists"])
        self.assertTrue(matrix["exact_ordered_matrix_equality"])
        self.assertEqual(matrix["duplicate_native_exact_row_kinds"], {"local": 0, "upstream": 0})
        self.assertIn("multiplicities as multisets", matrix["duplicate_handling"])
        self.assertEqual(len(matrix["regional_native_fingerprints"]["regions"]), 0)
        self.assertIn("Superseded", matrix["regional_native_fingerprints"]["method"])
        consequences = comparison["compatibility_consequences"]
        self.assertEqual(consequences["semantic_relation_equivalence"], "Verified")
        self.assertIn("Verified", consequences["overall_bellman_equivalence"])
        self.assertIn("Unverified", consequences["groth16_query_or_proving_key_translation"])
        alignment = comparison["exact_bellman_synthesis_alignment"]
        self.assertEqual(
            alignment["status"],
            "Verified: exact ordered Bellman Output synthesis for the pinned fixture.",
        )
        self.assertTrue(alignment["production_circuit_changed"])
        self.assertEqual(
            alignment["production_output"]["fingerprint"],
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertEqual(
            alignment["known_equation_form_differences"][
                "former_expanded_factor_only_rows"
            ],
            260,
        )
        self.assertEqual(
            alignment["known_equation_form_differences"][
                "remaining_expanded_factor_only_rows"
            ],
            0,
        )
        self.assertIn("Resolved", alignment["mapping_artifact_gap"])
        row_correspondence = alignment["row_correspondence_artifact"]
        self.assertEqual(
            row_correspondence["sha256"],
            "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761",
        )
        self.assertEqual(
            row_correspondence["row_mapping_fingerprint_sha256"],
            "69f6498dbc3d2504bcc7beb6285d3312dd68c790f41dff9b21d3c1e162de8537",
        )
        self.assertEqual(row_correspondence["row_counts"]["one_to_one_pairs"], 7827)
        self.assertEqual(row_correspondence["row_counts"]["unmatched_upstream"], 0)
        self.assertEqual(row_correspondence["row_counts"]["unmatched_local"], 0)
        self.assertEqual(row_correspondence["row_counts"]["native_a_b_c"], 7827)
        self.assertEqual(row_correspondence["row_counts"]["expanded_a_times_b_minus_c_only"], 0)
        self.assertEqual(row_correspondence["row_positions"]["same_index"], 7827)
        self.assertEqual(row_correspondence["row_positions"]["moved"], 0)

    def test_output_groth16_query_compatibility_remains_unverified(self):
        upstream = self.manifest["circuits"]["sapling-output"][
            "upstream_source_reconstruction"
        ]
        self.assertEqual(upstream["query_layout"]["status"], "Verified")
        self.assertEqual(
            upstream["query_layout"]["exact_auxiliary_to_query_index_mapping"],
            "Verified as identical auxiliary indices from the complete variable correspondence; authentic query-point values are not thereby demonstrated.",
        )
        self.assertEqual(
            upstream["qap_domain"],
            {
                "status": "Verified",
                "circuit_constraint_rows": 7827,
                "setup_dummy_input_constraints": 6,
                "domain_rows_before_padding": 7833,
                "domain_size": 8192,
                "padding_rows": 359,
                "basis": "Pinned generator adds one dummy constraint for each input, including ONE; EvaluationDomain pads the resulting coefficient count to a power of two. Both implementations use the same radix-2 root-of-unity ordering and coset generator 7.",
            },
        )
        comparison = upstream["semantic_matrix_comparison"]
        query = comparison["groth16_query_compatibility"]
        self.assertTrue(query["status"].startswith("Unverified"))
        self.assertEqual(query["query_layout"]["A_G1_count"], 7827)
        self.assertEqual(query["query_layout"]["B_G1_count"], 7827)
        self.assertEqual(query["query_layout"]["B_G2_count"], 7827)
        self.assertEqual(query["query_layout"]["L_G1_count"], 7821)
        self.assertEqual(query["query_layout"]["H_G1_count"], 8191)
        self.assertEqual(query["query_layout"]["IC_G1_count_including_one"], 6)
        self.assertTrue(
            query["query_translation_assessment"]["simple_index_permutation_suffices"]
        )
        self.assertFalse(
            query["query_translation_assessment"]["explicit_query_transformation_established"]
        )
        synthetic = query["synthetic_probe"]
        self.assertEqual(synthetic["status"], "Verified for bounded synthetic fixture only")
        self.assertEqual(synthetic["toxic_waste"]["tau"], 11)
        self.assertEqual(synthetic["toxic_waste"]["proof_randomizers_r_s"], [19, 23])
        self.assertEqual(
            synthetic["qap_polynomial_coefficients_sha256"],
            {
                "reference_fixture_abc": "4ac16be4127e30ea9f809af1e2ec1a0721a4d19817f6d5f9187de3f5a20f160c",
                "reordered_scaled_fixture_abc": "fe6cc0832cada50c17ff87071cd04a102c9835fe7880d8fd4f6c224043f5a1fa",
            },
        )
        self.assertEqual(
            synthetic["quotient_coefficients_sha256"],
            {
                "reference_fixture": "33e4df9d5b1a8070e4d813a65534d4b3cad05f47db35e6e45353a24c941f89a5",
                "reordered_scaled_fixture": "4bb457f9a9b998bcd62c861e968d34d1bd1c9c85a2ba8ba90866f6393cb29dc3",
            },
        )
        self.assertFalse(synthetic["real_parameter_evidence"])
        self.assertTrue(
            query["real_proving_key_compatibility"].startswith("Partially Verified")
        )
        self.assertTrue(
            query["real_verification_key_compatibility"].startswith("Partially Verified")
        )
        self.assertEqual(
            query["production_output_proof_generation"],
            "Unverified; not demonstrated",
        )

    def test_source_absence_is_explicitly_unverified(self):
        reconstruction = self.manifest["reconstruction_assessment"][
            "complete_authoritative_ordered_matrix_from_source_without_a_second_synthesizer"
        ]
        self.assertEqual(reconstruction["status"], "Blocked")
        self.assertFalse(reconstruction["value"])
        for circuit in self.manifest["circuits"].values():
            upstream = circuit["upstream_source_reconstruction"]
            self.assertEqual(
                set(upstream["upstream_to_local_comparison"].values())
                - ALLOWED_STATUSES,
                set(),
            )

    def test_manifest_serialization_is_deterministic(self):
        canonical = json.dumps(
            self.manifest,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertEqual(
            canonical,
            json.dumps(
                json.loads(self.manifest_bytes),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )
        self.assertEqual(
            canonical,
            json.dumps(
                self.manifest,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
        )

    def test_runtime_compatibility_metadata_matches_manifest_local_snapshots(self):
        for circuit_id, metadata in (
            ("sapling-spend", SAPLING_SPEND_METADATA),
            ("sapling-output", SAPLING_OUTPUT_METADATA),
        ):
            local = self.manifest["circuits"][circuit_id]["local"]
            self.assertEqual(
                metadata.application_public_input_order,
                tuple(item["name"] for item in local["application_public_inputs"]),
            )
            self.assertEqual(metadata.constraint_count, local["rows"])
            self.assertEqual(
                metadata.total_column_count,
                local["total_columns_including_one"],
            )
            self.assertEqual(
                metadata.auxiliary_column_count,
                local["auxiliary_columns"],
            )
            self.assertEqual(
                metadata.local_matrix_fingerprint,
                local["whole_circuit_matrix_fingerprint"],
            )
            self.assertEqual(
                metadata.has_implicit_one,
                local["implicit_one"]["local_column"] == 0,
            )

    def test_recorder_subset_and_component_cross_implementation_evidence(self):
        recorder = self.manifest["synthesis_recorder"]
        self.assertFalse(recorder["authoritative_upstream_matrix_export"])
        self.assertEqual(
            recorder["serializations"]["matrix_format"],
            "zycoin-bellman-recorder-matrix-v1",
        )
        self.assertIn(
            "combines duplicate variables",
            recorder["serializations"]["matrix_fingerprint"],
        )
        self.assertIn(
            "zero coefficients",
            recorder["serializations"]["full_recorder_serialization"],
        )
        self.assertFalse(recorder["serializations"]["upstream_test_hash_comparable"])
        self.assertIn(
            "after circuit rows",
            recorder["semantics"]["setup_dummy_constraints"],
        )
        self.assertIn(
            "LinearCombination variable and scaled-LC addition/subtraction semantics",
            recorder["pinned_api_audit"]["modeled"],
        )
        self.assertTrue(
            recorder["pinned_api_audit"]["unsupported_or_not_modeled"]
        )
        component = recorder["pedersen_component_cross_implementation"]
        self.assertEqual(component["status"], "Partially Verified")
        self.assertEqual(
            component["comparison_kind"],
            "Cross-implementation agreement; not authoritative Bellman execution or export",
        )
        self.assertTrue(component["local_matrix_serializations_equal"])
        self.assertFalse(component["upstream_matrix_export"])
        self.assertEqual(
            component["recorder_matrix_fingerprint"],
            "aa02682a888b8e6c6beba4bdce946ca4e1cbf56cca2d146430819065cb7132e7",
        )
        blake = recorder["blake2s_component_cross_implementation"]
        self.assertEqual(blake["status"], "Partially Verified")
        self.assertTrue(blake["local_matrix_serializations_equal"])
        self.assertTrue(blake["output_matches_python_hashlib"])
        self.assertFalse(blake["upstream_matrix_export"])
        fixture = recorder["independent_multi_constraint_fixture"]
        self.assertEqual(fixture["status"], "Verified")
        self.assertEqual(fixture["rows_after_dummy_inputs"], 5)
        self.assertEqual(fixture["domain_size"], 8)
        self.assertEqual(fixture["h_query_count"], 7)
        self.assertEqual(
            fixture["canonical_matrix_fingerprint_after_dummy_inputs"],
            "5b3c17e947d75d1686b43c6fe0b399a6cb1e2e1698e259c143989739f0035c04",
        )
        self.assertEqual(
            recorder["complete_spend_output_migration"]["status"],
            "Output completed; Spend not attempted",
        )
        self.assertEqual(
            recorder["complete_spend_output_migration"]["output_rows"],
            7827,
        )
        self.assertEqual(
            recorder["complete_spend_output_migration"]["spend_status"],
            "Not attempted",
        )
        output_recorder = self.manifest["circuits"]["sapling-output"][
            "recorder_reconstruction"
        ]
        self.assertEqual(output_recorder["status"], "Verified")
        self.assertEqual(output_recorder["recorder_rows_emitted"], 7827)
        self.assertFalse(output_recorder["production_assembly_changed"])
        self.assertEqual(
            output_recorder["local_production_and_recorder_reference"]["constraint_rows"],
            7827,
        )
        self.assertEqual(
            output_recorder["local_production_and_recorder_reference"][
                "recorder_ordered_abc_comparison"
            ],
            "Exact serialized matrix bytes matched production",
        )
        value_commitment = output_recorder["backend_neutral_value_commitment"]
        self.assertEqual(value_commitment["status"], "Partially Verified")
        self.assertEqual(
            value_commitment["production_recorder_evidence"]["rows"], 1889
        )
        self.assertEqual(
            value_commitment["production_recorder_evidence"][
                "columns_including_one"
            ],
            1888,
        )
        self.assertEqual(
            value_commitment["production_recorder_evidence"][
                "common_local_matrix_sha256"
            ],
            "885b7d51797f2d65e89e4ada3e8bdd5ca8fc3187eef421fbe4f7463bbc65d592",
        )
        self.assertEqual(
            output_recorder["resolved_blocking_boundary"]["path"],
            "src/sapling_gadgets.py::constrain_pedersen_hash",
        )
        entrypoint = output_recorder["backend_neutral_output_entrypoint"]
        self.assertEqual(entrypoint["status"], "Verified")
        self.assertTrue(entrypoint["recorder_attempt"]["entrypoint_guard_passed"])
        self.assertTrue(entrypoint["recorder_attempt"]["completed"])
        self.assertEqual(entrypoint["recorder_attempt"]["rows"], 7827)
        self.assertEqual(entrypoint["recorder_attempt"]["columns_including_one"], 7827)
        self.assertEqual(entrypoint["recorder_attempt"]["inputs_including_one"], 6)
        self.assertEqual(entrypoint["recorder_attempt"]["auxiliary_variables"], 7821)
        self.assertTrue(
            entrypoint["recorder_attempt"]["complete_output_matrix_available"]
        )
        self.assertEqual(
            entrypoint["full_output_recorder_synthesis"], "Completed"
        )
        self.assertEqual(
            entrypoint["upstream_bellman_matrix_equivalence"], "Unverified"
        )
        pedersen = output_recorder["backend_neutral_pedersen_hash"]
        self.assertEqual(pedersen["status"], "Verified")
        self.assertEqual(
            pedersen["isolated_relation_evidence"]["representations"]["montgomery"][
                "rows"
            ],
            1558,
        )
        self.assertEqual(
            pedersen["isolated_relation_evidence"]["representations"]["montgomery"][
                "columns_including_one"
            ],
            1559,
        )
        self.assertTrue(
            pedersen["isolated_relation_evidence"][
                "ordered_matrices_labels_variable_mappings_assignments_and_results_match"
            ]
        )
        self.assertTrue(
            all(
                item in pedersen["invalid_inputs_rejected_before_backend_mutation"]
                for item in (
                    "non-Boolean assigned bit",
                    "unassigned bit",
                    "foreign-backend variable",
                    "malformed bit constant",
                )
            )
        )
        ephemeral_key = output_recorder["backend_neutral_ephemeral_key"]
        self.assertEqual(ephemeral_key["status"], "Partially Verified")
        evidence = ephemeral_key["production_recorder_evidence"]
        self.assertEqual(
            evidence["valid_scalar_cases"],
            [
                "Sapling ephemeral-key reference fixture",
                "0",
                "1",
                "Jubjub scalar modulus minus one",
            ],
        )
        self.assertEqual(evidence["rows"], 3539)
        self.assertEqual(evidence["columns_including_one"], 3544)
        self.assertEqual(
            evidence["common_local_matrix_sha256"],
            "c70a14e6c311b6b029651659ff03a7fec711bd2c4333ccecca138280c65d0a1b",
        )
        self.assertTrue(
            evidence[
                "ordered_matrix_labels_variable_mappings_and_witness_assignments_match"
            ]
        )
        self.assertEqual(
            output_recorder["output_point_validation_status"]["status"],
            "Backend-neutral",
        )
        note_prelude = output_recorder["backend_neutral_note_commitment_prelude"]
        self.assertEqual(note_prelude["status"], "Partially Verified")
        prelude_evidence = note_prelude["production_recorder_evidence"]
        self.assertEqual(prelude_evidence["rows"], 6088)
        self.assertEqual(prelude_evidence["columns_including_one"], 6089)
        self.assertEqual(
            prelude_evidence["common_local_matrix_sha256"],
            "ee6e68379fb5e5eb144d460fd483acab8b69f68ffdf8e3437a15948502e62c6e",
        )
        self.assertTrue(
            prelude_evidence[
                "ordered_matrix_labels_variable_mappings_and_witness_assignments_match"
            ]
        )
        self.assertEqual(
            note_prelude["pedersen_migration_performed"], True
        )
        backend_slice = output_recorder["backend_neutral_slice"]
        self.assertEqual(backend_slice["status"], "Partially Verified")
        self.assertEqual(
            backend_slice["gadget"],
            "src/sapling_gadgets.py::constrain_jubjub_point",
        )
        self.assertEqual(backend_slice["production_rows"], 4)
        self.assertEqual(backend_slice["recorder_rows"], 4)
        self.assertEqual(
            backend_slice["production_matrix_fingerprint"],
            "2285a26c3911777b051fc133f62d8b2778a01fbe758c4d7bb63d0e5f153869a8",
        )
        self.assertEqual(
            len(output_recorder["remaining_concrete_dependencies"]),
            1,
        )
        audit = output_recorder["output_synthesis_dependency_audit"]
        self.assertEqual(audit["status"], "Verified")
        self.assertEqual(
            [stage["stage"] for stage in audit["allocation_order"]],
            [
                "public inputs",
                "value bits",
                "rcv bits",
                "value commitment intermediates",
                "g_d coordinates",
                "esk bits",
                "g_d checks and ephemeral-key multiplication",
                "pk_d representation",
                "rcm bits",
                "note commitment intermediates",
            ],
        )
        self.assertEqual(
            audit["allocation_order"][0]["order"],
            ["cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"],
        )
        self.assertEqual(
            audit["allocation_order"][7]["count"],
            256,
        )
        self.assertIn(
            "allocate_unchecked_jubjub_repr",
            audit["smallest_next_isolated_migration"]["operation"],
        )
        self.assertEqual(
            audit["smallest_next_isolated_migration"]["status"],
            "Completed in Phase 9.20.84",
        )
        self.assertEqual(
            len(audit["remaining_concrete_dependencies"]),
            5,
        )
        self.assertIn(
            "Blocked",
            audit["full_output_recorder_synthesis"],
        )
        self.assertIn(
            "Unverified",
            audit["upstream_bellman_equivalence"],
        )
        allocation = output_recorder[
            "backend_neutral_unchecked_jubjub_repr_allocation"
        ]
        self.assertEqual(allocation["status"], "Partially Verified")
        self.assertTrue(allocation["shared_operation_on_both_backends"])
        self.assertEqual(allocation["constraints_emitted"], 0)
        self.assertIn("255 little-endian bits", allocation["representation"])
        self.assertIn("outer/nested", allocation["namespace_behavior"])
        self.assertIn(
            "None/unassigned point input is rejected",
            allocation["unassigned_witness_behavior"],
        )
        self.assertTrue(
            any("off-curve points remain accepted" in item for item in allocation["checks"])
        )
        self.assertTrue(
            any("foreign R1CS variable" in item for item in allocation["checks"])
        )
        self.assertEqual(allocation["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(
            allocation["upstream_bellman_matrix_equivalence"], "Unverified"
        )
        boolean_audit = output_recorder["output_boolean_ownership_audit"]
        self.assertEqual(boolean_audit["status"], "Verified")
        self.assertFalse(boolean_audit["duplicate_boolean_constraints_observed"])
        self.assertEqual(
            [owner["boolean_rows"] for owner in boolean_audit["owners_and_order"][:4]],
            [64, 252, 256, 252],
        )
        self.assertIn(
            "message_bits_preconstrained=True",
            boolean_audit["pedersen_personalization"],
        )
        self.assertIn(
            "fixed-base 3-bit lookup relation",
            boolean_audit["recommended_next_isolated_migration"]["operation"],
        )
        self.assertEqual(boolean_audit["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(
            boolean_audit["upstream_bellman_matrix_equivalence"],
            "Unverified",
        )
        pk_d_boolean = output_recorder["backend_neutral_pk_d_boolean_enforcement"]
        self.assertEqual(pk_d_boolean["status"], "Partially Verified")
        self.assertTrue(pk_d_boolean["shared_operation_on_both_backends"])
        self.assertEqual(pk_d_boolean["constraints"]["count"], 256)
        self.assertTrue(pk_d_boolean["constraints"]["production_recorder_ordered_matrix_equal"])
        self.assertEqual(
            pk_d_boolean["constraints"]["local_matrix_fingerprint"],
            "d7ea7fec9edd70b8333431e6cc81379702bc6b7ce37676eac784893493608168",
        )
        self.assertIn("Foreign production and recorder variables", pk_d_boolean["ownership_checks"])
        self.assertEqual(pk_d_boolean["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(pk_d_boolean["upstream_bellman_matrix_equivalence"], "Unverified")
        rcm_audit = output_recorder["output_rcm_boolean_audit"]
        self.assertEqual(rcm_audit["status"], "Partially Verified")
        self.assertEqual(rcm_audit["allocation"]["count"], 252)
        self.assertEqual(
            rcm_audit["allocation"]["production_variable_indices"],
            "5063..5314 inclusive",
        )
        self.assertTrue(rcm_audit["boolean_enforcement"]["backend_neutral"])
        self.assertTrue(rcm_audit["boolean_enforcement"]["uses_constrain_jubjub_scalar_bit"])
        self.assertEqual(rcm_audit["boolean_enforcement"]["count"], 252)
        self.assertFalse(rcm_audit["downstream_reuse"]["duplicate_boolean_rows"])
        self.assertTrue(
            rcm_audit["isolated_cross_backend_evidence"]["ordered_rows_equal"]
        )
        self.assertEqual(
            rcm_audit["isolated_cross_backend_evidence"]["local_matrix_fingerprint"],
            "2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467",
        )
        self.assertEqual(
            rcm_audit["recommended_next_isolated_migration"]["operation"],
            "Assess the fixed-base 3-bit lookup relation and its concrete ownership/witness dependencies as the next isolated Output dependency.",
        )
        self.assertEqual(rcm_audit["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(rcm_audit["upstream_bellman_matrix_equivalence"], "Unverified")
        value_rcv_audit = output_recorder["output_value_and_rcv_boolean_audit"]
        self.assertEqual(value_rcv_audit["status"], "Partially Verified")
        self.assertEqual(
            value_rcv_audit["allocation"]["order"][0]["indices"], "6..69"
        )
        self.assertEqual(
            value_rcv_audit["allocation"]["order"][1]["indices"], "70..321"
        )
        self.assertIn(
            "_constrain_jubjub_scalar_bit",
            value_rcv_audit["boolean_enforcement"]["operation"],
        )
        self.assertEqual(
            value_rcv_audit["preconstrained_flags"]["output_value_call"],
            "Uses enforce_scalar_range=false and does not set bits_preconstrained, so all 64 value bits are constrained here.",
        )
        self.assertFalse(value_rcv_audit["downstream_duplicate_boolean_rows"])
        backend_neutral_boolean = value_rcv_audit[
            "backend_neutral_boolean_enforcement"
        ]
        self.assertEqual(backend_neutral_boolean["status"], "Partially Verified")
        self.assertTrue(
            backend_neutral_boolean["production_recorder_ordered_rows_equal"]
        )
        self.assertEqual(backend_neutral_boolean["value_bits"]["count"], 64)
        self.assertEqual(backend_neutral_boolean["rcv_bits"]["count"], 252)
        self.assertEqual(
            backend_neutral_boolean["value_bits"]["local_matrix_fingerprint"],
            "0647ab54621fcd156c698b16eac2aef84b1529bd5230926f6cf570ff820d7abc",
        )
        self.assertEqual(
            backend_neutral_boolean["rcv_bits"]["local_matrix_fingerprint"],
            "2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467",
        )
        self.assertEqual(
            value_rcv_audit["recommended_next_isolated_migration"]["operation"],
            "Assess the fixed-base 3-bit lookup relation and its concrete ownership/witness dependencies as the next isolated Output dependency.",
        )
        self.assertEqual(value_rcv_audit["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(value_rcv_audit["upstream_bellman_matrix_equivalence"], "Unverified")
        lookup_audit = output_recorder["output_fixed_base_lookup_audit"]
        self.assertEqual(lookup_audit["status"], "Partially Verified")
        self.assertEqual(
            lookup_audit["bit_window_order"]["table_index"],
            "a + 2*b + 4*c; absent high bits in the final partial window are literal zero.",
        )
        self.assertIn("65 value lookup rows plus 252 rcv lookup rows", lookup_audit["constraint_and_allocation_order"]["lookup_row_counts"])
        self.assertEqual(
            lookup_audit["backend_neutral_lookup"]["status"],
            "Verified",
        )
        self.assertIn(
            "SynthesisBackend",
            lookup_audit["backend_neutral_lookup"]["interface"],
        )
        self.assertIn(
            "3 Boolean input rows plus bc/u/v lookup rows = 6 rows; 7 columns",
            lookup_audit["backend_neutral_lookup"]["full_pattern_fixture"],
        )
        self.assertIn(
            "4 columns including ONE",
            lookup_audit["backend_neutral_lookup"]["partial_window_fixture"],
        )
        self.assertIn(
            "Spend Pedersen uses a separate signed three-bit lookup",
            lookup_audit["output_preconstrained_and_range_branches"]["shared_usage"],
        )
        self.assertEqual(
            lookup_audit["recommended_next_isolated_migration"]["operation"],
            "No fixed-base scalar validation operation remains concrete; inspect other Output synthesis dependencies to select the next isolated migration.",
        )
        scalar_validation = output_recorder[
            "backend_neutral_fixed_base_scalar_validation"
        ]
        self.assertEqual(scalar_validation["status"], "Partially Verified")
        self.assertIn(
            "No R1CS or concrete Variable type check remains",
            scalar_validation["concrete_backend_dependencies"],
        )
        self.assertEqual(
            scalar_validation["production_recorder_evidence"][
                "integrated_matrix_sha256"
            ],
            "aadef2e1b28c133bb86798085aa92f66525af7eac38d46e673f8f003bfb401f0",
        )
        self.assertEqual(
            scalar_validation["full_output_recorder_synthesis"], "Blocked"
        )
        self.assertEqual(
            scalar_validation["upstream_bellman_matrix_equivalence"],
            "Unverified",
        )
        self.assertIn(
            "The isolated lookup matches production and recorder",
            lookup_audit["recorder_comparison"],
        )
        windows = lookup_audit["backend_neutral_window_orchestration"]
        self.assertEqual(windows["status"], "Verified")
        self.assertIn("_constrain_fixed_base_windows", windows["operation"])
        self.assertEqual(
            windows["rows_columns"],
            "11 constraints and 16 columns including ONE in both backends. Row sequence: full-window bc/u/v, partial-window u/v, then four addition multiplication rows and two affine-addition relation rows.",
        )
        self.assertEqual(lookup_audit["full_output_recorder_synthesis"], "Blocked")
        self.assertEqual(lookup_audit["upstream_bellman_matrix_equivalence"], "Unverified")
        allocation = output_recorder["backend_neutral_allocation"]
        self.assertEqual(allocation["status"], "Partially Verified")
        self.assertTrue(allocation["shared_operation_on_both_backends"])
        self.assertEqual(allocation["rows"], 0)
        self.assertEqual(
            allocation["local_matrix_fingerprint"],
            "880efe8a2dffdedc69b198304e12aa7b2519c661cd0d6541be92ce50cee4d124",
        )
        representation = output_recorder["backend_neutral_representation"]
        self.assertEqual(representation["status"], "Partially Verified")
        self.assertEqual(representation["production_rows"], 776)
        self.assertEqual(representation["recorder_rows"], 776)
        self.assertEqual(representation["returned_representation_bits"], 256)
        self.assertTrue(representation["tampered_coordinate_rejected"])
        self.assertTrue(representation["tampered_representation_bit_rejected"])
        self.assertTrue(representation["noncanonical_modulus_alias_rejected"])
        point_selection = output_recorder["backend_neutral_point_selection"]
        self.assertEqual(point_selection["status"], "Partially Verified")
        self.assertEqual(point_selection["production_rows"], 3)
        self.assertEqual(point_selection["recorder_rows"], 3)
        self.assertEqual(
            point_selection["production_matrix_fingerprint"],
            "ffc4829f0e72c68da37758b7c077b8793a155658b36406ab577e61fd44b9d920",
        )
        self.assertTrue(point_selection["invalid_selector_rejected"])
        self.assertTrue(point_selection["tampered_selected_coordinate_rejected"])
        self.assertFalse(point_selection["upstream_bellman_matrix_export"])
        scalar_doubling = output_recorder["backend_neutral_scalar_doubling"]
        self.assertEqual(scalar_doubling["status"], "Partially Verified")
        self.assertEqual(scalar_doubling["production_rows"], 5)
        self.assertEqual(scalar_doubling["recorder_rows"], 5)
        self.assertEqual(
            scalar_doubling["production_matrix_fingerprint"],
            "12ba0c9c8b468d3aab43719068b117d58ebc06777ee7647ae0724378e586c8d6",
        )
        self.assertTrue(
            scalar_doubling["tampered_intermediates_and_output_coordinates_rejected"]
        )
        self.assertFalse(scalar_doubling["upstream_bellman_matrix_export"])


if __name__ == "__main__":
    unittest.main()
