import copy
import hashlib
import json
import unittest
from pathlib import Path

from src.groth16_qap import QAP, QAPAssignment
from src.jubjub import Point
from src.r1cs import R1CS
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness
from tests.sapling_parameter_query_mapping import (
    QueryMappingError,
    _spend_mapping_for_support,
    _validate_spend_assignment,
    build_output_query_index_mapping,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
OUTPUT = "sapling-output"


def _assigned_qap_input(system):
    auxiliary = tuple(
        system.witness_value(variable) for variable in system.variables[6:]
    )
    if any(value is None for value in auxiliary):
        raise AssertionError("Output fixture contains an unassigned auxiliary")
    return QAPAssignment(system.public_inputs(), auxiliary)


def _rebuild_upstream_output_system(row_artifact, variable_artifact):
    pairs = {
        pair["upstream_identity"]: pair for pair in variable_artifact["pairs"]
    }
    system = R1CS()
    variables = {"Input(0)": system.one}
    for index in range(1, 6):
        identity = f"Input({index})"
        variables[identity] = system.alloc_public(
            identity,
            int.from_bytes(
                bytes.fromhex(pairs[identity]["upstream_assignment_hex"]),
                "little",
            ),
        )
    for index in range(7821):
        identity = f"Aux({index})"
        variables[identity] = system.alloc_private(
            identity,
            int.from_bytes(
                bytes.fromhex(pairs[identity]["upstream_assignment_hex"]),
                "little",
            ),
        )

    def linear_combination(factor):
        return system.linear_combination(
            [
                (
                    variables[term["identity"]],
                    int.from_bytes(bytes.fromhex(term["coefficient_hex"]), "little"),
                )
                for term in factor["canonical_terms"]
            ]
        )

    for row in row_artifact["rows"]:
        factors = row["upstream_abc"]
        system.enforce(
            linear_combination(factors["a"]),
            linear_combination(factors["b"]),
            linear_combination(factors["c"]),
            row["upstream_label"],
        )
    return system


class SaplingParameterQueryMappingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.row_artifact = json.loads(
            (FIXTURES / "sapling_output_row_correspondence.json").read_text(
                encoding="utf-8"
            )
        )
        cls.variable_artifact = json.loads(
            (
                FIXTURES / "sapling_output_variable_correspondence.json"
            ).read_text(encoding="utf-8")
        )
        cls.spend_mapping = json.loads(
            (
                FIXTURES / "sapling_spend_parameter_query_index_mapping.json"
            ).read_text(encoding="utf-8")
        )
        cls.counts = {"a": 6298, "b_g1": 4850, "b_g2": 4850}
        cls.mapping = build_output_query_index_mapping(
            cls.row_artifact,
            cls.variable_artifact,
            cls.counts,
        )
        cls.output_mapping = json.loads(
            (
                FIXTURES / "sapling_output_parameter_query_index_mapping.json"
            ).read_text(encoding="utf-8")
        )

    def test_exact_output_support_maps_sparse_a_b_points(self):
        mapping = self.mapping
        self.assertEqual(len(mapping["a_query"]), 6298)
        self.assertEqual(len(mapping["b_g1_query"]), 4850)
        self.assertEqual(len(mapping["b_g2_query"]), 4850)
        self.assertEqual(
            [entry["query_index"] for entry in mapping["a_query"]],
            list(range(6298)),
        )
        self.assertEqual(
            [entry["query_index"] for entry in mapping["b_g1_query"]],
            list(range(4850)),
        )
        for section in ("a_query", "b_g1_query"):
            entries = mapping[section]
            identities = [entry["upstream_identity"] for entry in entries]
            columns = [entry["local_column"] for entry in entries]
            self.assertEqual(len(identities), len(set(identities)))
            self.assertEqual(len(columns), len(set(columns)))
        self.assertEqual(mapping["b_g1_query"], mapping["b_g2_query"])

    def test_dense_query_domains_are_not_misclassified_as_constraints(self):
        self.assertEqual(len(self.mapping["ic_query"]), 6)
        self.assertEqual(
            self.mapping["l_query"]["upstream_identity"],
            "Aux(query_index)",
        )
        self.assertEqual(
            self.mapping["h_query"]["semantic_role"],
            "QAP quotient coefficient degree",
        )
        self.assertIsNone(self.mapping["h_query"]["constraint_row_mapping"])

    def test_sparse_index_mapping_fingerprint_is_deterministic(self):
        regenerated = build_output_query_index_mapping(
            self.row_artifact,
            self.variable_artifact,
            self.counts,
        )
        self.assertEqual(regenerated, self.mapping)
        self.assertEqual(regenerated, self.output_mapping)
        self.assertEqual(
            self.mapping["mapping_fingerprint_sha256"],
            "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2",
        )

    def test_output_query_boundaries_and_subgroup_manifest_coverage(self):
        mapping = self.output_mapping
        identities = [f"Input({index})" for index in range(6)] + [
            f"Aux({index})" for index in range(7821)
        ]
        variable_pairs = sorted(
            self.variable_artifact["pairs"], key=lambda pair: pair["local_column"]
        )
        self.assertEqual(len(variable_pairs), 7827)
        self.assertEqual(
            [pair["upstream_identity"] for pair in variable_pairs], identities
        )
        self.assertEqual(
            [pair["local_column"] for pair in variable_pairs], list(range(7827))
        )
        for section, expected_count in (("a_query", 6298), ("b_g1_query", 4850)):
            entries = mapping[section]
            self.assertEqual(len(entries), expected_count)
            self.assertEqual(
                [entry["query_index"] for entry in entries],
                list(range(expected_count)),
            )
            self.assertEqual(
                [entry["upstream_identity"] for entry in entries],
                sorted(
                    (entry["upstream_identity"] for entry in entries),
                    key=lambda identity: (
                        0 if identity.startswith("Input(") else 1,
                        int(
                            identity[6:-1]
                            if identity.startswith("Input(")
                            else identity[4:-1]
                        ),
                    ),
                ),
            )
            for entry in entries:
                pair = variable_pairs[entry["local_column"]]
                self.assertEqual(pair["upstream_identity"], entry["upstream_identity"])
        self.assertEqual(
            mapping["a_query"][0],
            {
                "query_index": 0,
                "upstream_identity": "Input(0)",
                "local_column": 0,
            },
        )
        self.assertEqual(
            mapping["a_query"][-1],
            {
                "query_index": 6297,
                "upstream_identity": "Aux(7818)",
                "local_column": 7824,
            },
        )
        self.assertEqual(
            mapping["b_g1_query"][0],
            {
                "query_index": 0,
                "upstream_identity": "Input(0)",
                "local_column": 0,
            },
        )
        self.assertEqual(
            mapping["b_g1_query"][-1],
            {
                "query_index": 4849,
                "upstream_identity": "Aux(7820)",
                "local_column": 7826,
            },
        )
        self.assertEqual(mapping["b_g1_query"], mapping["b_g2_query"])
        self.assertEqual(
            mapping["ic_query"],
            [
                {
                    "query_index": index,
                    "upstream_identity": f"Input({index})",
                    "local_column": index,
                }
                for index in range(6)
            ],
        )
        self.assertEqual(
            mapping["l_query"],
            {
                "query_index_start": 0,
                "query_index_end_exclusive": 7821,
                "upstream_identity": "Aux(query_index)",
                "local_column": "6 + query_index",
            },
        )
        self.assertEqual(
            mapping["h_query"],
            {
                "query_index_start": 0,
                "query_index_end_exclusive": 8191,
                "semantic_role": "QAP quotient coefficient degree",
                "constraint_row_mapping": None,
            },
        )
        subgroup = json.loads(
            (ROOT / "reports" / "sapling-query-subgroup-validation.json").read_text(
                encoding="utf-8"
            )
        )
        output = subgroup["circuits"][OUTPUT]
        self.assertEqual(output["query_points_checked"], 32010)
        self.assertEqual(output["query_points_rejected"], 0)
        self.assertEqual(
            output["section_counts"],
            {"a": 6298, "b_g1": 4850, "b_g2": 4850, "h": 8191, "l": 7821},
        )
        for section, count in output["section_counts"].items():
            with self.subTest(section=section):
                self.assertEqual(
                    output["section_results"][section],
                    {"checked": count, "rejected": 0},
                )
        self.assertEqual(
            subgroup["validation_fingerprint_sha256"],
            "191e50613f303091c5fc4cfc88f45f36f1fe316b6fe12cd4c531671b6b349aa5",
        )

    def test_local_output_qap_matches_qap_rebuilt_from_pinned_rows(self):
        fixture = json.loads(
            (FIXTURES / "sapling_output_reference.json").read_text(encoding="utf-8")
        )["cases"][0]
        witness = make_sapling_output_witness(
            fixture["value"],
            bytes.fromhex(fixture["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(fixture["transmission_key"]), check_subgroup=True
            ),
            int.from_bytes(bytes.fromhex(fixture["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(fixture["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(fixture["esk"]), "little"),
        )
        local_system = R1CS()
        constrain_sapling_output(local_system, witness)
        upstream_system = _rebuild_upstream_output_system(
            self.row_artifact, self.variable_artifact
        )
        self.assertTrue(local_system.is_satisfied())
        self.assertTrue(upstream_system.is_satisfied())
        self.assertEqual(
            local_system.matrix_fingerprint(),
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertEqual(
            local_system.matrix_fingerprint(), upstream_system.matrix_fingerprint()
        )

        local_qap = QAP.from_r1cs(local_system)
        upstream_qap = QAP.from_r1cs(upstream_system)
        self.assertEqual(local_qap.domain.constraint_count, 7827)
        self.assertEqual(local_qap.domain.input_count, 6)
        self.assertEqual(local_qap.domain.row_count, 7833)
        self.assertEqual(local_qap.domain.padding_count, 359)
        self.assertEqual(local_qap.domain.size, 8192)
        self.assertEqual(local_qap.public_input_count, 5)
        self.assertEqual(local_qap.auxiliary_variable_count, 7821)
        self.assertEqual(
            local_qap.domain.fft_domain.omega,
            32731401973776920074999878620293785439674386180695720638377027142500196583783,
        )
        self.assertEqual(local_qap.domain.fft_domain.coset_generator, 7)
        local_assignment = _assigned_qap_input(local_system)
        upstream_assignment = _assigned_qap_input(upstream_system)
        self.assertEqual(local_assignment, upstream_assignment)
        self.assertEqual(
            local_qap.evaluations(local_assignment),
            upstream_qap.evaluations(upstream_assignment),
        )
        self.assertEqual(
            local_qap.polynomials(local_assignment),
            upstream_qap.polynomials(upstream_assignment),
        )
        local_h = local_qap.quotient(local_assignment)
        self.assertEqual(local_h, upstream_qap.quotient(upstream_assignment))
        self.assertEqual(len(local_h), 8191)
        self.assertEqual(
            hashlib.sha256(
                b"".join(
                    coefficient.to_bytes(32, "little") for coefficient in local_h
                )
            ).hexdigest(),
            "07df9be6c741c02bb72c8ea03e1a8852f4211bfaeed6e734d0813fc4ca3319ca",
        )

    def test_spend_sparse_indices_follow_semantic_variable_order(self):
        mapped = _spend_mapping_for_support(
            {"Aux(4)", "Input(0)", "Aux(1)"},
            {"Input(0)": 0, "Aux(1)": 9, "Aux(4)": 12},
            3,
            "Spend test",
        )
        self.assertEqual(
            mapped["upstream_variable_identities"],
            ["Input(0)", "Aux(1)", "Aux(4)"],
        )
        self.assertEqual(mapped["local_columns"], [0, 9, 12])

    def test_spend_unresolved_variable_has_no_fabricated_local_column(self):
        mapped = _spend_mapping_for_support(
            {"Aux(76805)"},
            {},
            1,
            "Spend test",
        )
        self.assertEqual(
            mapped["upstream_variable_identities"],
            ["Aux(76805)"],
        )
        self.assertEqual(mapped["local_columns"], [None])

    def test_spend_sparse_mapping_fails_closed_on_count_mismatch(self):
        with self.assertRaisesRegex(QueryMappingError, "structural support"):
            _spend_mapping_for_support(
                {"Input(0)", "Aux(0)"},
                {"Input(0)": 0, "Aux(0)": 8},
                1,
                "Spend test",
            )

    def test_spend_assignment_is_only_a_post_identity_consistency_check(self):
        pair = {
            "upstream_assignment": "8",
            "local_assignment": "8",
        }
        _validate_spend_assignment(pair, "Aux(2)", {"Aux(2)": 8})
        with self.assertRaisesRegex(QueryMappingError, "assignment consistency"):
            _validate_spend_assignment(pair, "Aux(2)", {"Aux(2)": 9})

    def test_spend_authentic_sparse_query_mapping_has_exact_coverage(self):
        sections = self.spend_mapping["query_sections"]
        counts = self.spend_mapping["counts"]
        self.assertEqual(len(sections["a"]["upstream_variable_identities"]), 85390)
        self.assertEqual(len(sections["b_g1"]["upstream_variable_identities"]), 61300)
        self.assertEqual(
            sections["b_g1"]["upstream_variable_identities"],
            sections["b_g2"]["upstream_variable_identities"],
        )
        self.assertEqual(
            sections["b_g1"]["local_columns"],
            sections["b_g2"]["local_columns"],
        )
        self.assertEqual(
            sum(column is None for column in sections["a"]["local_columns"]),
            1,
        )
        self.assertEqual(
            sum(column is None for column in sections["b_g1"]["local_columns"]),
            0,
        )
        self.assertEqual(
            sum(column is None for column in sections["l"]["local_columns"]),
            1,
        )
        unresolved_index = sections["a"]["upstream_variable_identities"].index(
            "Aux(76805)"
        )
        self.assertIsNone(sections["a"]["local_columns"][unresolved_index])
        self.assertEqual(counts["a_query_points"], 85390)
        self.assertEqual(counts["b_g1_query_points"], 61300)
        self.assertEqual(counts["b_g2_query_points"], 61300)

    def test_spend_mapping_fingerprint_and_order_are_deterministic(self):
        sections = self.spend_mapping["query_sections"]
        for name in ("a", "b_g1"):
            identities = sections[name]["upstream_variable_identities"]
            self.assertEqual(
                identities,
                sorted(
                    identities,
                    key=lambda identity: (
                        0 if identity.startswith("Input(") else 1,
                        int(
                            identity[6:-1]
                            if identity.startswith("Input(")
                            else identity[4:-1]
                        ),
                    ),
                ),
            )
        self.assertEqual(
            self.spend_mapping["mapping_fingerprint_sha256"],
            "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08",
        )
        fingerprint_payload = dict(self.spend_mapping)
        del fingerprint_payload["mapping_fingerprint_sha256"]
        canonical = json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(
                b"zycoin-sapling-spend-query-index-mapping-v1\0" + canonical
            ).hexdigest(),
            self.spend_mapping["mapping_fingerprint_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(
                (
                    FIXTURES
                    / "sapling_spend_parameter_query_index_mapping.json"
                ).read_bytes()
            ).hexdigest(),
            "dccf499fcdb7e6dfef6d850d4d60187b515dc32e5c3c8bfa2acb8c51e9a5cf23",
        )

    def test_rejects_mismatched_sparse_query_counts(self):
        with self.assertRaisesRegex(QueryMappingError, "structural support"):
            build_output_query_index_mapping(
                self.row_artifact,
                self.variable_artifact,
                {"a": 6297, "b_g1": 4850, "b_g2": 4850},
            )

    def test_rejects_duplicate_variable_identity(self):
        duplicated = copy.deepcopy(self.variable_artifact)
        duplicated["pairs"][1]["upstream_identity"] = (
            duplicated["pairs"][0]["upstream_identity"]
        )
        with self.assertRaisesRegex(QueryMappingError, "ambiguous"):
            build_output_query_index_mapping(
                self.row_artifact,
                duplicated,
                self.counts,
            )
