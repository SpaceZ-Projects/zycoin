import hashlib
import json
import unittest
from pathlib import Path

from src.jubjub import Point
from src.r1cs import R1CS
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness
from tests.sapling_output_correspondence import _canonical_json

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_PATH = (
    ROOT / "tests" / "fixtures" / "sapling_output_variable_correspondence.json"
)
WITNESS_PATH = ROOT / "tests" / "fixtures" / "sapling_output_reference.json"


class SaplingOutputCorrespondenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifact = json.loads(ARTIFACT_PATH.read_text(encoding="utf-8"))
        cls.fixture = json.loads(WITNESS_PATH.read_text(encoding="utf-8"))["cases"][0]

    def test_artifact_has_complete_one_to_one_variable_mapping(self):
        artifact = self.artifact
        self.assertEqual(
            artifact["format"],
            "zycoin-bellman-sapling-output-variable-correspondence-v1",
        )
        self.assertEqual(
            artifact["counts"],
            {
                "inputs_including_one": 6,
                "auxiliary_variables": 7821,
                "pairs": 7827,
                "unmatched_upstream": 0,
                "unmatched_local": 0,
                "ambiguous_upstream_keys": 0,
                "ambiguous_local_keys": 0,
                "assignment_mismatches": 0,
            },
        )
        pairs = artifact["pairs"]
        self.assertEqual(len(pairs), 7827)
        self.assertEqual(
            len({pair["upstream_identity"] for pair in pairs}), 7827
        )
        self.assertEqual(len({pair["local_identity"] for pair in pairs}), 7827)
        self.assertEqual(
            sum(pair["upstream_identity"].startswith("Input(") for pair in pairs),
            6,
        )
        self.assertEqual(
            sum(pair["upstream_identity"].startswith("Aux(") for pair in pairs),
            7821,
        )
        self.assertEqual(
            {pair["upstream_identity"] for pair in pairs if pair["upstream_identity"].startswith("Input(")},
            {f"Input({index})" for index in range(6)},
        )
        self.assertEqual(
            {pair["upstream_identity"] for pair in pairs if pair["upstream_identity"].startswith("Aux(")},
            {f"Aux({index})" for index in range(7821)},
        )
        self.assertEqual(
            artifact["pinned_upstream"]["export_sha256"],
            "ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe",
        )
        self.assertEqual(
            artifact["mapping_fingerprint_sha256"],
            "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc",
        )
        self.assertEqual(
            artifact["assignment_pairs_fingerprint_sha256"],
            "23a8c322d16b8b717ae877dabe44283973d1b6f36ae10fcaa358dd8d22ed0719",
        )
        self.assertEqual(
            hashlib.sha256(ARTIFACT_PATH.read_bytes()).hexdigest(),
            "3c9ce93d3bbaed16488492ea58017846b997378fceed70d7e145a1328430d113",
        )
        for pair in pairs:
            upstream_column = (
                int(pair["upstream_identity"][4:-1]) + 6
                if pair["upstream_identity"].startswith("Aux(")
                else int(pair["upstream_identity"][6:-1])
            )
            self.assertEqual(pair["local_column"], upstream_column)
            self.assertEqual(pair["local_identity"], pair["upstream_identity"])

    def test_local_output_assignments_match_every_semantic_pair(self):
        fixture = self.fixture
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
        system = R1CS()
        constrain_sapling_output(system, witness)

        self.assertTrue(system.is_satisfied())
        self.assertEqual(system.constraint_count, 7827)
        self.assertEqual(len(system.variables), 7827)
        for pair in self.artifact["pairs"]:
            variable = system.variables[pair["local_column"]]
            self.assertEqual(pair["local_identity"], (
                "Input(0)"
                if variable.index == 0
                else f"Input({variable.index})"
                if variable.kind == "public"
                else f"Aux({variable.index - 6})"
            ))
            self.assertEqual(pair["local_name"], variable.name)
            self.assertEqual(
                pair["upstream_assignment_hex"],
                pair["local_assignment_hex"],
            )
            self.assertEqual(
                int.from_bytes(bytes.fromhex(pair["local_assignment_hex"]), "little"),
                system._values[variable.index],
            )

    def test_correspondence_fingerprints_are_deterministic(self):
        artifact = self.artifact
        pairs = artifact["pairs"]
        mapping_payload = [
            [
                pair["upstream_identity"],
                pair["local_identity"],
                pair["semantic_key"],
            ]
            for pair in pairs
        ]
        assignment_payload = [
            [
                pair["upstream_identity"],
                pair["upstream_assignment_hex"],
                pair["local_identity"],
                pair["local_assignment_hex"],
            ]
            for pair in pairs
        ]
        self.assertEqual(
            artifact["mapping_fingerprint_sha256"],
            hashlib.sha256(
                b"zycoin-bellman-output-variable-mapping-v1\0"
                + _canonical_json(mapping_payload)
            ).hexdigest(),
        )
        self.assertEqual(
            artifact["assignment_pairs_fingerprint_sha256"],
            hashlib.sha256(
                b"zycoin-bellman-output-assignment-pairs-v1\0"
                + _canonical_json(assignment_payload)
            ).hexdigest(),
        )
        payload = dict(artifact)
        expected_artifact_hash = payload.pop("artifact_sha256")
        self.assertEqual(
            expected_artifact_hash,
            hashlib.sha256(
                b"zycoin-bellman-output-correspondence-artifact-v1\0"
                + _canonical_json(payload)
            ).hexdigest(),
        )
        self.assertEqual(
            expected_artifact_hash,
            "f371f44e88340c91a40227fcdac22d3826a1cf09a710c22aa95ee6cb70ba8998",
        )
