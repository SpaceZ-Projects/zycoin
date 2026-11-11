"""Tests for the production Sapling Output proving API."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import sapling_output_proof as api
from src.bls12_381 import G1_GENERATOR, SCALAR_MODULUS, add_g1, decode_g1, encode_g1
from src.groth16_qap import QAP, UnsatisfiedAssignmentError
from src.jubjub import Point
from src.sapling_gadgets import make_sapling_output_witness
from src.sapling_output_proof import (
    SAPLING_OUTPUT_PUBLIC_INPUT_ORDER,
    SAPLING_OUTPUT_QUERY_MAPPING_FINGERPRINT,
    SaplingOutputParameterError,
    SaplingOutputParameters,
    SaplingOutputProofError,
    load_sapling_output_parameters,
    prove_sapling_output,
    verify_sapling_output_proof,
)
from tests.benchmark_sapling_output_proving import (
    ASSIGNMENT_SHA256,
    MATRIX_FINGERPRINT,
    _witness_and_qap,
)

ROOT = Path(__file__).resolve().parents[1]
PARAMETER_PATH = Path(
    os.environ.get(
        "ZYCOIN_SAPLING_OUTPUT_PARAMS",
        Path.home() / "AppData" / "Roaming" / "ZcashParams" / "sapling-output.params",
    )
)


def _witness():
    case = json.loads(
        (ROOT / "tests" / "fixtures" / "sapling_output_reference.json").read_text(
            encoding="ascii"
        )
    )["cases"][0]
    return make_sapling_output_witness(
        case["value"],
        bytes.fromhex(case["diversifier"]),
        Point.from_bytes(bytes.fromhex(case["transmission_key"]), check_subgroup=True),
        int.from_bytes(bytes.fromhex(case["rcv"]), "little"),
        int.from_bytes(bytes.fromhex(case["rcm"]), "little"),
        int.from_bytes(bytes.fromhex(case["esk"]), "little"),
    )


def _public_inputs(witness) -> dict[str, bytes]:
    values = (
        witness.value_commitment.commitment.u,
        witness.value_commitment.commitment.v,
        witness.ephemeral_key.ephemeral_key.u,
        witness.ephemeral_key.ephemeral_key.v,
        witness.note_commitment.commitment.u,
    )
    return {
        name: value.to_bytes(32, "little")
        for name, value in zip(SAPLING_OUTPUT_PUBLIC_INPUT_ORDER, values)
    }


class SaplingOutputProductionApiUnitTests(unittest.TestCase):
    def test_embedded_sparse_supports_match_the_verified_mapping(self):
        mapping = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "sapling_output_parameter_query_index_mapping.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(
            mapping["mapping_fingerprint_sha256"],
            SAPLING_OUTPUT_QUERY_MAPPING_FINGERPRINT,
        )
        for name, mask_name in (
            ("a_query", "_A_SUPPORT_MASK"),
            ("b_g1_query", "_B_SUPPORT_MASK"),
            ("b_g2_query", "_B_SUPPORT_MASK"),
        ):
            expected = bytearray((7_827 + 7) // 8)
            for query_index, entry in enumerate(mapping[name]):
                self.assertEqual(entry["query_index"], query_index)
                column = entry["local_column"]
                expected[column // 8] |= 1 << (column % 8)
            self.assertEqual(bytes(expected), getattr(api, mask_name))

    def test_invalid_parameter_file_and_unissued_parameter_object_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            short_file = Path(directory) / "not-parameters.bin"
            short_file.write_bytes(b"bad")
            with self.assertRaises(SaplingOutputParameterError):
                load_sapling_output_parameters(short_file)
        with self.assertRaises(TypeError):
            SaplingOutputParameters()
        with self.assertRaises(TypeError):
            SaplingOutputParameters(None, None, "0" * 64)

    def test_api_rejects_parameter_objects_of_the_wrong_type(self):
        with self.assertRaises(TypeError):
            prove_sapling_output(None, object())
        with self.assertRaises(TypeError):
            verify_sapling_output_proof(b"", {}, object())

    def test_api_rejects_uninitialized_parameter_object(self):
        parameters = object.__new__(SaplingOutputParameters)
        with self.assertRaises(TypeError):
            prove_sapling_output(None, parameters)
        with self.assertRaises(TypeError):
            verify_sapling_output_proof(b"", {}, parameters)

    def test_api_does_not_expose_a_randomness_override(self):
        import inspect

        self.assertEqual(
            tuple(inspect.signature(prove_sapling_output).parameters),
            ("witness", "parameters"),
        )

    def test_parameter_pin_rejects_other_digest_even_with_matching_layout(self):
        manifest = SimpleNamespace(
            structurally_validated=True,
            format_version="bellman-0.15.0",
            sha256="0" * 64,
            blake2b512=api.SAPLING_OUTPUT_PARAMETER_BLAKE2B512,
            trailing_bytes=52_836,
            section_counts=tuple(api._expected_section_counts().items()),
        )
        with self.assertRaises(SaplingOutputParameterError):
            api._validate_parameter_manifest(manifest)


@unittest.skipUnless(PARAMETER_PATH.is_file(), "official Output parameters not supplied")
class SaplingOutputProductionApiAuthenticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parameters = load_sapling_output_parameters(PARAMETER_PATH)
        cls.witness = _witness()
        cls.public_inputs = _public_inputs(cls.witness)

    def test_secure_random_proofs_verify_and_interoperate_with_bellman(self):
        original_randbelow = secrets.randbelow
        random_draws: list[int] = []

        def secure_draw(upper_bound: int) -> int:
            value = original_randbelow(upper_bound)
            random_draws.append(value)
            return value

        with patch.object(api.secrets, "randbelow", side_effect=secure_draw):
            first = prove_sapling_output(self.witness, self.parameters)
            second = prove_sapling_output(self.witness, self.parameters)

        self.assertEqual(len(random_draws), 4)
        self.assertTrue(
            all(0 <= value < SCALAR_MODULUS for value in random_draws)
        )
        self.assertNotEqual(first, second)
        self.assertTrue(
            verify_sapling_output_proof(first, self.public_inputs, self.parameters)
        )
        self.assertTrue(
            verify_sapling_output_proof(second, self.public_inputs, self.parameters)
        )

        altered_inputs = dict(self.public_inputs)
        altered_value = (
            int.from_bytes(altered_inputs["cv.u"], "little") + 1
        ) % SCALAR_MODULUS
        altered_inputs["cv.u"] = altered_value.to_bytes(32, "little")
        reordered_values = dict(self.public_inputs)
        reordered_values["cv.u"], reordered_values["cv.v"] = (
            reordered_values["cv.v"],
            reordered_values["cv.u"],
        )
        altered_proof = (
            encode_g1(add_g1(decode_g1(first[:48]), G1_GENERATOR))
            + first[48:]
        )
        self.assertFalse(
            verify_sapling_output_proof(
                altered_proof, self.public_inputs, self.parameters
            )
        )
        with self.assertRaises(SaplingOutputProofError):
            verify_sapling_output_proof(first[:-1], self.public_inputs, self.parameters)
        with self.assertRaises(SaplingOutputProofError):
            verify_sapling_output_proof(
                first, {**self.public_inputs, "extra": b"\x00" * 32}, self.parameters
            )
        with self.assertRaises(SaplingOutputProofError):
            verify_sapling_output_proof(
                first, {**self.public_inputs, "cv.u": b"\xff" * 32}, self.parameters
            )
        self.assertFalse(
            verify_sapling_output_proof(first, altered_inputs, self.parameters)
        )
        self.assertFalse(
            verify_sapling_output_proof(first, reordered_values, self.parameters)
        )
        with self.assertRaises(SaplingOutputProofError):
            verify_sapling_output_proof(
                b"\x00" * 192, self.public_inputs, self.parameters
            )

        self._verify_both_with_bellman(
            first, second, altered_inputs, altered_proof
        )

    def test_parameter_objects_cannot_be_reconfigured_with_dataclass_replace(self):
        with self.assertRaises(TypeError):
            replace(self.parameters, parameter_sha256="0" * 64)

        altered_key = replace(
            self.parameters._verification_key,
            alpha_g1=G1_GENERATOR,
        )
        with self.assertRaises(TypeError):
            replace(self.parameters, _verification_key=altered_key)

        tampered = object.__new__(SaplingOutputParameters)
        object.__setattr__(tampered, "_queries", self.parameters._queries)
        object.__setattr__(tampered, "_verification_key", altered_key)
        object.__setattr__(tampered, "parameter_sha256", self.parameters.parameter_sha256)
        object.__setattr__(tampered, "_seal", self.parameters._seal)
        with self.assertRaises(TypeError):
            prove_sapling_output(self.witness, tampered)
        with self.assertRaises(TypeError):
            verify_sapling_output_proof(b"", {}, tampered)

        altered_queries = replace(
            self.parameters._queries,
            h_query=replace(
                self.parameters._queries.h_query,
                points=self.parameters._queries.h_query.points[:-1],
            ),
        )
        with self.assertRaises(TypeError):
            replace(self.parameters, _queries=altered_queries)

    def test_same_size_modified_official_parameter_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            tampered_path = Path(directory) / "tampered-output.params"
            shutil.copyfile(PARAMETER_PATH, tampered_path)
            with tampered_path.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                last_byte = stream.read(1)
                stream.seek(-1, os.SEEK_END)
                stream.write(bytes((last_byte[0] ^ 1,)))

            self.assertEqual(
                tampered_path.stat().st_size,
                api.SAPLING_OUTPUT_PARAMETER_BYTES,
            )
            with self.assertRaises(SaplingOutputParameterError):
                load_sapling_output_parameters(tampered_path)

    def test_unsatisfied_or_inconsistent_witness_is_rejected(self):
        invalid = replace(self.witness, esk=(self.witness.esk + 1) % (1 << 250))
        with patch.object(api.secrets, "randbelow", side_effect=AssertionError):
            with self.assertRaises(SaplingOutputProofError):
                prove_sapling_output(invalid, self.parameters)
            with patch.object(
                QAP,
                "validate_assignment",
                side_effect=UnsatisfiedAssignmentError("test-only unsatisfied QAP"),
            ), self.assertRaises(SaplingOutputProofError):
                prove_sapling_output(self.witness, self.parameters)

    def _verify_both_with_bellman(
        self,
        first: bytes,
        second: bytes,
        altered_inputs: dict[str, bytes],
        altered_proof: bytes,
    ) -> None:
        from tests.generate_verify_sapling_output_python_proof import (
            _verify_with_bellman,
        )

        system, _, assignment, _ = _witness_and_qap()
        self.assertEqual(system.matrix_fingerprint(), MATRIX_FINGERPRINT)
        values = (1, *assignment.public_inputs, *assignment.auxiliary_assignments)
        encoded_values = [
            value.to_bytes(32, "little").hex()
            for value in values
        ]
        assignment_sha256 = hashlib.sha256(
            b"".join(value.to_bytes(32, "little") for value in values)
        ).hexdigest()
        self.assertEqual(assignment_sha256, ASSIGNMENT_SHA256)

        public_hex = [
            self.public_inputs[name].hex()
            for name in SAPLING_OUTPUT_PUBLIC_INPUT_ORDER
        ]
        altered_hex = [
            altered_inputs[name].hex()
            for name in SAPLING_OUTPUT_PUBLIC_INPUT_ORDER
        ]
        reordered = list(public_hex)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        cases = [
            {
                "name": label,
                "proof_hex": proof.hex(),
                "public_inputs_hex": public_hex,
            }
            for label, proof in (("valid", first), ("valid-second", second))
        ]
        cases.extend(
            (
                {
                    "name": "altered-public-input",
                    "proof_hex": first.hex(),
                    "public_inputs_hex": altered_hex,
                },
                {
                    "name": "reordered-public-inputs",
                    "proof_hex": first.hex(),
                    "public_inputs_hex": reordered,
                },
                {
                    "name": "altered-proof-point",
                    "proof_hex": altered_proof.hex(),
                    "public_inputs_hex": public_hex,
                },
                {
                    "name": "malformed-proof",
                    "proof_hex": (first[:-1]).hex(),
                    "public_inputs_hex": public_hex,
                },
            )
        )

        temporary = tempfile.TemporaryDirectory(prefix="zycoin-output-api-bellman-")
        try:
            work = Path(temporary.name)
            assignment_path = work / "assignment.json"
            cases_path = work / "cases.json"
            result_path = work / "result.json"
            assignment_path.write_text(
                json.dumps(
                    {
                        "format": "zycoin-sapling-output-qap-assignment-input-v1",
                        "row_artifact_sha256": (
                            "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761"
                        ),
                        "variable_mapping_fingerprint_sha256": (
                            "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
                        ),
                        "matrix_fingerprint": MATRIX_FINGERPRINT,
                        "cases": [
                            {
                                "name": "zcash-note-encryption-vector-0",
                                "assignment_sha256": assignment_sha256,
                                "assignment_hex": encoded_values,
                            }
                        ],
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="ascii",
            )
            cases_path.write_text(
                json.dumps(
                    {
                        "format": "zycoin-python-output-proof-cases-v1",
                        "public_input_order": list(SAPLING_OUTPUT_PUBLIC_INPUT_ORDER),
                        "cases": cases,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="ascii",
            )
            result, _, _ = _verify_with_bellman(
                PARAMETER_PATH,
                assignment_path,
                cases_path,
                result_path,
            )
            results = {case["name"]: case for case in result["results"]}
            self.assertTrue(results["valid"]["accepted"])
            self.assertTrue(results["valid-second"]["accepted"])
            self.assertFalse(results["altered-public-input"]["accepted"])
            self.assertFalse(results["reordered-public-inputs"]["accepted"])
            self.assertFalse(results["malformed-proof"]["accepted"])
            self.assertTrue(result["witness_validation"]["satisfied"])
            self.assertEqual(
                result["witness_validation"]["constraints_checked"], 7_827
            )
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
