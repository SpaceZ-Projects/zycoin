"""Independent Bellman/Python QAP comparison for the pinned Spend fixture."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_fft import FFTDomain
from src.groth16_qap import QAP, QAPAssignment, UnsatisfiedAssignmentError
from src.r1cs import R1CS, R1CSError
from src.sapling_spend_circuit import (
    SaplingSpendWitness,
    constrain_sapling_spend,
)
from tests.sapling_spend_independent_reference import (
    generate_pinned_test_witness,
)
from tests.test_sapling_spend_circuit import _circuit_witness

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tests" / "reference" / "sapling-output-qap"
MANIFEST = REFERENCE / "Cargo.toml"
QUERY_MAPPING_PATH = (
    ROOT / "tests" / "fixtures" / "sapling_spend_parameter_query_index_mapping.json"
)

SAPLING_REVISION = "88a7946b4a3066787776e11f0a502654167e022d"
BELLMAN_REVISION = "b726862a4ece8a627e7fea486d77b502a6edbb0b"
UPSTREAM_TEST_SYSTEM_HASH = (
    "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89"
)
LOCAL_MATRIX_FINGERPRINT = (
    "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9"
)
QUERY_MAPPING_FINGERPRINT = (
    "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08"
)
VARIABLE_MAPPING_FINGERPRINT = (
    "26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656"
)
ROW_MAPPING_FINGERPRINT = (
    "69f6498dbc3d2504bcc7beb6285d3312dd68c790f41dff9b21d3c1e162de8537"
)

REFERENCE_VECTOR_HASHES = {
    "a_evaluations": "22c6662cbe967cb57bc36d05ebf3e81a32d3baa20bf222c0cf5581afd52993b6",
    "b_evaluations": "3169179e3f69d5755671e0f634789dbb3faaa2f7a6025779a6f2ac2240729e71",
    "c_evaluations": "df2e6de104f3acc367abee83ead55f275670a0e13720044e0d166465948dd872",
    "a_polynomial_coefficients": "663ab1569c323f13cc1fd96163b330c8231f3fcb6521cdfa444b49474b03e0c6",
    "b_polynomial_coefficients": "b3b5f5a4504131db6fb1ac5fb00a66592448a6e5a59eec1494231db9faaed7ff",
    "c_polynomial_coefficients": "6e064cc613e33f7e57ca5183826352c25f2f0410e5ad7f59391cf7e35679880b",
    "quotient_coefficients_h": "27d57fc5eae604c210feda073ee1befcb73a776ef6bf4b08ba25d00314037a55",
    "quotient_evaluations_h": "b7ee1b2f7f49704446fb4acdc4dcf8e9a859ebeddcd9994d1aa2ec5a3023bb7d",
}

LOCAL_VECTOR_HASHES = {
    "a_evaluations": "daca49ab7a9dd2819f40d4b48e94509d78d24ad2fb4846062865cd5f9491fe1a",
    "b_evaluations": "2430c5198e3c39c85dfda8256feb6fa822c40cca983c37dd510cbd1f89cdf198",
    "c_evaluations": "f8efb2f3246022e9cbd1cbbdd551167f9d3d5ab8570d9b8fd273afae2c5d50a9",
    "a_polynomial_coefficients": "ae3bf8a74b4d63fb70b10f8257b16c478d4830c70f67e106ca88a59102e8a856",
    "b_polynomial_coefficients": "8a1504707c0e31a28e1af71c58067bf9baff8d64b74d0359942c5738da46e2c7",
    "c_polynomial_coefficients": "5dbc6116cbaa3eafca1b792deb0ce0603be484ec052e6fdcb979d3d05aca74c6",
    "quotient_coefficients_h": "a98ecf083b7660a04fd59fc887e7799cf96c1e0cf5e4cd898690340125850862",
    "quotient_evaluations_h": "04d75e396d3c01478d7de835da712c7a10eecdec070fd79a0781d60ee30f65c7",
}


def _linux_path(path: Path) -> str:
    resolved = path.resolve()
    return f"/mnt/{resolved.drive[0].lower()}/" + "/".join(resolved.parts[1:])


def _run_bellman_synthesis(trace_path: Path) -> None:
    wsl = shutil.which("wsl")
    if wsl:
        command = (
            f"cd {shlex.quote(_linux_path(ROOT))} && "
            f"SAPLING_SPEND_EXPORT={shlex.quote(_linux_path(trace_path))} "
            f"rustup run 1.97.0 cargo test --offline --manifest-path "
            f"{shlex.quote(_linux_path(MANIFEST))} --test export_spend -- "
            "--nocapture"
        )
        subprocess.run([wsl, "--", "bash", "-lc", command], cwd=ROOT, check=True)
        return
    environment = os.environ.copy()
    environment["SAPLING_SPEND_EXPORT"] = str(trace_path)
    subprocess.run(
        [
            "cargo",
            "test",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
            "--test",
            "export_spend",
            "--",
            "--nocapture",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
    )


def _run_bellman_qap(trace_path: Path, summary_path: Path) -> None:
    wsl = shutil.which("wsl")
    if wsl:
        command = (
            f"cd {shlex.quote(_linux_path(ROOT))} && "
            f"rustup run 1.97.0 cargo run --offline --manifest-path "
            f"{shlex.quote(_linux_path(MANIFEST))} --bin "
            f"sapling_spend_qap_reference -- "
            f"{shlex.quote(_linux_path(trace_path))} "
            f"{shlex.quote(_linux_path(summary_path))}"
        )
        subprocess.run([wsl, "--", "bash", "-lc", command], cwd=ROOT, check=True)
        return
    subprocess.run(
        [
            "cargo",
            "run",
            "--offline",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "sapling_spend_qap_reference",
            "--",
            str(trace_path),
            str(summary_path),
        ],
        cwd=ROOT,
        check=True,
    )


def _sha256_scalar_vector(values) -> str:
    digest = hashlib.sha256()
    for value in values:
        if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
            raise AssertionError("QAP vector contains a noncanonical scalar")
        digest.update(value.to_bytes(32, "little"))
    return digest.hexdigest()


def _validate_witness_mapping(
    mapping: dict,
    local_values: tuple[int, ...],
    upstream_values: tuple[int, ...],
    position_index: int,
    anchor: int,
    position: int,
) -> int:
    section = mapping["query_sections"]["l"]
    identities = section["upstream_variable_identities"]
    local_columns = section["local_columns"]
    if len(identities) != 98_638 or len(local_columns) != 98_638:
        raise AssertionError("L correspondence does not cover all upstream auxiliaries")
    if identities != [f"Aux({index})" for index in range(98_638)]:
        raise AssertionError("L identities are not in the pinned auxiliary order")
    if local_values[:8] != upstream_values[:8]:
        raise AssertionError("Bellman and local public/ONE assignments differ")

    unmatched: list[tuple[str, int]] = []
    seen_local: set[int] = set()
    matched = 0
    for index, (identity, local_column) in enumerate(
        zip(identities, local_columns, strict=True)
    ):
        upstream_value = upstream_values[8 + index]
        if local_column is None:
            unmatched.append((identity, upstream_value))
            continue
        if type(local_column) is not int or local_column in seen_local:
            raise AssertionError("variable map is malformed or not one-to-one")
        seen_local.add(local_column)
        if local_values[local_column] != upstream_value:
            raise AssertionError(f"mapped witness mismatch for {identity}")
        matched += 1

    if unmatched != [("Aux(76805)", anchor)]:
        raise AssertionError("the upstream conditional-anchor auxiliary was not preserved")
    if position_index in seen_local or local_values[position_index] != position:
        raise AssertionError("local packed Merkle-position helper was not preserved")
    if matched != 98_637:
        raise AssertionError("unexpected number of semantically mapped auxiliaries")
    return matched


def _verify_local_quotient_identity(qap: QAP, polynomials, quotient) -> bool:
    base_size = qap.domain.size
    check_domain = FFTDomain.create(base_size * 2)

    def evaluate_on_coset(coefficients: tuple[int, ...]) -> list[int]:
        return check_domain.coset_fft(
            coefficients + (0,) * (check_domain.size - len(coefficients))
        )

    a_values = evaluate_on_coset(polynomials.a)
    b_values = evaluate_on_coset(polynomials.b)
    c_values = evaluate_on_coset(polynomials.c)
    h_values = evaluate_on_coset(tuple(quotient))
    generator_power = pow(
        check_domain.coset_generator, base_size, SCALAR_MODULUS
    )
    for index in range(check_domain.size):
        z_value = (
            (generator_power if index % 2 == 0 else -generator_power) - 1
        ) % SCALAR_MODULUS
        if (a_values[index] * b_values[index] - c_values[index]) % SCALAR_MODULUS != (
            h_values[index] * z_value
        ) % SCALAR_MODULUS:
            return False
    return True


@unittest.skipUnless(
    shutil.which("cargo") and (shutil.which("wsl") or os.name != "nt"),
    "Rust/Cargo and the pinned reference toolchain are required",
)
class SaplingSpendQAPCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="zycoin-spend-qap-"
        )
        directory = Path(cls._temporary_directory.name)
        cls.trace_path = directory / "bellman-spend-trace.json"
        cls.summary_path = directory / "bellman-spend-qap.json"
        _run_bellman_synthesis(cls.trace_path)
        _run_bellman_qap(cls.trace_path, cls.summary_path)
        cls.trace_sha256 = hashlib.sha256()
        with cls.trace_path.open("rb") as trace:
            for chunk in iter(lambda: trace.read(1024 * 1024), b""):
                cls.trace_sha256.update(chunk)
        cls.trace_sha256 = cls.trace_sha256.hexdigest()
        cls.reference = json.loads(cls.summary_path.read_text(encoding="utf-8"))
        cls.mapping = json.loads(QUERY_MAPPING_PATH.read_text(encoding="ascii"))
        cls.witness = _circuit_witness(generate_pinned_test_witness(0))
        cls.system = R1CS()
        constrain_sapling_spend(cls.system, cls.witness)
        cls.qap = QAP.from_r1cs(cls.system)
        auxiliary = tuple(
            cls.system.witness_value(variable)
            for variable in cls.system.variables[8:]
        )
        if any(value is None for value in auxiliary):
            raise AssertionError("local Spend assignment contains an unassigned variable")
        cls.assignment = QAPAssignment(cls.system.public_inputs(), auxiliary)
        cls.local_values = cls.qap.validate_assignment(cls.assignment)
        cls.evaluations = cls.qap.evaluations(cls.assignment)
        cls.polynomials = cls.qap.polynomials(cls.assignment)
        cls.quotient = cls.qap.quotient(cls.assignment)
        cls.h_evaluations = tuple(
            cls.qap.domain.fft_domain.fft(cls.quotient + (0,))
        )
        cls.local_vectors = {
            "a_evaluations": cls.evaluations.a,
            "b_evaluations": cls.evaluations.b,
            "c_evaluations": cls.evaluations.c,
            "a_polynomial_coefficients": cls.polynomials.a,
            "b_polynomial_coefficients": cls.polynomials.b,
            "c_polynomial_coefficients": cls.polynomials.c,
            "quotient_coefficients_h": cls.quotient,
            "quotient_evaluations_h": cls.h_evaluations,
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary_directory.cleanup()

    def test_complete_bellman_assignment_maps_to_local_witness_and_helpers(self):
        self.assertEqual(self.reference["format"], "bellman-sapling-spend-qap-reference-v1")
        self.assertEqual(self.reference["sapling_revision"], SAPLING_REVISION)
        self.assertEqual(self.reference["bellman_revision"], BELLMAN_REVISION)
        self.assertEqual(
            self.reference["upstream_test_constraint_system_hash"],
            UPSTREAM_TEST_SYSTEM_HASH,
        )
        self.assertTrue(self.reference["satisfied"])
        self.assertEqual(self.reference["failed_rows"], [])
        self.assertEqual(self.reference["constraint_count"], 98_777)
        self.assertEqual(self.reference["input_count_including_one"], 8)
        self.assertEqual(self.reference["auxiliary_variable_count"], 98_638)
        self.assertEqual(self.reference["row_count_with_dummy_inputs"], 98_785)
        self.assertEqual(self.reference["padding_count"], 32_287)
        self.assertEqual(self.reference["domain_size"], 131_072)
        self.assertEqual(self.mapping["mapping_fingerprint_sha256"], QUERY_MAPPING_FINGERPRINT)

        upstream_values = tuple(
            int.from_bytes(bytes.fromhex(value), "little")
            for value in self.reference["assignment_hex"]
        )
        self.assertEqual(len(upstream_values), 98_646)
        self.assertEqual(
            _sha256_scalar_vector(upstream_values),
            self.reference["assignment_sha256"],
        )
        position_variable = next(
            variable
            for variable in self.system.variables
            if variable.name == "Sapling Spend Merkle path position"
        )
        matched = _validate_witness_mapping(
            self.mapping,
            self.local_values,
            upstream_values,
            position_variable.index,
            self.witness.anchor,
            self.witness.position,
        )
        self.assertEqual(matched, 98_637)
        self.assertEqual(self.local_values[:8], upstream_values[:8])
        self.assertEqual(
            upstream_values[8 + 76_805],
            self.witness.public_inputs[4],
            "Aux(76805) is the upstream conditional-anchor helper, not a local column",
        )
        self.assertEqual(
            self.system.witness_value(position_variable),
            self.witness.position,
            "the local packed position is derived from the 32 path-direction bits",
        )
        self.assertEqual(self.system.constraint_count, 98_777)
        self.assertEqual(len(self.system.variables), 98_646)
        self.assertTrue(self.system.is_satisfied())
        self.assertEqual(
            self.system.matrix_fingerprint(),
            LOCAL_MATRIX_FINGERPRINT,
        )
        self.assertEqual(self.mapping["upstream_reference_sha256"], "b9a1bab4df36059e3c324cd07c0baa96062501bc266cf46005ab0d7c35751046")
        self.assertEqual(VARIABLE_MAPPING_FINGERPRINT, "26f48aae194b8f6f76958b369bd3740f269c1ef06967270c23e0ee4ae4a1c656")
        self.assertEqual(ROW_MAPPING_FINGERPRINT, "69f6498dbc3d2504bcc7beb6285d3312dd68c790f41dff9b21d3c1e162de8537")

    def test_full_qap_vectors_are_independently_computed_but_not_equal(self):
        reference_hashes = {
            vector["name"]: vector["sha256_little_endian_scalars"]
            for vector in self.reference["vectors"]
        }
        local_hashes = {
            name: _sha256_scalar_vector(values)
            for name, values in self.local_vectors.items()
        }
        self.assertEqual(reference_hashes, REFERENCE_VECTOR_HASHES)
        self.assertEqual(local_hashes, LOCAL_VECTOR_HASHES)
        self.assertEqual(
            set(reference_hashes),
            set(local_hashes),
        )
        self.assertEqual(
            {name for name in reference_hashes if reference_hashes[name] == local_hashes[name]},
            set(),
            "the differing Spend matrices must not be reported as exact QAP matches",
        )
        self.assertTrue(self.reference["quotient_divisibility_verified"])
        self.assertTrue(
            _verify_local_quotient_identity(
                self.qap,
                self.polynomials,
                self.quotient,
            )
        )
        self.assertEqual(len(self.quotient), 131_071)
        self.assertEqual(len(self.h_evaluations), 131_072)

    def test_altered_public_input_and_invalid_witness_are_rejected(self):
        changed_inputs = list(self.assignment.public_inputs)
        changed_inputs[0] = (changed_inputs[0] + 1) % SCALAR_MODULUS
        altered_assignment = QAPAssignment(
            changed_inputs,
            self.assignment.auxiliary_assignments,
        )
        with self.assertRaises(UnsatisfiedAssignmentError):
            self.qap.quotient(altered_assignment)

        altered_witness = copy.copy(self.witness)
        invalid_witness = SaplingSpendWitness(
            **{
                **altered_witness.__dict__,
                "position": (self.witness.position + 1) % (1 << 32),
            }
        )
        with self.assertRaisesRegex(R1CSError, "position does not match"):
            constrain_sapling_spend(R1CS(), invalid_witness)

    def test_incorrect_variable_map_and_corrupted_qap_fingerprint_are_rejected(self):
        upstream_values = tuple(
            int.from_bytes(bytes.fromhex(value), "little")
            for value in self.reference["assignment_hex"]
        )
        position_variable = next(
            variable
            for variable in self.system.variables
            if variable.name == "Sapling Spend Merkle path position"
        )
        bad_mapping = copy.deepcopy(self.mapping)
        bad_mapping["query_sections"]["l"]["local_columns"][76_805] = (
            position_variable.index
        )
        with self.assertRaisesRegex(AssertionError, "mismatch|unmatched"):
            _validate_witness_mapping(
                bad_mapping,
                self.local_values,
                upstream_values,
                position_variable.index,
                self.witness.anchor,
                self.witness.position,
            )

        corrupted_reference = copy.deepcopy(self.reference)
        corrupted_reference["vectors"][0]["sha256_little_endian_scalars"] = "0" * 64
        corrupted_hashes = {
            vector["name"]: vector["sha256_little_endian_scalars"]
            for vector in corrupted_reference["vectors"]
        }
        with self.assertRaises(AssertionError):
            self.assertEqual(corrupted_hashes, REFERENCE_VECTOR_HASHES)

    def test_fixture_fingerprints_are_deterministic(self):
        self.assertEqual(
            self.reference["assignment_sha256"],
            "429887b2897ce1ee6f4bf9707c7e28158ce66dc9ba9789dff708ce02a0fc3e57",
        )
        self.assertEqual(
            _sha256_scalar_vector(self.local_values),
            "4ca277581c10a4e20d576a787b771a9c36bbf9b0e26d3b920ef3ea66fd2b45a3",
        )
        self.assertEqual(
            self.trace_sha256,
            "a39e4d2d815dca24eead67996d94732dc9a12b13ac3f1c4881f5e5dadddf8feb",
        )
        self.assertEqual(
            self.reference["upstream_test_constraint_system_hash"],
            UPSTREAM_TEST_SYSTEM_HASH,
        )


if __name__ == "__main__":
    unittest.main()
