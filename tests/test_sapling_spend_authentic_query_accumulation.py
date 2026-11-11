"""Full-vector official Spend query accumulation against Bellman 0.15."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src.bls12_381 import (
    SCALAR_MODULUS,
    encode_g1_uncompressed,
    encode_g2_uncompressed,
    multi_scalar_multiply_g1,
    multi_scalar_multiply_g2,
)
from src.groth16_parameters import read_parameter_stream
from src.groth16_qap import QAP, QAPAssignment
from src.r1cs import R1CS
from src.sapling_spend_circuit import constrain_sapling_spend
from tests.sapling_spend_independent_reference import (
    generate_pinned_test_witness,
)
from tests.test_sapling_spend_circuit import _circuit_witness
from tests.test_sapling_spend_parameter_compatibility import (
    PARAMETER_BLAKE2B512,
    PARAMETER_BYTES,
    PARAMETER_PATH,
    PARAMETER_SHA256,
    SECTION_COUNTS,
    _bellman_export,
    _read_exact,
)
from tests.test_sapling_spend_qap_compatibility import (
    LOCAL_MATRIX_FINGERPRINT,
    QUERY_MAPPING_FINGERPRINT,
    _run_bellman_qap,
    _run_bellman_synthesis,
    _validate_witness_mapping,
)

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "tests" / "reference" / "sapling-output-qap"
MANIFEST = REFERENCE / "Cargo.toml"
MAPPING_PATH = (
    ROOT / "tests" / "fixtures" / "sapling_spend_parameter_query_index_mapping.json"
)
ACCUMULATION_MAGIC = b"ZYSPMS01"
ACCUMULATION_POINT_BYTES = {
    "ic": 96,
    "h": 96,
    "l": 96,
    "a": 96,
    "b_g1": 96,
    "b_g2": 192,
}


def _linux_path(path: Path) -> str:
    resolved = path.resolve()
    return f"/mnt/{resolved.drive[0].lower()}/" + "/".join(resolved.parts[1:])


def _run_bellman_accumulation(
    parameters: Path, summary: Path, mapping: Path, output: Path
) -> None:
    wsl = shutil.which("wsl")
    if wsl:
        command = (
            f"cd {shlex.quote(_linux_path(ROOT))} && "
            f"rustup run 1.97.0 cargo run --offline --release "
            f"--manifest-path {shlex.quote(_linux_path(MANIFEST))} "
            f"--bin authentic_spend_query_accumulation -- "
            f"{shlex.quote(_linux_path(parameters))} "
            f"{shlex.quote(_linux_path(summary))} "
            f"{shlex.quote(_linux_path(mapping))} "
            f"{shlex.quote(_linux_path(output))}"
        )
        subprocess.run([wsl, "--", "bash", "-lc", command], cwd=ROOT, check=True)
        return
    subprocess.run(
        [
            "cargo",
            "run",
            "--offline",
            "--release",
            "--manifest-path",
            str(MANIFEST),
            "--bin",
            "authentic_spend_query_accumulation",
            "--",
            str(parameters),
            str(summary),
            str(mapping),
            str(output),
        ],
        cwd=ROOT,
        check=True,
    )


def _identity_index(identity: str) -> int:
    if identity.startswith("Input(") and identity.endswith(")"):
        return int(identity[6:-1])
    if identity.startswith("Aux(") and identity.endswith(")"):
        return 8 + int(identity[4:-1])
    raise AssertionError(f"unknown upstream variable identity {identity!r}")


def _read_bellman_accumulations(path: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with path.open("rb") as stream:
        if _read_exact(stream, 8, "accumulation magic") != ACCUMULATION_MAGIC:
            raise AssertionError("Bellman accumulator export magic mismatch")
        for name, point_size in ACCUMULATION_POINT_BYTES.items():
            name_size = _read_exact(stream, 1, f"{name} name length")[0]
            section_name = _read_exact(stream, name_size, f"{name} name")
            count = int.from_bytes(_read_exact(stream, 4, f"{name} count"), "big")
            if section_name.decode("ascii") != name or count != 1:
                raise AssertionError(f"Bellman {name} accumulator section mismatch")
            result[name] = _read_exact(stream, point_size, f"{name} accumulator")
        if stream.read(1):
            raise AssertionError("trailing bytes in Bellman accumulator export")
    return result


@unittest.skipUnless(
    PARAMETER_PATH.is_file()
    and shutil.which("cargo")
    and (shutil.which("wsl") or os.name != "nt"),
    "official Spend parameters and the pinned Bellman reference are required",
)
class AuthenticSpendQueryAccumulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="zycoin-authentic-spend-msm-"
        )
        cls.addClassCleanup(cls._temporary_directory.cleanup)
        directory = Path(cls._temporary_directory.name)
        cls.trace_path = directory / "bellman-spend-trace.json"
        cls.summary_path = directory / "bellman-spend-qap.json"
        cls.point_export_path = directory / "bellman-query-points.bin"
        cls.bellman_accumulation_path = directory / "bellman-accumulations.bin"

        _run_bellman_synthesis(cls.trace_path)
        _run_bellman_qap(cls.trace_path, cls.summary_path)
        cls.summary = json.loads(cls.summary_path.read_text(encoding="utf-8"))
        cls.upstream_values = tuple(
            int.from_bytes(bytes.fromhex(value), "little")
            for value in cls.summary["assignment_hex"]
        )
        cls.upstream_h = tuple(
            int.from_bytes(bytes.fromhex(value), "little")
            for value in cls.summary["quotient_coefficients_h_hex"]
        )
        if (
            cls.summary["format"] != "bellman-sapling-spend-qap-reference-v1"
            or not cls.summary["quotient_divisibility_verified"]
            or len(cls.upstream_values) != 98_646
            or len(cls.upstream_h) != 131_071
        ):
            raise AssertionError("Bellman QAP reference is incomplete")

        cls.witness = _circuit_witness(generate_pinned_test_witness(0))
        cls.system = R1CS()
        constrain_sapling_spend(cls.system, cls.witness)
        cls.qap = QAP.from_r1cs(cls.system)
        auxiliary = tuple(
            cls.system.witness_value(variable) for variable in cls.system.variables[8:]
        )
        if any(value is None for value in auxiliary):
            raise AssertionError("local Spend assignment contains an unassigned value")
        cls.assignment = QAPAssignment(cls.system.public_inputs(), auxiliary)
        cls.local_values = cls.qap.validate_assignment(cls.assignment)
        cls.local_h = cls.qap.quotient(cls.assignment)
        if (
            cls.system.matrix_fingerprint() != LOCAL_MATRIX_FINGERPRINT
            or len(cls.local_values) != 98_646
            or len(cls.local_h) != 131_071
        ):
            raise AssertionError("local Spend matrix or QAP dimensions changed")

        mapping = json.loads(MAPPING_PATH.read_text(encoding="ascii"))
        if mapping["mapping_fingerprint_sha256"] != QUERY_MAPPING_FINGERPRINT:
            raise AssertionError("Spend query mapping fingerprint changed")
        position_variable = next(
            variable
            for variable in cls.system.variables
            if variable.name == "Sapling Spend Merkle path position"
        )
        _validate_witness_mapping(
            mapping,
            cls.local_values,
            cls.upstream_values,
            position_variable.index,
            cls.witness.anchor,
            cls.witness.position,
        )
        cls.mapping = mapping

        _bellman_export(PARAMETER_PATH, cls.point_export_path)
        _run_bellman_accumulation(
            PARAMETER_PATH,
            cls.summary_path,
            MAPPING_PATH,
            cls.bellman_accumulation_path,
        )
        cls.bellman_accumulations = _read_bellman_accumulations(
            cls.bellman_accumulation_path
        )

    def test_full_official_query_accumulations_compare_with_bellman_independently(self):
        digest = hashlib.sha256()
        blake = hashlib.blake2b(digest_size=64)
        with PARAMETER_PATH.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
                blake.update(chunk)
        self.assertEqual(PARAMETER_PATH.stat().st_size, PARAMETER_BYTES)
        self.assertEqual(digest.hexdigest(), PARAMETER_SHA256)
        self.assertEqual(blake.hexdigest(), PARAMETER_BLAKE2B512)

        parser_stream = PARAMETER_PATH.open("rb")
        self.addCleanup(parser_stream.close)
        parser = read_parameter_stream(parser_stream, allow_trailing_data=True)
        sections = iter(parser.sections())
        local_accumulations: dict[str, bytes] = {}
        point_total = 0

        with self.point_export_path.open("rb") as reference:
            self.assertEqual(
                _read_exact(reference, 8, "point export magic"), b"ZYQEXP01"
            )
            for name, count in SECTION_COUNTS.items():
                name_size = _read_exact(reference, 1, f"{name} name length")[0]
                section_name = _read_exact(reference, name_size, f"{name} name")
                reference_count = int.from_bytes(
                    _read_exact(reference, 4, f"{name} count"), "big"
                )
                self.assertEqual(section_name.decode("ascii"), name)
                self.assertEqual(reference_count, count)
                if name == "ic":
                    points = list(parser.metadata.verification_key.ic)
                    self.assertEqual(len(points), count)
                else:
                    section = next(sections)
                    self.assertEqual(section.name, name)
                    points = list(section)
                    self.assertEqual(len(points), count)

                encoder = (
                    encode_g2_uncompressed if name == "b_g2" else encode_g1_uncompressed
                )
                section_digest = hashlib.sha256()
                for index, point in enumerate(points):
                    encoded = encoder(point)
                    expected = _read_exact(reference, len(encoded), f"{name}[{index}]")
                    self.assertEqual(encoded, expected, f"official {name}[{index}]")
                    section_digest.update(encoded)
                    self.assertFalse(point.is_infinity)
                self.assertEqual(
                    section_digest.hexdigest(),
                    {
                        "ic": "9d05cfaa8f5cdb11cc8694e73ad76a2c541c94e0648d533089b80941a04f0d7b",
                        "h": "a8f3a93e8e5f144557701e66acbfdc751002e7a3302b5ad365fc7a342ce1437e",
                        "l": "afb42dbab478d8f3a571cbe038dee6a0d61da1ef8359c9931d264bcf170b97b6",
                        "a": "a26b506e2e525246c12d590342f13794a3d1199986d17f067d67dae2a05286d9",
                        "b_g1": "ac2dc83a3aee7f8d82c7b562b1838ada266ba73969b52159c41e6994c48196a7",
                        "b_g2": "334580c04c7acb927b0bf3c192c8909cc99d8201bd45a20ce41e06f2b789d8fe",
                    }[name],
                    f"complete official {name} point section hash",
                )
                point_total += count

                if name == "ic":
                    scalars = self.local_values[:8]
                elif name == "h":
                    scalars = self.local_h
                else:
                    query_mapping = self.mapping["query_sections"][name]
                    local_columns = query_mapping["local_columns"]
                    identities = query_mapping["upstream_variable_identities"]
                    self.assertEqual(len(local_columns), count)
                    self.assertEqual(len(identities), count)
                    scalars_list = []
                    for local_column, identity in zip(
                        local_columns, identities, strict=True
                    ):
                        upstream_value = self.upstream_values[_identity_index(identity)]
                        if local_column is None:
                            self.assertEqual(identity, "Aux(76805)")
                            self.assertEqual(upstream_value, self.witness.anchor)
                            scalars_list.append(upstream_value)
                        else:
                            self.assertEqual(
                                self.local_values[local_column],
                                upstream_value,
                                identity,
                            )
                            scalars_list.append(self.local_values[local_column])
                    scalars = tuple(scalars_list)

                self.assertEqual(len(points), len(scalars))
                self.assertTrue(
                    all(
                        type(scalar) is int and 0 <= scalar < SCALAR_MODULUS
                        for scalar in scalars
                    ),
                    f"{name} query scalars are noncanonical",
                )
                if name == "b_g2":
                    result = multi_scalar_multiply_g2(points, scalars)
                    local_accumulations[name] = encode_g2_uncompressed(result)
                else:
                    result = multi_scalar_multiply_g1(points, scalars)
                    local_accumulations[name] = encode_g1_uncompressed(result)

            self.assertEqual(reference.read(1), b"")
        self.assertEqual(point_total, 437_707)
        self.assertIsNone(next(sections, None))
        self.assertTrue(parser.validated)
        self.assertEqual(parser.manifest.sha256, PARAMETER_SHA256)
        self.assertEqual(parser.manifest.blake2b512, PARAMETER_BLAKE2B512)
        self.assertEqual(parser.manifest.trailing_bytes, 52_836)
        self.assertEqual(dict(parser.manifest.section_counts), SECTION_COUNTS)
        self.assertEqual(
            self.summary["assignment_sha256"],
            ("429887b2897ce1ee6f4bf9707c7e28158ce66dc9ba9789dff708ce02a0fc3e57"),
        )

        matches = {
            name: local_accumulations[name] == self.bellman_accumulations[name]
            for name in SECTION_COUNTS
        }
        self.assertEqual(
            matches,
            {
                "ic": True,
                "h": False,
                "l": True,
                "a": True,
                "b_g1": True,
                "b_g2": True,
            },
            "complete direct-index official-query accumulations changed",
        )
        print(
            "OFFICIAL SPEND FULL-VECTOR ACCUMULATION "
            + json.dumps(
                {
                    "parameter_sha256": parser.manifest.sha256,
                    "point_counts": SECTION_COUNTS,
                    "matches_bellman": matches,
                    "local_h_sha256": hashlib.sha256(
                        local_accumulations["h"]
                    ).hexdigest(),
                    "bellman_h_sha256": hashlib.sha256(
                        self.bellman_accumulations["h"]
                    ).hexdigest(),
                    "local_matrix_fingerprint": self.system.matrix_fingerprint(),
                    "bellman_assignment_sha256": self.summary["assignment_sha256"],
                },
                sort_keys=True,
            )
        )


if __name__ == "__main__":
    unittest.main()
