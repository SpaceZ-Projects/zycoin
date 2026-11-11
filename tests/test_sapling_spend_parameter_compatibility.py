"""Opt-in Spend parameter compatibility audit using the pinned Bellman reader."""

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

from src.bls12_381 import encode_g1_uncompressed, encode_g2_uncompressed
from src.groth16_parameters import read_parameter_stream
from src.sapling_spend_circuit import SPEND_PUBLIC_INPUT_ORDER

ROOT = Path(__file__).resolve().parents[1]
PARAMETER_PATH = Path(
    os.environ.get(
        "ZYCOIN_SAPLING_SPEND_PARAMS",
        Path.home() / "AppData" / "Roaming" / "ZcashParams" / "sapling-spend.params",
    )
)
PARAMETER_BYTES = 47_958_396
PARAMETER_SHA256 = "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13"
PARAMETER_BLAKE2B512 = (
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63"
    "991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c"
)
SECTION_COUNTS = {
    "ic": 8,
    "h": 131_071,
    "l": 98_638,
    "a": 85_390,
    "b_g1": 61_300,
    "b_g2": 61_300,
}


def _read_exact(stream, size: int, label: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise AssertionError(f"truncated Bellman query export at {label}")
    return data


def _bellman_export(parameters: Path, destination: Path) -> None:
    manifest = ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
    wsl = shutil.which("wsl")
    if wsl:
        def linux_path(path: Path) -> str:
            resolved = path.resolve()
            return f"/mnt/{resolved.drive[0].lower()}/" + "/".join(
                resolved.parts[1:]
            )

        root = linux_path(ROOT)
        converted_manifest = linux_path(manifest)
        converted_parameters = linux_path(parameters)
        converted_destination = linux_path(destination)
        command = (
            f"cd {shlex.quote(root)} && rustup run 1.97.0 cargo run --offline "
            f"--release --manifest-path {shlex.quote(converted_manifest)} "
            f"--bin export_parameter_queries -- "
            f"{shlex.quote(converted_parameters)} "
            f"{shlex.quote(converted_destination)}"
        )
        subprocess.run(
            [wsl, "--", "bash", "-lc", command],
            cwd=ROOT,
            check=True,
        )
        return
    subprocess.run(
        [
            "cargo",
            "run",
            "--offline",
            "--release",
            "--manifest-path",
            str(manifest),
            "--bin",
            "export_parameter_queries",
            "--",
            str(parameters),
            str(destination),
        ],
        cwd=ROOT,
        check=True,
    )


@unittest.skipUnless(
    PARAMETER_PATH.is_file() and shutil.which("cargo"),
    "official Spend parameters and Cargo are required",
)
class AuthenticSpendParameterCompatibilityTests(unittest.TestCase):
    def test_all_spend_query_points_match_bellman_015_independent_load(self):
        self.assertEqual(PARAMETER_PATH.stat().st_size, PARAMETER_BYTES)
        digest = hashlib.sha256()
        blake = hashlib.blake2b(digest_size=64)
        with PARAMETER_PATH.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                blake.update(chunk)
        self.assertEqual(digest.hexdigest(), PARAMETER_SHA256)
        self.assertEqual(blake.hexdigest(), PARAMETER_BLAKE2B512)

        with tempfile.TemporaryDirectory(prefix="zycoin-spend-query-audit-") as temp:
            export_path = Path(temp) / "bellman-spend-query-export.bin"
            _bellman_export(PARAMETER_PATH, export_path)
            with export_path.open("rb") as export_file:
                export_hash = hashlib.file_digest(export_file, "sha256").hexdigest()

            parameter_stream = PARAMETER_PATH.open("rb")
            self.addCleanup(parameter_stream.close)
            parser = read_parameter_stream(parameter_stream, allow_trailing_data=True)
            sections = iter(parser.sections())
            actual_hashes: dict[str, str] = {}
            total_points = 0
            identity_counts: dict[str, int] = {}
            with export_path.open("rb") as export:
                self.assertEqual(_read_exact(export, 8, "magic"), b"ZYQEXP01")
                for name, count in SECTION_COUNTS.items():
                    name_size = _read_exact(export, 1, f"{name} name length")[0]
                    section_name = _read_exact(export, name_size, f"{name} name")
                    self.assertEqual(section_name.decode("ascii"), name)
                    reference_count = int.from_bytes(
                        _read_exact(export, 4, f"{name} count"), "big"
                    )
                    self.assertEqual(reference_count, count)

                    if name == "ic":
                        points = iter(parser.metadata.verification_key.ic)
                    else:
                        section = next(sections)
                        self.assertEqual(section.name, name)
                        points = iter(section)

                    encoder = (
                        encode_g2_uncompressed if name == "b_g2"
                        else encode_g1_uncompressed
                    )
                    point_hash = hashlib.sha256()
                    identities = 0
                    for index in range(count):
                        point = next(points)
                        encoded = encoder(point)
                        reference = _read_exact(export, len(encoded), f"{name}[{index}]")
                        self.assertEqual(encoded, reference, f"{name}[{index}]")
                        point_hash.update(encoded)
                        identities += int(point.is_infinity)
                    self.assertIsNone(next(points, None), f"{name} has extra points")
                    self.assertEqual(identities, 0)
                    actual_hashes[name] = point_hash.hexdigest()
                    identity_counts[name] = identities
                    total_points += count
                self.assertEqual(export.read(1), b"")
            self.assertEqual(total_points, 437_707)

            self.assertIsNone(next(sections, None))
            manifest = parser.manifest
            self.assertEqual(manifest.sha256, PARAMETER_SHA256)
            self.assertEqual(manifest.blake2b512, PARAMETER_BLAKE2B512)
            self.assertEqual(manifest.trailing_bytes, 52_836)
            self.assertEqual(dict(manifest.section_counts), SECTION_COUNTS)

            mapping = json.loads(
                (
                    ROOT
                    / "tests"
                    / "fixtures"
                    / "sapling_spend_parameter_query_index_mapping.json"
                ).read_text(encoding="ascii")
            )
            self.assertEqual(
                mapping["mapping_fingerprint_sha256"],
                "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08",
            )
            self.assertEqual(
                mapping["query_sections"]["ic"]["upstream_variable_identities"],
                [
                    "Input(0)", "Input(1)", "Input(2)", "Input(3)",
                    "Input(4)", "Input(5)", "Input(6)", "Input(7)",
                ],
            )
            self.assertEqual(
                SPEND_PUBLIC_INPUT_ORDER,
                (
                    "rk.u",
                    "rk.v",
                    "cv.u",
                    "cv.v",
                    "anchor",
                    "nullifier_chunk_0",
                    "nullifier_chunk_1",
                ),
            )
            self.assertEqual(mapping["query_sections"]["h"]["query_index_start"], 0)
            self.assertEqual(
                mapping["query_sections"]["h"]["query_index_end_exclusive"],
                131_071,
            )
            self.assertEqual(
                mapping["query_sections"]["l"]["upstream_variable_identities"],
                [f"Aux({index})" for index in range(98_638)],
            )
            a_mapping = mapping["query_sections"]["a"]
            b1_mapping = mapping["query_sections"]["b_g1"]
            b2_mapping = mapping["query_sections"]["b_g2"]
            self.assertEqual(len(a_mapping["upstream_variable_identities"]), 85_390)
            self.assertEqual(len(b1_mapping["upstream_variable_identities"]), 61_300)
            self.assertEqual(b1_mapping, b2_mapping)
            self.assertEqual(
                [
                    identity
                    for identity in a_mapping["upstream_variable_identities"]
                    if identity == "Aux(76805)"
                ],
                ["Aux(76805)"],
            )
            self.assertEqual(
                sum(column is None for column in a_mapping["local_columns"]),
                1,
            )
            self.assertEqual(
                sum(column is None for column in b1_mapping["local_columns"]),
                0,
            )
            for name in ("a", "b_g1", "b_g2"):
                identities = mapping["query_sections"][name][
                    "upstream_variable_identities"
                ]
                ordering = [
                    (0, int(identity[6:-1]))
                    if identity.startswith("Input(")
                    else (1, int(identity[4:-1]))
                    for identity in identities
                ]
                self.assertEqual(ordering, sorted(ordering))

            print(
                "Spend Bellman query export SHA-256:",
                export_hash,
                "section hashes:",
                json.dumps(actual_hashes, sort_keys=True),
                "identities:",
                json.dumps(identity_counts, sort_keys=True),
            )


if __name__ == "__main__":
    unittest.main()
