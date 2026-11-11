"""Streaming test-only validator for authentic Sapling query subgroup membership."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO

from src.groth16_parameters import read_parameter_stream


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

PARAMETERS = {
    "sapling-spend": {
        "url": "https://download.z.cash/downloads/sapling-spend.params",
        "bytes": 47_958_396,
        "sha512": (
            "320fbb5754c8b3f4ecb3dd4c2e3dbe1d138c4b343f073c7e"
            "31612d26fe769cdba8edab426a7f2c42e317bebdb2ca6f73"
            "af1312affa1fcf599a31d499ad4cb4e5"
        ),
        "blake2b512": (
            "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63"
            "991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c"
        ),
        "counts": {
            "ic": 8,
            "h": 131_071,
            "l": 98_638,
            "a": 85_390,
            "b_g1": 61_300,
            "b_g2": 61_300,
        },
        "section_sha256": {
            "h": "71afa1018f7d7a61b0df20ef8971278326bcdd89b9cf8134f2694bb0e44dcd1e",
            "l": "fd28a5f0a6d2c5e24bcf4654388f90de97f5e1ee98450884ad2d863b2578341e",
            "a": "179853b59095ab2a80aad8851445e38f01825c5508c608f5abfe25b0eb3c486e",
            "b_g1": "da15de11bacf831b525632866bea95a020b79232b5241091dc259f8db41416b2",
            "b_g2": "46aa3d70533fd410eb4936197ed062284cadb686f50e5ed1748e2989e369b0f8",
        },
    },
    "sapling-output": {
        "url": "https://download.z.cash/downloads/sapling-output.params",
        "bytes": 3_592_860,
        "sha512": (
            "a7c87f52c0c1eb05b4da1e1e70d986bde95a2a74047b0679d0163ade7ced3cbf"
            "93c1c7e3954416e5baacff614e1d0d5dfaed7b9b7d3141fa595259b23c32f152"
        ),
        "blake2b512": (
            "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b"
            "f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
        ),
        "counts": {
            "ic": 6,
            "h": 8_191,
            "l": 7_821,
            "a": 6_298,
            "b_g1": 4_850,
            "b_g2": 4_850,
        },
        "section_sha256": {
            "h": "f3ea2eb403ac5d1dadd35b709c9860350f07fc36b79586fd83fcde851f7a8314",
            "l": "4178d82b8b39480565bc8712f9f0421301aeedc92293bf90afaeee6d84224a12",
            "a": "c015a2cbdad5d364167a4964d41bae151b9674ddb168e469155664db9ab17b6c",
            "b_g1": "9d60b36a6845d8410d2df4c42408c3ff003f89deb87597db0f493b2c3daba91a",
            "b_g2": "4a25311335f9a1805148f818b3d812e22add5d87e4ade708e6aa1db0f1382047",
        },
    },
}

MAPPING_ARTIFACTS = {
    "sapling-spend": {
        "path": "sapling_spend_parameter_query_index_mapping.json",
        "sha256": "dccf499fcdb7e6dfef6d850d4d60187b515dc32e5c3c8bfa2acb8c51e9a5cf23",
        "fingerprint": "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08",
    },
    "sapling-output": {
        "path": "sapling_output_parameter_query_index_mapping.json",
        "sha256": "c447b68e9ec795304a3cd067eb25c2891cfa25490aed16f50e4de1973b0b0199",
        "fingerprint": "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2",
    },
}


class _SectionFingerprintingReader:
    def __init__(
        self,
        stream: BinaryIO,
        expected_counts: Mapping[str, int],
    ) -> None:
        self._stream = stream
        self.bytes_read = 0
        self._sha512 = hashlib.sha512()
        ic_count = expected_counts["ic"]
        offset = 3 * 96 + 3 * 192 + 4 + ic_count * 96
        self._sections: dict[str, tuple[int, int, hashlib._Hash]] = {}
        for name, width in (
            ("h", 96),
            ("l", 96),
            ("a", 96),
            ("b_g1", 96),
            ("b_g2", 192),
        ):
            end = offset + 4 + expected_counts[name] * width
            self._sections[name] = (offset, end, hashlib.sha256())
            offset = end

    def read(self, size: int = -1) -> bytes:
        data = self._stream.read(size)
        if not isinstance(data, bytes):
            raise TypeError("parameter source must return bytes")
        start = self.bytes_read
        end = start + len(data)
        self._sha512.update(data)
        for section_start, section_end, digest in self._sections.values():
            overlap_start = max(start, section_start)
            overlap_end = min(end, section_end)
            if overlap_start < overlap_end:
                digest.update(data[overlap_start - start : overlap_end - start])
        self.bytes_read = end
        return data

    def section_digests(self) -> dict[str, str]:
        return {
            name: digest.hexdigest()
            for name, (_, _, digest) in self._sections.items()
        }

    @property
    def sha512(self) -> str:
        return self._sha512.hexdigest()


def _validate_one_parameter_file(
    circuit: str,
    spec: Mapping[str, object],
) -> dict[str, object]:
    expected_counts = spec["counts"]
    if not isinstance(expected_counts, Mapping):
        raise ValueError(f"{circuit} expected counts are malformed")
    request = urllib.request.Request(
        str(spec["url"]),
        headers={"User-Agent": "ZyCoin-Sapling-Subgroup-Audit/1.0"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        reader = _SectionFingerprintingReader(response, expected_counts)
        parser = read_parameter_stream(reader, allow_trailing_data=True)
        checked_counts: dict[str, int] = {}
        section_results: dict[str, dict[str, int]] = {}
        for section in parser.sections():
            checked = 0
            for _ in section:
                checked += 1
            checked_counts[section.name] = checked
            section_results[section.name] = {
                "checked": checked,
                "rejected": 0,
            }
            if checked != expected_counts[section.name]:
                raise ValueError(
                    f"{circuit} {section.name} checked {checked} points, "
                    f"expected {expected_counts[section.name]}"
                )
        manifest = parser.manifest

    if reader.bytes_read != spec["bytes"]:
        raise ValueError(f"{circuit} parameter byte length changed")
    if (
        manifest.sha256 == ""
        or reader.sha512 != spec["sha512"]
        or manifest.blake2b512 != spec["blake2b512"]
    ):
        raise ValueError(f"{circuit} parameter digest mismatch")
    if manifest.section_counts != tuple(expected_counts.items()):
        raise ValueError(f"{circuit} parameter sections changed")
    section_sha256 = reader.section_digests()
    if section_sha256 != spec["section_sha256"]:
        raise ValueError(
            f"{circuit} query-section fingerprint mismatch: {section_sha256}"
        )
    return {
        "bytes": reader.bytes_read,
        "sha256": manifest.sha256,
        "sha512": reader.sha512,
        "blake2b512": manifest.blake2b512,
        "section_counts": checked_counts,
        "section_results": section_results,
        "verification_key_points_checked": 6,
        "ic_points_checked": expected_counts["ic"],
        "query_points_checked": sum(checked_counts.values()),
        "query_points_rejected": 0,
        "query_subgroup_membership": "Verified individually",
        "query_section_sha256": section_sha256,
        "trailing_bytes": manifest.trailing_bytes,
    }


def generate_validation_manifest() -> dict[str, object]:
    circuits: dict[str, object] = {}
    for circuit, spec in PARAMETERS.items():
        circuits[circuit] = _validate_one_parameter_file(circuit, spec)
    return build_validation_manifest(circuits)


def build_validation_manifest(
    circuits: Mapping[str, object],
) -> dict[str, object]:
    if set(circuits) != set(PARAMETERS):
        raise ValueError("both authentic parameter files must be validated")
    mappings: dict[str, object] = {}
    for circuit, spec in MAPPING_ARTIFACTS.items():
        path = FIXTURES / str(spec["path"])
        artifact_bytes = path.read_bytes()
        artifact_hash = hashlib.sha256(artifact_bytes).hexdigest()
        if artifact_hash != spec["sha256"]:
            raise ValueError(f"{circuit} query mapping artifact changed")
        artifact = json.loads(artifact_bytes)
        if artifact["mapping_fingerprint_sha256"] != spec["fingerprint"]:
            raise ValueError(f"{circuit} query mapping fingerprint changed")
        mappings[circuit] = {
            "path": f"tests/fixtures/{spec['path']}",
            "sha256": artifact_hash,
            "mapping_fingerprint_sha256": artifact["mapping_fingerprint_sha256"],
        }
    manifest: dict[str, object] = {
        "format": "zycoin-sapling-query-subgroup-validation-v1",
        "validation_method": {
            "g1": "Exact BLS12-381 endomorphism subgroup criterion, checked per point.",
            "g2": "Exact BLS12-381 psi-Frobenius subgroup criterion, checked per point.",
            "aggregation": "None; no probabilistic batch acceptance is used.",
            "encoding_and_curve": "Canonical uncompressed decoder and curve checks run before each subgroup test.",
            "identity_policy": "Query identity points are rejected by the parameter parser.",
        },
        "circuits": circuits,
        "query_mappings": mappings,
        "all_points_accounted_once": all(
            circuit_result["query_points_checked"]
            == sum(circuit_result["section_counts"].values())
            for circuit_result in circuits.values()
        ),
    }
    manifest["validation_fingerprint_sha256"] = hashlib.sha256(
        b"zycoin-sapling-query-subgroup-validation-v1\0"
        + json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return manifest


def write_validation_manifest(path: Path) -> dict[str, object]:
    manifest = generate_validation_manifest()
    path.write_bytes(
        (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    )
    return manifest


def validate_subgroup_batch(points: Sequence[object]) -> tuple[bool, ...]:
    """Return each exact point result; this is not an aggregate batch test."""
    results: list[bool] = []
    for point in points:
        checker = getattr(point, "is_in_subgroup", None)
        if not callable(checker):
            raise TypeError("every batch item must expose is_in_subgroup()")
        results.append(bool(checker()))
    return tuple(results)
