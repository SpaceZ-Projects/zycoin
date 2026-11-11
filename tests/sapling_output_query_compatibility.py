"""Test-only exact comparison of Python and Bellman Output query points."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import BinaryIO

from src.bls12_381 import encode_g1_uncompressed, encode_g2_uncompressed
from src.groth16_parameters import read_parameter_stream

QUERY_EXPORT_MAGIC = b"ZYQEXP01"
QUERY_SECTION_LAYOUT = (
    ("ic", 6, 96),
    ("h", 8_191, 96),
    ("l", 7_821, 96),
    ("a", 6_298, 96),
    ("b_g1", 4_850, 96),
    ("b_g2", 4_850, 192),
)


class QueryCompatibilityError(ValueError):
    """Raised when the two implementations disagree on query serialization."""


def _read_exact(stream: BinaryIO, size: int, label: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise QueryCompatibilityError(f"truncated Bellman query export at {label}")
    return data


def compare_point_sequences(
    section: str,
    reference_points: Iterable[bytes],
    parsed_points: Iterable[bytes],
    expected_count: int,
) -> dict[str, int | str]:
    """Compare exact canonical bytes and order, rejecting count differences."""
    reference = iter(reference_points)
    parsed = iter(parsed_points)
    digest = hashlib.sha256()
    encoded_bytes = 0
    for index in range(expected_count):
        try:
            reference_point = next(reference)
            parsed_point = next(parsed)
        except StopIteration as error:
            raise QueryCompatibilityError(
                f"{section} query section is missing point {index}"
            ) from error
        if not isinstance(reference_point, bytes) or not isinstance(parsed_point, bytes):
            raise QueryCompatibilityError(f"{section} query encoding is not bytes")
        if len(reference_point) != len(parsed_point):
            raise QueryCompatibilityError(
                f"{section} query point {index} has an inconsistent encoding length"
            )
        if reference_point != parsed_point:
            raise QueryCompatibilityError(
                f"{section} query point {index} differs from Bellman"
            )
        digest.update(reference_point)
        encoded_bytes += len(reference_point)
    if next(reference, None) is not None or next(parsed, None) is not None:
        raise QueryCompatibilityError(f"{section} query section has extra points")
    return {
        "point_count": expected_count,
        "encoded_bytes": encoded_bytes,
        "sha256": digest.hexdigest(),
    }


def validate_query_index_mapping(
    actual: Mapping[str, object],
    independently_regenerated: Mapping[str, object],
) -> None:
    """Require the artifact's sparse and dense indices to match matrix evidence."""
    if actual != independently_regenerated:
        raise QueryCompatibilityError(
            "Output query indices differ from independently regenerated matrix mapping"
        )
    for section in ("a_query", "b_g1_query", "b_g2_query", "ic_query"):
        entries = actual.get(section)
        if not isinstance(entries, list):
            raise QueryCompatibilityError(f"{section} mapping is not a list")
        columns: list[int] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, Mapping):
                raise QueryCompatibilityError(f"{section} mapping entry is malformed")
            if entry.get("query_index") != index:
                raise QueryCompatibilityError(
                    f"{section} query index {index} is missing, repeated, or reordered"
                )
            column = entry.get("local_column")
            if type(column) is not int:
                raise QueryCompatibilityError(f"{section} local column is invalid")
            columns.append(column)
        if columns != sorted(set(columns)):
            raise QueryCompatibilityError(
                f"{section} variable ordering is not strictly increasing"
            )

    if actual.get("b_g1_query") != actual.get("b_g2_query"):
        raise QueryCompatibilityError("B_G1 and B_G2 sparse indices differ")


def _read_export_section(
    stream: BinaryIO,
    expected_name: str,
    expected_count: int,
) -> None:
    name_size = _read_exact(stream, 1, f"{expected_name} name length")[0]
    name = _read_exact(stream, name_size, f"{expected_name} name").decode("ascii")
    count = int.from_bytes(
        _read_exact(stream, 4, f"{expected_name} count"), "big"
    )
    if name != expected_name:
        raise QueryCompatibilityError(
            f"expected Bellman section {expected_name}, found {name}"
        )
    if count != expected_count:
        raise QueryCompatibilityError(
            f"Bellman {expected_name} count {count} != expected {expected_count}"
        )


def _point_encoder(section: str):
    if section == "b_g2":
        return encode_g2_uncompressed
    return encode_g1_uncompressed


def compare_parameter_queries(
    parameter_stream: BinaryIO,
    bellman_export_stream: BinaryIO,
) -> dict[str, object]:
    """Compare every parsed parameter query with Bellman's independent export."""
    if _read_exact(
        bellman_export_stream, len(QUERY_EXPORT_MAGIC), "export magic"
    ) != QUERY_EXPORT_MAGIC:
        raise QueryCompatibilityError("invalid Bellman query export header")

    parser = read_parameter_stream(parameter_stream, allow_trailing_data=True)
    manifest: dict[str, dict[str, int | str]] = {}
    total_points = 0
    parameter_sections = iter(parser.sections())

    for section_index, (name, count, point_size) in enumerate(QUERY_SECTION_LAYOUT):
        _read_export_section(bellman_export_stream, name, count)
        if section_index == 0:
            points = parser.metadata.verification_key.ic
            point_iterator = iter(points)
        else:
            section = next(parameter_sections, None)
            if section is None:
                raise QueryCompatibilityError(
                    f"Python parser omitted query section {name}"
                )
            if section.name != name:
                raise QueryCompatibilityError(
                    f"Python parser returned {section.name}, expected {name}"
                )
            point_iterator = section

        identity_counter = [0]

        def reference_points(name=name, count=count, point_size=point_size):
            for index in range(count):
                encoded = _read_exact(
                    bellman_export_stream,
                    point_size,
                    f"{name} point {index}",
                )
                yield encoded

        def parsed_points(
            name=name,
            point_iterator=point_iterator,
            identity_counter=identity_counter,
        ):
            for point in point_iterator:
                identity_counter[0] += int(point.is_infinity)
                yield _point_encoder(name)(point)

        comparison = compare_point_sequences(
            name, reference_points(), parsed_points(), count
        )
        identity_count = identity_counter[0]
        if identity_count:
            raise QueryCompatibilityError(
                f"{name} contains {identity_count} identity query points"
            )
        manifest[name] = {
            "point_count": count,
            "encoded_bytes": count * point_size,
            "sha256": comparison["sha256"],
            "identity_points": identity_count,
            "exact_matches": count,
        }
        total_points += count

    if next(parameter_sections, None) is not None:
        raise QueryCompatibilityError("Python parser returned extra query sections")
    if bellman_export_stream.read(1):
        raise QueryCompatibilityError("trailing bytes in Bellman query export")

    if not parser.validated:
        raise QueryCompatibilityError("Python parameter stream was not fully validated")
    parsed_manifest = parser.manifest
    if parsed_manifest.section_counts != (
        ("ic", 6),
        ("h", 8_191),
        ("l", 7_821),
        ("a", 6_298),
        ("b_g1", 4_850),
        ("b_g2", 4_850),
    ):
        raise QueryCompatibilityError("Python parser section counts changed")
    return {
        "format": "zycoin-bellman-output-query-point-comparison-v1",
        "sections": manifest,
        "total_points": total_points,
        "all_points_exact": True,
        "python_parameter_sha256": parsed_manifest.sha256,
        "trailing_parameter_bytes": parsed_manifest.trailing_bytes,
    }


def compare_parameter_queries_from_files(
    parameter_path: str,
    bellman_export_path: str,
) -> dict[str, object]:
    """Open external parameter and temporary Bellman-export files."""
    with (
        open(parameter_path, "rb") as parameter_stream,
        open(bellman_export_path, "rb") as export_stream,
    ):
        return compare_parameter_queries(parameter_stream, export_stream)
