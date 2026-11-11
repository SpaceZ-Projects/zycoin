"""Bounded streaming reader for Bellman 0.15.0 BLS12-381 parameters."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

from .bls12_381 import (
    G1Point,
    G2Point,
    decode_g1_uncompressed,
    decode_g2_uncompressed,
)

Groth16Point = G1Point | G2Point


class _BinaryReadable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


_G1_BYTES = 96
_G2_BYTES = 192
_FORMAT_VERSION = "bellman-0.15.0"
_MANIFEST_VALIDATION_TOKEN = object()
_QUERY_LAYOUT = (
    ("h", G1Point, _G1_BYTES),
    ("l", G1Point, _G1_BYTES),
    ("a", G1Point, _G1_BYTES),
    ("b_g1", G1Point, _G1_BYTES),
    ("b_g2", G2Point, _G2_BYTES),
)


class Groth16ParameterError(ValueError):
    """Raised when a Bellman parameter stream is malformed or out of bounds."""


@dataclass(frozen=True)
class ParameterLimits:
    """Hard bounds applied before processing count-prefixed point sections."""

    max_points_per_section: int = 1_000_000
    max_total_points: int = 2_000_000
    max_total_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        for name in (
            "max_points_per_section",
            "max_total_points",
            "max_total_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class Groth16VerificationKey:
    alpha_g1: G1Point
    beta_g1: G1Point
    beta_g2: G2Point
    gamma_g2: G2Point
    delta_g1: G1Point
    delta_g2: G2Point
    ic: tuple[G1Point, ...]


@dataclass(frozen=True)
class Groth16ParameterMetadata:
    """Validated key and stream format metadata; no circuit ID is present."""

    verification_key: Groth16VerificationKey

    @property
    def input_count(self) -> int:
        """Return IC entries, including Bellman's implicit ONE."""
        return len(self.verification_key.ic)


@dataclass(frozen=True)
class ParameterManifest:
    """Canonical structural summary and digests of an exact parameter stream."""

    format_version: str
    section_counts: tuple[tuple[str, int], ...]
    sha256: str
    blake2b512: str = ""
    trailing_bytes: int = 0
    trusted_digest_verified: bool = False
    _validation_token: object | None = field(default=None, repr=False, compare=False)

    @property
    def structurally_validated(self) -> bool:
        return self._validation_token is _MANIFEST_VALIDATION_TOKEN

    @property
    def ic_count(self) -> int:
        return dict(self.section_counts)["ic"]

    @property
    def application_public_input_count(self) -> int:
        return self.ic_count - 1

    @property
    def auxiliary_query_count(self) -> int:
        return dict(self.section_counts)["l"]

    @property
    def total_variable_count(self) -> int:
        return self.ic_count + self.auxiliary_query_count

    @property
    def constraint_domain_size(self) -> int:
        return dict(self.section_counts)["h"] + 1

    def canonical_json(self) -> str:
        """Return deterministic JSON suitable for storage or comparison."""
        return json.dumps(
            {
                "format_version": self.format_version,
                "recoverable_metadata": {
                    "application_public_input_count": (
                        self.application_public_input_count
                    ),
                    "auxiliary_query_count": self.auxiliary_query_count,
                    "constraint_domain_size": self.constraint_domain_size,
                    "ic_count_including_one": self.ic_count,
                    "total_variable_count": self.total_variable_count,
                },
                "section_counts": dict(self.section_counts),
                "sha256": self.sha256,
                "trailing_bytes": self.trailing_bytes,
                "blake2b512": self.blake2b512,
                "trusted_digest_verified": self.trusted_digest_verified,
                "structurally_validated": self.structurally_validated,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


class _BoundedReader:
    def __init__(self, stream: _BinaryReadable, maximum_bytes: int) -> None:
        if not callable(getattr(stream, "read", None)):
            raise TypeError("parameter source must be a binary file-like object")
        self._stream = stream
        self._maximum_bytes = maximum_bytes
        self.bytes_read = 0
        self._digest = hashlib.sha256()
        self._blake2b512 = hashlib.blake2b(digest_size=64)

    def read_exact(self, size: int, label: str) -> bytes:
        if type(size) is not int or size < 0:
            raise ValueError("read size must be a non-negative integer")
        if self.bytes_read + size > self._maximum_bytes:
            raise Groth16ParameterError("parameter stream exceeds byte limit")
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self._stream.read(size - len(chunks))
            if chunk is None or not isinstance(chunk, bytes):
                raise Groth16ParameterError(
                    f"{label} read did not return binary data"
                )
            if not chunk:
                raise Groth16ParameterError(f"truncated parameter stream at {label}")
            if len(chunk) > size - len(chunks):
                raise Groth16ParameterError(
                    f"{label} reader returned more bytes than requested"
                )
            chunks.extend(chunk)
            self.bytes_read += len(chunk)
            self._digest.update(chunk)
            self._blake2b512.update(chunk)
        return bytes(chunks)

    def require_eof(self) -> None:
        extra = self._stream.read(1)
        if extra is None or not isinstance(extra, bytes):
            raise Groth16ParameterError("parameter source did not return binary data")
        if extra:
            self.bytes_read += len(extra)
            self._digest.update(extra)
            self._blake2b512.update(extra)
            if self.bytes_read > self._maximum_bytes:
                raise Groth16ParameterError("parameter stream exceeds byte limit")
            if len(extra) > 1:
                raise Groth16ParameterError(
                    "EOF reader returned more bytes than requested"
                )
            raise Groth16ParameterError("trailing bytes after Groth16 parameters")

    def consume_trailing_data(self) -> int:
        trailing_bytes = 0
        while True:
            requested = min(4096, self._maximum_bytes - self.bytes_read + 1)
            extra = self._stream.read(requested)
            if extra is None or not isinstance(extra, bytes):
                raise Groth16ParameterError(
                    "parameter source did not return binary data"
                )
            if len(extra) > requested:
                raise Groth16ParameterError(
                    "trailing-data reader returned more bytes than requested"
                )
            if not extra:
                return trailing_bytes
            self.bytes_read += len(extra)
            if self.bytes_read > self._maximum_bytes:
                raise Groth16ParameterError("parameter stream exceeds byte limit")
            self._digest.update(extra)
            self._blake2b512.update(extra)
            trailing_bytes += len(extra)

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    @property
    def blake2b512(self) -> str:
        return self._blake2b512.hexdigest()


class ParameterSection(Iterator[Groth16Point]):
    """Single-pass, validated iterator over one query section."""

    def __init__(
        self,
        parser: Groth16ParameterStream,
        name: str,
        count: int,
        point_type: type[G1Point | G2Point],
    ) -> None:
        self.name = name
        self.count = count
        self.point_type = point_type
        self._parser = parser
        self._remaining = count
        self._started = False

    def __iter__(self) -> ParameterSection:
        if self._started:
            raise Groth16ParameterError(
                f"parameter section {self.name} can only be iterated once"
            )
        self._started = True
        return self

    def __next__(self) -> Groth16Point:
        if self._remaining == 0:
            raise StopIteration
        point = self._parser._read_point(
            self.name,
            self.point_type,
            _G1_BYTES if self.point_type is G1Point else _G2_BYTES,
        )
        self._remaining -= 1
        return point


class Groth16ParameterStream:
    """One-pass parser for the common Bellman 0.15.0 parameter encoding.

    The verification key is read and validated at construction. Query sections
    are then yielded in Bellman's H, L, A, B_G1, B_G2 order. Each section must
    be fully consumed before advancing; exhausting ``sections()`` validates
    cross-section dimensions and rejects trailing data. Bellman omits identity
    points from A and B queries, so those sections are compact and their counts
    need not equal the circuit's variable count.
    """

    def __init__(
        self,
        stream: _BinaryReadable,
        limits: ParameterLimits | None = None,
        allow_trailing_data: bool = False,
    ) -> None:
        if limits is None:
            limits = ParameterLimits()
        if not isinstance(limits, ParameterLimits):
            raise TypeError("limits must be a ParameterLimits instance")
        if type(allow_trailing_data) is not bool:
            raise TypeError("allow_trailing_data must be a bool")
        self._limits = limits
        self._allow_trailing_data = allow_trailing_data
        self._reader = _BoundedReader(stream, limits.max_total_bytes)
        self._points_read = 0
        self._trailing_bytes = 0
        self._sections_started = False
        self._validated = False
        self.metadata = Groth16ParameterMetadata(self._read_verification_key())
        self._section_counts = {"ic": self.metadata.input_count}

    @property
    def validated(self) -> bool:
        """Whether every query point and the exact end-of-stream were checked."""
        return self._validated

    @property
    def manifest(self) -> ParameterManifest:
        """Return the manifest only after the complete stream is validated."""
        if not self._validated:
            raise Groth16ParameterError(
                "parameter manifest is unavailable before full validation"
            )
        return ParameterManifest(
            _FORMAT_VERSION,
            tuple(self._section_counts.items()),
            self._reader.sha256,
            self._reader.blake2b512,
            self._trailing_bytes,
            _validation_token=_MANIFEST_VALIDATION_TOKEN,
        )

    def _read_count(self, name: str, point_size: int) -> int:
        count = int.from_bytes(self._reader.read_exact(4, f"{name} length"), "big")
        if count > self._limits.max_points_per_section:
            raise Groth16ParameterError(
                f"{name} point count exceeds configured section limit"
            )
        if self._points_read + count > self._limits.max_total_points:
            raise Groth16ParameterError("parameter point count exceeds total limit")
        if self._reader.bytes_read + count * point_size > self._limits.max_total_bytes:
            raise Groth16ParameterError(
                f"{name} point section exceeds configured byte limit"
            )
        return count

    def _read_point(
        self,
        name: str,
        point_type: type[G1Point | G2Point],
        point_size: int,
        reject_infinity: bool = True,
    ) -> Groth16Point:
        if self._points_read + 1 > self._limits.max_total_points:
            raise Groth16ParameterError(
                "parameter point count exceeds total limit"
            )
        encoded = self._reader.read_exact(point_size, f"{name} point")
        self._points_read += 1
        try:
            if point_type is G1Point:
                point = decode_g1_uncompressed(encoded, check_subgroup=True)
            else:
                point = decode_g2_uncompressed(encoded, check_subgroup=True)
        except ValueError as error:
            raise Groth16ParameterError(
                f"invalid {name} point {self._points_read}: {error}"
            ) from error
        if reject_infinity and point.is_infinity:
            raise Groth16ParameterError(
                f"{name} point {self._points_read} must not be the point at infinity"
            )
        return point

    def _read_verification_key(self) -> Groth16VerificationKey:
        alpha_g1 = self._read_point(
            "vk.alpha_g1", G1Point, _G1_BYTES, reject_infinity=False
        )
        beta_g1 = self._read_point(
            "vk.beta_g1", G1Point, _G1_BYTES, reject_infinity=False
        )
        beta_g2 = self._read_point(
            "vk.beta_g2", G2Point, _G2_BYTES, reject_infinity=False
        )
        gamma_g2 = self._read_point(
            "vk.gamma_g2", G2Point, _G2_BYTES, reject_infinity=False
        )
        delta_g1 = self._read_point(
            "vk.delta_g1", G1Point, _G1_BYTES, reject_infinity=False
        )
        delta_g2 = self._read_point(
            "vk.delta_g2", G2Point, _G2_BYTES, reject_infinity=False
        )
        ic_count = self._read_count("vk.ic", _G1_BYTES)
        if ic_count == 0:
            raise Groth16ParameterError("verification-key IC query must include ONE")
        ic = tuple(
            self._read_point("vk.ic", G1Point, _G1_BYTES)
            for _ in range(ic_count)
        )
        return Groth16VerificationKey(
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
            ic,
        )

    def sections(self) -> Iterator[ParameterSection]:
        if self._sections_started:
            raise Groth16ParameterError(
                "parameter query sections can only be read once"
            )
        self._sections_started = True
        return self._iter_sections()

    def _iter_sections(self) -> Iterator[ParameterSection]:
        section_counts: dict[str, int] = {}
        for name, point_type, point_size in _QUERY_LAYOUT:
            count = self._read_count(name, point_size)
            if name == "h" and (count + 1) & count:
                raise Groth16ParameterError(
                    "H query count must be one less than a power of two"
                )
            if name in ("a", "b_g1", "b_g2"):
                total_variables = self.metadata.input_count + section_counts["l"]
                if count > total_variables:
                    raise Groth16ParameterError(
                        f"{name} query count {count} exceeds input plus auxiliary "
                        f"count {total_variables}"
                    )
            if name == "b_g2":
                if count != section_counts["b_g1"]:
                    raise Groth16ParameterError(
                        "B_G1 and B_G2 query counts must match"
                    )
            section_counts[name] = count
            self._section_counts[name] = count
            section = ParameterSection(self, name, count, point_type)
            yield section
            if section._remaining:
                raise Groth16ParameterError(
                    f"query section {name} was not fully consumed"
                )
        if self._allow_trailing_data:
            self._trailing_bytes = self._reader.consume_trailing_data()
        else:
            self._reader.require_eof()
        self._validated = True


def read_parameter_stream(
    stream: _BinaryReadable,
    limits: ParameterLimits | None = None,
    allow_trailing_data: bool = False,
) -> Groth16ParameterStream:
    """Read a parameter VK; query data remains streaming.

    Set ``allow_trailing_data`` only for known wrappers that append data after
    the Bellman parameter serialization, such as Sapling ceremony transcripts.
    """
    return Groth16ParameterStream(stream, limits, allow_trailing_data)


def validate_parameter_stream(
    stream: _BinaryReadable,
    limits: ParameterLimits | None = None,
    expected_sha256: str | None = None,
    expected_sha256_from_trusted_source: bool = False,
    expected_blake2b512: str | None = None,
    expected_blake2b512_from_trusted_source: bool = False,
    allow_trailing_data: bool = False,
) -> ParameterManifest:
    """Validate a whole parameter stream without retaining query sections.

    Expected digests should only be supplied when obtained through a trusted,
    independent channel. Matching a caller-supplied digest does not itself
    authenticate its source or establish circuit compatibility. Bellman's
    compact A/B query sections remain compact; this validates their encodings
    but does not restore the circuit-specific omitted-point positions needed
    to use those sections as dense proving queries.
    """
    if type(expected_sha256_from_trusted_source) is not bool:
        raise TypeError("expected_sha256_from_trusted_source must be a bool")
    if expected_sha256_from_trusted_source and expected_sha256 is None:
        raise ValueError("a trusted source digest must be supplied")
    if type(expected_blake2b512_from_trusted_source) is not bool:
        raise TypeError("expected_blake2b512_from_trusted_source must be a bool")
    if expected_blake2b512_from_trusted_source and expected_blake2b512 is None:
        raise ValueError("a trusted source digest must be supplied")
    if expected_sha256 is not None and (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in expected_sha256
        )
    ):
        raise ValueError("expected_sha256 must be a 64-character hex digest")
    if expected_blake2b512 is not None and (
        not isinstance(expected_blake2b512, str)
        or len(expected_blake2b512) != 128
        or any(
            character not in "0123456789abcdefABCDEF"
            for character in expected_blake2b512
        )
    ):
        raise ValueError("expected_blake2b512 must be a 128-character hex digest")

    parser = read_parameter_stream(stream, limits, allow_trailing_data)
    for section in parser.sections():
        for _ in section:
            pass

    manifest = parser.manifest
    if expected_sha256 is not None and not hmac.compare_digest(
        manifest.sha256, expected_sha256.lower()
    ):
        raise Groth16ParameterError("parameter stream SHA-256 digest mismatch")
    if expected_blake2b512 is not None and not hmac.compare_digest(
        manifest.blake2b512, expected_blake2b512.lower()
    ):
        raise Groth16ParameterError("parameter stream BLAKE2b-512 digest mismatch")
    return ParameterManifest(
        manifest.format_version,
        manifest.section_counts,
        manifest.sha256,
        manifest.blake2b512,
        manifest.trailing_bytes,
        trusted_digest_verified=(
            expected_sha256_from_trusted_source
            or expected_blake2b512_from_trusted_source
        ),
        _validation_token=_MANIFEST_VALIDATION_TOKEN,
    )
