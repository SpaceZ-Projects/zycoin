import hashlib
import io
import unittest
from dataclasses import replace

from src.bls12_381 import (
    FIELD_MODULUS,
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    Fp2,
    G1Point,
    G2Point,
    decode_g1_uncompressed,
    decode_g2_uncompressed,
    encode_g1_uncompressed,
    encode_g2_uncompressed,
)
from src.groth16_compatibility import (
    SAPLING_OUTPUT_METADATA,
    SAPLING_SPEND_METADATA,
    CircuitMetadata,
    CompatibilityStatus,
    assess_parameter_compatibility,
)
from src.groth16_parameters import (
    Groth16ParameterError,
    ParameterLimits,
    read_parameter_stream,
    validate_parameter_stream,
)


def _counted(points, encoder):
    return len(points).to_bytes(4, "big") + b"".join(
        encoder(point) for point in points
    )


def _parameter_bytes(
    *,
    ic=(G1_GENERATOR,),
    h=(G1_GENERATOR,),
    l=(),
    a=(G1_GENERATOR,),
    b_g1=(G1_GENERATOR,),
    b_g2=(G2_GENERATOR,),
):
    verification_key = b"".join(
        (
            encode_g1_uncompressed(G1_GENERATOR),
            encode_g1_uncompressed(G1_GENERATOR),
            encode_g2_uncompressed(G2_GENERATOR),
            encode_g2_uncompressed(G2_GENERATOR),
            encode_g1_uncompressed(G1_GENERATOR),
            encode_g2_uncompressed(G2_GENERATOR),
            _counted(ic, encode_g1_uncompressed),
        )
    )
    queries = b"".join(
        (
            _counted(h, encode_g1_uncompressed),
            _counted(l, encode_g1_uncompressed),
            _counted(a, encode_g1_uncompressed),
            _counted(b_g1, encode_g1_uncompressed),
            _counted(b_g2, encode_g2_uncompressed),
        )
    )
    return verification_key + queries


def _g2_non_subgroup_point():
    return G2Point(
        Fp2(0, 1),
        Fp2(
            2973677408986561043442465346520108879172042883009249989176415018091420807192182638567116318576472649347015917690530,
            3086196438705319049925973437647385832154519810789273688466929354097832529895965677626713931657629044072635064607771,
        ),
    )


class _ChunkedReader:
    def __init__(self, value: bytes, chunk_size: int = 11) -> None:
        self._stream = io.BytesIO(value)
        self._chunk_size = chunk_size

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self._chunk_size
        return self._stream.read(min(size, self._chunk_size))


def _read_all_sections(parser):
    sections = []
    for section in parser.sections():
        points = tuple(section)
        sections.append((section.name, section.count, section.point_type, points))
    return sections


class UncompressedPointEncodingTests(unittest.TestCase):
    def test_coordinate_order_matches_bls12_381_encoding_spec(self):
        self.assertEqual(
            encode_g1_uncompressed(G1_GENERATOR),
            G1_GENERATOR.x.to_bytes(48, "big")
            + G1_GENERATOR.y.to_bytes(48, "big"),
        )
        self.assertEqual(
            encode_g2_uncompressed(G2_GENERATOR),
            b"".join(
                coordinate.to_bytes(48, "big")
                for coordinate in (
                    G2_GENERATOR.x.c1,
                    G2_GENERATOR.x.c0,
                    G2_GENERATOR.y.c1,
                    G2_GENERATOR.y.c0,
                )
            ),
        )

    def test_generator_and_infinity_round_trips(self):
        for point, encode, decode, size in (
            (G1_GENERATOR, encode_g1_uncompressed, decode_g1_uncompressed, 96),
            (G2_GENERATOR, encode_g2_uncompressed, decode_g2_uncompressed, 192),
            (G1_INFINITY, encode_g1_uncompressed, decode_g1_uncompressed, 96),
            (G2_INFINITY, encode_g2_uncompressed, decode_g2_uncompressed, 192),
        ):
            with self.subTest(point_type=type(point).__name__, size=size):
                encoded = encode(point)
                self.assertEqual(len(encoded), size)
                self.assertEqual(decode(encoded), point)
                self.assertEqual(encode(decode(encoded)), encoded)

    def test_g1_rejects_noncanonical_flags_coordinates_and_curve_points(self):
        valid = encode_g1_uncompressed(G1_GENERATOR)
        with self.assertRaises(ValueError):
            decode_g1_uncompressed(valid[:-1])
        for flag in (0x80, 0x20):
            malformed = bytearray(valid)
            malformed[0] |= flag
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                decode_g1_uncompressed(bytes(malformed))
        noncanonical = FIELD_MODULUS.to_bytes(48, "big") + bytes(48)
        with self.assertRaises(ValueError):
            decode_g1_uncompressed(noncanonical)
        with self.assertRaises(ValueError):
            decode_g1_uncompressed(bytes(96))
        malformed_infinity = b"\x40" + bytes(94) + b"\x01"
        with self.assertRaisesRegex(ValueError, "infinity"):
            decode_g1_uncompressed(malformed_infinity)

    def test_g2_rejects_noncanonical_flags_coordinates_and_curve_points(self):
        valid = encode_g2_uncompressed(G2_GENERATOR)
        with self.assertRaises(ValueError):
            decode_g2_uncompressed(valid[:-1])
        for flag in (0x80, 0x20):
            malformed = bytearray(valid)
            malformed[0] |= flag
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                decode_g2_uncompressed(bytes(malformed))
        noncanonical = FIELD_MODULUS.to_bytes(48, "big") + bytes(144)
        with self.assertRaises(ValueError):
            decode_g2_uncompressed(noncanonical)
        with self.assertRaises(ValueError):
            decode_g2_uncompressed(bytes(192))
        malformed_infinity = b"\x40" + bytes(190) + b"\x01"
        with self.assertRaisesRegex(ValueError, "infinity"):
            decode_g2_uncompressed(malformed_infinity)

    def test_uncompressed_decoders_enforce_subgroup_membership(self):
        g1_non_subgroup = G1Point(0, 2)
        g2_non_subgroup = _g2_non_subgroup_point()
        self.assertTrue(g1_non_subgroup.is_on_curve())
        self.assertFalse(g1_non_subgroup.is_in_subgroup())
        self.assertTrue(g2_non_subgroup.is_on_curve())
        self.assertFalse(g2_non_subgroup.is_in_subgroup())
        with self.assertRaisesRegex(ValueError, "subgroup"):
            decode_g1_uncompressed(encode_g1_uncompressed(g1_non_subgroup))
        with self.assertRaisesRegex(ValueError, "subgroup"):
            decode_g2_uncompressed(encode_g2_uncompressed(g2_non_subgroup))


class Groth16ParameterStreamTests(unittest.TestCase):
    def test_streams_sections_with_validated_metadata_and_point_types(self):
        parser = read_parameter_stream(_ChunkedReader(_parameter_bytes()))
        self.assertEqual(parser.metadata.input_count, 1)
        self.assertEqual(parser.metadata.verification_key.ic, (G1_GENERATOR,))
        self.assertFalse(parser.validated)
        sections = _read_all_sections(parser)
        self.assertEqual(
            [(name, count) for name, count, _, _ in sections],
            [("h", 1), ("l", 0), ("a", 1), ("b_g1", 1), ("b_g2", 1)],
        )
        self.assertIs(sections[0][2], G1Point)
        self.assertIs(sections[-1][2], G2Point)
        self.assertEqual(sections[-1][3], (G2_GENERATOR,))
        self.assertTrue(parser.validated)

    def test_accepts_zero_length_h_and_l_sections(self):
        parser = read_parameter_stream(
            io.BytesIO(_parameter_bytes(h=(), l=()))
        )
        sections = _read_all_sections(parser)
        self.assertEqual(sections[0][1], 0)
        self.assertEqual(sections[1][1], 0)
        self.assertTrue(parser.validated)

    def test_bounds_sections_and_total_stream_size_before_iteration(self):
        encoded = _parameter_bytes(h=(G1_GENERATOR,) * 2)
        with self.assertRaisesRegex(Groth16ParameterError, "section limit"):
            _read_all_sections(
                read_parameter_stream(
                    io.BytesIO(encoded),
                    ParameterLimits(max_points_per_section=1),
                )
            )

    def test_rejects_oversized_count_prefix_before_reading_points(self):
        encoded = bytearray(_parameter_bytes())
        h_prefix = 3 * 96 + 3 * 192 + 4 + 96
        encoded[h_prefix:h_prefix + 4] = (0xFFFFFFFF).to_bytes(4, "big")
        parser = read_parameter_stream(io.BytesIO(encoded))
        with self.assertRaisesRegex(Groth16ParameterError, "section limit"):
            next(parser.sections())

    def test_rejects_bad_query_cardinalities(self):
        cases = (
            ("H domain", _parameter_bytes(h=(G1_GENERATOR,) * 2)),
            ("A count", _parameter_bytes(a=(G1_GENERATOR,) * 2)),
            ("B G1 count", _parameter_bytes(b_g1=())),
            ("B G2 count", _parameter_bytes(b_g2=())),
        )
        for label, encoded in cases:
            with self.subTest(case=label):
                parser = read_parameter_stream(io.BytesIO(encoded))
                with self.assertRaises(Groth16ParameterError):
                    _read_all_sections(parser)

    def test_requires_an_ic_entry_for_the_implicit_one(self):
        with self.assertRaisesRegex(Groth16ParameterError, "include ONE"):
            read_parameter_stream(io.BytesIO(_parameter_bytes(ic=())))

    def test_rejects_truncated_headers_points_and_sections(self):
        encoded = _parameter_bytes()
        cases = (
            encoded[:5],
            encoded[:3 * 96 + 3 * 192 + 2],
            encoded[:-1],
        )
        for truncated in cases:
            with self.subTest(size=len(truncated)), self.assertRaises(
                Groth16ParameterError
            ):
                parser = read_parameter_stream(io.BytesIO(truncated))
                _read_all_sections(parser)

    def test_rejects_trailing_data(self):
        parser = read_parameter_stream(io.BytesIO(_parameter_bytes() + b"\x00"))
        with self.assertRaisesRegex(Groth16ParameterError, "trailing"):
            _read_all_sections(parser)
        self.assertFalse(parser.validated)

    def test_rejects_identity_and_invalid_query_points(self):
        off_curve = bytearray(_parameter_bytes())
        h_point_offset = 3 * 96 + 3 * 192 + 4 + 96 + 4
        off_curve[h_point_offset:h_point_offset + 96] = bytes(96)
        cases = (
            ("identity", _parameter_bytes(h=(G1_INFINITY,))),
            ("L identity", _parameter_bytes(l=(G1_INFINITY,))),
            ("A identity", _parameter_bytes(a=(G1_INFINITY,))),
            ("B_G1 identity", _parameter_bytes(b_g1=(G1_INFINITY,))),
            ("off curve", bytes(off_curve)),
        )
        for label, encoded in cases:
            with self.subTest(case=label):
                parser = read_parameter_stream(io.BytesIO(encoded))
                with self.assertRaises(Groth16ParameterError):
                    _read_all_sections(parser)

    def test_rejects_invalid_and_identity_g2_query_points(self):
        off_curve = bytearray(_parameter_bytes())
        off_curve[-192:] = bytes(192)
        cases = (
            ("identity", _parameter_bytes(b_g2=(G2_INFINITY,))),
            ("off curve", bytes(off_curve)),
        )
        for label, encoded in cases:
            with self.subTest(case=label):
                parser = read_parameter_stream(io.BytesIO(encoded))
                with self.assertRaises(Groth16ParameterError):
                    _read_all_sections(parser)

    def test_rejects_g2_non_subgroup_query_point(self):
        x = Fp2(2, 0)
        y = (x * x * x + Fp2(4, 4)).sqrt()
        self.assertIsNotNone(y)
        assert y is not None
        non_subgroup = G2Point(x, y)
        self.assertTrue(non_subgroup.is_on_curve())
        self.assertFalse(non_subgroup.is_in_subgroup())
        encoded = _parameter_bytes(
            b_g1=(G1_GENERATOR,),
            b_g2=(non_subgroup,),
        )
        parser = read_parameter_stream(io.BytesIO(encoded))
        with self.assertRaisesRegex(Groth16ParameterError, "subgroup"):
            _read_all_sections(parser)

    def test_allows_identity_in_fixed_verification_key_elements(self):
        encoded = bytearray(_parameter_bytes())
        fixed_points = (
            (G1_INFINITY, encode_g1_uncompressed),
            (G1_INFINITY, encode_g1_uncompressed),
            (G2_INFINITY, encode_g2_uncompressed),
            (G2_INFINITY, encode_g2_uncompressed),
            (G1_INFINITY, encode_g1_uncompressed),
            (G2_INFINITY, encode_g2_uncompressed),
        )
        offset = 0
        for point, encoder in fixed_points:
            encoded_point = encoder(point)
            encoded[offset:offset + len(encoded_point)] = encoded_point
            offset += len(encoded_point)
        parser = read_parameter_stream(io.BytesIO(encoded))
        verification_key = parser.metadata.verification_key
        self.assertEqual(
            (
                verification_key.alpha_g1,
                verification_key.beta_g1,
                verification_key.beta_g2,
                verification_key.gamma_g2,
                verification_key.delta_g1,
                verification_key.delta_g2,
            ),
            (G1_INFINITY, G1_INFINITY, G2_INFINITY, G2_INFINITY, G1_INFINITY, G2_INFINITY),
        )

    def test_rejects_identity_in_ic_and_query_elements(self):
        encoded = bytearray(_parameter_bytes(ic=(G1_INFINITY,)))
        ic_point_offset = 3 * 96 + 3 * 192 + 4
        encoded[ic_point_offset:ic_point_offset + 96] = encode_g1_uncompressed(
            G1_INFINITY
        )
        with self.assertRaisesRegex(Groth16ParameterError, "infinity"):
            read_parameter_stream(io.BytesIO(encoded))

    def test_rejects_non_subgroup_query_points(self):
        non_subgroup = G1Point(0, 2)
        encoded = bytearray(_parameter_bytes())
        h_point_offset = 3 * 96 + 3 * 192 + 4 + 96 + 4
        encoded[h_point_offset:h_point_offset + 96] = encode_g1_uncompressed(
            non_subgroup
        )
        parser = read_parameter_stream(io.BytesIO(encoded))
        with self.assertRaisesRegex(Groth16ParameterError, "subgroup"):
            _read_all_sections(parser)

    def test_requires_consuming_each_section_and_prevents_reuse(self):
        parser = read_parameter_stream(io.BytesIO(_parameter_bytes()))
        sections = parser.sections()
        next(sections)
        with self.assertRaises(Groth16ParameterError):
            next(sections)

        parser = read_parameter_stream(io.BytesIO(_parameter_bytes()))
        _read_all_sections(parser)
        with self.assertRaises(Groth16ParameterError):
            parser.sections()

    def test_enforces_byte_and_total_point_limits(self):
        encoded = _parameter_bytes()
        parser = read_parameter_stream(
            io.BytesIO(encoded),
            ParameterLimits(
                max_points_per_section=10,
                max_total_points=7,
                max_total_bytes=4096,
            ),
        )
        with self.assertRaisesRegex(Groth16ParameterError, "total limit"):
            _read_all_sections(parser)
        with self.assertRaisesRegex(Groth16ParameterError, "total limit"):
            validate_parameter_stream(
                io.BytesIO(encoded),
                ParameterLimits(
                    max_points_per_section=10,
                    max_total_points=5,
                    max_total_bytes=4096,
                ),
            )
        with self.assertRaisesRegex(Groth16ParameterError, "byte limit"):
            read_parameter_stream(
                io.BytesIO(encoded),
                ParameterLimits(
                    max_points_per_section=10,
                    max_total_points=100,
                    max_total_bytes=128,
                ),
            )


class ParameterValidationTests(unittest.TestCase):
    def test_returns_canonical_manifest_with_digest_of_original_stream(self):
        encoded = _parameter_bytes()
        manifest = validate_parameter_stream(
            _ChunkedReader(encoded),
            expected_sha256=hashlib.sha256(encoded).hexdigest().upper(),
        )
        self.assertEqual(manifest.format_version, "bellman-0.15.0")
        self.assertEqual(
            manifest.section_counts,
            (("ic", 1), ("h", 1), ("l", 0), ("a", 1), ("b_g1", 1), ("b_g2", 1)),
        )
        self.assertEqual(manifest.sha256, hashlib.sha256(encoded).hexdigest())
        self.assertEqual(
            manifest.canonical_json(),
            f'{{"blake2b512":"{hashlib.blake2b(encoded, digest_size=64).hexdigest()}",'
            '"format_version":"bellman-0.15.0",'
            '"recoverable_metadata":{"application_public_input_count":0,'
            '"auxiliary_query_count":0,"constraint_domain_size":2,'
            '"ic_count_including_one":1,"total_variable_count":1},'
            '"section_counts":{"a":1,"b_g1":1,"b_g2":1,"h":1,"ic":1,"l":0},'
            f'"sha256":"{hashlib.sha256(encoded).hexdigest()}",'
            '"structurally_validated":true,"trailing_bytes":0,'
            '"trusted_digest_verified":false}',
        )
        self.assertEqual(manifest.application_public_input_count, 0)
        self.assertEqual(manifest.auxiliary_query_count, 0)
        self.assertEqual(manifest.total_variable_count, 1)
        self.assertEqual(manifest.constraint_domain_size, 2)

    def test_accepts_compact_identity_omitting_a_and_b_queries(self):
        encoded = _parameter_bytes(a=(), b_g1=(), b_g2=())
        manifest = validate_parameter_stream(io.BytesIO(encoded))
        self.assertEqual(dict(manifest.section_counts)["a"], 0)
        self.assertEqual(dict(manifest.section_counts)["b_g1"], 0)
        self.assertEqual(dict(manifest.section_counts)["b_g2"], 0)
        independent_sparsity = validate_parameter_stream(
            io.BytesIO(
                _parameter_bytes(
                    a=(), b_g1=(G1_GENERATOR,), b_g2=(G2_GENERATOR,)
                )
            )
        )
        self.assertEqual(dict(independent_sparsity.section_counts)["a"], 0)
        self.assertEqual(dict(independent_sparsity.section_counts)["b_g1"], 1)

    def test_validates_without_retaining_query_points(self):
        class ObservedStream(_ChunkedReader):
            def __init__(self, value):
                super().__init__(value)
                self.bytes_returned = 0

            def read(self, size: int = -1) -> bytes:
                result = super().read(size)
                self.bytes_returned += len(result)
                return result

        encoded = _parameter_bytes(h=(G1_GENERATOR,) * 3)
        source = ObservedStream(encoded)
        manifest = validate_parameter_stream(source)
        self.assertEqual(source.bytes_returned, len(encoded))
        self.assertEqual(dict(manifest.section_counts)["h"], 3)

    def test_rejects_bad_expected_digest_without_claiming_authenticity(self):
        encoded = _parameter_bytes()
        with self.assertRaisesRegex(Groth16ParameterError, "digest mismatch"):
            validate_parameter_stream(io.BytesIO(encoded), expected_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "must be supplied"):
            validate_parameter_stream(
                io.BytesIO(encoded),
                expected_sha256_from_trusted_source=True,
            )
        expected_digest = hashlib.sha256(encoded).hexdigest()
        trusted = validate_parameter_stream(
            io.BytesIO(encoded),
            expected_sha256=expected_digest,
            expected_sha256_from_trusted_source=True,
        )
        untrusted = validate_parameter_stream(
            io.BytesIO(encoded), expected_sha256=expected_digest
        )
        self.assertTrue(trusted.trusted_digest_verified)
        self.assertFalse(untrusted.trusted_digest_verified)
        for invalid in ("", "not-a-digest", "0" * 63, "g" * 64):
            with self.subTest(expected_sha256=invalid), self.assertRaises(ValueError):
                validate_parameter_stream(
                    io.BytesIO(encoded), expected_sha256=invalid
                )

    def test_verifies_trusted_blake2b512_digest(self):
        encoded = _parameter_bytes()
        expected_digest = hashlib.blake2b(encoded, digest_size=64).hexdigest()
        trusted = validate_parameter_stream(
            io.BytesIO(encoded),
            expected_blake2b512=expected_digest.upper(),
            expected_blake2b512_from_trusted_source=True,
        )
        self.assertEqual(trusted.blake2b512, expected_digest)
        self.assertTrue(trusted.trusted_digest_verified)
        with self.assertRaisesRegex(Groth16ParameterError, "BLAKE2b-512"):
            validate_parameter_stream(
                io.BytesIO(encoded), expected_blake2b512="0" * 128
            )
        with self.assertRaisesRegex(ValueError, "must be supplied"):
            validate_parameter_stream(
                io.BytesIO(encoded),
                expected_blake2b512_from_trusted_source=True,
            )
        for invalid in ("", "0" * 127, "g" * 128):
            with self.subTest(expected_blake2b512=invalid), self.assertRaises(
                ValueError
            ):
                validate_parameter_stream(
                    io.BytesIO(encoded), expected_blake2b512=invalid
                )

    def test_hashes_bounded_trailing_transcript_bytes_when_enabled(self):
        parameters = _parameter_bytes()
        transcript = b"ceremony transcript"
        encoded = parameters + transcript
        expected_digest = hashlib.blake2b(encoded, digest_size=64).hexdigest()
        manifest = validate_parameter_stream(
            io.BytesIO(encoded),
            expected_blake2b512=expected_digest,
            expected_blake2b512_from_trusted_source=True,
            allow_trailing_data=True,
        )
        self.assertEqual(manifest.trailing_bytes, len(transcript))
        self.assertEqual(manifest.blake2b512, expected_digest)
        with self.assertRaisesRegex(Groth16ParameterError, "byte limit"):
            validate_parameter_stream(
                io.BytesIO(encoded),
                ParameterLimits(max_total_bytes=len(parameters) + 2),
                allow_trailing_data=True,
            )

    def test_truncated_or_altered_trailer_fails_pinned_whole_file_digest(self):
        parameters = _parameter_bytes()
        transcript = b"phase2 transcript fixture"
        encoded = parameters + transcript
        expected_digest = hashlib.sha256(encoded).hexdigest()

        for label, mutated in (
            ("truncated", encoded[:-1]),
            ("altered", encoded[:-1] + bytes([encoded[-1] ^ 1])),
        ):
            with self.subTest(label=label), self.assertRaisesRegex(
                Groth16ParameterError, "SHA-256 digest mismatch"
            ):
                validate_parameter_stream(
                    io.BytesIO(mutated),
                    expected_sha256=expected_digest,
                    expected_sha256_from_trusted_source=True,
                    allow_trailing_data=True,
                )

    def test_opaque_trailer_is_hashed_but_not_cryptographically_interpreted(self):
        parameters = _parameter_bytes()
        opaque_trailer = bytes(52_836)
        encoded = parameters + opaque_trailer
        expected_digest = hashlib.blake2b(encoded, digest_size=64).hexdigest()
        manifest = validate_parameter_stream(
            io.BytesIO(encoded),
            expected_blake2b512=expected_digest,
            expected_blake2b512_from_trusted_source=True,
            allow_trailing_data=True,
        )
        self.assertEqual(manifest.trailing_bytes, 52_836)
        self.assertTrue(manifest.trusted_digest_verified)
        self.assertFalse(hasattr(manifest, "transcript_verified"))

    def test_rejects_structural_count_inconsistencies(self):
        cases = (
            _parameter_bytes(h=(G1_GENERATOR,) * 2),
            _parameter_bytes(b_g1=()),
            _parameter_bytes(b_g2=()),
            _parameter_bytes(a=(G1_GENERATOR,) * 2),
        )
        for encoded in cases:
            with self.subTest(size=len(encoded)), self.assertRaises(
                Groth16ParameterError
            ):
                validate_parameter_stream(io.BytesIO(encoded))

    def test_rejects_non_subgroup_points_in_vk_ic_and_g1_query(self):
        non_subgroup = G1Point(0, 2)
        default = _parameter_bytes()
        fixed_length = 3 * 96 + 3 * 192
        ic_point_offset = fixed_length + 4
        h_point_offset = ic_point_offset + 96 + 4
        cases = (
            ("VK", 0),
            ("IC", ic_point_offset),
            ("H", h_point_offset),
        )
        for label, offset in cases:
            encoded = bytearray(default)
            encoded[offset:offset + 96] = encode_g1_uncompressed(non_subgroup)
            with self.subTest(section=label), self.assertRaisesRegex(
                Groth16ParameterError, "subgroup"
            ):
                validate_parameter_stream(io.BytesIO(encoded))

    def test_rejects_non_subgroup_g2_query_point(self):
        non_subgroup = _g2_non_subgroup_point()
        encoded = bytearray(_parameter_bytes())
        encoded[-192:] = encode_g2_uncompressed(non_subgroup)
        with self.assertRaisesRegex(Groth16ParameterError, "subgroup"):
            validate_parameter_stream(io.BytesIO(encoded))

    def test_rejects_non_subgroup_g2_verification_key_point(self):
        non_subgroup = _g2_non_subgroup_point()
        encoded = bytearray(_parameter_bytes())
        encoded[2 * 96:2 * 96 + 192] = encode_g2_uncompressed(non_subgroup)
        with self.assertRaisesRegex(Groth16ParameterError, "subgroup"):
            validate_parameter_stream(io.BytesIO(encoded))

    def test_rejects_forbidden_infinity_points_and_bad_streams(self):
        cases = (
            ("IC infinity", _parameter_bytes(ic=(G1_INFINITY,))),
            ("H infinity", _parameter_bytes(h=(G1_INFINITY,))),
            ("B_G2 infinity", _parameter_bytes(b_g2=(G2_INFINITY,))),
            ("truncated", _parameter_bytes()[:-1]),
            ("trailing", _parameter_bytes() + b"\x00"),
        )
        for label, encoded in cases:
            with self.subTest(case=label), self.assertRaises(Groth16ParameterError):
                validate_parameter_stream(io.BytesIO(encoded))

    def test_manifest_is_unavailable_until_stream_validation_completes(self):
        parser = read_parameter_stream(io.BytesIO(_parameter_bytes()))
        with self.assertRaisesRegex(Groth16ParameterError, "before full validation"):
            _ = parser.manifest


class CircuitCompatibilityTests(unittest.TestCase):
    def _validated_manifest(self, trusted=False):
        encoded = _parameter_bytes()
        kwargs = {}
        if trusted:
            kwargs = {
                "expected_sha256": hashlib.sha256(encoded).hexdigest(),
                "expected_sha256_from_trusted_source": True,
            }
        return validate_parameter_stream(io.BytesIO(encoded), **kwargs)

    def _tiny_matching_circuit(self):
        return CircuitMetadata(
            circuit_id="synthetic",
            application_public_input_order=(),
            constraint_count=1,
            total_column_count=1,
            auxiliary_column_count=0,
            has_implicit_one=True,
            local_matrix_fingerprint="a" * 64,
            local_matrix_serialization_version="synthetic-matrix-v1",
            trusted_upstream_metadata=True,
            upstream_constraint_count=1,
            upstream_public_input_order=(),
            upstream_total_column_count=1,
            upstream_auxiliary_column_count=0,
            upstream_has_implicit_one=True,
            upstream_matrix_fingerprint="a" * 64,
            upstream_matrix_serialization_version="synthetic-matrix-v1",
        )

    def test_explicit_metadata_covers_spend_and_output_shapes(self):
        self.assertEqual(
            SAPLING_SPEND_METADATA.application_public_input_order,
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
        self.assertEqual(SAPLING_SPEND_METADATA.constraint_count, 98_777)
        self.assertEqual(SAPLING_SPEND_METADATA.total_column_count, 98_646)
        self.assertEqual(SAPLING_SPEND_METADATA.auxiliary_column_count, 98_638)
        self.assertTrue(SAPLING_SPEND_METADATA.has_implicit_one)
        self.assertEqual(len(SAPLING_SPEND_METADATA.local_matrix_fingerprint), 64)
        self.assertEqual(
            SAPLING_SPEND_METADATA.local_matrix_serialization_version,
            "zycoin-r1cs-matrix-v1",
        )

        self.assertEqual(
            SAPLING_OUTPUT_METADATA.application_public_input_order,
            ("cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"),
        )
        self.assertEqual(SAPLING_OUTPUT_METADATA.constraint_count, 7_827)
        self.assertEqual(SAPLING_OUTPUT_METADATA.total_column_count, 7_827)
        self.assertEqual(SAPLING_OUTPUT_METADATA.auxiliary_column_count, 7_821)
        self.assertTrue(SAPLING_OUTPUT_METADATA.has_implicit_one)
        self.assertEqual(
            SAPLING_OUTPUT_METADATA.local_matrix_fingerprint,
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertEqual(
            SAPLING_OUTPUT_METADATA.local_matrix_serialization_version,
            "zycoin-r1cs-matrix-v1",
        )

    def test_equal_counts_do_not_pass_missing_fingerprint_and_order(self):
        assessment = assess_parameter_compatibility(
            self._validated_manifest(trusted=True),
            self._tiny_matching_circuit(),
        )
        self.assertEqual(
            assessment.check("application_public_input_count").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("total_column_count").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("matrix_fingerprint").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("application_public_input_order").status,
            CompatibilityStatus.UNVERIFIED,
        )
        self.assertFalse(assessment.compatible)

    def test_matching_dimensions_with_different_matrix_fingerprints_mismatch(self):
        circuit = replace(
            self._tiny_matching_circuit(),
            upstream_matrix_fingerprint="b" * 64,
        )
        assessment = assess_parameter_compatibility(
            self._validated_manifest(trusted=True), circuit
        )
        self.assertEqual(
            assessment.check("application_public_input_count").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("total_column_count").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("matrix_fingerprint").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertFalse(assessment.compatible)

    def test_untrusted_or_missing_metadata_cannot_pass_gate(self):
        untrusted = assess_parameter_compatibility(
            self._validated_manifest(trusted=False),
            self._tiny_matching_circuit(),
        )
        self.assertEqual(
            untrusted.check("parameter_digest_trust").status,
            CompatibilityStatus.UNVERIFIED,
        )
        self.assertFalse(untrusted.compatible)

        missing = CircuitMetadata(
            circuit_id="missing",
            application_public_input_order=None,
            constraint_count=None,
            total_column_count=None,
            auxiliary_column_count=None,
            has_implicit_one=None,
            local_matrix_fingerprint=None,
            local_matrix_serialization_version=None,
        )
        assessment = assess_parameter_compatibility(
            self._validated_manifest(trusted=True), missing
        )
        for property_name in (
            "application_public_input_count",
            "constraint_count",
            "auxiliary_column_count",
            "total_column_count",
            "implicit_one_handling",
            "matrix_fingerprint",
            "matrix_serialization_version",
        ):
            with self.subTest(property=property_name):
                self.assertEqual(
                    assessment.check(property_name).status,
                    CompatibilityStatus.UNVERIFIED,
                )
        self.assertFalse(assessment.compatible)

    def test_wrong_public_input_count_and_circuit_metadata_mismatch(self):
        circuit = replace(
            self._tiny_matching_circuit(),
            application_public_input_order=("public_0",),
            total_column_count=3,
            auxiliary_column_count=1,
            upstream_constraint_count=2,
        )
        assessment = assess_parameter_compatibility(
            self._validated_manifest(trusted=True), circuit
        )
        self.assertEqual(
            assessment.check("application_public_input_count").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertEqual(
            assessment.check("total_column_count").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertEqual(
            assessment.check("auxiliary_column_count").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertEqual(
            assessment.check("local_vs_upstream_constraint_count").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertFalse(assessment.compatible)

    def test_rejects_manually_constructed_unvalidated_manifest(self):
        manifest = self._validated_manifest()
        unvalidated = type(manifest)(
            manifest.format_version,
            manifest.section_counts,
            manifest.sha256,
            manifest.blake2b512,
        )
        with self.assertRaisesRegex(ValueError, "completed stream validation"):
            assess_parameter_compatibility(
                unvalidated, self._tiny_matching_circuit()
            )

    def test_matching_row_count_is_not_matrix_equivalence(self):
        spend = replace(
            SAPLING_SPEND_METADATA,
            upstream_matrix_fingerprint="0" * 64,
            upstream_matrix_serialization_version="zycoin-r1cs-matrix-v1",
        )
        assessment = assess_parameter_compatibility(
            self._validated_manifest(trusted=True), spend
        )
        self.assertEqual(
            assessment.check("local_vs_upstream_constraint_count").status,
            CompatibilityStatus.VERIFIED,
        )
        self.assertEqual(
            assessment.check("matrix_fingerprint").status,
            CompatibilityStatus.MISMATCHED,
        )
        self.assertFalse(assessment.compatible)


if __name__ == "__main__":
    unittest.main()
