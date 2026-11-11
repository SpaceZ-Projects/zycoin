"""Pinned pure-Python Sapling Output Groth16 proving and verification API.

This API accepts only the hash-pinned official Output parameter file. It does
not validate the ceremony transcript or establish general parameter-to-circuit
binding; see the Sapling Groth16 readiness report for those limitations.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, NoReturn

from .bls12_381 import (
    G1_INFINITY,
    G2_INFINITY,
    SCALAR_MODULUS,
    G1Point,
    G2Point,
    decode_g1,
    decode_g2,
    encode_g1,
    encode_g2,
)
from .groth16_compatibility import SAPLING_OUTPUT_METADATA
from .groth16_parameters import (
    Groth16ParameterError,
    ParameterManifest,
    read_parameter_stream,
)
from .groth16_parameters import (
    Groth16VerificationKey as ParameterVerificationKey,
)
from .groth16_proof import (
    Groth16ProvingQueries,
    ProofAssemblyError,
    assemble_proof_elements,
)
from .groth16_qap import QAP, QAPAssignment, QAPError
from .groth16_queries import (
    G1Query,
    G2Query,
    ValidatedG1Point,
    ValidatedG2Point,
)
from .groth16_verification import (
    Groth16Proof,
    Groth16VerificationError,
    Groth16VerificationKey,
    verify_groth16_proof,
)
from .r1cs import R1CS, R1CSError
from .sapling_gadgets import (
    SaplingOutputWitness,
    constrain_sapling_output,
)

SAPLING_OUTPUT_PUBLIC_INPUT_ORDER: Final = (
    "cv.u",
    "cv.v",
    "epk.u",
    "epk.v",
    "cmu.u",
)

SAPLING_OUTPUT_PARAMETER_SHA256: Final = (
    "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4"
)
SAPLING_OUTPUT_PARAMETER_BLAKE2B512: Final = (
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60"
    "bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028"
)
SAPLING_OUTPUT_PARAMETER_BYTES: Final = 3_592_860
SAPLING_OUTPUT_QUERY_MAPPING_FINGERPRINT: Final = (
    "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2"
)
SAPLING_OUTPUT_MATRIX_FINGERPRINT: Final = (
    "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
)

_VARIABLE_COUNT: Final = 7_827
_A_QUERY_COUNT: Final = 6_298
_B_QUERY_COUNT: Final = 4_850
_H_QUERY_COUNT: Final = 8_191
_L_QUERY_COUNT: Final = 7_821
_TRANSCRIPT_BYTES: Final = 52_836
_MASK_BYTES: Final = (_VARIABLE_COUNT + 7) // 8

# Compressed little-endian bitsets of columns retained by Bellman's compact
# A and B queries. Bits are generated from the pinned query-index mapping.
_A_SUPPORT_MASK_B85: Final = (
    "c-s5_9}3pT@2~s&>+9?5D2&>_|M7!*Og+?Nls>I||L6a}g8lK|U)SAT|GRYmyX"
    "${<jdBJH=P7}Bn{WAiPVqT{L_ATditA#DR~JtxNzo>=KpC-&0KW<h%>"
)
_B_SUPPORT_MASK_B85: Final = (
    "c-lMo9}3+1<!r0Iytug79fk4hKYn12MGw^&8C98U@7wSBKL7vkdi(!}|Nq}Nf"
    "ByIX|G(GY`~SbbZV$+Q#)kU;>_31Ec?JfC2OyDu5BL86bN~PEpYs3yfB*XjsA"
    "~WJ&;S1a|NQtbP?n$J&u{w!Aay|X4F3s({qwF}u8Q)1ooTyv`PVI@oWa5&lrZ"
    "NDIB_Vp5F{jtQl*$8MZCJ1{|Gp(mnNA7%9zCl04GgZXa"
)


class SaplingOutputProofError(ValueError):
    """Raised when an Output proof, witness, or public-input encoding is invalid."""


class SaplingOutputParameterError(ValueError):
    """Raised when parameters are malformed or do not match the supported pins."""


def _decode_support_mask(encoded: str, expected_digest: str) -> bytes:
    try:
        compressed = base64.b85decode(encoded.encode("ascii"))
        mask = zlib.decompress(compressed)
    except (ValueError, UnicodeEncodeError, zlib.error) as error:
        raise RuntimeError("embedded Output query support map is malformed") from error
    if len(mask) != _MASK_BYTES or not hmac.compare_digest(
        hashlib.sha256(compressed).hexdigest(), expected_digest
    ):
        raise RuntimeError("embedded Output query support map failed its pin")
    return mask


_A_SUPPORT_MASK: Final = _decode_support_mask(
    _A_SUPPORT_MASK_B85,
    "1d54fee4b49650396d1b619b755a583ad135a7fe98cdfffd1b25a8cc8ed22901",
)
_B_SUPPORT_MASK: Final = _decode_support_mask(
    _B_SUPPORT_MASK_B85,
    "fd46367ee47983714db29dc4ffbe7ded6cd4e494c8195ce271b38defc676864c",
)


def _support_columns(mask: bytes, expected_count: int) -> tuple[int, ...]:
    columns = tuple(
        index
        for index in range(_VARIABLE_COUNT)
        if mask[index // 8] & (1 << (index % 8))
    )
    if len(columns) != expected_count:
        raise RuntimeError("embedded Output query support count differs from pin")
    unused_bits = (0xFF << (_VARIABLE_COUNT % 8)) & 0xFF
    if mask[-1] & unused_bits:
        raise RuntimeError("embedded Output query support has out-of-range bits")
    return columns


_A_SUPPORT_COLUMNS: Final = _support_columns(_A_SUPPORT_MASK, _A_QUERY_COUNT)
_B_SUPPORT_COLUMNS: Final = _support_columns(_B_SUPPORT_MASK, _B_QUERY_COUNT)


def _expand_sparse_query(
    compact_points: tuple[G1Point, ...] | tuple[G2Point, ...],
    support_columns: tuple[int, ...],
    identity: G1Point | G2Point,
    expected_count: int,
) -> tuple[G1Point, ...] | tuple[G2Point, ...]:
    if len(compact_points) != expected_count or len(support_columns) != expected_count:
        raise SaplingOutputParameterError(
            "compact Output query count does not match the pinned sparse map"
        )
    dense = [identity] * _VARIABLE_COUNT
    for column, point in zip(support_columns, compact_points):
        if point.is_infinity:
            raise SaplingOutputParameterError(
                "serialized compact Output query contains an identity point"
            )
        dense[column] = point
    return tuple(dense)


def _expected_section_counts() -> dict[str, int]:
    return {
        "ic": 6,
        "h": _H_QUERY_COUNT,
        "l": _L_QUERY_COUNT,
        "a": _A_QUERY_COUNT,
        "b_g1": _B_QUERY_COUNT,
        "b_g2": _B_QUERY_COUNT,
    }


def _validate_parameter_manifest(manifest: ParameterManifest) -> None:
    if not manifest.structurally_validated:
        raise SaplingOutputParameterError("parameter stream was not fully validated")
    if (
        manifest.format_version != "bellman-0.15.0"
        or manifest.sha256 != SAPLING_OUTPUT_PARAMETER_SHA256
        or manifest.blake2b512 != SAPLING_OUTPUT_PARAMETER_BLAKE2B512
        or manifest.trailing_bytes != _TRANSCRIPT_BYTES
        or dict(manifest.section_counts) != _expected_section_counts()
    ):
        raise SaplingOutputParameterError(
            "parameters do not match the pinned Sapling Output source and layout"
        )


@dataclass(frozen=True, repr=False, init=False)
class SaplingOutputParameters:
    """Opaque, fully validated official Output parameters.

    Construct instances with :func:`load_sapling_output_parameters`; proving
    queries and key points are intentionally not part of the public interface.
    """

    _queries: Groth16ProvingQueries = field(repr=False)
    _verification_key: Groth16VerificationKey = field(repr=False)
    parameter_sha256: str
    _seal: _ParametersSeal = field(repr=False, compare=False)

    def __new__(
        cls, *args: object, **kwargs: object
    ) -> NoReturn:
        raise TypeError(
            "SaplingOutputParameters must be created by "
            "load_sapling_output_parameters"
        )

    def _validate_issued_state(self) -> None:
        seal = getattr(self, "_seal", None)
        queries = getattr(self, "_queries", None)
        verification_key = getattr(self, "_verification_key", None)
        parameter_sha256 = getattr(self, "parameter_sha256", None)
        if (
            not isinstance(seal, _ParametersSeal)
            or seal.queries is not queries
            or seal.verification_key is not verification_key
            or seal.parameter_sha256 != parameter_sha256
            or parameter_sha256 != SAPLING_OUTPUT_PARAMETER_SHA256
        ):
            raise TypeError(
                "SaplingOutputParameters must be issued by the loader and "
                "must not be altered"
            )


@dataclass(frozen=True)
class _ParametersSeal:
    queries: Groth16ProvingQueries = field(repr=False)
    verification_key: Groth16VerificationKey = field(repr=False)
    parameter_sha256: str


def load_sapling_output_parameters(
    parameter_source: str | Path,
) -> SaplingOutputParameters:
    """Load and fully validate the one supported official Output parameter file.

    The source is accepted only when its complete Bellman serialization and
    trailing transcript bytes match the pinned SHA-256 and BLAKE2b-512 values.
    Every serialized key/query point is checked for curve and subgroup
    membership before this function returns.
    """
    if not isinstance(parameter_source, (str, Path)):
        raise TypeError("parameter_source must be a filesystem path")
    try:
        path = Path(parameter_source).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SaplingOutputParameterError("parameter source is unavailable") from error
    if not path.is_file():
        raise SaplingOutputParameterError("parameter source must be a regular file")
    if path.stat().st_size != SAPLING_OUTPUT_PARAMETER_BYTES:
        raise SaplingOutputParameterError("official Output parameter byte length differs")
    try:
        with path.open("rb") as stream:
            parser = read_parameter_stream(stream, allow_trailing_data=True)
            verification_key = parser.metadata.verification_key
            sections = {
                section.name: tuple(section)
                for section in parser.sections()
            }
            manifest = parser.manifest
    except (OSError, Groth16ParameterError) as error:
        raise SaplingOutputParameterError(
            "official Output parameter stream is malformed"
        ) from error
    _validate_parameter_manifest(manifest)
    a_query = _expand_sparse_query(
        sections["a"], _A_SUPPORT_COLUMNS, G1_INFINITY, _A_QUERY_COUNT
    )
    b_g1_query = _expand_sparse_query(
        sections["b_g1"], _B_SUPPORT_COLUMNS, G1_INFINITY, _B_QUERY_COUNT
    )
    b_g2_query = _expand_sparse_query(
        sections["b_g2"], _B_SUPPORT_COLUMNS, G2_INFINITY, _B_QUERY_COUNT
    )
    queries = Groth16ProvingQueries(
        alpha_g1=ValidatedG1Point(verification_key.alpha_g1),
        beta_g1=ValidatedG1Point(verification_key.beta_g1),
        beta_g2=ValidatedG2Point(verification_key.beta_g2),
        delta_g1=ValidatedG1Point(verification_key.delta_g1),
        delta_g2=ValidatedG2Point(verification_key.delta_g2),
        a_query=G1Query(a_query),
        b_g1_query=G1Query(b_g1_query),
        b_g2_query=G2Query(b_g2_query),
        l_query=G1Query(sections["l"]),
        h_query=G1Query(sections["h"]),
    )
    groth16_verification_key = _verification_key_from_parameters(verification_key)
    seal = _ParametersSeal(queries, groth16_verification_key, manifest.sha256)
    parameters = object.__new__(SaplingOutputParameters)
    object.__setattr__(parameters, "_queries", queries)
    object.__setattr__(parameters, "_verification_key", groth16_verification_key)
    object.__setattr__(parameters, "parameter_sha256", manifest.sha256)
    object.__setattr__(parameters, "_seal", seal)
    return parameters


def _verification_key_from_parameters(
    key: ParameterVerificationKey,
) -> Groth16VerificationKey:
    # The parser's VK has the same point types; keep only verifier material.
    return Groth16VerificationKey(
        alpha_g1=key.alpha_g1,
        beta_g2=key.beta_g2,
        gamma_g2=key.gamma_g2,
        delta_g2=key.delta_g2,
        ic_query=key.ic,
    )


def _synthesize_validated_witness(
    witness: SaplingOutputWitness,
) -> tuple[QAP, QAPAssignment]:
    if not isinstance(witness, SaplingOutputWitness):
        raise TypeError("witness must be a SaplingOutputWitness")
    system = R1CS()
    try:
        constrain_sapling_output(system, witness)
    except (R1CSError, TypeError) as error:
        raise SaplingOutputProofError("Sapling Output witness is invalid") from error

    if (
        system.constraint_count != SAPLING_OUTPUT_METADATA.constraint_count
        or len(system.variables) != SAPLING_OUTPUT_METADATA.total_column_count
        or system.public_input_count
        != SAPLING_OUTPUT_METADATA.application_public_input_count
        or system.matrix_fingerprint() != SAPLING_OUTPUT_MATRIX_FINGERPRINT
    ):
        raise SaplingOutputProofError(
            "synthesized Output circuit does not match supported metadata"
        )
    values = tuple(system.witness_value(variable) for variable in system.variables)
    if any(value is None for value in values):
        raise SaplingOutputProofError("Output witness contains an unassigned variable")

    expected_public_inputs = (
        witness.value_commitment.commitment.u,
        witness.value_commitment.commitment.v,
        witness.ephemeral_key.ephemeral_key.u,
        witness.ephemeral_key.ephemeral_key.v,
        witness.note_commitment.commitment.u,
    )
    if tuple(values[1:6]) != expected_public_inputs:
        raise SaplingOutputProofError(
            "synthesized Output public inputs do not match their pinned order"
        )
    qap = QAP.from_r1cs(system)
    assignment = QAPAssignment(values[1:6], values[6:])
    try:
        qap.validate_assignment(assignment)
    except QAPError as error:
        raise SaplingOutputProofError(
            "Sapling Output witness does not satisfy every circuit constraint"
        ) from error
    if (
        qap.variable_count != _VARIABLE_COUNT
        or qap.auxiliary_variable_count != _L_QUERY_COUNT
        or qap.domain.size != _H_QUERY_COUNT + 1
    ):
        raise SaplingOutputProofError("Output QAP dimensions do not match supported pins")
    return qap, assignment


def prove_sapling_output(
    witness: SaplingOutputWitness,
    parameters: SaplingOutputParameters,
) -> bytes:
    """Create a canonical compressed proof using OS-backed secure randomness.

    No RNG override is accepted. Deterministic randomizers are confined to
    test-only drivers and fixtures. The returned bytes encode G1/G2/G1.
    """
    if not isinstance(parameters, SaplingOutputParameters):
        raise TypeError("parameters must come from load_sapling_output_parameters")
    parameters._validate_issued_state()
    qap, assignment = _synthesize_validated_witness(witness)
    r: int | None = None
    s: int | None = None
    try:
        r = secrets.randbelow(SCALAR_MODULUS)
        s = secrets.randbelow(SCALAR_MODULUS)
        assembled = assemble_proof_elements(
            qap, assignment, parameters._queries, r, s
        )
        return (
            encode_g1(assembled.a)
            + encode_g2(assembled.b)
            + encode_g1(assembled.c)
        )
    except ProofAssemblyError as error:
        raise SaplingOutputProofError("Output proof assembly failed") from error
    finally:
        # Drop local references promptly; Python cannot guarantee memory wiping.
        r = None
        s = None
        del assignment
        del qap


def _decode_public_inputs(
    public_inputs: Mapping[str, bytes],
) -> tuple[int, ...]:
    if not isinstance(public_inputs, Mapping):
        raise TypeError("public_inputs must map Output input names to 32-byte encodings")
    if set(public_inputs) != set(SAPLING_OUTPUT_PUBLIC_INPUT_ORDER):
        raise SaplingOutputProofError(
            "public_inputs must contain exactly the five named Sapling Output inputs"
        )
    values: list[int] = []
    for name in SAPLING_OUTPUT_PUBLIC_INPUT_ORDER:
        encoded = public_inputs[name]
        if not isinstance(encoded, bytes) or len(encoded) != 32:
            raise SaplingOutputProofError(
                f"public input {name} must be a 32-byte little-endian scalar"
            )
        value = int.from_bytes(encoded, "little")
        if value >= SCALAR_MODULUS:
            raise SaplingOutputProofError(
                f"public input {name} is not a canonical scalar encoding"
            )
        values.append(value)
    return tuple(values)


def verify_sapling_output_proof(
    proof_encoding: bytes,
    public_inputs: Mapping[str, bytes],
    parameters: SaplingOutputParameters,
) -> bool:
    """Verify a canonical proof against the pinned Output key and named inputs.

    Returns ``False`` for a well-formed proof that fails the Groth16 equation.
    Malformed encodings or mismatched input names raise
    :class:`SaplingOutputProofError`.
    """
    if not isinstance(parameters, SaplingOutputParameters):
        raise TypeError("parameters must come from load_sapling_output_parameters")
    parameters._validate_issued_state()
    values = _decode_public_inputs(public_inputs)
    if not isinstance(proof_encoding, bytes) or len(proof_encoding) != 192:
        raise SaplingOutputProofError(
            "Output proof must be exactly 192 compressed G1/G2/G1 bytes"
        )
    try:
        a_bytes, b_bytes, c_bytes = (
            proof_encoding[:48],
            proof_encoding[48:144],
            proof_encoding[144:],
        )
        a, b, c = decode_g1(a_bytes), decode_g2(b_bytes), decode_g1(c_bytes)
        if (
            encode_g1(a) != a_bytes
            or encode_g2(b) != b_bytes
            or encode_g1(c) != c_bytes
        ):
            raise SaplingOutputProofError("Output proof encoding is not canonical")
        proof = Groth16Proof(a, b, c)
        return verify_groth16_proof(
            parameters._verification_key,
            proof,
            values,
        )
    except (ValueError, Groth16VerificationError) as error:
        if isinstance(error, SaplingOutputProofError):
            raise
        raise SaplingOutputProofError("Output proof encoding is invalid") from error


__all__ = [
    "SAPLING_OUTPUT_MATRIX_FINGERPRINT",
    "SAPLING_OUTPUT_PARAMETER_BLAKE2B512",
    "SAPLING_OUTPUT_PARAMETER_BYTES",
    "SAPLING_OUTPUT_PARAMETER_SHA256",
    "SAPLING_OUTPUT_PUBLIC_INPUT_ORDER",
    "SAPLING_OUTPUT_QUERY_MAPPING_FINGERPRINT",
    "SaplingOutputParameterError",
    "SaplingOutputParameters",
    "SaplingOutputProofError",
    "load_sapling_output_parameters",
    "prove_sapling_output",
    "verify_sapling_output_proof",
]
