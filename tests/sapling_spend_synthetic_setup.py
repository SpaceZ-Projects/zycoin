"""Insecure, test-only full-size Groth16 setup helpers for Sapling Spend.

The setup uses published-in-test-source toxic-waste scalars. Its private file
format is deliberately incompatible with the production Bellman parameter
loader. Never use these keys or proofs outside test fixtures.
"""

from __future__ import annotations

import array
import hashlib
import json
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from src.bls12_381 import (
    FIELD_MODULUS,
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
    Fp2,
    G1Point,
    G2Point,
    _add_g1_projective,
    _add_g2_projective,
    _double_g1_projective,
    _double_g2_projective,
    decode_g1_uncompressed,
    decode_g2_uncompressed,
    encode_g1_uncompressed,
    encode_g2_uncompressed,
)
from src.groth16_proof import Groth16ProvingQueries
from src.groth16_qap import QAP
from src.groth16_queries import (
    G1Query,
    G2Query,
    ValidatedG1Point,
    ValidatedG2Point,
)
from src.groth16_verification import Groth16VerificationKey

_MAGIC = b"ZYCOIN-TEST-SYNTH-G16\x00\x01"
_FORMAT = "zycoin-test-only-insecure-synthetic-groth16-v1"
_CIRCUIT_ID = "sapling-spend-local"
_LOCAL_MATRIX_FINGERPRINT = (
    "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9"
)
_TOXIC_WASTE = {
    "alpha": 3,
    "beta": 5,
    "gamma": 7,
    "delta": 11,
    "tau": 2,
}
_SECTION_ORDER = (
    ("vk_alpha_g1", "g1", "alpha"),
    ("vk_beta_g1", "g1", "beta"),
    ("vk_beta_g2", "g2", "beta"),
    ("vk_gamma_g2", "g2", "gamma"),
    ("vk_delta_g1", "g1", "delta"),
    ("vk_delta_g2", "g2", "delta"),
    ("ic", "g1", "ic"),
    ("h", "g1", "h"),
    ("l", "g1", "l"),
    ("a", "g1", "a"),
    ("b_g1", "g1", "b"),
    ("b_g2", "g2", "b"),
)
_POINT_BYTES = {"g1": 96, "g2": 192}
_HEADER_LIMIT = 16_384
_FILE_LIMIT = 128 * 1024 * 1024


class SyntheticParameterError(ValueError):
    """Malformed or mismatched test-only synthetic parameter file."""


@dataclass(frozen=True)
class SyntheticSpendParameters:
    """Loaded test-only key and query vectors, bound to one local matrix."""

    circuit_fingerprint: str
    toxic_waste: tuple[int, int, int, int, int]
    queries: Groth16ProvingQueries
    verification_key: Groth16VerificationKey
    file_sha256: str
    file_size: int


def _barycentric_weights_at_tau(qap: QAP, tau: int) -> list[int]:
    """Compute Lagrange basis values with one batch inversion."""
    size = qap.domain.size
    modulus = SCALAR_MODULUS
    omega = qap.domain.fft_domain.omega
    denominators = [0] * size
    prefixes = [1] * (size + 1)
    omega_power = 1
    for row in range(size):
        denominators[row] = (tau - omega_power) % modulus
        if denominators[row] == 0:
            raise SyntheticParameterError("tau lies in the QAP evaluation domain")
        prefixes[row + 1] = prefixes[row] * denominators[row] % modulus
        omega_power = omega_power * omega % modulus

    inverse_product = pow(prefixes[size], -1, modulus)
    inverse_denominators = [0] * size
    for row in range(size - 1, -1, -1):
        inverse_denominators[row] = inverse_product * prefixes[row] % modulus
        inverse_product = inverse_product * denominators[row] % modulus

    vanishing = (pow(tau, size, modulus) - 1) % modulus
    scale = vanishing * pow(size, -1, modulus) % modulus
    weights = [0] * size
    omega_power = pow(omega, size - 1, modulus)
    for row in range(size - 1, -1, -1):
        weights[row] = scale * omega_power * inverse_denominators[row] % modulus
        omega_power = omega_power * qap.domain.fft_domain.omega_inverse % modulus
    return weights


def _row_major_query_scalars(
    qap: QAP, weights: Sequence[int]
) -> tuple[list[int], list[int], list[int]]:
    modulus = SCALAR_MODULUS
    variable_count = qap.variable_count
    sums = [[0] * variable_count for _ in range(3)]
    for row_index, constraint in enumerate(qap.system.iter_constraints()):
        weight = weights[row_index]
        for side, expression in enumerate(
            (constraint.left, constraint.right, constraint.output)
        ):
            target = sums[side]
            for variable_index, coefficient in expression.terms:
                target[variable_index] = (
                    target[variable_index] + coefficient * weight
                ) % modulus

    input_count = qap.domain.input_count
    for input_index in range(input_count):
        row_index = qap.domain.constraint_count + input_index
        sums[0][input_index] = (sums[0][input_index] + weights[row_index]) % modulus
    return sums[0], sums[1], sums[2]


def _column_major_reference(qap: QAP, weights: Sequence[int], side: int) -> list[int]:
    """Independent CSC traversal for every column's QAP value at tau."""
    variable_count = qap.variable_count
    input_count = qap.domain.input_count
    counts = [0] * variable_count
    expressions = ("left", "right", "output")
    for constraint in qap.system.iter_constraints():
        for variable_index, _ in getattr(constraint, expressions[side]).terms:
            counts[variable_index] += 1
    if side == 0:
        for input_index in range(input_count):
            counts[input_index] += 1

    offsets = [0] * (variable_count + 1)
    for index, count in enumerate(counts):
        offsets[index + 1] = offsets[index] + count
    cursors = array.array("I", offsets[:-1])
    term_rows = array.array("I", [0]) * offsets[-1]
    term_coefficients = bytearray(offsets[-1] * 32)

    for row_index, constraint in enumerate(qap.system.iter_constraints()):
        expression = getattr(constraint, expressions[side])
        for variable_index, coefficient in expression.terms:
            position = cursors[variable_index]
            cursors[variable_index] += 1
            term_rows[position] = row_index
            start = position * 32
            term_coefficients[start : start + 32] = coefficient.to_bytes(32, "big")
    if side == 0:
        for input_index in range(input_count):
            position = cursors[input_index]
            cursors[input_index] += 1
            term_rows[position] = qap.domain.constraint_count + input_index
            start = position * 32
            term_coefficients[start : start + 32] = (1).to_bytes(32, "big")

    result = [0] * variable_count
    for variable_index in range(variable_count):
        total = 0
        for position in range(offsets[variable_index], offsets[variable_index + 1]):
            start = position * 32
            coefficient = int.from_bytes(term_coefficients[start : start + 32], "big")
            total += coefficient * weights[term_rows[position]]
        result[variable_index] = total % SCALAR_MODULUS
    return result


def _expected_counts(qap: QAP) -> dict[str, int]:
    return {
        "vk_alpha_g1": 1,
        "vk_beta_g1": 1,
        "vk_beta_g2": 1,
        "vk_gamma_g2": 1,
        "vk_delta_g1": 1,
        "vk_delta_g2": 1,
        "ic": qap.domain.input_count,
        "h": qap.domain.size - 1,
        "l": qap.auxiliary_variable_count,
        "a": qap.variable_count,
        "b_g1": qap.variable_count,
        "b_g2": qap.variable_count,
    }


def _header(qap: QAP) -> dict[str, object]:
    return {
        "format": _FORMAT,
        "security": "INSECURE TEST MATERIAL; TOXIC WASTE IS PUBLIC AND KNOWN",
        "circuit_id": _CIRCUIT_ID,
        "circuit_fingerprint": qap.system.matrix_fingerprint(),
        "rows": qap.system.constraint_count,
        "columns": qap.variable_count,
        "public_inputs_including_one": qap.domain.input_count,
        "domain_size": qap.domain.size,
        "section_counts": _expected_counts(qap),
        "toxic_waste_scalars": _TOXIC_WASTE,
        "point_encoding": "canonical uncompressed BLS12-381; identity permitted",
    }


def _fixed_base_tables(group: str) -> list[list[tuple]]:
    window_count = 32
    if group == "g1":
        base = (G1_GENERATOR.x, G1_GENERATOR.y, 1)
        tables = []
        for _ in range(window_count):
            entries = [(0, 1, 0)]
            current = (0, 1, 0)
            for _digit in range(1, 256):
                current = _add_g1_projective(current, base, FIELD_MODULUS)
                entries.append(current)
            tables.append(entries)
            for _ in range(8):
                base = _double_g1_projective(base, FIELD_MODULUS)
        return tables

    base = (G2_GENERATOR.x, G2_GENERATOR.y, Fp2(1))
    tables = []
    for _ in range(window_count):
        zero = Fp2()
        entries = [(zero, Fp2(1), zero)]
        current = (zero, Fp2(1), zero)
        for _digit in range(1, 256):
            current = _add_g2_projective(current, base)
            entries.append(current)
        tables.append(entries)
        for _ in range(8):
            base = _double_g2_projective(base)
    return tables


def _normalize_g1_batch(
    points: Sequence[tuple[int, int, int]],
) -> list[G1Point]:
    prefixes = [1]
    modulus = FIELD_MODULUS
    for _, _, z in points:
        prefixes.append(prefixes[-1] if z == 0 else prefixes[-1] * z % modulus)
    inverse_product = pow(prefixes[-1], -1, modulus)
    output = [None] * len(points)
    for index in range(len(points) - 1, -1, -1):
        x, y, z = points[index]
        if z == 0:
            output[index] = G1_INFINITY
            continue
        inverse_z = inverse_product * prefixes[index] % modulus
        inverse_product = inverse_product * z % modulus
        inverse_z_squared = inverse_z * inverse_z % modulus
        output[index] = G1Point(
            x * inverse_z_squared % modulus,
            y * inverse_z_squared * inverse_z % modulus,
        )
    return output


def _normalize_g2_batch(
    points: Sequence[tuple[Fp2, Fp2, Fp2]],
) -> list[G2Point]:
    prefixes = [Fp2(1)]
    for _, _, z in points:
        prefixes.append(prefixes[-1] if z == Fp2() else prefixes[-1] * z)
    inverse_product = prefixes[-1].inverse()
    output = [None] * len(points)
    for index in range(len(points) - 1, -1, -1):
        x, y, z = points[index]
        if z == Fp2():
            output[index] = G2_INFINITY
            continue
        inverse_z = inverse_product * prefixes[index]
        inverse_product = inverse_product * z
        inverse_z_squared = inverse_z * inverse_z
        output[index] = G2Point(
            x * inverse_z_squared,
            y * inverse_z_squared * inverse_z,
        )
    return output


def _iter_fixed_base_points(
    group: str, scalars: Iterable[int]
) -> Iterable[G1Point | G2Point]:
    """Fixed-window setup-point generation with bounded batch normalization."""
    tables = _fixed_base_tables(group)
    if group == "g1":
        infinity = (0, 1, 0)

        def add_projective(left, right):
            return _add_g1_projective(left, right, FIELD_MODULUS)

        normalize = _normalize_g1_batch
    else:
        zero = Fp2()
        infinity = (zero, Fp2(1), zero)
        add_projective = _add_g2_projective
        normalize = _normalize_g2_batch

    projective_batch = []
    for scalar in scalars:
        if type(scalar) is not int or not 0 <= scalar < SCALAR_MODULUS:
            raise SyntheticParameterError("setup exponent is not canonical")
        result = infinity
        window = 0
        while scalar:
            digit = scalar & 0xFF
            if digit:
                result = add_projective(result, tables[window][digit])
            scalar >>= 8
            window += 1
        projective_batch.append(result)
        if len(projective_batch) == 512:
            yield from normalize(projective_batch)
            projective_batch.clear()
    if projective_batch:
        yield from normalize(projective_batch)


def _write_synthetic_parameter_file(qap: QAP, destination: Path) -> tuple[str, int]:
    if qap.system.matrix_fingerprint() != _LOCAL_MATRIX_FINGERPRINT:
        raise SyntheticParameterError("refusing non-local Spend circuit")
    toxic = _TOXIC_WASTE
    alpha, beta, gamma, delta, tau = (
        toxic[name] for name in ("alpha", "beta", "gamma", "delta", "tau")
    )
    modulus = SCALAR_MODULUS
    weights = _barycentric_weights_at_tau(qap, tau)
    a_values, b_values, c_values = _row_major_query_scalars(qap, weights)

    extended = [
        (beta * a_values[index] + alpha * b_values[index] + c_values[index]) % modulus
        for index in range(qap.variable_count)
    ]
    gamma_inverse = pow(gamma, -1, modulus)
    delta_inverse = pow(delta, -1, modulus)
    ic_values = tuple(
        extended[index] * gamma_inverse % modulus
        for index in range(qap.domain.input_count)
    )
    l_values = tuple(
        extended[index] * delta_inverse % modulus
        for index in range(qap.domain.input_count, qap.variable_count)
    )
    vanishing = (pow(tau, qap.domain.size, modulus) - 1) % modulus
    h_values = [0] * (qap.domain.size - 1)
    tau_power = 1
    for index in range(len(h_values)):
        h_values[index] = tau_power * vanishing * delta_inverse % modulus
        tau_power = tau_power * tau % modulus

    scalar_sections: dict[str, Sequence[int] | Iterable[int]] = {
        "vk_alpha_g1": (alpha,),
        "vk_beta_g1": (beta,),
        "vk_beta_g2": (beta,),
        "vk_gamma_g2": (gamma,),
        "vk_delta_g1": (delta,),
        "vk_delta_g2": (delta,),
        "ic": ic_values,
        "h": h_values,
        "l": l_values,
        "a": a_values,
        "b_g1": b_values,
        "b_g2": b_values,
    }
    header = json.dumps(
        _header(qap), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(header) > _HEADER_LIMIT:
        raise SyntheticParameterError("synthetic parameter header exceeds limit")

    digest = hashlib.sha256()
    with destination.open("wb") as stream:

        def write(data: bytes) -> None:
            stream.write(data)
            digest.update(data)

        write(_MAGIC)
        write(struct.pack(">I", len(header)))
        write(header)
        for name, group, _ in _SECTION_ORDER:
            encoded_name = name.encode("ascii")
            scalars = scalar_sections[name]
            count = _expected_counts(qap)[name]
            if len(scalars) != count:
                raise SyntheticParameterError(f"{name} scalar count is inconsistent")
            write(bytes((len(encoded_name),)))
            write(encoded_name)
            write(struct.pack(">I", count))
            if group == "g1":
                encoder = encode_g1_uncompressed
            else:
                encoder = encode_g2_uncompressed
            for point in _iter_fixed_base_points(group, scalars):
                write(encoder(point))
        file_digest = digest.digest()
        stream.write(file_digest)
        stream.flush()
    return file_digest.hex(), destination.stat().st_size


def _trusted_generated_g1(point: G1Point) -> ValidatedG1Point:
    if not point.is_on_curve():
        raise SyntheticParameterError("serialized G1 point is not on curve")
    # Every byte is hash-checked against the file just written; the writer
    # derives points only by multiplying the prime-order G1 generator.
    wrapped = object.__new__(ValidatedG1Point)
    object.__setattr__(wrapped, "point", point)
    return wrapped


def _trusted_generated_g2(point: G2Point) -> ValidatedG2Point:
    if not point.is_on_curve():
        raise SyntheticParameterError("serialized G2 point is not on curve")
    wrapped = object.__new__(ValidatedG2Point)
    object.__setattr__(wrapped, "point", point)
    return wrapped


def _read_exact(stream: BinaryIO, length: int, digest: hashlib._Hash) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise SyntheticParameterError("truncated test-only parameter file")
    digest.update(value)
    return value


def _load_synthetic_parameter_file(
    source: Path,
    qap: QAP,
    expected_file_sha256: str,
) -> SyntheticSpendParameters:
    file_size = source.stat().st_size
    if file_size > _FILE_LIMIT:
        raise SyntheticParameterError("test-only parameter file exceeds size limit")
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        if _read_exact(stream, len(_MAGIC), digest) != _MAGIC:
            raise SyntheticParameterError("not a test-only synthetic parameter file")
        header_length = struct.unpack(">I", _read_exact(stream, 4, digest))[0]
        if not 1 <= header_length <= _HEADER_LIMIT:
            raise SyntheticParameterError("invalid test-only header length")
        try:
            header = json.loads(
                _read_exact(stream, header_length, digest).decode("ascii")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SyntheticParameterError(
                "malformed test-only parameter header"
            ) from error
        if header != _header(qap):
            raise SyntheticParameterError("test-only parameters do not match circuit")
        if header["security"] != (
            "INSECURE TEST MATERIAL; TOXIC WASTE IS PUBLIC AND KNOWN"
        ):
            raise SyntheticParameterError("synthetic security marker is missing")

        loaded: dict[str, list[ValidatedG1Point] | list[ValidatedG2Point]] = {}
        for name, group, _ in _SECTION_ORDER:
            name_length = _read_exact(stream, 1, digest)[0]
            if not 1 <= name_length <= 32:
                raise SyntheticParameterError("invalid section name length")
            section_name = _read_exact(stream, name_length, digest).decode("ascii")
            count = struct.unpack(">I", _read_exact(stream, 4, digest))[0]
            if section_name != name or count != _expected_counts(qap)[name]:
                raise SyntheticParameterError("synthetic section order/count mismatch")
            point_list: list[ValidatedG1Point] | list[ValidatedG2Point] = []
            point_size = _POINT_BYTES[group]
            for _ in range(count):
                encoded = _read_exact(stream, point_size, digest)
                try:
                    if group == "g1":
                        point = decode_g1_uncompressed(encoded, check_subgroup=False)
                        wrapper = _trusted_generated_g1(point)
                    else:
                        point = decode_g2_uncompressed(encoded, check_subgroup=False)
                        wrapper = _trusted_generated_g2(point)
                except ValueError as error:
                    raise SyntheticParameterError(
                        f"invalid synthetic {group.upper()} encoding"
                    ) from error
                point_list.append(wrapper)
            loaded[name] = point_list
        content_digest = digest.digest()
        footer = stream.read(32)
        if len(footer) != 32 or footer != content_digest or stream.read(1):
            raise SyntheticParameterError(
                "synthetic parameter checksum/trailer mismatch"
            )
        if content_digest.hex() != expected_file_sha256:
            raise SyntheticParameterError("synthetic parameter file digest mismatch")

    alpha_g1 = loaded["vk_alpha_g1"][0]
    beta_g1 = loaded["vk_beta_g1"][0]
    beta_g2 = loaded["vk_beta_g2"][0]
    gamma_g2 = loaded["vk_gamma_g2"][0]
    delta_g1 = loaded["vk_delta_g1"][0]
    delta_g2 = loaded["vk_delta_g2"][0]
    ic = tuple(point.point for point in loaded["ic"])
    queries = Groth16ProvingQueries(
        alpha_g1=alpha_g1,
        beta_g1=beta_g1,
        beta_g2=beta_g2,
        delta_g1=delta_g1,
        delta_g2=delta_g2,
        a_query=G1Query(loaded["a"]),
        b_g1_query=G1Query(loaded["b_g1"]),
        b_g2_query=G2Query(loaded["b_g2"]),
        l_query=G1Query(loaded["l"]),
        h_query=G1Query(loaded["h"]),
    )
    verification_key = Groth16VerificationKey(
        alpha_g1=alpha_g1,
        beta_g2=beta_g2,
        gamma_g2=gamma_g2,
        delta_g2=delta_g2,
        ic_query=ic,
    )
    return SyntheticSpendParameters(
        circuit_fingerprint=header["circuit_fingerprint"],
        toxic_waste=tuple(
            _TOXIC_WASTE[name] for name in ("alpha", "beta", "gamma", "delta", "tau")
        ),
        queries=queries,
        verification_key=verification_key,
        file_sha256=content_digest.hex(),
        file_size=file_size,
    )


def _reference_qap_column_value(
    qap: QAP, side: int, variable_index: int, tau: int
) -> int:
    """Independent single-column reference using inverse FFT interpolation."""
    expressions = ("left", "right", "output")
    evaluations = [0] * qap.domain.size
    for row_index, constraint in enumerate(qap.system.iter_constraints()):
        for index, coefficient in getattr(constraint, expressions[side]).terms:
            if index == variable_index:
                evaluations[row_index] = coefficient
                break
    if side == 0 and variable_index < qap.domain.input_count:
        evaluations[qap.domain.constraint_count + variable_index] = 1
    coefficients = qap.domain.fft_domain.ifft(evaluations)
    value = 0
    for coefficient in reversed(coefficients):
        value = (value * tau + coefficient) % SCALAR_MODULUS
    return value


def _reference_witness_qap_at_tau(
    qap: QAP, assignment_values: Sequence[int], weights: Sequence[int]
) -> tuple[int, int, int]:
    result = [0, 0, 0]
    for row_index, constraint in enumerate(qap.system.iter_constraints()):
        for side, expression in enumerate(
            (constraint.left, constraint.right, constraint.output)
        ):
            value = 0
            for variable_index, coefficient in expression.terms:
                value += coefficient * assignment_values[variable_index]
            result[side] = (
                result[side] + (value % SCALAR_MODULUS) * weights[row_index]
            ) % SCALAR_MODULUS
    for input_index, value in enumerate(assignment_values[: qap.domain.input_count]):
        row_index = qap.domain.constraint_count + input_index
        result[0] = (result[0] + value * weights[row_index]) % SCALAR_MODULUS
    return result[0], result[1], result[2]


def _scalar_vector_sha256(values: Sequence[int]) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.to_bytes(32, "little"))
    return digest.hexdigest()
