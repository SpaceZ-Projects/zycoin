"""Pure-Python reproduction of the pinned Sapling Spend test inputs.

This module computes reference values outside the R1CS gadgets. It is not a
Spend circuit assembler or an implementation of Bellman's constraint system.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from hashlib import blake2s

from .bls12_381 import SCALAR_MODULUS as BLS_SCALAR_MODULUS
from .jubjub import (
    CURVE_D,
    IDENTITY,
    Point,
    find_group_hash,
    group_hash,
    proving_key_base,
    spending_key_base,
)
from .jubjub import FIELD_MODULUS as JUBJUB_BASE_MODULUS
from .jubjub import SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS

PINNED_SAPLING_CRYPTO_COMMIT = "88a7946b4a3066787776e11f0a502654167e022d"
PINNED_ZCASH_TEST_VECTORS_COMMIT = "78321beacb0e0477e33cd002b56585a107c2708c"
PINNED_TEST_SEED = bytes.fromhex("5862be3d763d318d17db37325406bce5")
EXTERNAL_CV_TEST_SEED = bytes.fromhex("5962be3d763d318d17db37325406bce5")
RNG_VERSION = "rand_xorshift 0.5.0 / rand_core 0.10.1"
PUBLIC_INPUT_ORDER = (
    "rk.u",
    "rk.v",
    "cv.u",
    "cv.v",
    "anchor",
    "nullifier_chunk_0",
    "nullifier_chunk_1",
)


class XorShiftRng:
    """rand_xorshift 0.5.0 with rand_core 0.10.1 byte/word conventions."""

    def __init__(self, seed: bytes) -> None:
        if not isinstance(seed, bytes) or len(seed) != 16:
            raise ValueError("XorShiftRng seed must be exactly 16 bytes")
        self._state = [
            int.from_bytes(seed[offset:offset + 4], "little")
            for offset in range(0, 16, 4)
        ]
        if not any(self._state):
            self._state = [0xBAD5EED] * 4

    def next_u32(self) -> int:
        x, y, z, w = self._state
        t = (x ^ ((x << 11) & 0xFFFFFFFF)) & 0xFFFFFFFF
        result = (w ^ (w >> 19) ^ t ^ (t >> 8)) & 0xFFFFFFFF
        self._state[:] = [y, z, w, result]
        return result

    def next_u64(self) -> int:
        low = self.next_u32()
        high = self.next_u32()
        return low | (high << 32)

    def fill_bytes(self, length: int) -> bytes:
        if isinstance(length, bool) or not isinstance(length, int) or length < 0:
            raise ValueError("byte count must be a non-negative integer")
        output = bytearray()
        while len(output) < length:
            output.extend(self.next_u32().to_bytes(4, "little"))
        return bytes(output[:length])

    def random_field(self, modulus: int) -> int:
        if modulus <= 0:
            raise ValueError("field modulus must be positive")
        return int.from_bytes(self.fill_bytes(64), "little") % modulus

    def random_jubjub_scalar(self) -> int:
        return self.random_field(JUBJUB_SCALAR_MODULUS)

    def random_bls_scalar(self) -> int:
        return self.random_field(BLS_SCALAR_MODULUS)

    def random_jubjub_subgroup_point(self) -> Point:
        while True:
            v = self.random_field(JUBJUB_BASE_MODULUS)
            sign = self.next_u32() % 2
            encoded = bytearray(v.to_bytes(32, "little"))
            encoded[31] |= sign << 7
            try:
                point = Point.from_bytes(bytes(encoded))._multiply_unreduced(8)
            except ValueError:
                continue
            if point != IDENTITY:
                return point


@dataclass(frozen=True)
class SpendReferenceWitness:
    value: int
    rcv: int
    ak: Point
    nsk: int
    nk: Point
    ivk: int
    diversifier: bytes
    diversifier_base: Point
    transmission_key: Point
    rcm: int
    note_commitment: Point
    ar: int
    randomized_key: Point
    value_commitment: Point
    authentication_path: tuple[tuple[int, bool], ...]
    position: int
    anchor: int
    nullifier: bytes
    public_inputs: tuple[int, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "rcv": _scalar_hex(self.rcv),
            "proof_generation_key": {
                "ak": self.ak.encode().hex(),
                "nsk": _scalar_hex(self.nsk),
            },
            "nk": self.nk.encode().hex(),
            "ivk": _scalar_hex(self.ivk),
            "payment_address": {
                "diversifier": self.diversifier.hex(),
                "g_d": self.diversifier_base.encode().hex(),
                "pk_d": self.transmission_key.encode().hex(),
            },
            "rcm": _scalar_hex(self.rcm),
            "note_commitment": {
                "point": self.note_commitment.encode().hex(),
                "cmu": _base_hex(self.note_commitment.u),
            },
            "ar": _scalar_hex(self.ar),
            "rk": {
                "u": self.randomized_key.u,
                "v": self.randomized_key.v,
                "encoding": self.randomized_key.encode().hex(),
            },
            "cv": {
                "u": self.value_commitment.u,
                "v": self.value_commitment.v,
            },
            "authentication_path": [
                {"sibling": _base_hex(sibling), "direction": direction}
                for sibling, direction in self.authentication_path
            ],
            "position": self.position,
            "anchor": _base_hex(self.anchor),
            "nullifier": self.nullifier.hex(),
            "public_input_order": list(PUBLIC_INPUT_ORDER),
            "public_inputs": list(self.public_inputs),
            "bellman_implicit_one": 1,
        }


def _scalar_hex(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def _base_hex(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def _bits_le(value: int, width: int) -> list[int]:
    return [(value >> bit) & 1 for bit in range(width)]


def _repr_bits(point: Point) -> list[int]:
    return _bits_le(point.v, 255) + [point.u & 1]


def _pedersen_generators(count: int) -> tuple[Point, ...]:
    return tuple(
        find_group_hash(b"Zcash_PH", index.to_bytes(4, "little"))
        for index in range(count)
    )


_PROJECTIVE_IDENTITY = (0, 1, 1, 0)


def _projective_add(left, right):
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % JUBJUB_BASE_MODULUS
    b = (y1 + x1) * (y2 + x2) % JUBJUB_BASE_MODULUS
    c = 2 * CURVE_D * t1 * t2 % JUBJUB_BASE_MODULUS
    d_term = 2 * z1 * z2 % JUBJUB_BASE_MODULUS
    e = (b - a) % JUBJUB_BASE_MODULUS
    f = (d_term - c) % JUBJUB_BASE_MODULUS
    g = (d_term + c) % JUBJUB_BASE_MODULUS
    h = (b + a) % JUBJUB_BASE_MODULUS
    return (
        e * f % JUBJUB_BASE_MODULUS,
        g * h % JUBJUB_BASE_MODULUS,
        f * g % JUBJUB_BASE_MODULUS,
        e * h % JUBJUB_BASE_MODULUS,
    )


def _projective_multiply(point: Point, scalar: int):
    addend = (point.u, point.v, 1, point.u * point.v % JUBJUB_BASE_MODULUS)
    result = _PROJECTIVE_IDENTITY
    while scalar:
        if scalar & 1:
            result = _projective_add(result, addend)
        addend = _projective_add(addend, addend)
        scalar >>= 1
    return result


def _projective_to_point(point) -> Point:
    x, y, z, _ = point
    inverse = pow(z, JUBJUB_BASE_MODULUS - 2, JUBJUB_BASE_MODULUS)
    return Point(
        x * inverse % JUBJUB_BASE_MODULUS,
        y * inverse % JUBJUB_BASE_MODULUS,
    )


@lru_cache(maxsize=1)
def _value_commitment_generators() -> tuple[Point, Point]:
    return (
        find_group_hash(b"Zcash_cv", b"v"),
        find_group_hash(b"Zcash_cv", b"r"),
    )


@lru_cache(maxsize=1)
def _note_randomness_generator() -> Point:
    return find_group_hash(b"Zcash_PH", b"r")


@lru_cache(maxsize=1)
def _nullifier_position_generator() -> Point:
    return find_group_hash(b"Zcash_J_", b"")


def _pedersen_hash(bits: list[int], generators: tuple[Point, ...]) -> Point:
    padded = bits + [0] * (-len(bits) % 3)
    result = _PROJECTIVE_IDENTITY
    for segment_index, offset in enumerate(range(0, len(padded), 189)):
        if segment_index >= len(generators):
            raise ValueError("Pedersen input exceeds generator capacity")
        accumulator = 0
        power = 1
        for index in range(offset, min(offset + 189, len(padded)), 3):
            s0, s1, s2 = padded[index:index + 3]
            chunk = (1 + s0 + 2 * s1) * (-1 if s2 else 1)
            accumulator = (
                accumulator + chunk * power
            ) % JUBJUB_SCALAR_MODULUS
            power = power * 16 % JUBJUB_SCALAR_MODULUS
        result = _projective_add(
            result,
            _projective_multiply(generators[segment_index], accumulator),
        )
    return _projective_to_point(result)


def _note_commitment(
    value: int, g_d: Point, pk_d: Point, rcm: int
) -> Point:
    message = (
        [1] * 6
        + _bits_le(value, 64)
        + _bits_le(int.from_bytes(g_d.encode(), "little"), 256)
        + _bits_le(int.from_bytes(pk_d.encode(), "little"), 256)
    )
    base = _pedersen_hash(message, _pedersen_generators(4))
    return base + _note_randomness_generator().multiply(rcm)


def _value_commitment(value: int, randomness: int) -> Point:
    value_base, randomness_base = _value_commitment_generators()
    return (
        value_base.multiply(value)
        + randomness_base.multiply(randomness)
    )


def _merkle_root(
    note_cmu: int, path: tuple[tuple[int, bool], ...]
) -> tuple[int, int]:
    current = note_cmu
    position = 0
    generators = _pedersen_generators(3)
    for depth, (sibling, direction) in enumerate(path):
        if direction:
            left, right = sibling, current
            position |= 1 << depth
        else:
            left, right = current, sibling
        parent = _pedersen_hash(
            _bits_le(depth, 6)
            + _bits_le(left, 255)
            + _bits_le(right, 255),
            generators,
        )
        current = parent.u
    return current, position


def _pack_bits_le(bits: list[int]) -> bytes:
    output = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        output[index // 8] |= bit << (index % 8)
    return bytes(output)


def _derive_nullifier(nk: Point, note_commitment: Point, position: int) -> bytes:
    rho = note_commitment + _nullifier_position_generator().multiply(position)
    preimage = _pack_bits_le(_repr_bits(nk) + _repr_bits(rho))
    return blake2s(preimage, digest_size=32, person=b"Zcash_nf").digest()


def _multipack_nullifier(nullifier: bytes) -> tuple[int, int]:
    bits = _bits_le(int.from_bytes(nullifier, "little"), 256)
    return sum(bit << index for index, bit in enumerate(bits[:254])), sum(
        bit << index for index, bit in enumerate(bits[254:])
    )


def _build_witness(
    rng: XorShiftRng,
    value: int,
    rcv: int,
) -> SpendReferenceWitness:
    ak = rng.random_jubjub_subgroup_point()
    nsk = rng.random_jubjub_scalar()
    nk = proving_key_base().multiply(nsk)
    ivk_hash = blake2s(
        _pack_bits_le(_repr_bits(ak) + _repr_bits(nk)),
        digest_size=32,
        person=b"Zcashivk",
    ).digest()
    ivk = int.from_bytes(ivk_hash, "little") & ((1 << 251) - 1)
    if ivk == 0:
        raise ValueError("pinned Spend test generated a zero IVK")

    while True:
        diversifier = rng.fill_bytes(11)
        g_d = group_hash(b"Zcash_gd", diversifier)
        if g_d is not None:
            break
    pk_d = g_d.multiply(ivk)
    rcm = rng.random_jubjub_scalar()
    sibling = rng.random_bls_scalar()
    direction = rng.next_u32() % 2 != 0
    path = ((sibling, direction),) * 32
    ar = rng.random_jubjub_scalar()

    note_cm = _note_commitment(value, g_d, pk_d, rcm)
    rk = ak + spending_key_base().multiply(ar)
    cv = _value_commitment(value, rcv)
    anchor, position = _merkle_root(note_cm.u, path)
    nullifier = _derive_nullifier(nk, note_cm, position)
    public_inputs = (
        rk.u,
        rk.v,
        cv.u,
        cv.v,
        anchor,
        *_multipack_nullifier(nullifier),
    )
    return SpendReferenceWitness(
        value=value,
        rcv=rcv,
        ak=ak,
        nsk=nsk,
        nk=nk,
        ivk=ivk,
        diversifier=diversifier,
        diversifier_base=g_d,
        transmission_key=pk_d,
        rcm=rcm,
        note_commitment=note_cm,
        ar=ar,
        randomized_key=rk,
        value_commitment=cv,
        authentication_path=path,
        position=position,
        anchor=anchor,
        nullifier=nullifier,
        public_inputs=public_inputs,
    )


def generate_pinned_test_witness(iteration: int = 0) -> SpendReferenceWitness:
    """Reproduce one case from pinned `test_input_circuit_with_bls12_381`."""
    if isinstance(iteration, bool) or not isinstance(iteration, int) or not 0 <= iteration < 10:
        raise ValueError("pinned test iteration must be in [0, 10)")
    rng = XorShiftRng(PINNED_TEST_SEED)
    witness = None
    for _ in range(iteration + 1):
        value = rng.next_u64()
        rcv = rng.random_jubjub_scalar()
        witness = _build_witness(rng, value, rcv)
    if witness is None:
        raise AssertionError("iteration loop did not produce a witness")
    return witness


def generate_external_cv_witnesses() -> tuple[SpendReferenceWitness, ...]:
    """Reproduce the ten upstream external-cv cases with their fixed openings."""
    rng = XorShiftRng(EXTERNAL_CV_TEST_SEED)
    return tuple(
        _build_witness(rng, value, 1000 * (value + 1))
        for value in range(10)
    )


__all__ = [
    "EXTERNAL_CV_TEST_SEED",
    "PINNED_SAPLING_CRYPTO_COMMIT",
    "PINNED_TEST_SEED",
    "PINNED_ZCASH_TEST_VECTORS_COMMIT",
    "PUBLIC_INPUT_ORDER",
    "RNG_VERSION",
    "SpendReferenceWitness",
    "XorShiftRng",
    "generate_external_cv_witnesses",
    "generate_pinned_test_witness",
]
