"""Independent pure-Python reproduction of the pinned Sapling Spend inputs.

This test-only implementation uses affine Edwards arithmetic and does not
import ZyCoin's Spend reference generator, verifier, or R1CS gadgets.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import blake2s

FIELD_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
SCALAR_MODULUS = 6554484396890773809930967563523245729705921265872317281365359162392183254199
BLS_SCALAR_MODULUS = FIELD_MODULUS
CURVE_D = (-10240 * pow(10241, FIELD_MODULUS - 2, FIELD_MODULUS)) % FIELD_MODULUS
GROUP_HASH_PERSONALIZATION = (
    b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"
)
PINNED_SEED = bytes.fromhex("5862be3d763d318d17db37325406bce5")
PUBLIC_INPUT_ORDER = (
    "rk.u",
    "rk.v",
    "cv.u",
    "cv.v",
    "anchor",
    "nullifier_chunk_0",
    "nullifier_chunk_1",
)


def _sqrt(value: int) -> int | None:
    value %= FIELD_MODULUS
    if value == 0:
        return 0
    if pow(value, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != 1:
        return None

    odd = FIELD_MODULUS - 1
    twos = 0
    while odd % 2 == 0:
        twos += 1
        odd //= 2
    non_residue = 2
    while pow(
        non_residue, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS
    ) != FIELD_MODULUS - 1:
        non_residue += 1

    c = pow(non_residue, odd, FIELD_MODULUS)
    root = pow(value, (odd + 1) // 2, FIELD_MODULUS)
    residue = pow(value, odd, FIELD_MODULUS)
    exponent = twos
    while residue != 1:
        index = 1
        squared = residue * residue % FIELD_MODULUS
        while squared != 1:
            squared = squared * squared % FIELD_MODULUS
            index += 1
        if index >= exponent:
            return None
        factor = pow(c, 1 << (exponent - index - 1), FIELD_MODULUS)
        root = root * factor % FIELD_MODULUS
        c = factor * factor % FIELD_MODULUS
        residue = residue * c % FIELD_MODULUS
        exponent = index
    return root


@dataclass(frozen=True)
class RefPoint:
    u: int
    v: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "u", self.u % FIELD_MODULUS)
        object.__setattr__(self, "v", self.v % FIELD_MODULUS)

    def __add__(self, other: RefPoint) -> RefPoint:
        product = self.u * other.u * self.v * other.v % FIELD_MODULUS
        u_num = (self.u * other.v + self.v * other.u) % FIELD_MODULUS
        v_num = (self.v * other.v + self.u * other.u) % FIELD_MODULUS
        u_den = (1 + CURVE_D * product) % FIELD_MODULUS
        v_den = (1 - CURVE_D * product) % FIELD_MODULUS
        if not u_den or not v_den:
            raise ValueError("invalid Edwards addition denominator")
        u = u_num * pow(u_den, FIELD_MODULUS - 2, FIELD_MODULUS)
        v = v_num * pow(v_den, FIELD_MODULUS - 2, FIELD_MODULUS)
        return RefPoint(u, v)

    def multiply(self, scalar: int) -> RefPoint:
        if scalar < 0:
            raise ValueError("scalar must be non-negative")
        scalar %= SCALAR_MODULUS
        result = IDENTITY
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result

    def encode(self) -> bytes:
        encoded = bytearray(self.v.to_bytes(32, "little"))
        encoded[31] |= (self.u & 1) << 7
        return bytes(encoded)


IDENTITY = RefPoint(0, 1)


def _decode_point(encoded: bytes) -> RefPoint:
    if len(encoded) != 32:
        raise ValueError("point encoding must be 32 bytes")
    sign = encoded[31] >> 7
    v_bytes = encoded[:31] + bytes((encoded[31] & 0x7F,))
    v = int.from_bytes(v_bytes, "little")
    if v >= FIELD_MODULUS:
        raise ValueError("non-canonical v coordinate")
    v2 = v * v % FIELD_MODULUS
    denominator = (CURVE_D * v2 + 1) % FIELD_MODULUS
    if denominator == 0:
        raise ValueError("invalid point denominator")
    u2 = (v2 - 1) * pow(denominator, FIELD_MODULUS - 2, FIELD_MODULUS)
    u = _sqrt(u2)
    if u is None or (u == 0 and sign):
        raise ValueError("invalid point encoding")
    if u & 1 != sign:
        u = -u % FIELD_MODULUS
    return RefPoint(u, v)


class ReferenceXorShift:
    """Direct transcription of rand_xorshift 0.5.0 and rand_core 0.10.1."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 16:
            raise ValueError("seed must be 16 bytes")
        self.state = [
            int.from_bytes(seed[offset:offset + 4], "little")
            for offset in range(0, 16, 4)
        ]
        if not any(self.state):
            self.state = [0xBAD5EED] * 4

    def next_u32(self) -> int:
        x, y, z, w = self.state
        shifted = (x ^ (x << 11)) & 0xFFFFFFFF
        result = (w ^ (w >> 19) ^ shifted ^ (shifted >> 8)) & 0xFFFFFFFF
        self.state = [y, z, w, result]
        return result

    def next_u64(self) -> int:
        low = self.next_u32()
        high = self.next_u32()
        return low | high << 32

    def read(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            output.extend(self.next_u32().to_bytes(4, "little"))
        return bytes(output[:length])

    def sample(self, modulus: int) -> int:
        return int.from_bytes(self.read(64), "little") % modulus

    def sample_point(self) -> RefPoint:
        while True:
            v = self.sample(FIELD_MODULUS)
            sign = self.next_u32() % 2
            try:
                point = _decode_point(
                    (v | (sign << 255)).to_bytes(32, "little")
                ).multiply(8)
            except ValueError:
                continue
            if point != IDENTITY:
                return point


def _group_hash(personalization: bytes, message: bytes) -> RefPoint | None:
    digest = blake2s(
        GROUP_HASH_PERSONALIZATION + message,
        digest_size=32,
        person=personalization,
    ).digest()
    try:
        point = _decode_point(digest).multiply(8)
    except ValueError:
        return None
    return None if point == IDENTITY else point


def _find_group_hash(personalization: bytes, message: bytes) -> RefPoint:
    for counter in range(256):
        point = _group_hash(personalization, message + bytes((counter,)))
        if point is not None:
            return point
    raise ValueError("no point found for group hash")


def _bits(value: int, width: int) -> list[int]:
    return [(value >> index) & 1 for index in range(width)]


def _point_bits(point: RefPoint) -> list[int]:
    return _bits(point.v, 255) + [point.u & 1]


def _derive_nk(nsk: int) -> RefPoint:
    return _find_group_hash(b"Zcash_H_", b"").multiply(nsk)


def _derive_ivk(ak: RefPoint, nk: RefPoint) -> int:
    digest = blake2s(
        _pack_bits(_point_bits(ak) + _point_bits(nk)),
        digest_size=32,
        person=b"Zcashivk",
    ).digest()
    return int.from_bytes(digest, "little") & ((1 << 251) - 1)


def _pack_bits(bits: list[int]) -> bytes:
    result = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        result[index // 8] |= bit << (index % 8)
    return bytes(result)


def _pedersen_generators(count: int) -> tuple[RefPoint, ...]:
    return tuple(
        _find_group_hash(b"Zcash_PH", index.to_bytes(4, "little"))
        for index in range(count)
    )


def _pedersen_hash(bits: list[int], generators: tuple[RefPoint, ...]) -> RefPoint:
    result = IDENTITY
    chunk_index = 0
    while chunk_index * 189 < len(bits):
        segment = bits[chunk_index * 189:(chunk_index + 1) * 189]
        accumulator = 0
        power = 1
        for offset in range(0, len(segment), 3):
            a = segment[offset]
            b = segment[offset + 1] if offset + 1 < len(segment) else 0
            c = segment[offset + 2] if offset + 2 < len(segment) else 0
            digit = (1 + a + 2 * b) * (-1 if c else 1)
            accumulator = (
                accumulator + digit * power
            ) % SCALAR_MODULUS
            power = power * 16 % SCALAR_MODULUS
        if chunk_index >= len(generators):
            raise ValueError("Pedersen input exceeds generator capacity")
        result = result + generators[chunk_index].multiply(accumulator)
        chunk_index += 1
    return result


def value_commitment(value: int, randomness: int) -> RefPoint:
    value_generator = _find_group_hash(b"Zcash_cv", b"v")
    randomness_generator = _find_group_hash(b"Zcash_cv", b"r")
    return (
        value_generator.multiply(value)
        + randomness_generator.multiply(randomness)
    )


def _note_commitment(
    value: int, diversifier_base: RefPoint, transmission_key: RefPoint, rcm: int
) -> RefPoint:
    message = (
        [1] * 6
        + _bits(value, 64)
        + _bits(int.from_bytes(diversifier_base.encode(), "little"), 256)
        + _bits(int.from_bytes(transmission_key.encode(), "little"), 256)
    )
    note_base = _pedersen_hash(message, _pedersen_generators(4))
    randomness_base = _find_group_hash(b"Zcash_PH", b"r")
    return note_base + randomness_base.multiply(rcm)


def _merkle_root(
    note_cmu: int, path: tuple[tuple[int, bool], ...]
) -> tuple[int, int]:
    node = note_cmu
    position = 0
    generators = _pedersen_generators(3)
    for level, (sibling, direction) in enumerate(path):
        left, right = (sibling, node) if direction else (node, sibling)
        prefix = _bits(level, 6)
        parent = _pedersen_hash(
            prefix + _bits(left, 255) + _bits(right, 255),
            generators,
        )
        node = parent.u
        position |= int(direction) << level
    return node, position


def _derive_nullifier(
    nullifier_key: RefPoint, note_commitment: RefPoint, position: int
) -> bytes:
    position_base = _find_group_hash(b"Zcash_J_", b"")
    rho = note_commitment + position_base.multiply(position)
    preimage = _pack_bits(_point_bits(nullifier_key) + _point_bits(rho))
    return blake2s(preimage, digest_size=32, person=b"Zcash_nf").digest()


def _multipack(nullifier: bytes) -> tuple[int, int]:
    value = int.from_bytes(nullifier, "little")
    return value & ((1 << 254) - 1), value >> 254


@dataclass(frozen=True)
class IndependentSpendWitness:
    value: int
    rcv: int
    ak: RefPoint
    nsk: int
    nk: RefPoint
    ivk: int
    diversifier: bytes
    diversifier_base: RefPoint
    transmission_key: RefPoint
    rcm: int
    note_commitment: RefPoint
    ar: int
    randomized_key: RefPoint
    cv: RefPoint
    authentication_path: tuple[tuple[int, bool], ...]
    position: int
    anchor: int
    nullifier: bytes
    public_inputs: tuple[int, ...]

    def as_dict(self) -> dict[str, object]:
        def point_dict(point: RefPoint) -> dict[str, object]:
            return {
                "u": point.u,
                "v": point.v,
                "encoding": point.encode().hex(),
            }

        return {
            "value": self.value,
            "rcv": self.rcv.to_bytes(32, "little").hex(),
            "proof_generation_key": {
                "ak": self.ak.encode().hex(),
                "nsk": self.nsk.to_bytes(32, "little").hex(),
            },
            "nk": self.nk.encode().hex(),
            "ivk": self.ivk.to_bytes(32, "little").hex(),
            "payment_address": {
                "diversifier": self.diversifier.hex(),
                "g_d": self.diversifier_base.encode().hex(),
                "pk_d": self.transmission_key.encode().hex(),
            },
            "rcm": self.rcm.to_bytes(32, "little").hex(),
            "note_commitment": {
                "point": self.note_commitment.encode().hex(),
                "cmu": self.note_commitment.u.to_bytes(32, "little").hex(),
            },
            "ar": self.ar.to_bytes(32, "little").hex(),
            "rk": point_dict(self.randomized_key),
            "cv": {
                "u": self.cv.u,
                "v": self.cv.v,
            },
            "authentication_path": [
                {
                    "sibling": sibling.to_bytes(32, "little").hex(),
                    "direction": direction,
                }
                for sibling, direction in self.authentication_path
            ],
            "position": self.position,
            "anchor": self.anchor.to_bytes(32, "little").hex(),
            "nullifier": self.nullifier.hex(),
            "public_input_order": list(PUBLIC_INPUT_ORDER),
            "public_inputs": list(self.public_inputs),
            "bellman_implicit_one": 1,
        }


def _witness_for_case(
    rng: ReferenceXorShift, value: int, rcv: int
) -> IndependentSpendWitness:
    ak = rng.sample_point()
    nsk = rng.sample(SCALAR_MODULUS)
    nk = _derive_nk(nsk)
    ivk = _derive_ivk(ak, nk)
    if ivk == 0:
        raise ValueError("pinned test sampled a zero IVK")

    while True:
        diversifier = rng.read(11)
        diversifier_base = _group_hash(b"Zcash_gd", diversifier)
        if diversifier_base is not None:
            break
    transmission_key = diversifier_base.multiply(ivk)
    rcm = rng.sample(SCALAR_MODULUS)
    sibling = rng.sample(BLS_SCALAR_MODULUS)
    direction = rng.next_u32() % 2 != 0
    path = ((sibling, direction),) * 32
    ar = rng.sample(SCALAR_MODULUS)

    note_cm = _note_commitment(value, diversifier_base, transmission_key, rcm)
    spending_base = _find_group_hash(b"Zcash_G_", b"")
    randomized_key = ak + spending_base.multiply(ar)
    cv = value_commitment(value, rcv)
    anchor, position = _merkle_root(note_cm.u, path)
    nullifier = _derive_nullifier(nk, note_cm, position)
    public_inputs = (
        randomized_key.u,
        randomized_key.v,
        cv.u,
        cv.v,
        anchor,
        *_multipack(nullifier),
    )
    return IndependentSpendWitness(
        value,
        rcv,
        ak,
        nsk,
        nk,
        ivk,
        diversifier,
        diversifier_base,
        transmission_key,
        rcm,
        note_cm,
        ar,
        randomized_key,
        cv,
        path,
        position,
        anchor,
        nullifier,
        public_inputs,
    )


def generate_pinned_test_witness(
    iteration: int = 0,
) -> IndependentSpendWitness:
    if isinstance(iteration, bool) or not isinstance(iteration, int):
        raise TypeError("iteration must be an integer")
    if not 0 <= iteration < 10:
        raise ValueError("iteration must be in [0, 10)")
    rng = ReferenceXorShift(PINNED_SEED)
    witness = None
    for _ in range(iteration + 1):
        value = rng.next_u64()
        rcv = rng.sample(SCALAR_MODULUS)
        witness = _witness_for_case(rng, value, rcv)
    if witness is None:
        raise AssertionError("iteration loop produced no witness")
    return witness
