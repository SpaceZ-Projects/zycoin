"""Pure-Python Jubjub arithmetic used by Sapling key derivation."""

from dataclasses import dataclass
from functools import lru_cache
from hashlib import blake2s

FIELD_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184513
SCALAR_MODULUS = 6554484396890773809930967563523245729705921265872317281365359162392183254199
CURVE_D = (-10240 * pow(10241, FIELD_MODULUS - 2, FIELD_MODULUS)) % FIELD_MODULUS
GROUP_HASH_PERSONALIZATION = b"096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0"


def _sqrt(value):
    value %= FIELD_MODULUS
    if value == 0:
        return 0
    if pow(value, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != 1:
        return None

    q = FIELD_MODULUS - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 2
    while pow(z, (FIELD_MODULUS - 1) // 2, FIELD_MODULUS) != FIELD_MODULUS - 1:
        z += 1

    c = pow(z, q, FIELD_MODULUS)
    root = pow(value, (q + 1) // 2, FIELD_MODULUS)
    residue = pow(value, q, FIELD_MODULUS)
    m = s
    while residue != 1:
        i = 1
        squared = residue * residue % FIELD_MODULUS
        while squared != 1:
            squared = squared * squared % FIELD_MODULUS
            i += 1
        if i >= m:
            return None
        factor = pow(c, 1 << (m - i - 1), FIELD_MODULUS)
        root = root * factor % FIELD_MODULUS
        c = factor * factor % FIELD_MODULUS
        residue = residue * c % FIELD_MODULUS
        m = i
    return root


@dataclass(frozen=True)
class Point:
    u: int
    v: int

    def __post_init__(self):
        object.__setattr__(self, "u", self.u % FIELD_MODULUS)
        object.__setattr__(self, "v", self.v % FIELD_MODULUS)

    @classmethod
    def from_bytes(cls, data, check_subgroup=False):
        if not isinstance(data, bytes) or len(data) != 32:
            raise ValueError("Jubjub points must be encoded as 32 bytes")
        sign = data[31] >> 7
        encoded_v = data[:31] + bytes((data[31] & 0x7F,))
        v = int.from_bytes(encoded_v, "little")
        if v >= FIELD_MODULUS:
            raise ValueError("non-canonical Jubjub point encoding")

        v_squared = v * v % FIELD_MODULUS
        numerator = (v_squared - 1) % FIELD_MODULUS
        denominator = (CURVE_D * v_squared + 1) % FIELD_MODULUS
        if denominator == 0:
            raise ValueError("invalid Jubjub point")
        u_squared = numerator * pow(
            denominator, FIELD_MODULUS - 2, FIELD_MODULUS
        ) % FIELD_MODULUS
        u = _sqrt(u_squared)
        if u is None or (u == 0 and sign):
            raise ValueError("invalid Jubjub point encoding")
        if u & 1 != sign:
            u = (-u) % FIELD_MODULUS
        point = cls(u, v)
        if not point.is_on_curve():
            raise ValueError("point is not on Jubjub")
        if check_subgroup and not point.is_in_subgroup():
            raise ValueError("Jubjub point is not in the prime-order subgroup")
        return point

    def is_on_curve(self):
        u2 = self.u * self.u % FIELD_MODULUS
        v2 = self.v * self.v % FIELD_MODULUS
        return (-u2 + v2 - 1 - CURVE_D * u2 * v2) % FIELD_MODULUS == 0

    def __add__(self, other):
        product = (
            self.u * other.u * self.v * other.v
        ) % FIELD_MODULUS
        u_numerator = (
            self.u * other.v + self.v * other.u
        ) % FIELD_MODULUS
        v_numerator = (
            self.v * other.v + self.u * other.u
        ) % FIELD_MODULUS
        u_denominator = (1 + CURVE_D * product) % FIELD_MODULUS
        v_denominator = (1 - CURVE_D * product) % FIELD_MODULUS
        if not u_denominator or not v_denominator:
            raise ValueError("invalid Jubjub point addition")
        u = u_numerator * pow(
            u_denominator, FIELD_MODULUS - 2, FIELD_MODULUS
        ) % FIELD_MODULUS
        v = v_numerator * pow(
            v_denominator, FIELD_MODULUS - 2, FIELD_MODULUS
        ) % FIELD_MODULUS
        return Point(u, v)

    def multiply(self, scalar):
        if not isinstance(scalar, int):
            raise TypeError("Jubjub scalar must be an integer")
        scalar %= SCALAR_MODULUS
        return self._multiply_unreduced(scalar)

    def _multiply_unreduced(self, scalar):
        result = IDENTITY
        addend = self
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        return result

    def is_in_subgroup(self):
        return self._multiply_unreduced(SCALAR_MODULUS) == IDENTITY

    def encode(self):
        encoded = bytearray(self.v.to_bytes(32, "little"))
        encoded[31] |= (self.u & 1) << 7
        return bytes(encoded)


IDENTITY = Point(0, 1)


def group_hash(personalization, message):
    if not isinstance(personalization, bytes) or len(personalization) > 8:
        raise ValueError("BLAKE2s personalization must be at most 8 bytes")
    digest = blake2s(
        GROUP_HASH_PERSONALIZATION + message,
        person=personalization,
    ).digest()
    try:
        point = Point.from_bytes(digest).multiply(8)
    except ValueError:
        return None
    return None if point == IDENTITY else point


def find_group_hash(personalization, message):
    for counter in range(256):
        point = group_hash(personalization, message + bytes((counter,)))
        if point is not None:
            return point
    raise ValueError("no valid Jubjub group hash found")


@lru_cache(maxsize=1)
def spending_key_base():
    return find_group_hash(b"Zcash_G_", b"")


@lru_cache(maxsize=1)
def proving_key_base():
    return find_group_hash(b"Zcash_H_", b"")
