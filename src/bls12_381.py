"""Pure-Python BLS12-381 field, curve, encoding, and pairing primitives.

This module is intended for offline research and verification. Python integer
arithmetic is variable-time and is not suitable for handling production secrets.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union


FIELD_MODULUS = (
    4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
)
SCALAR_MODULUS = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)
ATE_LOOP_COUNT = 0xD201000000010000
_FP2_NONRESIDUE = (1, 1)


def _inverse(value: int, modulus: int) -> int:
    value %= modulus
    if value == 0:
        raise ZeroDivisionError("zero has no multiplicative inverse")
    return pow(value, modulus - 2, modulus)


def _sqrt_fp(value: int) -> Optional[int]:
    value %= FIELD_MODULUS
    if value == 0:
        return 0
    root = pow(value, (FIELD_MODULUS + 1) // 4, FIELD_MODULUS)
    if root * root % FIELD_MODULUS != value:
        return None
    return root


@dataclass(frozen=True)
class Fp:
    """Canonical element of the BLS12-381 base field."""

    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int:
            raise TypeError("Fp value must be an integer")
        object.__setattr__(self, "value", self.value % FIELD_MODULUS)

    def __add__(self, other: Union[int, "Fp"]) -> "Fp":
        value = other.value if isinstance(other, Fp) else other
        if not isinstance(value, int):
            return NotImplemented
        return Fp(self.value + value)

    __radd__ = __add__

    def __sub__(self, other: Union[int, "Fp"]) -> "Fp":
        value = other.value if isinstance(other, Fp) else other
        if not isinstance(value, int):
            return NotImplemented
        return Fp(self.value - value)

    def __rsub__(self, other: Union[int, "Fp"]) -> "Fp":
        value = other.value if isinstance(other, Fp) else other
        if not isinstance(value, int):
            return NotImplemented
        return Fp(value - self.value)

    def __mul__(self, other: Union[int, "Fp"]) -> "Fp":
        value = other.value if isinstance(other, Fp) else other
        if not isinstance(value, int):
            return NotImplemented
        return Fp(self.value * value)

    __rmul__ = __mul__

    def __neg__(self) -> "Fp":
        return Fp(-self.value)

    def __truediv__(self, other: Union[int, "Fp"]) -> "Fp":
        value = other.value if isinstance(other, Fp) else other
        if not isinstance(value, int):
            return NotImplemented
        return Fp(self.value * _inverse(value, FIELD_MODULUS))

    def __pow__(self, exponent: int) -> "Fp":
        if not isinstance(exponent, int):
            raise TypeError("field exponent must be an integer")
        if exponent < 0:
            return self.inverse() ** -exponent
        return Fp(pow(self.value, exponent, FIELD_MODULUS))

    def inverse(self) -> "Fp":
        return Fp(_inverse(self.value, FIELD_MODULUS))


@dataclass(frozen=True)
class Scalar:
    """Canonical element of the BLS12-381 scalar field."""

    value: int

    def __post_init__(self) -> None:
        if type(self.value) is not int:
            raise TypeError("scalar value must be an integer")
        object.__setattr__(self, "value", self.value % SCALAR_MODULUS)

    def __add__(self, other: Union[int, "Scalar"]) -> "Scalar":
        value = other.value if isinstance(other, Scalar) else other
        if not isinstance(value, int):
            return NotImplemented
        return Scalar(self.value + value)

    __radd__ = __add__

    def __sub__(self, other: Union[int, "Scalar"]) -> "Scalar":
        value = other.value if isinstance(other, Scalar) else other
        if not isinstance(value, int):
            return NotImplemented
        return Scalar(self.value - value)

    def __rsub__(self, other: Union[int, "Scalar"]) -> "Scalar":
        value = other.value if isinstance(other, Scalar) else other
        if not isinstance(value, int):
            return NotImplemented
        return Scalar(value - self.value)

    def __mul__(self, other: Union[int, "Scalar"]) -> "Scalar":
        value = other.value if isinstance(other, Scalar) else other
        if not isinstance(value, int):
            return NotImplemented
        return Scalar(self.value * value)

    __rmul__ = __mul__

    def __neg__(self) -> "Scalar":
        return Scalar(-self.value)

    def __truediv__(self, other: Union[int, "Scalar"]) -> "Scalar":
        value = other.value if isinstance(other, Scalar) else other
        if not isinstance(value, int):
            return NotImplemented
        return Scalar(self.value * _inverse(value, SCALAR_MODULUS))

    def __pow__(self, exponent: int) -> "Scalar":
        if not isinstance(exponent, int):
            raise TypeError("field exponent must be an integer")
        if exponent < 0:
            return self.inverse() ** -exponent
        return Scalar(pow(self.value, exponent, SCALAR_MODULUS))

    def inverse(self) -> "Scalar":
        return Scalar(_inverse(self.value, SCALAR_MODULUS))


@dataclass(frozen=True)
class Fp2:
    """Element ``c0 + c1*i`` of Fp[i]/(i² + 1)."""

    c0: int = 0
    c1: int = 0

    def __post_init__(self) -> None:
        if type(self.c0) is not int or type(self.c1) is not int:
            raise TypeError("Fp2 coefficients must be integers")
        object.__setattr__(self, "c0", self.c0 % FIELD_MODULUS)
        object.__setattr__(self, "c1", self.c1 % FIELD_MODULUS)

    @classmethod
    def coerce(cls, value: Union[int, "Fp2"]) -> "Fp2":
        if isinstance(value, cls):
            return value
        if type(value) is int:
            return cls(value)
        return NotImplemented

    def __add__(self, other: Union[int, "Fp2"]) -> "Fp2":
        value = self.coerce(other)
        if value is NotImplemented:
            return NotImplemented
        return Fp2(self.c0 + value.c0, self.c1 + value.c1)

    __radd__ = __add__

    def __sub__(self, other: Union[int, "Fp2"]) -> "Fp2":
        value = self.coerce(other)
        if value is NotImplemented:
            return NotImplemented
        return Fp2(self.c0 - value.c0, self.c1 - value.c1)

    def __rsub__(self, other: Union[int, "Fp2"]) -> "Fp2":
        value = self.coerce(other)
        if value is NotImplemented:
            return NotImplemented
        return value - self

    def __neg__(self) -> "Fp2":
        return Fp2(-self.c0, -self.c1)

    def __mul__(self, other: Union[int, "Fp2"]) -> "Fp2":
        value = self.coerce(other)
        if value is NotImplemented:
            return NotImplemented
        return Fp2(
            self.c0 * value.c0 - self.c1 * value.c1,
            self.c0 * value.c1 + self.c1 * value.c0,
        )

    __rmul__ = __mul__

    def __truediv__(self, other: Union[int, "Fp2"]) -> "Fp2":
        value = self.coerce(other)
        if value is NotImplemented:
            return NotImplemented
        return self * value.inverse()

    def inverse(self) -> "Fp2":
        norm = (self.c0 * self.c0 + self.c1 * self.c1) % FIELD_MODULUS
        inverse_norm = _inverse(norm, FIELD_MODULUS)
        return Fp2(self.c0 * inverse_norm, -self.c1 * inverse_norm)

    def __pow__(self, exponent: int) -> "Fp2":
        if not isinstance(exponent, int):
            raise TypeError("field exponent must be an integer")
        if exponent < 0:
            return self.inverse() ** -exponent
        result = Fp2(1)
        factor = self
        while exponent:
            if exponent & 1:
                result = result * factor
            factor = factor * factor
            exponent >>= 1
        return result

    def sqrt(self) -> Optional["Fp2"]:
        if self == Fp2():
            return Fp2()
        if self.c1 == 0:
            real_root = _sqrt_fp(self.c0)
            if real_root is not None:
                return Fp2(real_root)
            imaginary_root = _sqrt_fp(-self.c0)
            return Fp2(0, imaginary_root) if imaginary_root is not None else None

        norm_root = _sqrt_fp(
            self.c0 * self.c0 + self.c1 * self.c1
        )
        if norm_root is None:
            return None

        inverse_two = (FIELD_MODULUS + 1) // 2
        for candidate in (norm_root, -norm_root):
            real_square = (self.c0 + candidate) * inverse_two % FIELD_MODULUS
            real_root = _sqrt_fp(real_square)
            if real_root in (None, 0):
                continue
            imaginary_root = self.c1 * _inverse(
                2 * real_root, FIELD_MODULUS
            ) % FIELD_MODULUS
            root = Fp2(real_root, imaginary_root)
            if root * root == self:
                return root
        return None

    def is_zero(self) -> bool:
        return self.c0 == 0 and self.c1 == 0


# Exact torsion-free criteria from zkcrypto/bls12_381 g1.rs and g2.rs:
# endomorphism(P) = -[x²]P for G1, and psi(P) = [x]P for G2.
_G2_PSI_BASE = Fp2(1, 1)
_G2_PSI_COEFF_X = _G2_PSI_BASE ** (-((FIELD_MODULUS - 1) // 3))
_G2_PSI_COEFF_Y = _G2_PSI_BASE ** (-((FIELD_MODULUS - 1) // 2))
_G1_ENDOMORPHISM_BETA = pow(2, (FIELD_MODULUS - 1) // 3, FIELD_MODULUS)
_BLS_X_MAGNITUDE = 0xD201000000010000


@dataclass(frozen=True)
class Fp6:
    """Element ``c0 + c1*v + c2*v²`` with ``v³ = 1 + i``."""

    c0: Fp2 = Fp2()
    c1: Fp2 = Fp2()
    c2: Fp2 = Fp2()

    def __post_init__(self) -> None:
        if not all(isinstance(value, Fp2) for value in (self.c0, self.c1, self.c2)):
            raise TypeError("Fp6 coefficients must be Fp2 elements")

    def __add__(self, other: "Fp6") -> "Fp6":
        if not isinstance(other, Fp6):
            return NotImplemented
        return Fp6(self.c0 + other.c0, self.c1 + other.c1, self.c2 + other.c2)

    def __sub__(self, other: "Fp6") -> "Fp6":
        if not isinstance(other, Fp6):
            return NotImplemented
        return Fp6(self.c0 - other.c0, self.c1 - other.c1, self.c2 - other.c2)

    def __neg__(self) -> "Fp6":
        return Fp6(-self.c0, -self.c1, -self.c2)

    def __mul__(self, other: Union[int, Fp2, "Fp6"]) -> "Fp6":
        if isinstance(other, (int, Fp2)):
            return Fp6(self.c0 * other, self.c1 * other, self.c2 * other)
        if not isinstance(other, Fp6):
            return NotImplemented
        product = [Fp2() for _ in range(5)]
        left = (self.c0, self.c1, self.c2)
        right = (other.c0, other.c1, other.c2)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                product[i + j] = product[i + j] + a * b
        nonresidue = Fp2(*_FP2_NONRESIDUE)
        for degree in (4, 3):
            product[degree - 3] = product[degree - 3] + product[degree] * nonresidue
        return Fp6(product[0], product[1], product[2])

    __rmul__ = __mul__

    def inverse(self) -> "Fp6":
        if self.is_zero():
            raise ZeroDivisionError("zero has no multiplicative inverse")
        return self ** (FIELD_MODULUS**6 - 2)

    def __truediv__(self, other: Union[int, Fp2, "Fp6"]) -> "Fp6":
        if isinstance(other, Fp6):
            return self * other.inverse()
        if isinstance(other, (int, Fp2)):
            return Fp6(self.c0 / other, self.c1 / other, self.c2 / other)
        return NotImplemented

    def __pow__(self, exponent: int) -> "Fp6":
        if not isinstance(exponent, int):
            raise TypeError("field exponent must be an integer")
        if exponent < 0:
            return self.inverse() ** -exponent
        result = Fp6(Fp2(1))
        factor = self
        while exponent:
            if exponent & 1:
                result = result * factor
            factor = factor * factor
            exponent >>= 1
        return result

    def is_zero(self) -> bool:
        return self.c0.is_zero() and self.c1.is_zero() and self.c2.is_zero()


@dataclass(frozen=True)
class Fp12:
    """Element of Fp[w]/(w¹² - 2w⁶ + 2), in polynomial coefficient order."""

    coefficients: Tuple[int, ...] = (0,) * 12

    def __post_init__(self) -> None:
        if len(self.coefficients) != 12:
            raise ValueError("Fp12 requires exactly 12 coefficients")
        if any(type(value) is not int for value in self.coefficients):
            raise TypeError("Fp12 coefficients must be integers")
        object.__setattr__(
            self,
            "coefficients",
            tuple(value % FIELD_MODULUS for value in self.coefficients),
        )

    @classmethod
    def from_int(cls, value: int) -> "Fp12":
        return cls((value,) + (0,) * 11)

    @classmethod
    def zero(cls) -> "Fp12":
        return cls()

    @classmethod
    def one(cls) -> "Fp12":
        return cls.from_int(1)

    def __add__(self, other: "Fp12") -> "Fp12":
        if not isinstance(other, Fp12):
            return NotImplemented
        return Fp12(tuple(a + b for a, b in zip(self.coefficients, other.coefficients)))

    def __sub__(self, other: "Fp12") -> "Fp12":
        if not isinstance(other, Fp12):
            return NotImplemented
        return Fp12(tuple(a - b for a, b in zip(self.coefficients, other.coefficients)))

    def __neg__(self) -> "Fp12":
        return Fp12(tuple(-value for value in self.coefficients))

    def __mul__(self, other: Union[int, "Fp12"]) -> "Fp12":
        if isinstance(other, int):
            return Fp12(tuple(value * other for value in self.coefficients))
        if not isinstance(other, Fp12):
            return NotImplemented
        product = [0] * 23
        for i, left in enumerate(self.coefficients):
            if left:
                for j, right in enumerate(other.coefficients):
                    if right:
                        product[i + j] += left * right
        for degree in range(22, 11, -1):
            value = product[degree]
            product[degree - 6] += 2 * value
            product[degree - 12] -= 2 * value
        return Fp12(tuple(product[:12]))

    __rmul__ = __mul__

    def inverse(self) -> "Fp12":
        if self.is_zero():
            raise ZeroDivisionError("zero has no multiplicative inverse")
        return self ** (FIELD_MODULUS**12 - 2)

    def __truediv__(self, other: "Fp12") -> "Fp12":
        if not isinstance(other, Fp12):
            return NotImplemented
        return self * other.inverse()

    def __pow__(self, exponent: int) -> "Fp12":
        if not isinstance(exponent, int):
            raise TypeError("field exponent must be an integer")
        if exponent < 0:
            return self.inverse() ** -exponent
        result = Fp12.one()
        factor = self
        while exponent:
            if exponent & 1:
                result = result * factor
            factor = factor * factor
            exponent >>= 1
        return result

    def is_zero(self) -> bool:
        return not any(self.coefficients)


@dataclass(frozen=True)
class G1Point:
    x: Optional[int]
    y: Optional[int]

    def __post_init__(self) -> None:
        if (self.x is None) != (self.y is None):
            raise ValueError("point-at-infinity coordinates must both be None")
        if self.x is not None:
            if type(self.x) is not int or type(self.y) is not int:
                raise TypeError("G1 coordinates must be integers")
            if not (0 <= self.x < FIELD_MODULUS and 0 <= self.y < FIELD_MODULUS):
                raise ValueError("G1 coordinates must be canonical field elements")

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def is_on_curve(self) -> bool:
        return self.is_infinity or (
            self.y * self.y - self.x * self.x * self.x - 4
        ) % FIELD_MODULUS == 0

    def is_in_subgroup(self) -> bool:
        _require_g1(self)
        return _is_g1_in_prime_subgroup(self)

    def encode(self) -> bytes:
        return encode_g1(self)


@dataclass(frozen=True)
class G2Point:
    x: Optional[Fp2]
    y: Optional[Fp2]

    def __post_init__(self) -> None:
        if (self.x is None) != (self.y is None):
            raise ValueError("point-at-infinity coordinates must both be None")
        if self.x is not None and (
            not isinstance(self.x, Fp2) or not isinstance(self.y, Fp2)
        ):
            raise TypeError("G2 coordinates must be Fp2 elements")

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def is_on_curve(self) -> bool:
        if self.is_infinity:
            return True
        return self.y * self.y == self.x * self.x * self.x + Fp2(4, 4)

    def is_in_subgroup(self) -> bool:
        _require_g2(self)
        return _is_g2_in_prime_subgroup(self)

    def encode(self) -> bytes:
        return encode_g2(self)


G1_INFINITY = G1Point(None, None)
G2_INFINITY = G2Point(None, None)
G1_GENERATOR = G1Point(
    3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507,
    1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569,
)
G2_GENERATOR = G2Point(
    Fp2(
        352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160,
        3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758,
    ),
    Fp2(
        1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905,
        927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582,
    ),
)


def add_g1(left: G1Point, right: G1Point) -> G1Point:
    _require_g1(left)
    _require_g1(right)
    if left.is_infinity:
        return right
    if right.is_infinity:
        return left
    if left.x == right.x:
        if (left.y + right.y) % FIELD_MODULUS == 0:
            return G1_INFINITY
        slope = (3 * left.x * left.x) * _inverse(2 * left.y, FIELD_MODULUS)
    else:
        slope = (right.y - left.y) * _inverse(right.x - left.x, FIELD_MODULUS)
    slope %= FIELD_MODULUS
    x = (slope * slope - left.x - right.x) % FIELD_MODULUS
    y = (slope * (left.x - x) - left.y) % FIELD_MODULUS
    return G1Point(x, y)


def add_g2(left: G2Point, right: G2Point) -> G2Point:
    _require_g2(left)
    _require_g2(right)
    if left.is_infinity:
        return right
    if right.is_infinity:
        return left
    if left.x == right.x:
        if left.y + right.y == Fp2():
            return G2_INFINITY
        slope = (left.x * left.x * 3) / (left.y * 2)
    else:
        slope = (right.y - left.y) / (right.x - left.x)
    x = slope * slope - left.x - right.x
    y = slope * (left.x - x) - left.y
    return G2Point(x, y)


def multiply_g1(point: G1Point, scalar: int) -> G1Point:
    _require_g1(point)
    if not isinstance(scalar, int):
        raise TypeError("G1 scalar must be an integer")
    if scalar < 0:
        if point.is_infinity:
            return point
        return multiply_g1(G1Point(point.x, (-point.y) % FIELD_MODULUS), -scalar)
    return _g1_from_projective(_multiply_g1_projective_point(point, scalar))


def multiply_g2(point: G2Point, scalar: int) -> G2Point:
    _require_g2(point)
    if not isinstance(scalar, int):
        raise TypeError("G2 scalar must be an integer")
    if scalar < 0:
        if point.is_infinity:
            return point
        return multiply_g2(G2Point(point.x, -point.y), -scalar)
    return _g2_from_projective(_multiply_g2_projective_point(point, scalar))


def _g1_from_projective(
    point: tuple[int, int, int],
) -> G1Point:
    x, y, z = point
    if z == 0:
        return G1_INFINITY
    z_inverse = _inverse(z, FIELD_MODULUS)
    z_inverse_squared = z_inverse * z_inverse % FIELD_MODULUS
    return G1Point(
        x * z_inverse_squared % FIELD_MODULUS,
        y * z_inverse_squared * z_inverse % FIELD_MODULUS,
    )


def _g2_from_projective(
    point: tuple[Fp2, Fp2, Fp2],
) -> G2Point:
    x, y, z = point
    if z == Fp2():
        return G2_INFINITY
    z_inverse = z.inverse()
    z_inverse_squared = z_inverse * z_inverse
    return G2Point(x * z_inverse_squared, y * z_inverse_squared * z_inverse)


def _msm_window_size(point_count: int, group: str) -> int:
    if point_count < 32:
        return 3
    if point_count < 128:
        return 4
    if point_count < 512:
        return 5
    if point_count < 2_048:
        return 8 if group == "g2" else 7
    return 10 if group == "g2" else 9


def _add_g1_mixed_projective(
    left: tuple[int, int, int],
    right: G1Point,
    modulus: int,
) -> tuple[int, int, int]:
    x1, y1, z1 = left
    if z1 == 0:
        return (right.x, right.y, 1)
    z1_squared = z1 * z1 % modulus
    u2 = right.x * z1_squared % modulus
    s2 = right.y * z1 * z1_squared % modulus
    if x1 == u2:
        if y1 != s2:
            return (0, 1, 0)
        return _double_g1_projective(left, modulus)
    h = (u2 - x1) % modulus
    i = (2 * h) ** 2 % modulus
    j = h * i % modulus
    r = 2 * (s2 - y1) % modulus
    v = x1 * i % modulus
    x3 = (r * r - j - 2 * v) % modulus
    y3 = (r * (v - x3) - 2 * y1 * j) % modulus
    z3 = 2 * z1 * h % modulus
    return (x3, y3, z3)


def _add_g2_mixed_projective(
    left: tuple[Fp2, Fp2, Fp2],
    right: G2Point,
) -> tuple[Fp2, Fp2, Fp2]:
    x1, y1, z1 = left
    zero = Fp2()
    if z1 == zero:
        return (right.x, right.y, Fp2(1))
    z1_squared = z1 * z1
    u2 = right.x * z1_squared
    s2 = right.y * z1 * z1_squared
    if x1 == u2:
        if y1 != s2:
            return (zero, Fp2(1), zero)
        return _double_g2_projective(left)
    h = u2 - x1
    i = (2 * h) * (2 * h)
    j = h * i
    r = 2 * (s2 - y1)
    v = x1 * i
    x3 = r * r - j - 2 * v
    y3 = r * (v - x3) - 2 * y1 * j
    z3 = 2 * z1 * h
    return (x3, y3, z3)


def multi_scalar_multiply_g1(
    points: tuple[G1Point, ...] | list[G1Point],
    scalars: tuple[int, ...] | list[int],
) -> G1Point:
    """Evaluate a G1 linear combination with a projective windowed MSM."""
    if len(points) != len(scalars):
        raise ValueError("G1 point and scalar counts do not match")
    if not points:
        return G1_INFINITY
    for point in points:
        _require_g1(point)
    for scalar in scalars:
        if type(scalar) is not int or scalar < 0:
            raise ValueError("G1 MSM scalars must be non-negative integers")
    maximum_bits = max((scalar.bit_length() for scalar in scalars), default=0)
    if maximum_bits == 0:
        return G1_INFINITY

    window = _msm_window_size(len(points), "g1")
    bucket_count = (1 << window) - 1
    windows = (maximum_bits + window - 1) // window
    result = (0, 1, 0)
    for window_index in range(windows - 1, -1, -1):
        if result[2] != 0:
            for _ in range(window):
                result = _double_g1_projective(result, FIELD_MODULUS)
        buckets = [(0, 1, 0)] * bucket_count
        shift = window_index * window
        mask = (1 << window) - 1
        for point, scalar in zip(points, scalars):
            digit = (scalar >> shift) & mask
            if digit and not point.is_infinity:
                buckets[digit - 1] = _add_g1_mixed_projective(
                    buckets[digit - 1], point, FIELD_MODULUS
                )
        running = (0, 1, 0)
        window_sum = (0, 1, 0)
        for bucket in reversed(buckets):
            running = _add_g1_projective(running, bucket, FIELD_MODULUS)
            window_sum = _add_g1_projective(
                window_sum, running, FIELD_MODULUS
            )
        result = _add_g1_projective(result, window_sum, FIELD_MODULUS)
    return _g1_from_projective(result)


def multi_scalar_multiply_g2(
    points: tuple[G2Point, ...] | list[G2Point],
    scalars: tuple[int, ...] | list[int],
) -> G2Point:
    """Evaluate a G2 linear combination with a projective windowed MSM."""
    if len(points) != len(scalars):
        raise ValueError("G2 point and scalar counts do not match")
    if not points:
        return G2_INFINITY
    for point in points:
        _require_g2(point)
    for scalar in scalars:
        if type(scalar) is not int or scalar < 0:
            raise ValueError("G2 MSM scalars must be non-negative integers")
    maximum_bits = max((scalar.bit_length() for scalar in scalars), default=0)
    if maximum_bits == 0:
        return G2_INFINITY

    window = _msm_window_size(len(points), "g2")
    bucket_count = (1 << window) - 1
    windows = (maximum_bits + window - 1) // window
    zero = Fp2()
    infinity = (zero, Fp2(1), zero)
    result = infinity
    for window_index in range(windows - 1, -1, -1):
        if result[2] != zero:
            for _ in range(window):
                result = _double_g2_projective(result)
        buckets = [infinity] * bucket_count
        shift = window_index * window
        mask = (1 << window) - 1
        for point, scalar in zip(points, scalars):
            digit = (scalar >> shift) & mask
            if digit and not point.is_infinity:
                buckets[digit - 1] = _add_g2_mixed_projective(
                    buckets[digit - 1], point
                )
        running = infinity
        window_sum = infinity
        for bucket in reversed(buckets):
            running = _add_g2_projective(running, bucket)
            window_sum = _add_g2_projective(window_sum, running)
        result = _add_g2_projective(result, window_sum)
    return _g2_from_projective(result)


def _multiply_g1_projective_point(
    point: G1Point, scalar: int
) -> tuple[int, int, int]:
    if point.is_infinity:
        return (0, 1, 0)
    modulus = FIELD_MODULUS
    result = (0, 1, 0)
    addend = (point.x, point.y, 1)
    while scalar:
        if scalar & 1:
            result = _add_g1_projective(result, addend, modulus)
        addend = _double_g1_projective(addend, modulus)
        scalar >>= 1
    return result


def _double_g1_projective(
    point: tuple[int, int, int], modulus: int
) -> tuple[int, int, int]:
    x, y, z = point
    if z == 0 or y == 0:
        return (0, 1, 0)
    a = x * x % modulus
    b = y * y % modulus
    c = b * b % modulus
    d = 2 * ((x + b) ** 2 - a - c) % modulus
    e = 3 * a % modulus
    f = e * e % modulus
    x3 = (f - 2 * d) % modulus
    y3 = (e * (d - x3) - 8 * c) % modulus
    z3 = 2 * y * z % modulus
    return (x3, y3, z3)


def _add_g1_projective(
    left: tuple[int, int, int],
    right: tuple[int, int, int],
    modulus: int,
) -> tuple[int, int, int]:
    x1, y1, z1 = left
    x2, y2, z2 = right
    if z1 == 0:
        return right
    if z2 == 0:
        return left
    z1_squared = z1 * z1 % modulus
    z2_squared = z2 * z2 % modulus
    u1 = x1 * z2_squared % modulus
    u2 = x2 * z1_squared % modulus
    s1 = y1 * z2 * z2_squared % modulus
    s2 = y2 * z1 * z1_squared % modulus
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _double_g1_projective(left, modulus)
    h = (u2 - u1) % modulus
    i = (2 * h) ** 2 % modulus
    j = h * i % modulus
    r = 2 * (s2 - s1) % modulus
    v = u1 * i % modulus
    x3 = (r * r - j - 2 * v) % modulus
    y3 = (r * (v - x3) - 2 * s1 * j) % modulus
    z3 = ((z1 + z2) ** 2 - z1_squared - z2_squared) * h % modulus
    return (x3, y3, z3)


def _multiply_g2_projective_point(
    point: G2Point, scalar: int
) -> tuple[Fp2, Fp2, Fp2]:
    if point.is_infinity:
        return (Fp2(), Fp2(1), Fp2())
    zero = Fp2()
    result = (zero, Fp2(1), zero)
    addend = (point.x, point.y, Fp2(1))
    while scalar:
        if scalar & 1:
            result = _add_g2_projective(result, addend)
        addend = _double_g2_projective(addend)
        scalar >>= 1
    return result


def _is_g1_in_prime_subgroup(point: G1Point) -> bool:
    if point.is_infinity:
        return True
    scalar = _BLS_X_MAGNITUDE * _BLS_X_MAGNITUDE
    x_times_x_squared = _multiply_g1_projective_point(point, scalar)
    if x_times_x_squared[2] == 0:
        return False
    x, y, z = x_times_x_squared
    negative_scaled = (x, -y % FIELD_MODULUS, z)
    beta = _G1_ENDOMORPHISM_BETA
    endomorphism = G1Point(point.x * beta % FIELD_MODULUS, point.y)
    z_squared = negative_scaled[2] ** 2 % FIELD_MODULUS
    z_cubed = z_squared * negative_scaled[2] % FIELD_MODULUS
    return (
        negative_scaled[0] == endomorphism.x * z_squared % FIELD_MODULUS
        and negative_scaled[1] == endomorphism.y * z_cubed % FIELD_MODULUS
    )


def _is_g2_in_prime_subgroup(point: G2Point) -> bool:
    if point.is_infinity:
        return True
    scaled = _multiply_g2_projective_point(point, _BLS_X_MAGNITUDE)
    x, y, z = scaled
    if z == Fp2():
        return False
    scaled = (x, -y, z)
    psi_x = Fp2(point.x.c0, -point.x.c1) * _G2_PSI_COEFF_X
    psi_y = Fp2(point.y.c0, -point.y.c1) * _G2_PSI_COEFF_Y
    z_squared = z * z
    z_cubed = z_squared * z
    return scaled[0] == psi_x * z_squared and scaled[1] == psi_y * z_cubed


def _double_g2_projective(
    point: tuple[Fp2, Fp2, Fp2]
) -> tuple[Fp2, Fp2, Fp2]:
    x, y, z = point
    zero = Fp2()
    if z == zero or y == zero:
        return (zero, Fp2(1), zero)
    a = x * x
    b = y * y
    c = b * b
    d = 2 * ((x + b) * (x + b) - a - c)
    e = 3 * a
    f = e * e
    x3 = f - 2 * d
    y3 = e * (d - x3) - 8 * c
    z3 = 2 * y * z
    return (x3, y3, z3)


def _add_g2_projective(
    left: tuple[Fp2, Fp2, Fp2],
    right: tuple[Fp2, Fp2, Fp2],
) -> tuple[Fp2, Fp2, Fp2]:
    x1, y1, z1 = left
    x2, y2, z2 = right
    zero = Fp2()
    if z1 == zero:
        return right
    if z2 == zero:
        return left
    z1_squared = z1 * z1
    z2_squared = z2 * z2
    u1 = x1 * z2_squared
    u2 = x2 * z1_squared
    s1 = y1 * z2 * z2_squared
    s2 = y2 * z1 * z1_squared
    if u1 == u2:
        if s1 != s2:
            return (zero, Fp2(1), zero)
        return _double_g2_projective(left)
    h = u2 - u1
    i = (2 * h) * (2 * h)
    j = h * i
    r = 2 * (s2 - s1)
    v = u1 * i
    x3 = r * r - j - 2 * v
    y3 = r * (v - x3) - 2 * s1 * j
    z3 = ((z1 + z2) * (z1 + z2) - z1_squared - z2_squared) * h
    return (x3, y3, z3)


def _require_g1(point: G1Point) -> None:
    if not isinstance(point, G1Point) or not point.is_on_curve():
        raise ValueError("invalid G1 point")


def _require_g2(point: G2Point) -> None:
    if not isinstance(point, G2Point) or not point.is_on_curve():
        raise ValueError("invalid G2 point")


def _sign_fp(value: int) -> bool:
    return value > FIELD_MODULUS // 2


def _sign_fp2(value: Fp2) -> bool:
    return _sign_fp(value.c1) if value.c1 else _sign_fp(value.c0)


def encode_g1(point: G1Point) -> bytes:
    _require_g1(point)
    if point.is_infinity:
        return bytes((0xC0,)) + bytes(47)
    encoded = bytearray(point.x.to_bytes(48, "big"))
    encoded[0] |= 0x80
    if _sign_fp(point.y):
        encoded[0] |= 0x20
    return bytes(encoded)


def encode_g2(point: G2Point) -> bytes:
    _require_g2(point)
    if point.is_infinity:
        return bytes((0xC0,)) + bytes(95)
    encoded = bytearray(
        point.x.c1.to_bytes(48, "big") + point.x.c0.to_bytes(48, "big")
    )
    encoded[0] |= 0x80
    if _sign_fp2(point.y):
        encoded[0] |= 0x20
    return bytes(encoded)


def decode_g1(data: bytes, check_subgroup: bool = True) -> G1Point:
    if not isinstance(data, bytes) or len(data) != 48:
        raise ValueError("compressed G1 encodings must be exactly 48 bytes")
    encoded = bytearray(data)
    compressed = bool(encoded[0] & 0x80)
    infinity = bool(encoded[0] & 0x40)
    sort = bool(encoded[0] & 0x20)
    if not compressed:
        raise ValueError("uncompressed G1 encodings are not supported")
    encoded[0] &= 0x1F
    x = int.from_bytes(encoded, "big")
    if infinity:
        if sort or x:
            raise ValueError("non-canonical G1 infinity encoding")
        return G1_INFINITY
    if x >= FIELD_MODULUS:
        raise ValueError("non-canonical G1 x-coordinate")
    y = _sqrt_fp((x * x * x + 4) % FIELD_MODULUS)
    if y is None:
        raise ValueError("G1 x-coordinate has no curve point")
    if _sign_fp(y) != sort:
        y = (-y) % FIELD_MODULUS
    point = G1Point(x, y)
    if check_subgroup and not point.is_in_subgroup():
        raise ValueError("G1 point is not in the prime-order subgroup")
    return point


def decode_g2(data: bytes, check_subgroup: bool = True) -> G2Point:
    if not isinstance(data, bytes) or len(data) != 96:
        raise ValueError("compressed G2 encodings must be exactly 96 bytes")
    encoded = bytearray(data)
    compressed = bool(encoded[0] & 0x80)
    infinity = bool(encoded[0] & 0x40)
    sort = bool(encoded[0] & 0x20)
    if not compressed:
        raise ValueError("uncompressed G2 encodings are not supported")
    encoded[0] &= 0x1F
    c1 = int.from_bytes(encoded[:48], "big")
    c0 = int.from_bytes(encoded[48:], "big")
    if infinity:
        if sort or c0 or c1:
            raise ValueError("non-canonical G2 infinity encoding")
        return G2_INFINITY
    if c0 >= FIELD_MODULUS or c1 >= FIELD_MODULUS:
        raise ValueError("non-canonical G2 x-coordinate")
    x = Fp2(c0, c1)
    y = (x * x * x + Fp2(4, 4)).sqrt()
    if y is None:
        raise ValueError("G2 x-coordinate has no curve point")
    if _sign_fp2(y) != sort:
        y = -y
    point = G2Point(x, y)
    if check_subgroup and not point.is_in_subgroup():
        raise ValueError("G2 point is not in the prime-order subgroup")
    return point


def encode_g1_uncompressed(point: G1Point) -> bytes:
    """Encode a G1 point as the pinned BLS12-381 uncompressed form."""
    _require_g1(point)
    if point.is_infinity:
        return bytes((0x40,)) + bytes(95)
    return point.x.to_bytes(48, "big") + point.y.to_bytes(48, "big")


def encode_g2_uncompressed(point: G2Point) -> bytes:
    """Encode a G2 point as the pinned BLS12-381 uncompressed form."""
    _require_g2(point)
    if point.is_infinity:
        return bytes((0x40,)) + bytes(191)
    return b"".join(
        coordinate.to_bytes(48, "big")
        for coordinate in (
            point.x.c1,
            point.x.c0,
            point.y.c1,
            point.y.c0,
        )
    )


def decode_g1_uncompressed(data: bytes, check_subgroup: bool = True) -> G1Point:
    """Decode canonical uncompressed G1, checking curve and subgroup validity."""
    if not isinstance(data, bytes) or len(data) != 96:
        raise ValueError("uncompressed G1 encodings must be exactly 96 bytes")
    encoded = bytearray(data)
    compressed = bool(encoded[0] & 0x80)
    infinity = bool(encoded[0] & 0x40)
    sort = bool(encoded[0] & 0x20)
    if compressed:
        raise ValueError("compressed flag set in uncompressed G1 encoding")
    if sort:
        raise ValueError("sort flag set in uncompressed G1 encoding")
    encoded[0] &= 0x1F
    if infinity:
        if any(encoded):
            raise ValueError("non-canonical uncompressed G1 infinity encoding")
        return G1_INFINITY
    x = int.from_bytes(encoded[:48], "big")
    y = int.from_bytes(encoded[48:], "big")
    if x >= FIELD_MODULUS or y >= FIELD_MODULUS:
        raise ValueError("non-canonical uncompressed G1 coordinate")
    point = G1Point(x, y)
    if not point.is_on_curve():
        raise ValueError("uncompressed G1 point is not on the curve")
    if check_subgroup and not point.is_in_subgroup():
        raise ValueError("uncompressed G1 point is not in the prime-order subgroup")
    return point


def decode_g2_uncompressed(data: bytes, check_subgroup: bool = True) -> G2Point:
    """Decode canonical uncompressed G2, checking curve and subgroup validity."""
    if not isinstance(data, bytes) or len(data) != 192:
        raise ValueError("uncompressed G2 encodings must be exactly 192 bytes")
    encoded = bytearray(data)
    compressed = bool(encoded[0] & 0x80)
    infinity = bool(encoded[0] & 0x40)
    sort = bool(encoded[0] & 0x20)
    if compressed:
        raise ValueError("compressed flag set in uncompressed G2 encoding")
    if sort:
        raise ValueError("sort flag set in uncompressed G2 encoding")
    encoded[0] &= 0x1F
    if infinity:
        if any(encoded):
            raise ValueError("non-canonical uncompressed G2 infinity encoding")
        return G2_INFINITY
    coordinates = tuple(
        int.from_bytes(encoded[index:index + 48], "big")
        for index in range(0, 192, 48)
    )
    if any(coordinate >= FIELD_MODULUS for coordinate in coordinates):
        raise ValueError("non-canonical uncompressed G2 coordinate")
    x = Fp2(coordinates[1], coordinates[0])
    y = Fp2(coordinates[3], coordinates[2])
    point = G2Point(x, y)
    if not point.is_on_curve():
        raise ValueError("uncompressed G2 point is not on the curve")
    if check_subgroup and not point.is_in_subgroup():
        raise ValueError("uncompressed G2 point is not in the prime-order subgroup")
    return point


def _fp2_embedding(value: Fp2) -> Fp12:
    coefficients = [0] * 12
    coefficients[0] = value.c0 - value.c1
    coefficients[6] = value.c1
    return Fp12(tuple(coefficients))


def _twist(
    point: G2Point, w2_inverse: Fp12, w3_inverse: Fp12
) -> Tuple[Fp12, Fp12]:
    return _fp2_embedding(point.x) * w2_inverse, _fp2_embedding(point.y) * w3_inverse


def _line_function(
    left: Tuple[Fp12, Fp12],
    right: Tuple[Fp12, Fp12],
    target: Tuple[Fp12, Fp12],
) -> Tuple[Fp12, Fp12]:
    x1, y1 = left
    x2, y2 = right
    xt, yt = target
    if x1 != x2:
        slope_numerator = y2 - y1
        slope_denominator = x2 - x1
    elif y1 == y2:
        slope_numerator = x1 * x1 * 3
        slope_denominator = y1 * 2
        if slope_denominator.is_zero():
            return xt - x1, Fp12.one()
    else:
        return xt - x1, Fp12.one()
    numerator = slope_numerator * (xt - x1) - slope_denominator * (yt - y1)
    return numerator, slope_denominator


def miller_loop(q: G2Point, p: G1Point) -> Fp12:
    """Compute the unreduced optimal-Ate Miller value for subgroup points."""
    _require_g1(p)
    _require_g2(q)
    if not p.is_in_subgroup() or not q.is_in_subgroup():
        raise ValueError("pairing inputs must be in their prime-order subgroups")
    if p.is_infinity or q.is_infinity:
        return Fp12.one()

    target = (Fp12.from_int(p.x), Fp12.from_int(p.y))
    w = Fp12((0, 1) + (0,) * 10)
    w2_inverse = (w * w).inverse()
    w3_inverse = (w * w * w).inverse()
    q_twisted = _twist(q, w2_inverse, w3_inverse)
    running = q
    running_twisted = q_twisted
    numerator = Fp12.one()
    denominator = Fp12.one()
    for bit_index in range(ATE_LOOP_COUNT.bit_length() - 2, -1, -1):
        line_numerator, line_denominator = _line_function(
            running_twisted, running_twisted, target
        )
        numerator = numerator * numerator * line_numerator
        denominator = denominator * denominator * line_denominator
        running = add_g2(running, running)
        running_twisted = _twist(running, w2_inverse, w3_inverse)
        if (ATE_LOOP_COUNT >> bit_index) & 1:
            line_numerator, line_denominator = _line_function(
                running_twisted, q_twisted, target
            )
            numerator = numerator * line_numerator
            denominator = denominator * line_denominator
            running = add_g2(running, q)
            running_twisted = _twist(running, w2_inverse, w3_inverse)
    return numerator / denominator


def final_exponentiate(value: Fp12) -> Fp12:
    """Map a nonzero Miller value into the order-r target subgroup."""
    if not isinstance(value, Fp12):
        raise TypeError("final exponentiation requires an Fp12 element")
    if value.is_zero():
        raise ValueError("cannot final-exponentiate zero")
    return value ** ((FIELD_MODULUS**12 - 1) // SCALAR_MODULUS)


def pairing(q: G2Point, p: G1Point) -> Fp12:
    """Return the reduced optimal-Ate pairing ``e(q, p)``."""
    _require_g1(p)
    _require_g2(q)
    if p.is_infinity or q.is_infinity:
        return Fp12.one()
    return final_exponentiate(miller_loop(q, p))
