"""Radix-2 FFT foundation over the BLS12-381 scalar field.

The interface uses canonical integer coefficients and natural-order
evaluations. It does not construct QAPs or implement Groth16 operations.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .bls12_381 import SCALAR_MODULUS

MULTIPLICATIVE_GENERATOR = 7
TWO_ADICITY = 32
MAX_DOMAIN_SIZE = 1 << (TWO_ADICITY - 1)


class FFTError(ValueError):
    """Raised when an FFT domain or input vector is invalid."""


@dataclass(frozen=True)
class FFTDomain:
    """A radix-2 subgroup domain with explicit natural-order conventions.

    The default maximum size mirrors Bellman 0.15.0's ``exp < S`` check:
    BLS12-381 scalar-field two-adicity is 32, so the largest accepted domain
    has size 2**31. Constructing this metadata does not allocate that many
    coefficients; callers remain responsible for their input memory.
    """

    size: int
    omega: int
    omega_inverse: int
    size_inverse: int
    coset_generator: int
    coset_generator_inverse: int

    def __post_init__(self) -> None:
        if type(self.size) is not int or not 1 <= self.size <= MAX_DOMAIN_SIZE:
            raise FFTError("domain size is outside Bellman's supported range")
        if self.size & (self.size - 1):
            raise FFTError("domain size must be a power of two")
        for name in (
            "omega",
            "omega_inverse",
            "size_inverse",
            "coset_generator",
            "coset_generator_inverse",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
                raise FFTError(f"{name} must be a canonical scalar-field value")
        if pow(self.omega, self.size, SCALAR_MODULUS) != 1:
            raise FFTError("domain root has an unsupported order")
        if self.size > 1 and pow(
            self.omega, self.size // 2, SCALAR_MODULUS
        ) == 1:
            raise FFTError("domain root is not primitive")
        if self.omega * self.omega_inverse % SCALAR_MODULUS != 1:
            raise FFTError("inverse root is inconsistent")
        if self.size * self.size_inverse % SCALAR_MODULUS != 1:
            raise FFTError("domain normalization factor is inconsistent")
        if self.coset_generator != MULTIPLICATIVE_GENERATOR:
            raise FFTError("unsupported coset generator")
        if (
            self.coset_generator * self.coset_generator_inverse
            % SCALAR_MODULUS
            != 1
        ):
            raise FFTError("inverse coset generator is inconsistent")
        if pow(self.coset_generator, self.size, SCALAR_MODULUS) == 1:
            raise FFTError("coset generator lies in the evaluation subgroup")

    @classmethod
    def create(cls, size: int, root: int | None = None) -> FFTDomain:
        """Create a domain using Bellman's canonical root, or a checked root."""
        if type(size) is not int or size < 1:
            raise FFTError("domain size must be a positive integer")
        if size & (size - 1):
            raise FFTError("domain size must be a power of two")
        if size > MAX_DOMAIN_SIZE:
            raise FFTError(
                f"domain size exceeds Bellman limit {MAX_DOMAIN_SIZE}"
            )

        if root is None:
            omega = pow(
                MULTIPLICATIVE_GENERATOR,
                (SCALAR_MODULUS - 1) // size,
                SCALAR_MODULUS,
            )
        else:
            if type(root) is not int or not 0 <= root < SCALAR_MODULUS:
                raise FFTError("root must be a canonical scalar-field element")
            omega = root
            if pow(omega, size, SCALAR_MODULUS) != 1:
                raise FFTError("root does not have an order dividing the domain size")
            if size > 1 and pow(omega, size // 2, SCALAR_MODULUS) == 1:
                raise FFTError("root is not primitive for the domain size")

        generator = MULTIPLICATIVE_GENERATOR
        if pow(generator, size, SCALAR_MODULUS) == 1:
            raise FFTError("coset generator lies in the evaluation subgroup")
        return cls(
            size=size,
            omega=omega,
            omega_inverse=pow(omega, -1, SCALAR_MODULUS),
            size_inverse=pow(size, -1, SCALAR_MODULUS),
            coset_generator=generator,
            coset_generator_inverse=pow(generator, -1, SCALAR_MODULUS),
        )

    def fft(self, coefficients: Sequence[int]) -> list[int]:
        """Evaluate coefficients at omega**j in natural j order."""
        values = _validated_values(coefficients, self.size)
        return _radix2_fft(values, self.omega)

    def ifft(self, evaluations: Sequence[int]) -> list[int]:
        """Recover coefficients from natural-order evaluations."""
        values = _validated_values(evaluations, self.size)
        transformed = _radix2_fft(values, self.omega_inverse)
        return [
            value * self.size_inverse % SCALAR_MODULUS for value in transformed
        ]

    def coset_fft(self, coefficients: Sequence[int]) -> list[int]:
        """Evaluate on coset_generator * <omega>, in natural order."""
        values = _validated_values(coefficients, self.size)
        power = 1
        for index in range(self.size):
            values[index] = values[index] * power % SCALAR_MODULUS
            power = power * self.coset_generator % SCALAR_MODULUS
        return _radix2_fft(values, self.omega)

    def icoset_fft(self, evaluations: Sequence[int]) -> list[int]:
        """Invert coset_fft, returning the original coefficients."""
        coefficients = self.ifft(evaluations)
        power = 1
        for index in range(self.size):
            coefficients[index] = coefficients[index] * power % SCALAR_MODULUS
            power = power * self.coset_generator_inverse % SCALAR_MODULUS
        return coefficients


def _validated_values(values: Sequence[int], expected_size: int) -> list[int]:
    if not isinstance(values, Sequence):
        raise TypeError("FFT input must be a sequence of canonical integers")
    if len(values) != expected_size:
        raise FFTError(
            f"FFT input length {len(values)} does not match domain size "
            f"{expected_size}"
        )
    result: list[int] = []
    for index, value in enumerate(values):
        if type(value) is not int or not 0 <= value < SCALAR_MODULUS:
            raise FFTError(
                f"FFT input at index {index} is not a canonical scalar-field value"
            )
        result.append(value)
    return result


def _radix2_fft(values: list[int], root: int) -> list[int]:
    size = len(values)
    if size == 1:
        return values

    bits = size.bit_length() - 1
    for index in range(size):
        reversed_index = _reverse_bits(index, bits)
        if index < reversed_index:
            values[index], values[reversed_index] = (
                values[reversed_index],
                values[index],
            )

    width = 2
    while width <= size:
        half_width = width // 2
        step = pow(root, size // width, SCALAR_MODULUS)
        for block_start in range(0, size, width):
            twiddle = 1
            for offset in range(half_width):
                even_index = block_start + offset
                odd_index = even_index + half_width
                even = values[even_index]
                odd = values[odd_index] * twiddle % SCALAR_MODULUS
                values[even_index] = (even + odd) % SCALAR_MODULUS
                values[odd_index] = (even - odd) % SCALAR_MODULUS
                twiddle = twiddle * step % SCALAR_MODULUS
        width *= 2
    return values


def _reverse_bits(value: int, width: int) -> int:
    reversed_value = 0
    for _ in range(width):
        reversed_value = (reversed_value << 1) | (value & 1)
        value >>= 1
    return reversed_value


__all__ = [
    "MAX_DOMAIN_SIZE",
    "MULTIPLICATIVE_GENERATOR",
    "TWO_ADICITY",
    "FFTDomain",
    "FFTError",
]
