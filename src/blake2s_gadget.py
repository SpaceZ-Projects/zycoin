"""Constrained BLAKE2s-256 gadgets for Sapling R1CS compositions."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import blake2s

from .bls12_381 import SCALAR_MODULUS
from .r1cs import R1CS, LinearCombination, R1CSError, Variable


@dataclass(frozen=True)
class _NegatedBit:
    variable: Variable


CircuitBit = int | Variable | _NegatedBit
Word = tuple[CircuitBit, ...]

_WORD_BITS = 32
_BLOCK_BITS = 512
_BLOCK_BYTES = 64
_MASK32 = (1 << _WORD_BITS) - 1
_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_SIGMA = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
)


@dataclass(frozen=True)
class Blake2sWitness:
    input_bits: tuple[int, ...]
    personalization: bytes
    digest: bytes


def bytes_to_bits_le(data: bytes) -> tuple[int, ...]:
    """Encode bytes in the little-endian bit order used by Bellman's gadget."""
    if not isinstance(data, bytes):
        raise TypeError("BLAKE2s input data must be bytes")
    return tuple((byte >> bit) & 1 for byte in data for bit in range(8))


def bits_to_bytes_le(bits: Sequence[CircuitBit], system: R1CS) -> bytes:
    """Read assigned bits as little-endian bytes."""
    values = tuple(_read_bit(system, bit) for bit in bits)
    if len(values) % 8:
        raise R1CSError("BLAKE2s output bits must contain complete bytes")
    return bytes(
        sum(bit << offset for offset, bit in enumerate(values[start:start + 8]))
        for start in range(0, len(values), 8)
    )


def make_blake2s_witness(
    input_bits: Sequence[int | bool],
    personalization: bytes,
) -> Blake2sWitness:
    """Prepare expected digest data from assigned bit values.

    This witness helper is not a substitute for ``constrain_blake2s``, which
    reconstructs the digest through R1CS constraints.
    """
    if not isinstance(personalization, bytes) or len(personalization) != 8:
        raise R1CSError("BLAKE2s personalization must contain exactly 8 bytes")
    if len(input_bits) % 8:
        raise R1CSError("BLAKE2s input must contain complete bytes")
    values = tuple(_constant_bit(bit) for bit in input_bits)
    message = _constant_bits_to_bytes(values)
    digest = blake2s(message, digest_size=32, person=personalization).digest()
    return Blake2sWitness(values, personalization, digest)


def constrain_blake2s(
    system: R1CS,
    input_bits: Sequence[CircuitBit],
    personalization: bytes,
    witness: Blake2sWitness,
    label: str = "BLAKE2s",
    *,
    input_bits_preconstrained: bool = False,
) -> tuple[CircuitBit, ...]:
    """Constrain the full unkeyed BLAKE2s-256 digest.

    Input and output bit sequences are little-endian within each byte. Variable
    inputs are Boolean-constrained unless the caller proves they were
    constrained earlier. Compression additions use Boolean result/carry bits
    and an integer reconstruction equation; XORs use quadratic R1CS equations.
    The host-generated digest is only checked against the constrained result.
    """
    if not isinstance(witness, Blake2sWitness):
        raise TypeError("witness must be a Blake2sWitness")
    if type(input_bits_preconstrained) is not bool:
        raise TypeError("input_bits_preconstrained must be a bool")
    if not isinstance(personalization, bytes) or len(personalization) != 8:
        raise R1CSError("BLAKE2s personalization must contain exactly 8 bytes")
    if personalization != witness.personalization:
        raise R1CSError("BLAKE2s witness personalization does not match")
    if len(input_bits) % 8:
        raise R1CSError("BLAKE2s input must contain complete bytes")
    if len(input_bits) // 8 >= 1 << 64:
        raise R1CSError("BLAKE2s input length must be less than 2^64 bytes")
    if len(witness.digest) != 32:
        raise R1CSError("BLAKE2s witness digest must contain 32 bytes")
    if len(witness.input_bits) != len(input_bits):
        raise R1CSError("BLAKE2s witness input length does not match")

    for index, bit in enumerate(input_bits):
        value = _read_bit(system, bit)
        if value != witness.input_bits[index]:
            raise R1CSError("BLAKE2s witness does not match the input assignment")
        variable = _backing_variable(bit)
        if variable is not None and not input_bits_preconstrained:
            _constrain_boolean(
                system, variable, f"{label} input bit[{index}]"
            )

    h = [
        _constant_word(
            _IV[0] ^ 0x01010020
            if index == 0
            else _IV[index]
            ^ (
                int.from_bytes(personalization[:4], "little")
                if index == 6
                else int.from_bytes(personalization[4:], "little")
                if index == 7
                else 0
            )
        )
        for index in range(8)
    ]

    blocks = [
        _block_words(input_bits[start:start + _BLOCK_BITS])
        for start in range(0, len(input_bits), _BLOCK_BITS)
    ]
    if not blocks:
        blocks = [[_constant_word(0) for _ in range(16)]]

    for block_index, block in enumerate(blocks[:-1]):
        h = _compress(
            system,
            h,
            block,
            (block_index + 1) * _BLOCK_BYTES,
            False,
            f"{label} block[{block_index}]",
        )
    h = _compress(
        system,
        h,
        blocks[-1],
        len(input_bits) // 8,
        True,
        f"{label} block[{len(blocks) - 1}] final",
    )

    output = tuple(bit for word in h for bit in word)
    if len(output) != 256:
        raise R1CSError("internal BLAKE2s output length is not 256 bits")
    if bits_to_bytes_le(output, system) != witness.digest:
        raise R1CSError("constrained BLAKE2s result does not match its witness")
    return output


def constrain_sapling_ivk(
    system: R1CS,
    ak_repr_bits: Sequence[CircuitBit],
    nk_repr_bits: Sequence[CircuitBit],
    label: str = "Sapling incoming viewing key",
    *,
    input_bits_preconstrained: bool = False,
    materialize_output: bool = True,
) -> tuple[CircuitBit, ...]:
    """Constrain CRH^ivk and return its low 251 little-endian bits.

    Set ``materialize_output=False`` to preserve Bellman-like complemented-bit
    aliases for a downstream gadget that accepts preconstrained bit expressions.
    """
    if len(ak_repr_bits) != 256 or len(nk_repr_bits) != 256:
        raise R1CSError("Sapling ak and nk representations must each contain 256 bits")
    if type(materialize_output) is not bool:
        raise TypeError("materialize_output must be a bool")
    preimage = tuple(ak_repr_bits) + tuple(nk_repr_bits)
    witness = make_blake2s_witness(
        tuple(_read_bit(system, bit) for bit in preimage), b"Zcashivk"
    )
    digest = constrain_blake2s(
        system,
        preimage,
        b"Zcashivk",
        witness,
        label,
        input_bits_preconstrained=input_bits_preconstrained,
    )
    return (
        _materialize_word(system, digest[:251], f"{label} output")
        if materialize_output
        else digest[:251]
    )


def constrain_sapling_nullifier_hash(
    system: R1CS,
    nk_repr_bits: Sequence[CircuitBit],
    rho_repr_bits: Sequence[CircuitBit],
    label: str = "Sapling nullifier PRF",
    *,
    input_bits_preconstrained: bool = False,
    materialize_output: bool = True,
) -> tuple[CircuitBit, ...]:
    """Constrain PRF^nf and return all 256 little-endian digest bits.

    Set ``materialize_output=False`` to preserve Bellman-like complemented-bit
    aliases for a downstream gadget that accepts preconstrained bit expressions.
    """
    if len(nk_repr_bits) != 256 or len(rho_repr_bits) != 256:
        raise R1CSError("Sapling nk and rho representations must each contain 256 bits")
    if type(materialize_output) is not bool:
        raise TypeError("materialize_output must be a bool")
    preimage = tuple(nk_repr_bits) + tuple(rho_repr_bits)
    witness = make_blake2s_witness(
        tuple(_read_bit(system, bit) for bit in preimage), b"Zcash_nf"
    )
    digest = constrain_blake2s(
        system,
        preimage,
        b"Zcash_nf",
        witness,
        label,
        input_bits_preconstrained=input_bits_preconstrained,
    )
    return (
        _materialize_word(system, digest, f"{label} output")
        if materialize_output
        else digest
    )


def _compress(
    system: R1CS,
    h: list[Word],
    message: list[Word],
    counter: int,
    final: bool,
    label: str,
) -> list[Word]:
    if len(h) != 8 or len(message) != 16:
        raise R1CSError("invalid BLAKE2s compression state")
    v = list(h) + [_constant_word(word) for word in _IV]
    v[12] = _word_xor(
        system, v[12], _constant_word(counter & _MASK32), f"{label} counter low"
    )
    v[13] = _word_xor(
        system,
        v[13],
        _constant_word((counter >> 32) & _MASK32),
        f"{label} counter high",
    )
    if final:
        v[14] = _word_xor(
            system, v[14], _constant_word(_MASK32), f"{label} final flag"
        )

    additions = _PackedEqualities(system, label)
    for round_index, sigma in enumerate(_SIGMA):
        round_label = f"{label} round[{round_index}]"
        _mix_g(system, v, (0, 4, 8, 12), message[sigma[0]], message[sigma[1]],
               f"{round_label} g[0]", additions)
        _mix_g(system, v, (1, 5, 9, 13), message[sigma[2]], message[sigma[3]],
               f"{round_label} g[1]", additions)
        _mix_g(system, v, (2, 6, 10, 14), message[sigma[4]], message[sigma[5]],
               f"{round_label} g[2]", additions)
        _mix_g(system, v, (3, 7, 11, 15), message[sigma[6]], message[sigma[7]],
               f"{round_label} g[3]", additions)
        _mix_g(system, v, (0, 5, 10, 15), message[sigma[8]], message[sigma[9]],
               f"{round_label} g[4]", additions)
        _mix_g(system, v, (1, 6, 11, 12), message[sigma[10]], message[sigma[11]],
               f"{round_label} g[5]", additions)
        _mix_g(system, v, (2, 7, 8, 13), message[sigma[12]], message[sigma[13]],
               f"{round_label} g[6]", additions)
        _mix_g(system, v, (3, 4, 9, 14), message[sigma[14]], message[sigma[15]],
               f"{round_label} g[7]", additions)

    additions.finish()
    return [
        _word_xor(
            system,
            _word_xor(system, h[index], v[index], f"{label} hash xor a[{index}]"),
            v[index + 8],
            f"{label} hash xor b[{index}]",
        )
        for index in range(8)
    ]


def _mix_g(
    system: R1CS,
    state: list[Word],
    indices: tuple[int, int, int, int],
    x: Word,
    y: Word,
    label: str,
    additions: _PackedEqualities,
) -> None:
    a, b, c, d = indices
    state[a] = _word_add(
        system, (state[a], state[b], x), f"{label} add[0]", additions
    )
    state[d] = _word_rotate_right(
        _word_xor(system, state[d], state[a], f"{label} xor[0]"), 16
    )
    state[c] = _word_add(
        system, (state[c], state[d]), f"{label} add[1]", additions
    )
    state[b] = _word_rotate_right(
        _word_xor(system, state[b], state[c], f"{label} xor[1]"), 12
    )
    state[a] = _word_add(
        system, (state[a], state[b], y), f"{label} add[2]", additions
    )
    state[d] = _word_rotate_right(
        _word_xor(system, state[d], state[a], f"{label} xor[2]"), 8
    )
    state[c] = _word_add(
        system, (state[c], state[d]), f"{label} add[3]", additions
    )
    state[b] = _word_rotate_right(
        _word_xor(system, state[b], state[c], f"{label} xor[3]"), 7
    )


def _word_add(
    system: R1CS,
    words: Sequence[Word],
    label: str,
    additions: _PackedEqualities,
) -> Word:
    if len(words) not in (2, 3) or any(len(word) != _WORD_BITS for word in words):
        raise R1CSError("BLAKE2s word addition expects two or three 32-bit words")
    total = sum(_word_value(system, word) for word in words)
    output_value = total & _MASK32
    carry_value = total >> _WORD_BITS
    if all(
        _backing_variable(bit) is None
        for word in words
        for bit in word
    ):
        return _constant_word(output_value)
    output = tuple(
        system.alloc_private(f"{label} bit[{index}]", (output_value >> index) & 1)
        for index in range(_WORD_BITS)
    )
    for index, bit in enumerate(output):
        _constrain_boolean(system, bit, f"{label} bit[{index}] boolean")

    carry_width = 1 if len(words) == 2 else 2
    carry = tuple(
        system.alloc_private(
            f"{label} carry[{index}]", (carry_value >> index) & 1
        )
        for index in range(carry_width)
    )
    for index, bit in enumerate(carry):
        _constrain_boolean(system, bit, f"{label} carry[{index}] boolean")

    input_sum = _word_lc(system, words[0])
    for word in words[1:]:
        input_sum = input_sum + _word_lc(system, word)
    carry_lc = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(carry))
    )
    additions.add(
        input_sum,
        _word_lc(system, output) + carry_lc * (1 << _WORD_BITS),
        _WORD_BITS + carry_width,
        f"{label} modular addition",
    )
    return output


def _word_xor(system: R1CS, left: Word, right: Word, label: str) -> Word:
    if len(left) != _WORD_BITS or len(right) != _WORD_BITS:
        raise R1CSError("BLAKE2s XOR operands must be 32-bit words")
    return tuple(
        _xor_bit(system, a, b, f"{label} bit[{index}]")
        for index, (a, b) in enumerate(zip(left, right))
    )


def _xor_bit(
    system: R1CS, left: CircuitBit, right: CircuitBit, label: str
) -> CircuitBit:
    left_value = _read_bit(system, left)
    right_value = _read_bit(system, right)
    output_value = left_value ^ right_value
    if _backing_variable(left) is None and _backing_variable(right) is None:
        return output_value
    if _backing_variable(left) is None:
        return right if left_value == 0 else _negate_bit(right)
    if _backing_variable(right) is None:
        return left if right_value == 0 else _negate_bit(left)

    left_variable = _backing_variable(left)
    right_variable = _backing_variable(right)
    if left_variable is None or right_variable is None:
        raise R1CSError("BLAKE2s XOR operands must be bits")
    left_negated = isinstance(left, _NegatedBit)
    right_negated = isinstance(right, _NegatedBit)
    raw_output_value = (
        system._witness_value(left_variable)
        ^ system._witness_value(right_variable)
    )
    output = system.alloc_private(label, raw_output_value)
    system.enforce(
        left_variable.lc() * 2,
        right_variable,
        left_variable.lc() + right_variable.lc() - output.lc(),
        f"{label} XOR relation",
    )
    return _negate_bit(output) if left_negated != right_negated else output


def _word_rotate_right(word: Word, count: int) -> Word:
    return tuple(word[(index + count) % _WORD_BITS] for index in range(_WORD_BITS))


def _block_words(bits: Sequence[CircuitBit]) -> list[Word]:
    if len(bits) > _BLOCK_BITS:
        raise R1CSError("BLAKE2s block exceeds 64 bytes")
    padded = tuple(bits) + (0,) * (_BLOCK_BITS - len(bits))
    return [
        tuple(padded[start:start + _WORD_BITS])
        for start in range(0, _BLOCK_BITS, _WORD_BITS)
    ]


def _constant_word(value: int) -> Word:
    if type(value) is not int or not 0 <= value <= _MASK32:
        raise R1CSError("BLAKE2s constant word must be an unsigned 32-bit integer")
    return tuple((value >> index) & 1 for index in range(_WORD_BITS))


def _word_lc(system: R1CS, word: Word):
    variables = []
    constant = 0
    for index, bit in enumerate(word):
        coefficient = 1 << index
        if isinstance(bit, Variable):
            variables.append((bit, coefficient))
        elif isinstance(bit, _NegatedBit):
            variables.append((bit.variable, -coefficient))
            constant += coefficient
        else:
            constant += _constant_bit(bit) * coefficient
    return system.linear_combination(variables, constant)


def _constrain_boolean(system: R1CS, variable: Variable, label: str) -> None:
    system.enforce(
        1 - variable.lc(),
        variable,
        0,
        label,
    )


def _backing_variable(bit: CircuitBit) -> Variable | None:
    if isinstance(bit, Variable):
        return bit
    if isinstance(bit, _NegatedBit):
        return bit.variable
    return None


def _negate_bit(bit: CircuitBit) -> CircuitBit:
    if isinstance(bit, _NegatedBit):
        return bit.variable
    if isinstance(bit, Variable):
        return _NegatedBit(bit)
    return 1 - _constant_bit(bit)


def _materialize_word(system: R1CS, word: Word, label: str) -> Word:
    result: list[CircuitBit] = []
    for index, bit in enumerate(word):
        if isinstance(bit, _NegatedBit):
            variable = system.alloc_private(
                f"{label} bit[{index}]", _read_bit(system, bit)
            )
            system.enforce_equal(
                variable.lc() + bit.variable.lc(),
                1,
                f"{label} bit[{index}] complement",
            )
            result.append(variable)
        else:
            result.append(bit)
    return tuple(result)


def _word_value(system: R1CS, word: Word) -> int:
    return sum(_read_bit(system, bit) << index for index, bit in enumerate(word))


def _read_bit(system: R1CS, bit: CircuitBit) -> int:
    if isinstance(bit, Variable):
        value = system._witness_value(bit)
        if value not in (0, 1):
            raise R1CSError("BLAKE2s bit is unassigned or invalid")
        return int(value)
    if isinstance(bit, _NegatedBit):
        return 1 - _read_bit(system, bit.variable)
    return _constant_bit(bit)


def _constant_bit(value: CircuitBit) -> int:
    if type(value) not in (int, bool) or value not in (0, 1):
        raise R1CSError("BLAKE2s bits must be zero or one")
    return int(value)


def _constant_bits_to_bytes(bits: Sequence[int]) -> bytes:
    return bytes(
        sum(bit << offset for offset, bit in enumerate(bits[start:start + 8]))
        for start in range(0, len(bits), 8)
    )


class _PackedEqualities:
    def __init__(self, system: R1CS, label: str) -> None:
        self._system = system
        self._label = label
        self._capacity = SCALAR_MODULUS.bit_length() - 1
        self._bits_used = 0
        self._batch_index = 0
        self._first_label: str | None = None
        self._left = system.linear_combination(())
        self._right = system.linear_combination(())

    def add(
        self,
        left: LinearCombination,
        right: LinearCombination,
        num_bits: int,
        label: str,
    ) -> None:
        if self._capacity <= self._bits_used + num_bits:
            self._flush()
        if self._bits_used == 0:
            self._first_label = label
        coefficient = 1 << self._bits_used
        self._left = self._left + left * coefficient
        self._right = self._right + right * coefficient
        self._bits_used += num_bits

    def finish(self) -> None:
        self._flush()

    def _flush(self) -> None:
        if self._bits_used == 0:
            return
        self._system.enforce(
            self._left,
            1,
            self._right,
            f"{self._label} packed additions[{self._batch_index}] "
            f"from {self._first_label}",
        )
        self._batch_index += 1
        self._bits_used = 0
        self._first_label = None
        self._left = self._system.linear_combination(())
        self._right = self._system.linear_combination(())


__all__ = [
    "Blake2sWitness",
    "bits_to_bytes_le",
    "bytes_to_bits_le",
    "constrain_blake2s",
    "constrain_sapling_ivk",
    "constrain_sapling_nullifier_hash",
    "make_blake2s_witness",
]
