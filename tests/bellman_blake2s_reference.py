"""Python transcription of Bellman 0.15.0's BLAKE2s gadget synthesis.

This is source-derived test code, not an exported Bellman matrix.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Protocol

from src.bellman_synthesis import RecorderLinearCombination, RecorderVariable
from src.r1cs import R1CS
from src.r1cs import LinearCombination as LocalLinearCombination
from src.r1cs import Variable as LocalVariable

Variable = LocalVariable | RecorderVariable
LinearCombination = LocalLinearCombination | RecorderLinearCombination


class _SynthesisSystem(Protocol):
    def alloc_private(self, name: str, value: int | None) -> Any: ...

    def linear_combination(
        self, terms: Iterable[tuple[Any, int]], constant: int = 0
    ) -> Any: ...

    def enforce(self, left: Any, right: Any, output: Any, label: str = "") -> None: ...

    def _witness_value(self, variable: Any) -> Any: ...

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
class _Negated:
    variable: Variable


Bit = int | LocalVariable | RecorderVariable | _Negated
Word = tuple[Bit, ...]


@dataclass
class _MultiEq:
    system: _SynthesisSystem
    bits_used: int = 0
    left: LinearCombination | None = None
    right: LinearCombination | None = None
    batch: int = 0

    def __post_init__(self) -> None:
        self.left = self.system.linear_combination(())
        self.right = self.system.linear_combination(())

    def add(
        self, left: LinearCombination, right: LinearCombination, width: int
    ) -> None:
        if self.bits_used + width >= 254:
            self.flush()
        coefficient = 1 << self.bits_used
        assert self.left is not None and self.right is not None
        self.left = self.left + left * coefficient
        self.right = self.right + right * coefficient
        self.bits_used += width

    def flush(self) -> None:
        if not self.bits_used:
            return
        assert self.left is not None and self.right is not None
        self.system.enforce(self.left, 1, self.right, f"Bellman MultiEq {self.batch}")
        self.batch += 1
        self.bits_used = 0
        self.left = self.system.linear_combination(())
        self.right = self.system.linear_combination(())


def build_bellman_compression_reference() -> R1CS:
    """Synthesize Bellman's pinned one-block, 512-variable-bit test case."""
    system = R1CS()
    message_bits = tuple(
        system.alloc_private(f"input bit {index}", 1) for index in range(512)
    )
    for bit in message_bits:
        system.enforce(1 - bit.lc(), bit, 0, "Bellman allocated-bit boolean")
    constrain_bellman_blake2s_reference(system, message_bits, b"12345678")
    return system


def constrain_bellman_blake2s_reference(
    system: _SynthesisSystem,
    input_bits: tuple[Bit, ...],
    personalization: bytes,
) -> tuple[Bit, ...]:
    """Synthesize Bellman's full BLAKE2s hash over already-admitted bits."""
    if len(personalization) != 8 or len(input_bits) % 8:
        raise ValueError("invalid Bellman BLAKE2s input or personalization")
    h: list[Word] = [
        _constant_word(_IV[0] ^ 0x01010020),
        *(_constant_word(value) for value in _IV[1:6]),
        _constant_word(
            _IV[6] ^ int.from_bytes(personalization[:4], "little")
        ),
        _constant_word(
            _IV[7] ^ int.from_bytes(personalization[4:], "little")
        ),
    ]
    blocks = [
        _block_words(input_bits[start : start + 512])
        for start in range(0, len(input_bits), 512)
    ]
    if not blocks:
        blocks = [[_constant_word(0) for _ in range(16)]]
    for block_index, block in enumerate(blocks[:-1]):
        h = _compress(
            system,
            h,
            block,
            (block_index + 1) * 64,
            False,
        )
    h = _compress(
        system,
        h,
        blocks[-1],
        len(input_bits) // 8,
        True,
    )
    return tuple(bit for word in h for bit in word)


def bellman_bits_to_bytes(system: _SynthesisSystem, bits: tuple[Bit, ...]) -> bytes:
    if len(bits) % 8:
        raise ValueError("Bellman bit output must contain complete bytes")
    values = tuple(_value(bit, system) for bit in bits)
    return bytes(
        sum(bit << offset for offset, bit in enumerate(values[start : start + 8]))
        for start in range(0, len(values), 8)
    )


def _compress(
    system: _SynthesisSystem, h: list[Word], message: list[Word], counter: int, final: bool
) -> list[Word]:
    state = list(h) + [_constant_word(value) for value in _IV]
    state[12] = _xor_word(state[12], _constant_word(counter & 0xFFFFFFFF), system)
    state[13] = _xor_word(
        state[13], _constant_word(counter >> 32), system
    )
    if final:
        state[14] = _xor_word(
            state[14], _constant_word(0xFFFFFFFF), system
        )

    multieq = _MultiEq(system)
    for sigma in _SIGMA:
        for indices, first, second in (
            ((0, 4, 8, 12), 0, 1),
            ((1, 5, 9, 13), 2, 3),
            ((2, 6, 10, 14), 4, 5),
            ((3, 7, 11, 15), 6, 7),
            ((0, 5, 10, 15), 8, 9),
            ((1, 6, 11, 12), 10, 11),
            ((2, 7, 8, 13), 12, 13),
            ((3, 4, 9, 14), 14, 15),
        ):
            _mix(
                system,
                state,
                indices,
                message[sigma[first]],
                message[sigma[second]],
                multieq,
            )
    multieq.flush()

    return [
        _xor_word(
            _xor_word(h[index], state[index], system),
            state[index + 8],
            system,
        )
        for index in range(8)
    ]


def _mix(
    system: _SynthesisSystem,
    state: list[Word],
    indices: tuple[int, int, int, int],
    x: Word,
    y: Word,
    multieq: _MultiEq,
) -> None:
    a, b, c, d = indices
    state[a] = _add(system, (state[a], state[b], x), multieq)
    state[d] = _rotate(_xor_word(state[d], state[a], system), 16)
    state[c] = _add(system, (state[c], state[d]), multieq)
    state[b] = _rotate(_xor_word(state[b], state[c], system), 12)
    state[a] = _add(system, (state[a], state[b], y), multieq)
    state[d] = _rotate(_xor_word(state[d], state[a], system), 8)
    state[c] = _add(system, (state[c], state[d]), multieq)
    state[b] = _rotate(_xor_word(state[b], state[c], system), 7)


def _add(system: _SynthesisSystem, words: tuple[Word, ...], multieq: _MultiEq) -> Word:
    total = sum(_word_value(word, system) for word in words)
    max_value = len(words) * 0xFFFFFFFF
    width = max_value.bit_length()
    if all(_backing(bit) is None for word in words for bit in word):
        return _constant_word(total & 0xFFFFFFFF)

    result: list[Variable] = []
    for index in range(width):
        bit = system.alloc_private(
            f"Bellman result bit[{index}]", (total >> index) & 1
        )
        system.enforce(1 - bit.lc(), bit, 0, "Bellman allocated-bit boolean")
        result.append(bit)

    left = _word_lc(system, words[0])
    for word in words[1:]:
        left = left + _word_lc(system, word)
    right = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(result))
    )
    multieq.add(left, right, width)
    return tuple(result[:32])


def _xor_word(left: Word, right: Word, system: _SynthesisSystem) -> Word:
    return tuple(_xor_bit(a, b, system) for a, b in zip(left, right))


def _xor_bit(left: Bit, right: Bit, system: _SynthesisSystem) -> Bit:
    left_value = _value(left, system)
    right_value = _value(right, system)
    if _backing(left) is None:
        return _negate(right) if left_value else right
    if _backing(right) is None:
        return _negate(left) if right_value else left

    left_variable = _backing(left)
    right_variable = _backing(right)
    assert left_variable is not None and right_variable is not None
    raw = system.alloc_private(
        "Bellman XOR result",
        int(system._witness_value(left_variable))
        ^ int(system._witness_value(right_variable)),
    )
    system.enforce(
        left_variable.lc() * 2,
        right_variable,
        left_variable.lc() + right_variable.lc() - raw.lc(),
        "Bellman XOR",
    )
    negated = isinstance(left, _Negated) != isinstance(right, _Negated)
    return _Negated(raw) if negated else raw


def _word_lc(system: _SynthesisSystem, word: Word) -> LinearCombination:
    terms: list[tuple[Variable, int]] = []
    constant = 0
    for index, bit in enumerate(word):
        coefficient = 1 << index
        if isinstance(bit, (LocalVariable, RecorderVariable)):
            terms.append((bit, coefficient))
        elif isinstance(bit, _Negated):
            terms.append((bit.variable, -coefficient))
            constant += coefficient
        else:
            constant += bit * coefficient
    return system.linear_combination(terms, constant)


def _word_value(word: Word, system: _SynthesisSystem) -> int:
    return sum(_value(bit, system) << index for index, bit in enumerate(word))


def _value(bit: Bit, system: _SynthesisSystem) -> int:
    if isinstance(bit, _Negated):
        return 1 - int(system._witness_value(bit.variable))
    if isinstance(bit, (LocalVariable, RecorderVariable)):
        return int(system._witness_value(bit))
    return bit


def _backing(bit: Bit) -> Variable | None:
    if isinstance(bit, _Negated):
        return bit.variable
    return bit if isinstance(bit, (LocalVariable, RecorderVariable)) else None


def _negate(bit: Bit) -> Bit:
    if isinstance(bit, _Negated):
        return bit.variable
    if isinstance(bit, (LocalVariable, RecorderVariable)):
        return _Negated(bit)
    return 1 - bit


def _rotate(word: Word, amount: int) -> Word:
    return tuple(word[(index + amount) % 32] for index in range(32))


def _constant_word(value: int) -> Word:
    return tuple((value >> index) & 1 for index in range(32))


def _block_words(bits: tuple[Bit, ...]) -> list[Word]:
    if len(bits) > 512:
        raise ValueError("Bellman BLAKE2s block exceeds 512 bits")
    padded = bits + (0,) * (512 - len(bits))
    return [
        tuple(padded[start : start + 32])
        for start in range(0, 512, 32)
    ]
