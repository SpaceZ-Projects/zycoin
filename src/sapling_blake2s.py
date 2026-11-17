"""Source-ordered Sapling BLAKE2s constraint gadget."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .blake2s_gadget import (
    CircuitBit,
    _NegatedBit,
    _read_bit,
    bits_to_bytes_le,
    make_blake2s_witness,
)
from .r1cs import R1CS, LinearCombination, R1CSError, Variable

Bit = CircuitBit
Word = tuple[Bit, ...]

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


@dataclass
class _MultiEq:
    system: R1CS
    annotation_prefix: str
    bits_used: int = 0
    left: LinearCombination | None = None
    right: LinearCombination | None = None
    batch: int = 0

    def __post_init__(self) -> None:
        self.left = self.system.linear_combination(())
        self.right = self.system.linear_combination(())

    def add(
        self,
        left: LinearCombination,
        right: LinearCombination,
        width: int,
        annotation_prefix: str,
    ) -> None:
        if self.bits_used + width >= 254:
            self.flush(annotation_prefix)
        coefficient = 1 << self.bits_used
        assert self.left is not None and self.right is not None
        self.left = self.left + left * coefficient
        self.right = self.right + right * coefficient
        self.bits_used += width

    def flush(self, annotation_prefix: str) -> None:
        if not self.bits_used:
            return
        assert self.left is not None and self.right is not None
        label = f"{annotation_prefix}/multieq {self.batch}"
        self.system.enforce(self.left, 1, self.right, label)
        self.batch += 1
        self.bits_used = 0
        self.left = self.system.linear_combination(())
        self.right = self.system.linear_combination(())


def constrain_sapling_blake2s(
    system: R1CS,
    input_bits: Sequence[Bit],
    personalization: bytes,
    annotation_prefix: str,
) -> tuple[Bit, ...]:
    """Constrain BLAKE2s with the pinned Sapling Bellman row and label order."""
    if not isinstance(system, R1CS):
        raise TypeError("system must be an R1CS")
    if not isinstance(input_bits, Sequence):
        raise TypeError("BLAKE2s input bits must be a sequence")
    if not isinstance(personalization, bytes) or len(personalization) != 8:
        raise R1CSError("BLAKE2s personalization must contain exactly 8 bytes")
    if len(input_bits) % 8:
        raise R1CSError("BLAKE2s input must contain complete bytes")
    if len(input_bits) // 8 >= 1 << 64:
        raise R1CSError("BLAKE2s input length must be less than 2^64 bytes")
    if not isinstance(annotation_prefix, str) or not annotation_prefix:
        raise TypeError("BLAKE2s annotation prefix must be a non-empty string")

    values = tuple(_read_bit(system, bit) for bit in input_bits)
    if any(value not in (0, 1) for value in values):
        raise R1CSError("BLAKE2s input bits must be Boolean")
    witness = make_blake2s_witness(values, personalization)

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
        _block_words(tuple(input_bits[start : start + 512]))
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
            f"{annotation_prefix}/block {block_index}",
        )
    h = _compress(
        system,
        h,
        blocks[-1],
        len(input_bits) // 8,
        True,
        f"{annotation_prefix}/final block",
    )
    output = tuple(bit for word in h for bit in word)
    if len(output) != 256:
        raise R1CSError("internal BLAKE2s output length is not 256 bits")
    if bits_to_bytes_le(output, system) != witness.digest:
        raise R1CSError("constrained BLAKE2s result does not match its witness")
    return output


def _compress(
    system: R1CS,
    h: list[Word],
    message: list[Word],
    counter: int,
    final: bool,
    annotation_prefix: str,
) -> list[Word]:
    state = list(h) + [_constant_word(value) for value in _IV]
    state[12] = _xor_word(
        state[12],
        _constant_word(counter & 0xFFFFFFFF),
        system,
        _annotation_path(annotation_prefix, "first xor"),
    )
    state[13] = _xor_word(
        state[13],
        _constant_word(counter >> 32),
        system,
        _annotation_path(annotation_prefix, "second xor"),
    )
    if final:
        state[14] = _xor_word(
            state[14],
            _constant_word(0xFFFFFFFF),
            system,
            _annotation_path(annotation_prefix, "third xor"),
        )

    multieq = _MultiEq(system, annotation_prefix)
    for round_index, sigma in enumerate(_SIGMA):
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
                _annotation_path(
                    annotation_prefix,
                    f"round {round_index}/mixing invocation {first // 2 + 1}",
                ),
            )
    multieq.flush(annotation_prefix)

    result = []
    for index in range(8):
        prefix = _annotation_path(
            annotation_prefix, f"h[{index}] ^ v[{index}] ^ v[{index} + 8]"
        )
        first = _xor_word(
            h[index],
            state[index],
            system,
            _annotation_path(prefix, "first xor"),
        )
        result.append(
            _xor_word(
                first,
                state[index + 8],
                system,
                _annotation_path(prefix, "second xor"),
            )
        )
    return result


def _mix(
    system: R1CS,
    state: list[Word],
    indices: tuple[int, int, int, int],
    x: Word,
    y: Word,
    multieq: _MultiEq,
    annotation_prefix: str,
) -> None:
    a, b, c, d = indices
    state[a] = _add(
        system,
        (state[a], state[b], x),
        multieq,
        _annotation_path(annotation_prefix, "mixing step 1"),
    )
    state[d] = _rotate(
        _xor_word(
            state[d],
            state[a],
            system,
            _annotation_path(annotation_prefix, "mixing step 2"),
        ),
        16,
    )
    state[c] = _add(
        system,
        (state[c], state[d]),
        multieq,
        _annotation_path(annotation_prefix, "mixing step 3"),
    )
    state[b] = _rotate(
        _xor_word(
            state[b],
            state[c],
            system,
            _annotation_path(annotation_prefix, "mixing step 4"),
        ),
        12,
    )
    state[a] = _add(
        system,
        (state[a], state[b], y),
        multieq,
        _annotation_path(annotation_prefix, "mixing step 5"),
    )
    state[d] = _rotate(
        _xor_word(
            state[d],
            state[a],
            system,
            _annotation_path(annotation_prefix, "mixing step 6"),
        ),
        8,
    )
    state[c] = _add(
        system,
        (state[c], state[d]),
        multieq,
        _annotation_path(annotation_prefix, "mixing step 7"),
    )
    state[b] = _rotate(
        _xor_word(
            state[b],
            state[c],
            system,
            _annotation_path(annotation_prefix, "mixing step 8"),
        ),
        7,
    )


def _add(
    system: R1CS,
    words: tuple[Word, ...],
    multieq: _MultiEq,
    annotation_prefix: str,
) -> Word:
    total = sum(_word_value(word, system) for word in words)
    width = (len(words) * 0xFFFFFFFF).bit_length()
    if all(_backing(bit) is None for word in words for bit in word):
        return _constant_word(total & 0xFFFFFFFF)

    result: list[Variable] = []
    for index in range(width):
        variable_name = f"{annotation_prefix}/result bit {index}/boolean"
        bit = system.alloc_private(variable_name, (total >> index) & 1)
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{annotation_prefix}/result bit {index}/boolean constraint",
        )
        result.append(bit)

    left = _word_lc(system, words[0])
    for word in words[1:]:
        left = left + _word_lc(system, word)
    right = system.linear_combination(
        tuple((bit, 1 << index) for index, bit in enumerate(result))
    )
    multieq.add(left, right, width, annotation_prefix)
    return tuple(result[:32])


def _xor_word(
    left: Word,
    right: Word,
    system: R1CS,
    annotation_prefix: str,
) -> Word:
    return tuple(
        _xor_bit(
            left_bit,
            right_bit,
            system,
            _annotation_path(annotation_prefix, f"xor of bit {index}"),
        )
        for index, (left_bit, right_bit) in enumerate(zip(left, right))
    )


def _xor_bit(
    left: Bit,
    right: Bit,
    system: R1CS,
    annotation_prefix: str,
) -> Bit:
    left_value = _value(left, system)
    right_value = _value(right, system)
    if _backing(left) is None:
        return _negate(right) if left_value else right
    if _backing(right) is None:
        return _negate(left) if right_value else left

    left_variable = _backing(left)
    right_variable = _backing(right)
    assert left_variable is not None and right_variable is not None
    if isinstance(left, _NegatedBit) and not isinstance(right, _NegatedBit):
        left_variable, right_variable = right_variable, left_variable

    raw = system.alloc_private(
        f"{annotation_prefix}/xor result",
        int(system._witness_value(left_variable))
        ^ int(system._witness_value(right_variable)),
    )
    system.enforce(
        left_variable.lc() * 2,
        right_variable,
        left_variable.lc() + right_variable.lc() - raw.lc(),
        f"{annotation_prefix}/xor constraint",
    )
    negated = isinstance(left, _NegatedBit) != isinstance(right, _NegatedBit)
    return _NegatedBit(raw) if negated else raw


def _annotation_path(prefix: str, child: str) -> str:
    return f"{prefix}/{child}"


def _word_lc(system: R1CS, word: Word) -> LinearCombination:
    terms: list[tuple[Variable, int]] = []
    constant = 0
    for index, bit in enumerate(word):
        coefficient = 1 << index
        if isinstance(bit, Variable):
            terms.append((bit, coefficient))
        elif isinstance(bit, _NegatedBit):
            terms.append((bit.variable, -coefficient))
            constant += coefficient
        else:
            constant += int(bit) * coefficient
    return system.linear_combination(terms, constant)


def _word_value(word: Word, system: R1CS) -> int:
    return sum(_value(bit, system) << index for index, bit in enumerate(word))


def _value(bit: Bit, system: R1CS) -> int:
    return _read_bit(system, bit)


def _backing(bit: Bit) -> Variable | None:
    if isinstance(bit, _NegatedBit):
        return bit.variable
    return bit if isinstance(bit, Variable) else None


def _negate(bit: Bit) -> Bit:
    if isinstance(bit, _NegatedBit):
        return bit.variable
    if isinstance(bit, Variable):
        return _NegatedBit(bit)
    return 1 - int(bit)


def _rotate(word: Word, amount: int) -> Word:
    return tuple(word[(index + amount) % 32] for index in range(32))


def _constant_word(value: int) -> Word:
    return tuple((value >> index) & 1 for index in range(32))


def _block_words(bits: tuple[Bit, ...]) -> list[Word]:
    if len(bits) > 512:
        raise R1CSError("BLAKE2s block exceeds 512 bits")
    padded = bits + (0,) * (512 - len(bits))
    return [
        tuple(padded[start : start + 32])
        for start in range(0, 512, 32)
    ]


__all__ = ["constrain_sapling_blake2s"]
