"""Source-derived Bellman 0.15.0 Sapling Pedersen synthesis transcription.

This is a Python reference model, not an exported Bellman constraint matrix.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from typing import Generic, Protocol, TypeGuard, TypeVar

from src.bellman_synthesis import RecorderLinearCombination, RecorderVariable
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import CURVE_D, Point, find_group_hash
from src.r1cs import LinearCombination, Variable

_PEDERSEN_GENERATOR_COUNT = 6
_CHUNKS_PER_GENERATOR = 63
_MONTGOMERY_A = 40962
_MONTGOMERY_SCALE_LIMBS = (
    0x8F4535F7CF82B8D9,
    0xCE4069703DA88ABD,
    0x31DE341E77D764E5,
    0x2762DE61E862645E,
)
_MONTGOMERY_SCALE = sum(
    limb << (64 * index)
    for index, limb in enumerate(_MONTGOMERY_SCALE_LIMBS)
) % SCALAR_MODULUS


VariableT = TypeVar("VariableT", Variable, RecorderVariable)
LinearCombinationT = TypeVar(
    "LinearCombinationT", LinearCombination, RecorderLinearCombination
)


class _ReferenceSystem(Protocol[VariableT, LinearCombinationT]):
    def alloc_private(self, name: str, value: int | None) -> VariableT: ...

    def linear_combination(
        self,
        terms: Iterable[tuple[VariableT, int]],
        constant: int = 0,
    ) -> LinearCombinationT: ...

    def enforce(
        self,
        left: int | VariableT | LinearCombinationT,
        right: int | VariableT | LinearCombinationT,
        output: int | VariableT | LinearCombinationT,
        label: str = "",
    ) -> None: ...

    def _witness_value(self, variable: VariableT) -> int | None: ...


@dataclass(frozen=True)
class _Num(Generic[VariableT, LinearCombinationT]):
    expression: LinearCombinationT
    value: int
    variable: VariableT | None = None


def _is_reference_variable(value: object) -> TypeGuard[VariableT]:
    return isinstance(value, (Variable, RecorderVariable))


def _read_bit(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    bit: int | bool | VariableT,
) -> int:
    if _is_reference_variable(bit):
        value = system._witness_value(bit)
        if value not in (0, 1):
            raise ValueError("reference Pedersen input is not a Boolean")
        return int(value)
    if type(bit) not in (int, bool) or bit not in (0, 1):
        raise ValueError("reference Pedersen input is not a Boolean")
    return int(bit)


def _and(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    left: int | bool | VariableT,
    right: int | bool | VariableT,
    label: str,
) -> int | bool | VariableT:
    left_value = _read_bit(system, left)
    right_value = _read_bit(system, right)
    value = left_value & right_value
    if not _is_reference_variable(left):
        return right if left_value else 0
    if not _is_reference_variable(right):
        return left if right_value else 0
    result = system.alloc_private(label, value)
    system.enforce(left, right, result, f"{label} AND")
    return result


def _mobius_coefficients(values: tuple[int, int, int, int]) -> tuple[int, ...]:
    zero, one, two, three = values
    return (
        zero,
        one - zero,
        two - zero,
        three - two - one + zero,
    )


def _lookup_expression(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    coefficients: tuple[int, ...],
    bits: tuple[
        int | bool | VariableT,
        int | bool | VariableT,
        int | bool | VariableT,
    ],
) -> LinearCombinationT:
    constant = coefficients[0]
    terms = []
    for bit, coefficient in zip(bits, coefficients[1:]):
        if _is_reference_variable(bit):
            terms.append((bit, coefficient))
        else:
            constant += bit * coefficient
    return system.linear_combination(tuple(terms), constant)


def _coordinate_lookup(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    coords: tuple[tuple[int, int], ...],
    bits: tuple[int | VariableT, int | VariableT, int | VariableT],
    label: str,
) -> tuple[_Num[VariableT, LinearCombinationT], _Num[VariableT, LinearCombinationT]]:
    a, b, sign = bits
    a_value = _read_bit(system, a)
    b_value = _read_bit(system, b)
    sign_value = _read_bit(system, sign)
    selected_index = a_value + 2 * b_value
    selected_x, selected_y = coords[selected_index]
    y_value = (selected_y * (-1 if sign_value else 1)) % SCALAR_MODULUS

    y = system.alloc_private(f"{label} y", y_value)
    precomp = _and(system, a, b, f"{label} precomp")
    x_values = tuple(point[0] for point in coords)
    y_values = tuple(point[1] for point in coords)
    x_expression = _lookup_expression(
        system,
        _mobius_coefficients(x_values),
        (a, b, precomp),
    )
    y_expression = _lookup_expression(
        system,
        _mobius_coefficients(y_values),
        (a, b, precomp),
    )
    system.enforce(
        2 * y_expression,
        sign,
        y_expression - y.lc(),
        f"{label} conditional y lookup",
    )
    return (
        _Num(x_expression, selected_x),
        _Num(y.lc(), y_value, y),
    )


def _montgomery_add(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    left: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ],
    right: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ],
    label: str,
) -> tuple[
    _Num[VariableT, LinearCombinationT],
    _Num[VariableT, LinearCombinationT],
]:
    x1, y1 = left
    x2, y2 = right
    denominator = (x2.value - x1.value) % SCALAR_MODULUS
    if denominator == 0:
        raise ValueError("Bellman Montgomery addition has equal x coordinates")
    lam_value = (
        (y2.value - y1.value)
        * pow(denominator, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    ) % SCALAR_MODULUS
    lam = system.alloc_private(f"{label} lambda", lam_value)
    system.enforce(
        x2.expression - x1.expression,
        lam,
        y2.expression - y1.expression,
        f"{label} evaluate lambda",
    )

    x_value = (
        lam_value * lam_value
        - _MONTGOMERY_A
        - x1.value
        - x2.value
    ) % SCALAR_MODULUS
    x = system.alloc_private(f"{label} xprime", x_value)
    system.enforce(
        lam,
        lam,
        _MONTGOMERY_A + x1.expression + x2.expression + x.lc(),
        f"{label} evaluate xprime",
    )

    y_value = (
        -y1.value - lam_value * (x_value - x1.value)
    ) % SCALAR_MODULUS
    y = system.alloc_private(f"{label} yprime", y_value)
    system.enforce(
        x1.expression - x.lc(),
        lam,
        y.lc() + y1.expression,
        f"{label} evaluate yprime",
    )
    return _Num(x.lc(), x_value, x), _Num(y.lc(), y_value, y)


def _montgomery_to_edwards(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    point: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ],
    label: str,
) -> tuple[
    _Num[VariableT, LinearCombinationT],
    _Num[VariableT, LinearCombinationT],
]:
    x, y = point
    if y.value == 0 or (x.value + 1) % SCALAR_MODULUS == 0:
        raise ValueError("Bellman Montgomery conversion has a zero denominator")
    u_value = (
        _MONTGOMERY_SCALE
        * x.value
        * pow(y.value, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    ) % SCALAR_MODULUS
    u = system.alloc_private(f"{label} u", u_value)
    system.enforce(
        y.expression,
        u,
        _MONTGOMERY_SCALE * x.expression,
        f"{label} u computation",
    )

    v_value = (
        (x.value - 1)
        * pow(x.value + 1, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    ) % SCALAR_MODULUS
    v = system.alloc_private(f"{label} v", v_value)
    system.enforce(
        x.expression + 1,
        v,
        x.expression - 1,
        f"{label} v computation",
    )
    return _Num(u.lc(), u_value, u), _Num(v.lc(), v_value, v)


def _edwards_add(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    left: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ],
    right: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ],
    label: str,
) -> tuple[
    _Num[VariableT, LinearCombinationT],
    _Num[VariableT, LinearCombinationT],
]:
    u1, v1 = left
    u2, v2 = right
    uppercase_value = ((u1.value + v1.value) * (u2.value + v2.value)) % SCALAR_MODULUS
    uppercase = system.alloc_private(f"{label} U", uppercase_value)
    system.enforce(
        u1.expression + v1.expression,
        u2.expression + v2.expression,
        uppercase,
        f"{label} U computation",
    )

    a_value = v2.value * u1.value % SCALAR_MODULUS
    a = system.alloc_private(f"{label} A", a_value)
    system.enforce(v2.expression, u1.expression, a, f"{label} A computation")

    b_value = u2.value * v1.value % SCALAR_MODULUS
    b = system.alloc_private(f"{label} B", b_value)
    system.enforce(u2.expression, v1.expression, b, f"{label} B computation")

    c_value = CURVE_D * a_value * b_value % SCALAR_MODULUS
    c = system.alloc_private(f"{label} C", c_value)
    system.enforce(
        CURVE_D * a.lc(),
        b,
        c,
        f"{label} C computation",
    )

    if (1 + c_value) % SCALAR_MODULUS == 0:
        raise ValueError("Bellman Edwards addition has a zero u denominator")
    if (1 - c_value) % SCALAR_MODULUS == 0:
        raise ValueError("Bellman Edwards addition has a zero v denominator")
    u3_value = (
        (a_value + b_value)
        * pow(1 + c_value, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    ) % SCALAR_MODULUS
    u3 = system.alloc_private(f"{label} u3", u3_value)
    system.enforce(
        1 + c.lc(),
        u3,
        a.lc() + b.lc(),
        f"{label} u3 computation",
    )

    v3_value = (
        (uppercase_value - a_value - b_value)
        * pow(1 - c_value, SCALAR_MODULUS - 2, SCALAR_MODULUS)
    ) % SCALAR_MODULUS
    v3 = system.alloc_private(f"{label} v3", v3_value)
    system.enforce(
        1 - c.lc(),
        v3,
        uppercase.lc() - a.lc() - b.lc(),
        f"{label} v3 computation",
    )
    return _Num(u3.lc(), u3_value, u3), _Num(v3.lc(), v3_value, v3)


def _montgomery_coordinates(point: Point) -> tuple[int, int]:
    if point.v == 1:
        raise ValueError("Pedersen table unexpectedly contains the identity")
    if point.u == 0:
        return 0, 0
    x = (1 + point.v) * pow(
        1 - point.v, SCALAR_MODULUS - 2, SCALAR_MODULUS
    ) % SCALAR_MODULUS
    y = (
        x
        * pow(point.u, SCALAR_MODULUS - 2, SCALAR_MODULUS)
        * _MONTGOMERY_SCALE
    ) % SCALAR_MODULUS
    return x, y


@lru_cache(maxsize=1)
def _pedersen_montgomery_tables() -> tuple[tuple[tuple[tuple[int, int], ...], ...], ...]:
    tables = []
    for generator_index in range(_PEDERSEN_GENERATOR_COUNT):
        base = find_group_hash(
            b"Zcash_PH", generator_index.to_bytes(4, "little")
        )
        windows = []
        for _ in range(_CHUNKS_PER_GENERATOR):
            current = base
            coords = []
            for _ in range(4):
                coords.append(_montgomery_coordinates(current))
                current = current + base
            windows.append(tuple(coords))
            base = base.multiply(16)
        tables.append(tuple(windows))
    return tuple(tables)


def synthesize_pedersen_hash(
    system: _ReferenceSystem[VariableT, LinearCombinationT],
    personalization_bits: tuple[int, ...],
    message_bits: tuple[int | VariableT, ...],
    label: str = "Bellman Pedersen hash",
) -> tuple[VariableT, VariableT]:
    """Transcribe pinned Sapling circuit synthesis into the Python R1CS."""
    if len(personalization_bits) != 6:
        raise ValueError("Pedersen personalization requires six bits")
    bits: tuple[int | VariableT, ...] = personalization_bits + message_bits
    if not bits:
        raise ValueError("Pedersen input must not be empty")

    tables = _pedersen_montgomery_tables()
    edwards_result: tuple[
        _Num[VariableT, LinearCombinationT],
        _Num[VariableT, LinearCombinationT],
    ] | None = None
    bit_offset = 0
    segment_index = 0
    while bit_offset < len(bits):
        if segment_index >= _PEDERSEN_GENERATOR_COUNT:
            raise ValueError("Pedersen input exceeds generator capacity")
        segment_result: tuple[
            _Num[VariableT, LinearCombinationT],
            _Num[VariableT, LinearCombinationT],
        ] | None = None
        window_index = 0
        while bit_offset < len(bits) and window_index < _CHUNKS_PER_GENERATOR:
            chunk = bits[bit_offset:bit_offset + 3]
            bit_offset += len(chunk)
            chunk += (0,) * (3 - len(chunk))
            selected = _coordinate_lookup(
                system,
                tables[segment_index][window_index],
                (chunk[0], chunk[1], chunk[2]),
                f"{label} segment[{segment_index}] window[{window_index}]",
            )
            if segment_result is None:
                segment_result = selected
            else:
                segment_result = _montgomery_add(
                    system,
                    selected,
                    segment_result,
                    f"{label} segment[{segment_index}] addition[{window_index}]",
                )
            window_index += 1

        if segment_result is None:
            raise ValueError("Pedersen segment has no windows")
        converted = _montgomery_to_edwards(
            system,
            segment_result,
            f"{label} segment[{segment_index}] conversion",
        )
        if edwards_result is None:
            edwards_result = converted
        else:
            edwards_result = _edwards_add(
                system,
                converted,
                edwards_result,
                f"{label} segment[{segment_index}] combination",
            )
        segment_index += 1

    if edwards_result is None:
        raise ValueError("Pedersen input must not be empty")
    u, v = edwards_result[0].variable, edwards_result[1].variable
    if u is None or v is None:
        raise AssertionError("upstream Pedersen output coordinates are unallocated")
    return u, v
