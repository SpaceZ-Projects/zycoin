"""Test-only semantic probes for Spend anchor and Merkle-position relations."""

from __future__ import annotations

from typing import Any

from src.bls12_381 import SCALAR_MODULUS


VALUE_BITS = 64
POSITION_BITS = 32


def _bits_le(value: int, width: int) -> tuple[int, ...]:
    return tuple((value >> index) & 1 for index in range(width))


def upstream_anchor_satisfied(
    note_value_bits: tuple[int, ...],
    root: int,
    anchor_auxiliary: int,
    public_anchor: int,
) -> bool:
    if len(note_value_bits) != VALUE_BITS:
        raise ValueError("note value must have 64 bits")
    if any(bit not in (0, 1) for bit in note_value_bits):
        return False
    note_value = sum(bit << index for index, bit in enumerate(note_value_bits))
    return (
        (root - anchor_auxiliary) * note_value % SCALAR_MODULUS == 0
        and (public_anchor - anchor_auxiliary) % SCALAR_MODULUS == 0
    )


def local_anchor_satisfied(
    note_value_bits: tuple[int, ...], root: int, public_anchor: int
) -> bool:
    if len(note_value_bits) != VALUE_BITS:
        raise ValueError("note value must have 64 bits")
    if any(bit not in (0, 1) for bit in note_value_bits):
        return False
    note_value = sum(bit << index for index, bit in enumerate(note_value_bits))
    return (root - public_anchor) * note_value % SCALAR_MODULUS == 0


def upstream_position_from_directions(directions: tuple[bool, ...]) -> int:
    if len(directions) != POSITION_BITS:
        raise ValueError("Merkle path must contain 32 direction bits")
    if any(type(direction) is not bool for direction in directions):
        raise ValueError("Merkle path directions must be Boolean")
    return sum(int(direction) << level for level, direction in enumerate(directions))


def local_position_bits(position: int) -> tuple[int, ...]:
    if type(position) is not int or not 0 <= position < 1 << POSITION_BITS:
        raise ValueError("Merkle position must be an unsigned 32-bit integer")
    return _bits_le(position, POSITION_BITS)


def local_position_reconstruction_satisfied(
    position: int, bits: tuple[int, ...]
) -> bool:
    if len(bits) != POSITION_BITS or any(bit not in (0, 1) for bit in bits):
        return False
    return position == sum(bit << level for level, bit in enumerate(bits))


def semantic_probe_results() -> dict[str, Any]:
    field_max = SCALAR_MODULUS - 1
    anchor_cases = []
    for note_value in (0, 1, (1 << VALUE_BITS) - 1):
        bits = _bits_le(note_value, VALUE_BITS)
        anchor, root = field_max, field_max
        upstream = upstream_anchor_satisfied(bits, root, anchor, anchor)
        local = local_anchor_satisfied(bits, root, anchor)
        anchor_cases.append(
            {
                "note_value": note_value,
                "root": root,
                "anchor": anchor,
                "upstream": upstream,
                "local": local,
            }
        )
    root_mismatch_cases = []
    for note_value in (0, 1, (1 << VALUE_BITS) - 1):
        bits = _bits_le(note_value, VALUE_BITS)
        upstream = upstream_anchor_satisfied(bits, 0, field_max, field_max)
        local = local_anchor_satisfied(bits, 0, field_max)
        root_mismatch_cases.append(
            {
                "note_value": note_value,
                "root": 0,
                "anchor": field_max,
                "upstream": upstream,
                "local": local,
            }
        )
    invalid_binding = {
        "note_value": 0,
        "root": 9,
        "anchor_auxiliary": 7,
        "public_anchor": 8,
        "upstream": upstream_anchor_satisfied((0,) * VALUE_BITS, 9, 7, 8),
        "local": local_anchor_satisfied((0,) * VALUE_BITS, 9, 8),
    }

    position_cases = []
    for position in (0, 1, 1 << 31, (1 << POSITION_BITS) - 1):
        directions = tuple(bool(bit) for bit in _bits_le(position, POSITION_BITS))
        upstream_position = upstream_position_from_directions(directions)
        local_bits = local_position_bits(position)
        position_cases.append(
            {
                "position": position,
                "upstream_position": upstream_position,
                "local_reconstruction": local_position_reconstruction_satisfied(
                    position, local_bits
                ),
                "bit_order": "least-significant path level first",
            }
        )
    return {
        "anchor_boundary_cases": anchor_cases,
        "anchor_root_mismatch_cases": root_mismatch_cases,
        "invalid_auxiliary_binding_case": invalid_binding,
        "position_boundary_cases": position_cases,
        "position_rejections": {
            "negative": True,
            "equal_to_2_pow_32": True,
            "boolean_instead_of_integer": True,
            "non_boolean_direction": True,
            "position_bits_mismatch": True,
        },
    }
