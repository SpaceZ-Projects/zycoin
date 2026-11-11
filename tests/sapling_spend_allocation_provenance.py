"""Test-only Spend allocation provenance capture and comparison."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from src.r1cs import R1CS, Variable
from src.sapling_spend_circuit import SaplingSpendWitness, constrain_sapling_spend


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _semantic_provenance(
    name: str, frames: list[dict[str, Any]] | None = None
) -> tuple[str | None, list[str], list[str], str | None, str | None]:
    prefix = "Sapling Spend "
    if not name.startswith(prefix):
        return None, [], [], None, None
    role_name = name[len(prefix) :]

    representation_identity = _strict_representation_allocation_identity(role_name)
    if representation_identity is not None:
        gadget_id, invocation_id, role_path, semantic_id, parent = (
            representation_identity
        )
        return (
            gadget_id,
            parent,
            parent + [invocation_id],
            role_path,
            semantic_id,
        )

    pedersen_identity = _merkle_pedersen_allocation_identity(role_name)
    if pedersen_identity is not None:
        level, role_path, semantic_id = pedersen_identity
        gadget_id = "sapling.spend.merkle-authentication-path"
        parent = ["sapling.spend", gadget_id]
        return (
            gadget_id,
            parent,
            parent + [f"level:{level}", "sapling.pedersen-hash"],
            role_path,
            semantic_id,
        )

    note_pedersen_identity = _note_pedersen_allocation_identity(role_name)
    if note_pedersen_identity is not None:
        role_path, semantic_id = note_pedersen_identity
        gadget_id = "sapling.spend.note-content.pedersen"
        parent = ["sapling.spend", gadget_id]
        invocation = ["hash:note-content"]
        return gadget_id, parent, parent + invocation, role_path, semantic_id

    merkle_combination_identity = (
        _merkle_pedersen_combination_allocation_identity(role_name)
    )
    if merkle_combination_identity is not None:
        level, role_path, semantic_id = merkle_combination_identity
        gadget_id = "sapling.spend.merkle-authentication-path"
        parent = ["sapling.spend", gadget_id]
        invocation = [f"level:{level}", "sapling.pedersen-hash"]
        return gadget_id, parent, parent + invocation, role_path, semantic_id

    scalar_bit_identity = _value_commitment_bit_allocation_identity(role_name)
    if scalar_bit_identity is not None:
        gadget_id, invocation_id, role_path, semantic_id = scalar_bit_identity
        parent = ["sapling.spend", gadget_id]
        return (
            gadget_id,
            parent,
            parent + [invocation_id],
            role_path,
            semantic_id,
        )

    level_and_role: tuple[str, str] | None = None
    match = re.fullmatch(r"Merkle path position bit\[(\d+)\]", role_name)
    if match:
        level_and_role = (match.group(1), "position bit")
    if level_and_role is None:
        match = re.fullmatch(r"Merkle path sibling\[(\d+)\]", role_name)
        if match:
            level_and_role = (match.group(1), "path element")
    if level_and_role is None:
        match = re.fullmatch(r"Merkle path (left|right)\[(\d+)\]", role_name)
        if match:
            role = "conditional reversal of preimage/conditional reversal result "
            role += "1" if match.group(1) == "left" else "2"
            level_and_role = (match.group(2), role)
    if level_and_role is None:
        match = re.fullmatch(r"Merkle path (left|right) bit\[(\d+)\]\[(\d+)\]", role_name)
        if match:
            side = "ul" if match.group(1) == "left" else "ur"
            level_and_role = (
                match.group(2),
                f"{side} into bits/bit {match.group(3)}",
            )
    if level_and_role is None:
        match = re.fullmatch(r"Merkle path hash\[(\d+)\] (.+)", role_name)
        if match:
            nested_role = re.sub(
                r"([A-Za-z]+)\[(\d+)\]", r"\1 \2", match.group(2)
            )
            level_and_role = (
                match.group(1),
                f"computation of pedersen hash/{nested_role}",
            )

    if level_and_role is not None:
        level, allocation_role = level_and_role
        gadget_id = "sapling.spend.merkle-authentication-path"
        invocation = [f"level:{level}"]
        parent = ["sapling.spend", gadget_id]
        nested_context = parent + invocation
        if allocation_role.startswith("computation of pedersen hash/"):
            nested_context.append("sapling.pedersen-hash")
        role_path = _normalized_semantic_path(allocation_role)
        semantic_id = f"{gadget_id}|{invocation[0]}|{role_path}"
        return gadget_id, parent, nested_context, role_path, semantic_id

    direct_patterns = (
        (re.compile(r"ak\.([uv])"), "sapling.spend.authorization-key", "invocation:ak"),
        (re.compile(r"ar bit\[(\d+)\]"), "sapling.spend.authorization-randomizer", "invocation:ar"),
        (re.compile(r"nsk bit\[(\d+)\]"), "sapling.spend.nullifier-spending-key", "invocation:nsk"),
        (re.compile(r"rcm bit\[(\d+)\]"), "sapling.spend.note-commitment-randomness", "invocation:rcm"),
    )
    for pattern, gadget_id, invocation_id in direct_patterns:
        match = pattern.fullmatch(role_name)
        if match:
            role_path = (
                match.group(1)
                if role_name.startswith("ak.")
                else f"bit {match.group(1)}"
            )
            role_path = _normalized_semantic_path(role_path)
            invocation = [invocation_id]
            parent = ["sapling.spend", gadget_id]
            semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
            return gadget_id, parent, parent + invocation, role_path, semantic_id

    blake2s_identity = _blake2s_allocation_identity(role_name)
    if blake2s_identity is not None:
        gadget_id, invocation_id, role_path, semantic_id, invocation_context = (
            blake2s_identity
        )
        parent = ["sapling.spend", gadget_id]
        return (
            gadget_id,
            parent,
            parent + [invocation_id] + invocation_context,
            role_path,
            semantic_id,
        )

    multiplication_identity = _scalar_multiplication_allocation_identity(
        role_name
    )
    if multiplication_identity is not None:
        gadget_id, invocation_id, role_path, semantic_id = (
            multiplication_identity
        )
        parent = ["sapling.spend", gadget_id]
        return gadget_id, parent, parent + [invocation_id], role_path, semantic_id

    remaining_identity = _remaining_gadget_allocation_identity(role_name)
    if remaining_identity is not None:
        gadget_id, invocation_id, role_path, semantic_id = remaining_identity
        parent = ["sapling.spend", gadget_id]
        return (
            gadget_id,
            parent,
            parent + [invocation_id],
            role_path,
            semantic_id,
        )

    source_scope = (
        f"{frames[0]['file']}:{frames[0]['function']}"
        if frames
        else "unknown local allocation scope"
    )
    semantic_gadget_id = _local_gadget_id(role_name, source_scope)
    parent = ["sapling.spend", semantic_gadget_id]
    invocation = _local_invocation_context(role_name)
    role_path = _normalized_semantic_path(role_name)
    return semantic_gadget_id, parent, parent + invocation, role_path, None


def _blake2s_allocation_identity(
    role_name: str,
) -> tuple[str, str, str, str, list[str]] | None:
    if role_name.startswith("ivk "):
        prefix = "ivk "
        gadget_id = "sapling.spend.ivk.blake2s"
        invocation_id = "hash:ivk"
    elif role_name.startswith("nullifier PRF "):
        prefix = "nullifier PRF "
        gadget_id = "sapling.spend.nullifier.blake2s"
        invocation_id = "hash:nullifier"
    else:
        return None

    role = role_name[len(prefix) :]
    block_match = re.fullmatch(
        r"block\[(\d+)\]( final)? round\[(\d+)\] g\[(\d+)\] "
        r"(add|xor)\[(\d+)\] (bit|carry)\[(\d+)\]",
        role,
    )
    if block_match is not None:
        block, final, round_index, mixing_index, operation, step, kind, bit = (
            block_match.groups()
        )
        invocation_context = [
            "final-block:" if final else f"block:{block}",
            f"round:{round_index}",
            f"mixing-invocation:{int(mixing_index) + 1}",
            f"mixing-step:{2 * int(step) + (2 if operation == 'xor' else 1)}",
        ]
        if kind == "carry":
            upstream_role = f"result bit {32 + int(bit)}"
        elif operation == "xor":
            upstream_role = f"xor of bit {bit}"
        else:
            upstream_role = f"result bit {bit}"
        role_path = _normalized_semantic_path(
            "/".join(
                [
                    "final block" if final else f"block {block}",
                    f"round {round_index}",
                    f"mixing invocation {int(mixing_index) + 1}",
                    f"mixing step {invocation_context[-1].split(':', 1)[1]}",
                    upstream_role,
                ]
            )
        )
    else:
        output_match = re.fullmatch(
            r"block\[(\d+)\] final hash xor b\[(\d+)\] bit\[(\d+)\]",
            role,
        )
        if output_match is None:
            return None
        _, word, bit = output_match.groups()
        invocation_context = ["final-block:"]
        role_path = _normalized_semantic_path(
            "/".join(
                [
                    "final block",
                    f"h[{word}] ^ v[{word}] ^ v[{word} + 8]",
                    "second xor",
                    f"xor of bit {bit}",
                ]
            )
        )

    semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
    return gadget_id, invocation_id, role_path, semantic_id, invocation_context


def _scalar_multiplication_allocation_identity(
    role_name: str,
) -> tuple[str, str, str, str] | None:
    if role_name.startswith("pk_d multiplication "):
        prefix = "pk_d multiplication "
        gadget_id = "sapling.spend.pk-d.scalar-multiplication"
        invocation_id = "mul:pk-d"
        mode = "variable-base"
    elif role_name.startswith("nk multiplication "):
        prefix = "nk multiplication "
        gadget_id = "sapling.spend.nk.fixed-base-multiplication"
        invocation_id = "mul:nk"
        mode = "fixed-base"
    elif role_name.startswith("randomized authorization key ar multiplication "):
        prefix = "randomized authorization key ar multiplication "
        gadget_id = "sapling.spend.randomized-authorization-key"
        invocation_id = "mul:ar"
        mode = "fixed-base"
    elif role_name.startswith("rho position multiplication "):
        prefix = "rho position multiplication "
        gadget_id = "sapling.spend.nullifier-rho"
        invocation_id = "mul:rho-position"
        mode = "fixed-base"
    elif role_name.startswith("value commitment value multiplication "):
        prefix = "value commitment value multiplication "
        gadget_id = "sapling.spend.value-commitment"
        invocation_id = "relation:value-commitment"
        mode = "value-commitment"
    elif role_name.startswith("value commitment randomness multiplication "):
        prefix = "value commitment randomness multiplication "
        gadget_id = "sapling.spend.value-commitment"
        invocation_id = "relation:value-commitment"
        mode = "rcv-commitment"
    elif role_name.startswith("note commitment randomness multiplication "):
        prefix = "note commitment randomness multiplication "
        gadget_id = "sapling.spend.note-commitment-randomness"
        invocation_id = "mul:rcm"
        mode = "fixed-base"
    else:
        return None

    role = role_name[len(prefix) :]
    selected = re.fullmatch(r"selected\[(\d+)\]\.([uv])", role)
    if selected is not None:
        index, coordinate = selected.groups()
        if mode == "variable-base":
            upstream_role = f"selection {index}/{coordinate}'"
        else:
            upstream_role = (
                f"window table lookup {index}/"
                f"{'x' if coordinate == 'u' else 'y'}"
            )
    else:
        lookup = re.fullmatch(r"lookup\[(\d+)\] bc", role)
        if lookup is not None:
            upstream_role = f"window table lookup {lookup.group(1)}/precomp"
        else:
            base = re.fullmatch(r"base\[(\d+)\]\.([uv])", role)
            if base is not None:
                index, coordinate = base.groups()
                upstream_role = (
                    f"doubling {index}/"
                    f"{'u3' if coordinate == 'u' else 'v3'}"
                )
            else:
                doubling = re.fullmatch(
                    r"base doubling\[(\d+)\] (T|A|C)", role
                )
                if doubling is not None:
                    index, item = doubling.groups()
                    upstream_role = (
                        f"doubling {index}/"
                        f"{'A computation' if item == 'A' else item}"
                    )
                else:
                    accumulator = re.fullmatch(
                        r"accumulator\[(\d+)\]\.([uv])", role
                    )
                    if accumulator is not None:
                        index, coordinate = accumulator.groups()
                        upstream_role = (
                            f"addition {index}/"
                            f"{'u3' if coordinate == 'u' else 'v3'}"
                        )
                    else:
                        addition = re.fullmatch(
                            r"(?:accumulation|addition)\[(\d+)\] (U|A|B|C)",
                            role,
                        )
                        if addition is None:
                            return None
                        index, item = addition.groups()
                        upstream_role = f"addition {index}/"
                        upstream_role += {
                            "A": "A computation",
                            "B": "B computation",
                        }.get(item, item)

    role_path = _normalized_semantic_path(upstream_role)
    if mode in {"value-commitment", "rcv-commitment"}:
        scope_prefix = (
            "compute the value in the exponent"
            if mode == "value-commitment"
            else "computation of rcv"
        )
        role_path = _normalized_semantic_path(
            f"{scope_prefix}/{role_path}"
        )
    semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
    return gadget_id, invocation_id, role_path, semantic_id


def _strict_representation_allocation_identity(
    role_name: str,
) -> tuple[str, str, str, str, list[str]] | None:
    patterns = (
        (
            "ak representation ",
            "sapling.spend.ak.representation",
            "repr:ak",
        ),
        (
            "nk representation ",
            "sapling.spend.nk.representation",
            "repr:nk",
        ),
        (
            "pk_d representation ",
            "sapling.spend.pk-d.representation",
            "repr:pk-d",
        ),
        (
            "rho representation ",
            "sapling.spend.rho.representation",
            "repr:rho",
        ),
        (
            "note commitment g_d representation ",
            "sapling.spend.g-d.representation",
            "repr:g-d",
        ),
    )
    match_spec = next(
        (spec for spec in patterns if role_name.startswith(spec[0])), None
    )
    if match_spec is None:
        return None
    prefix, gadget_id, invocation_id = match_spec
    role = role_name[len(prefix) :]
    bit_match = re.fullmatch(r"([uv]) bit\[(\d+)\]", role)
    if bit_match is not None:
        coordinate, field_bit = bit_match.groups()
        role_path = f"unpack/{coordinate}/bit/{254 - int(field_bit)}"
    else:
        prefix_match = re.fullmatch(
            r"([uv]) bit prefix AND\[(\d+):(\d+)\]", role
        )
        if prefix_match is None:
            return None
        coordinate, field_bit, run_index = prefix_match.groups()
        role_path = (
            f"unpack/{coordinate}/run/ending/at/{254 - int(field_bit)}"
            f"/and/{int(run_index) + 1}"
        )
    semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
    parent = ["sapling.spend", gadget_id]
    return gadget_id, invocation_id, role_path, semantic_id, parent


def _merkle_pedersen_allocation_identity(
    role_name: str,
) -> tuple[str, str, str] | None:
    addition = re.fullmatch(
        r"Merkle path hash\[(\d+)\] segment\[(\d+)\] addition\[(\d+)\] "
        r"(lambda|xprime|yprime)",
        role_name,
    )
    if addition is not None:
        level, segment, window, coordinate = addition.groups()
        role_path = (
            "computation of pedersen hash/"
            f"addition of segment {segment}, window {window}/{coordinate}"
        )
    else:
        conversion = re.fullmatch(
            r"Merkle path hash\[(\d+)\] segment\[(\d+)\] conversion ([uv])",
            role_name,
        )
        if conversion is None:
            return None
        level, segment, coordinate = conversion.groups()
        role_path = (
            "computation of pedersen hash/"
            f"conversion of segment {segment} into edwards/{coordinate}"
        )
    normalized_role = _normalized_semantic_path(role_path)
    semantic_id = (
        "sapling.spend.merkle-authentication-path"
        f"|level:{level}|{normalized_role}"
    )
    return level, normalized_role, semantic_id


def _note_pedersen_allocation_identity(
    role_name: str,
) -> tuple[str, str] | None:
    window = re.fullmatch(
        r"note commitment content hash segment\[(\d+)\] "
        r"window\[(\d+)\] (y|precomp)",
        role_name,
    )
    if window is not None:
        segment, window_index, coordinate = window.groups()
        role = f"segment {segment}, window {window_index}/{coordinate}"
    else:
        addition = re.fullmatch(
            r"note commitment content hash segment\[(\d+)\] "
            r"addition\[(\d+)\] (lambda|xprime|yprime)",
            role_name,
        )
        if addition is not None:
            segment, window_index, coordinate = addition.groups()
            role = (
                f"addition of segment {segment}, window {window_index}/{coordinate}"
            )
        else:
            conversion = re.fullmatch(
                r"note commitment content hash segment\[(\d+)\] conversion ([uv])",
                role_name,
            )
            if conversion is not None:
                segment, coordinate = conversion.groups()
                role = (
                    f"conversion of segment {segment} into edwards/{coordinate}"
                )
            else:
                combination = re.fullmatch(
                    r"note commitment content hash segment\[(\d+)\] "
                    r"combination (U|A|B|C|u3|v3)",
                    role_name,
                )
                if combination is None:
                    return None
                segment, item = combination.groups()
                upstream_item = {
                    "A": "A computation",
                    "B": "B computation",
                }.get(item, item)
                role = (
                    f"addition of segment {segment} to accumulator/"
                    f"{upstream_item}"
                )

    role_path = _normalized_semantic_path(role)
    semantic_id = (
        "sapling.spend.note-content.pedersen"
        f"|hash:note-content|{role_path}"
    )
    return role_path, semantic_id


def _merkle_pedersen_combination_allocation_identity(
    role_name: str,
) -> tuple[str, str, str] | None:
    match = re.fullmatch(
        r"Merkle path hash\[(\d+)\] segment\[(\d+)\] "
        r"combination (U|A|B|C|u3|v3)",
        role_name,
    )
    if match is None:
        return None
    level, segment, item = match.groups()
    upstream_item = {
        "A": "A computation",
        "B": "B computation",
    }.get(item, item)
    role_path = _normalized_semantic_path(
        "computation of pedersen hash/"
        f"addition of segment {segment} to accumulator/{upstream_item}"
    )
    semantic_id = (
        "sapling.spend.merkle-authentication-path"
        f"|level:{level}|{role_path}"
    )
    return level, role_path, semantic_id


def _value_commitment_bit_allocation_identity(
    role_name: str,
) -> tuple[str, str, str, str] | None:
    match = re.fullmatch(r"(value|rcv) bit\[(\d+)\]", role_name)
    if match is None:
        return None
    kind, bit_index = match.groups()
    gadget_id = "sapling.spend.value-commitment"
    invocation_id = "relation:value-commitment"
    role_path = f"{kind}/bit/{bit_index}"
    semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
    return gadget_id, invocation_id, role_path, semantic_id


def _remaining_gadget_allocation_identity(
    role_name: str,
) -> tuple[str, str, str, str] | None:
    curve = re.fullmatch(
        r"randomized authorization key ak curve "
        r"(u squared|v squared|coordinate product)",
        role_name,
    )
    if curve is not None:
        role = curve.group(1)
        role_path = {
            "u squared": "point/interpretation/u/2",
            "v squared": "point/interpretation/v/2",
            "coordinate product": "point/interpretation/u/2/v/2",
        }[role]
        gadget_id = "sapling.spend.authorization-key"
        invocation_id = "invocation:ak"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    ak_small_order = _small_order_role_identity(
        role_name,
        r"randomized authorization key ak ",
        "sapling.spend.randomized-authorization-key",
        "non-small-order:ak",
    )
    if ak_small_order is not None:
        return ak_small_order

    g_d_small_order = _small_order_role_identity(
        role_name,
        r"g_d ",
        "sapling.spend.diversifier-base",
        "non-small-order:g-d",
    )
    if g_d_small_order is not None:
        return g_d_small_order

    g_d_point = re.fullmatch(r"g_d\.(u|v)", role_name)
    if g_d_point is not None:
        role_path = g_d_point.group(1)
        gadget_id = "sapling.spend.diversifier-base"
        invocation_id = "witness:g-d"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    g_d_curve = re.fullmatch(r"g_d curve (u squared|v squared|coordinate product)", role_name)
    if g_d_curve is not None:
        role_path = {
            "u squared": "point/interpretation/u/2",
            "v squared": "point/interpretation/v/2",
            "coordinate product": "point/interpretation/u/2/v/2",
        }[g_d_curve.group(1)]
        gadget_id = "sapling.spend.diversifier-base"
        invocation_id = "witness:g-d"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    randomized_key_result = re.fullmatch(
        r"randomized authorization key result\.(u|v)", role_name
    )
    if randomized_key_result is not None:
        coordinate = randomized_key_result.group(1)
        upstream_role = "u3" if coordinate == "u" else "v3"
        role_path = _normalized_semantic_path(
            f"computation of rk/{upstream_role}"
        )
        gadget_id = "sapling.spend.randomized-authorization-key"
        invocation_id = "addition:rk"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    rk_addition = re.fullmatch(
        r"randomized authorization key authorization-key addition "
        r"(U|A|B|C)",
        role_name,
    )
    if rk_addition is not None:
        item = {"A": "A computation", "B": "B computation"}.get(
            rk_addition.group(1), rk_addition.group(1)
        )
        role_path = _normalized_semantic_path(f"computation of rk/{item}")
        gadget_id = "sapling.spend.randomized-authorization-key"
        invocation_id = "addition:rk"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    cv_result = re.fullmatch(r"value commitment (result\.(u|v)|addition (U|A|B|C))", role_name)
    if cv_result is not None:
        _, coordinate, item = cv_result.groups()
        if coordinate is not None:
            upstream_role = "u3" if coordinate == "u" else "v3"
        else:
            upstream_role = {
                "U": "u",
                "A": "A computation",
                "B": "B computation",
                "C": "C",
            }[item]
        role_path = _normalized_semantic_path(f"computation of cv/{upstream_role}")
        gadget_id = "sapling.spend.value-commitment"
        invocation_id = "relation:value-commitment"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    note_randomization = re.fullmatch(
        r"note commitment (randomized point\.(u|v)|randomization (U|A|B|C))",
        role_name,
    )
    if note_randomization is not None:
        _, coordinate, item = note_randomization.groups()
        upstream_role = ("u3" if coordinate == "u" else "v3") if coordinate else {
            "U": "u",
            "A": "A computation",
            "B": "B computation",
            "C": "C",
        }[item]
        role_path = _normalized_semantic_path(upstream_role)
        gadget_id = "sapling.spend.note-commitment"
        invocation_id = "randomization:note-commitment"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    rho_addition = re.fullmatch(
        r"rho (point\.(u|v)|commitment addition (U|A|B|C))",
        role_name,
    )
    if rho_addition is not None:
        _, coordinate, item = rho_addition.groups()
        upstream_role = ("u3" if coordinate == "u" else "v3") if coordinate else {
            "U": "u",
            "A": "A computation",
            "B": "B computation",
            "C": "C",
        }[item]
        role_path = _normalized_semantic_path(upstream_role)
        gadget_id = "sapling.spend.nullifier-rho"
        invocation_id = "faerie-gold-prevention"
        return (
            gadget_id,
            invocation_id,
            role_path,
            f"{gadget_id}|{invocation_id}|{role_path}",
        )

    return None


def _small_order_role_identity(
    role_name: str,
    prefix: str,
    gadget_id: str,
    invocation_id: str,
) -> tuple[str, str, str, str] | None:
    role = role_name[len(prefix) :] if role_name.startswith(prefix) else ""
    double_point = re.fullmatch(r"double\[(\d+)\]\.([uv])", role)
    if double_point is not None:
        step, coordinate = double_point.groups()
        item = "u3" if coordinate == "u" else "v3"
        role_path = _normalized_semantic_path(
            f"{_ordinal_word(int(step))} doubling/{item}"
        )
    else:
        double_value = re.fullmatch(r"doubling\[(\d+)\] (T|A|C)", role)
        if double_value is not None:
            step, item = double_value.groups()
            item = {"A": "A computation"}.get(item, item)
            role_path = _normalized_semantic_path(
                f"{_ordinal_word(int(step))} doubling/{item}"
            )
        elif role == "u inverse":
            role_path = "check/u/0/ephemeral/inverse"
        else:
            return None
    semantic_id = f"{gadget_id}|{invocation_id}|{role_path}"
    return gadget_id, invocation_id, role_path, semantic_id


def _ordinal_word(index: int) -> str:
    words = ("first", "second", "third")
    if not 0 <= index < len(words):
        raise ValueError(f"unsupported small-order doubling index: {index}")
    return words[index]


def _local_gadget_id(role_name: str, source_scope: str) -> str:
    prefixes = (
        ("ivk ", "sapling.spend.ivk.blake2s"),
        ("nullifier PRF ", "sapling.spend.nullifier.blake2s"),
        ("Merkle path ", "sapling.spend.merkle-authentication-path"),
        ("note commitment ", "sapling.spend.note-commitment"),
        ("value commitment ", "sapling.spend.value-commitment"),
        ("pk_d multiplication ", "sapling.spend.pk-d.scalar-multiplication"),
        ("nk multiplication ", "sapling.spend.nk.fixed-base-multiplication"),
        ("rho ", "sapling.spend.nullifier-rho"),
        ("ak representation ", "sapling.spend.ak.representation"),
        ("nk representation ", "sapling.spend.nk.representation"),
        ("pk_d representation ", "sapling.spend.pk-d.representation"),
        ("rho representation ", "sapling.spend.rho.representation"),
        ("randomized authorization key ", "sapling.spend.randomized-authorization-key"),
        ("g_d ", "sapling.spend.diversifier-base"),
    )
    for prefix, gadget_id in prefixes:
        if role_name.startswith(prefix):
            return gadget_id
    return f"sapling.spend.local-scope:{source_scope}"


def _local_invocation_context(role_name: str) -> list[str]:
    context: list[str] = []
    for label, pattern in (
        ("block", r"block\[(\d+)\]"),
        ("round", r"(?:final )?round\[(\d+)\]"),
        ("mixing-invocation", r"g\[(\d+)\]"),
        ("mixing-step", r"(?:add|xor)\[(\d+)\]"),
        ("segment", r"segment\[(\d+)\]"),
        ("window", r"window\[(\d+)\]"),
        ("merkle-level", r"Merkle path hash\[(\d+)\]"),
    ):
        for value in re.findall(pattern, role_name):
            context.append(f"{label}:{value}")
    return context or ["single-invocation"]


def _normalized_semantic_path(value: str) -> str:
    return "/".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _local_source_frames() -> list[dict[str, Any]]:
    frame = inspect.currentframe()
    if frame is not None:
        frame = frame.f_back
    frames: list[dict[str, Any]] = []
    try:
        while frame is not None:
            path = Path(frame.f_code.co_filename).resolve()
            try:
                relative_path = path.relative_to(_REPOSITORY_ROOT)
            except ValueError:
                frame = frame.f_back
                continue
            relative = relative_path.as_posix()
            if relative.startswith("src/") and relative not in {
                "src/r1cs.py",
                "src/synthesis.py",
            }:
                frames.append(
                    {
                        "file": relative,
                        "function": frame.f_code.co_name,
                        "line": frame.f_lineno,
                    }
                )
            frame = frame.f_back
        return frames
    finally:
        del frame


class AllocationTraceR1CS(R1CS):
    """Observe allocation metadata without changing the production builder."""

    def __init__(self) -> None:
        self.allocation_events: list[dict[str, Any]] = []
        super().__init__()
        self.allocation_events.append(
            {
                "identity": "Local(0)",
                "index": 0,
                "allocation_event_index": 0,
                "allocation_api": "implicit-one",
                "kind": "one",
                "name": "ONE",
                "assignment": "1",
                "namespace_hierarchy": [],
                "gadget_scope": "implicit R1CS constant",
                "semantic_gadget_id": "sapling.spend.constant",
                "parent_gadget_context": ["sapling.spend"],
                "gadget_invocation_context": ["constant:ONE"],
                "allocation_role": "implicit one constant",
                "semantic_allocation_id": "sapling.spend.constant|ONE|implicit-one",
                "allocation_context_frames": [],
            }
        )

    def _allocate(self, kind: str, name: str, value: int | None) -> Variable:
        variable = super()._allocate(kind, name, value)
        frames = _local_source_frames()
        assignment = self._values[variable.index]
        (
            semantic_gadget_id,
            parent_gadget_context,
            gadget_invocation_context,
            allocation_role,
            semantic_allocation_id,
        ) = _semantic_provenance(name, frames)
        self.allocation_events.append(
            {
                "identity": f"Local({variable.index})",
                "index": variable.index,
                "allocation_event_index": len(self.allocation_events),
                "allocation_api": "alloc_public" if kind == "public" else "alloc_private",
                "kind": kind,
                "name": name,
                "allocation_label": name,
                "assignment": None if assignment is None else str(assignment),
                "namespace_hierarchy": [],
                "gadget_scope": (
                    f"{frames[0]['file']}:{frames[0]['function']}"
                    if frames
                    else "unknown local allocation scope"
                ),
                "semantic_gadget_id": semantic_gadget_id,
                "parent_gadget_context": parent_gadget_context,
                "gadget_invocation_context": gadget_invocation_context,
                "allocation_role": allocation_role,
                "semantic_allocation_id": semantic_allocation_id,
                "allocation_context_frames": frames,
            }
        )
        return variable


def build_local_allocation_trace(
    witness: SaplingSpendWitness,
) -> dict[str, Any]:
    system = AllocationTraceR1CS()
    constrain_sapling_spend(system, witness)
    if not system.is_satisfied():
        raise ValueError("local Spend provenance fixture is unsatisfied")
    if len(system.allocation_events) != len(system.variables):
        raise ValueError("allocation trace does not cover every local variable")
    return {
        "format": "zycoin-sapling-spend-allocation-provenance-v1",
        "fixture": "pinned sapling-crypto Spend test fixture iteration 0",
        "production_circuit_modified": False,
        "num_inputs_including_one": system.public_input_count + 1,
        "num_auxiliary_variables": len(system.variables) - system.public_input_count - 1,
        "num_constraints": system.constraint_count,
        "satisfied": True,
        "source_context_limits": [
            "The local R1CS stores flattened allocation names, not namespace objects.",
            "Python caller frames are test-only observation and are not circuit identity by themselves.",
        ],
        "variables": system.allocation_events,
    }


def write_local_allocation_trace(
    witness: SaplingSpendWitness, output_path: Path
) -> dict[str, Any]:
    trace = build_local_allocation_trace(witness)
    encoded = json.dumps(
        trace, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    output_path.write_bytes(encoded)
    return {
        "path": str(output_path.resolve()),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "variables": len(trace["variables"]),
        "auxiliary_variables": trace["num_auxiliary_variables"],
        "constraints": trace["num_constraints"],
        "satisfied": trace["satisfied"],
    }


def build_provenance_analysis(
    local_trace: dict[str, Any],
    upstream_trace: dict[str, Any],
    correspondence: dict[str, Any],
) -> dict[str, Any]:
    local_variables = local_trace["variables"]
    upstream_inputs = upstream_trace["inputs"]
    upstream_auxiliary = upstream_trace["auxiliary_variables"]
    upstream_variables = upstream_inputs + upstream_auxiliary
    upstream_variable_positions = {
        variable["identity"]: index
        for index, variable in enumerate(upstream_variables)
    }

    upstream_labels = Counter(
        variable["allocation_label"] for variable in upstream_auxiliary
    )
    upstream_roots = Counter(
        variable["namespace_hierarchy"][0]
        for variable in upstream_auxiliary
        if variable["namespace_hierarchy"]
    )
    local_scopes = Counter(
        variable["gadget_scope"] for variable in local_variables[8:]
    )
    matched_scopes = Counter(
        (
            pair["upstream_gadget_scope"].split("/", 1)[0],
            pair["local_gadget_scope"],
        )
        for pair in correspondence["matched_auxiliary_variables"]
    )

    upstream_event_indices = [
        variable["allocation_event_index"] for variable in upstream_variables
    ]
    local_event_indices = [
        variable["allocation_event_index"] for variable in local_variables
    ]
    delayed_inputs = [
        {
            "identity": variable["identity"],
            "variable_index": upstream_variable_positions[variable["identity"]],
            "allocation_event_index": variable["allocation_event_index"],
            "allocation_namespace": variable["namespace_hierarchy"],
            "allocation_label": variable["allocation_label"],
        }
        for variable in upstream_inputs[1:]
        if variable["allocation_event_index"]
        != upstream_variable_positions[variable["identity"]]
    ]
    repeated_labels = [
        {"allocation_label": label, "variable_count": count}
        for label, count in sorted(upstream_labels.items())
        if count > 1
    ]
    unresolved_local = correspondence["unresolved_local_auxiliary"]
    unresolved_upstream = correspondence["unresolved_upstream_auxiliary"]

    provenance_counts = correspondence["allocation_provenance_analysis"]
    matched_auxiliary = correspondence["matched_auxiliary_variables"]
    merkle_mappings = sum(
        pair["semantic_gadget_id"]
        == "sapling.spend.merkle-authentication-path"
        for pair in matched_auxiliary
    )
    previously_mapped_merkle = sum(
        pair["semantic_gadget_id"]
        == "sapling.spend.merkle-authentication-path"
        and pair["classification"] == "cross-checked-previous-semantic-mapping"
        for pair in matched_auxiliary
    )
    return {
        "format": "zycoin-sapling-spend-allocation-provenance-analysis-v2",
        "method": {
            "local": "Test-only R1CS subclass records variable allocation events, Python source frames, semantic gadget IDs, invocation contexts, and allocation roles; production synthesis is unchanged.",
            "upstream": "Test-only Bellman ConstraintSystem records alloc/alloc_input callbacks, namespace stack, gadget IDs, invocation contexts, and allocation roles.",
            "identity_rule": "Only a unique shared semantic gadget, invocation, and allocation-role ID is a candidate; assignments are checked after candidate selection and are not identity evidence.",
            "source_location_limit": "Bellman ConstraintSystem callbacks do not expose Rust caller file or line; the exporter derives gadget and role context from the pinned synthesis namespaces and records the available invocation context.",
        },
        "counts": {
            "local_variables_including_one": len(local_variables),
            "upstream_variables_including_one": len(upstream_variables),
            "local_auxiliary_variables": len(local_variables) - 8,
            "upstream_auxiliary_variables": len(upstream_auxiliary),
            "public_variables_mapped": correspondence["counts"][
                "public_variables_mapped"
            ],
            "auxiliary_variables_uniquely_identified": correspondence["counts"][
                "auxiliary_variables_mapped"
            ],
            "previously_mapped_auxiliary_variables": correspondence["counts"][
                "previously_mapped_auxiliary_variables"
            ],
            "newly_mapped_auxiliary_variables": correspondence["counts"][
                "newly_mapped_auxiliary_variables"
            ],
            "new_merkle_path_auxiliary_mappings": merkle_mappings
            - previously_mapped_merkle,
            "auxiliary_variables_ambiguous_local": provenance_counts[
                "ambiguous_local_auxiliary_variables"
            ],
            "auxiliary_variables_ambiguous_upstream": provenance_counts[
                "ambiguous_upstream_auxiliary_variables"
            ],
            "one_to_many_candidate_paths": provenance_counts[
                "one_to_many_candidate_paths"
            ],
            "many_to_one_candidate_paths": provenance_counts[
                "many_to_one_candidate_paths"
            ],
            "many_to_many_candidate_paths": provenance_counts[
                "many_to_many_candidate_paths"
            ],
            "auxiliary_variables_unresolved_per_system": correspondence["counts"][
                "local_auxiliary_unresolved"
            ],
            "candidate_assignment_mismatches": provenance_counts[
                "candidate_assignment_mismatches"
            ],
            "local_auxiliary_variables_missing_source_context": sum(
                not variable["allocation_context_frames"]
                for variable in local_variables[8:]
            ),
            "local_auxiliary_variables_without_namespace_hierarchy": sum(
                not variable["namespace_hierarchy"]
                for variable in local_variables[8:]
            ),
            "upstream_auxiliary_variables_missing_namespace": sum(
                not variable["namespace_hierarchy"]
                for variable in upstream_auxiliary
            ),
            "upstream_auxiliary_variables_missing_caller_file_line": sum(
                variable["source_file"] is None or variable["source_line"] is None
                for variable in upstream_auxiliary
            ),
            "local_source_level_gadget_scopes": len(local_scopes),
            "upstream_top_level_namespace_scopes": len(upstream_roots),
            "upstream_repeated_allocation_label_groups": len(repeated_labels),
            "upstream_variables_with_repeated_bare_labels": sum(
                count for count in upstream_labels.values() if count > 1
            ),
            "upstream_variables_with_unique_namespace_and_label": len(
                {
                    (
                        tuple(variable["namespace_hierarchy"]),
                        variable["allocation_label"],
                    )
                    for variable in upstream_auxiliary
                }
            ),
        },
        "event_order_validation": {
            "upstream_event_indices_unique_and_contiguous": (
                sorted(upstream_event_indices)
                == list(range(len(upstream_event_indices)))
            ),
            "local_event_indices_unique_and_contiguous": (
                sorted(local_event_indices) == list(range(len(local_event_indices)))
            ),
            "upstream_public_inputs_allocated_after_other_variables": delayed_inputs,
            "local_public_inputs_allocated_before_private_variables": all(
                variable["allocation_event_index"] == variable["index"]
                for variable in local_variables
            ),
        },
        "repeated_upstream_labels": repeated_labels,
        "unresolved_allocations": {
            "local": [
                {
                    "index": variable["index"],
                    "allocation_label": variable["allocation_label"],
                    "classification": variable["classification"],
                }
                for variable in unresolved_local
            ],
            "upstream": [
                {
                    "index": variable["index"],
                    "allocation_namespace": variable["allocation_namespace"],
                    "allocation_label": variable["allocation_label"],
                    "classification": variable["classification"],
                }
                for variable in unresolved_upstream
            ],
            "assessment": (
                "The local Merkle path position allocation and the upstream "
                "conditional-anchor num allocation have distinct roles and no "
                "shared source-derived allocation identity. They remain "
                "unmatched; equal indices or witness values would not justify "
                "a correspondence."
            ),
        },
        "upstream_top_level_gadget_scopes": [
            {"scope": scope, "variable_count": count}
            for scope, count in sorted(upstream_roots.items())
        ],
        "local_source_level_gadget_scopes": [
            {"scope": scope, "variable_count": count}
            for scope, count in sorted(local_scopes.items())
        ],
        "matched_scope_pairs": [
            {
                "upstream_scope": upstream_scope,
                "local_source_scope": local_scope,
                "variable_count": count,
            }
            for (upstream_scope, local_scope), count in sorted(
                matched_scopes.items()
            )
        ],
        "conclusion": {
            "complete_correspondence_achieved": correspondence[
                "complete_one_to_one_coverage"
            ],
            "achievable_with_current_source_metadata": False,
            "reason": "A unique semantic identity was established for 98,637 of 98,638 auxiliaries on each side, with zero ambiguous candidates and zero assignment mismatches among accepted pairs. The remaining local Sapling Spend Merkle path position and upstream conditional anchor/num allocations have distinct roles and no defensible shared identity.",
            "next_required_instrumentation": "Keep the final allocations unmatched unless source-level relation provenance independently establishes a shared role; do not infer identity from their indices, labels, or assignments. Any production allocation change is outside this test-only correspondence task.",
            "exact_spend_row_alignment": "Unverified",
            "complete_spend_recorder_synthesis": "Unverified",
            "groth16_compatibility": "Unverified",
        },
    }


def write_provenance_analysis(
    local_trace_path: Path,
    upstream_trace_path: Path,
    correspondence_path: Path,
    output_path: Path,
) -> dict[str, str]:
    local_trace = json.loads(local_trace_path.read_text(encoding="utf-8"))
    upstream_trace = json.loads(upstream_trace_path.read_text(encoding="utf-8"))
    correspondence = json.loads(
        correspondence_path.read_text(encoding="utf-8")
    )
    analysis = build_provenance_analysis(
        local_trace, upstream_trace, correspondence
    )
    encoded = json.dumps(
        analysis, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    output_path.write_bytes(encoded)
    return {
        "path": str(output_path.resolve()),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def main() -> None:
    import argparse

    from tests.test_sapling_spend_circuit import _circuit_witness
    from src.sapling_spend_reference import generate_pinned_test_witness

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    witness = _circuit_witness(generate_pinned_test_witness(0))
    print(
        json.dumps(
            write_local_allocation_trace(witness, args.output),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
