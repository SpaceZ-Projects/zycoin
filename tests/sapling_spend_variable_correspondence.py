"""Fail-closed, test-only Spend variable correspondence utilities."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


_INPUT_IDENTITIES = (
    ("ONE", "ONE", "sapling:implicit-one"),
    ("Sapling Spend public rk.u", "rk/u/input variable", "sapling:public:rk.u"),
    ("Sapling Spend public rk.v", "rk/v/input variable", "sapling:public:rk.v"),
    (
        "Sapling Spend public cv.u",
        "value commitment/commitment point/u/input variable",
        "sapling:public:cv.u",
    ),
    (
        "Sapling Spend public cv.v",
        "value commitment/commitment point/v/input variable",
        "sapling:public:cv.v",
    ),
    ("Sapling Spend public anchor", "anchor/input variable", "sapling:public:anchor"),
    ("Sapling Spend public nullifier_chunk_0", "pack nullifier/input 0", "sapling:public:nullifier_chunk_0"),
    ("Sapling Spend public nullifier_chunk_1", "pack nullifier/input 1", "sapling:public:nullifier_chunk_1"),
)


def _identity_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().casefold())


def _assignment_decimal(value: str | None) -> str | None:
    if value is None:
        return None
    return str(int.from_bytes(bytes.fromhex(value), "little"))


def validate_complete_mapping(
    local_variables: list[dict[str, Any]],
    upstream_variables: list[dict[str, Any]],
    pairs: list[dict[str, Any]],
) -> None:
    """Validate a proposed complete map whose pairs carry semantic_identity."""
    local_by_index = {v["index"]: v for v in local_variables}
    upstream_by_index = {v["index"]: v for v in upstream_variables}
    if len(local_by_index) != len(local_variables):
        raise ValueError("local variable indices are not unique")
    if len(upstream_by_index) != len(upstream_variables):
        raise ValueError("upstream variable indices are not unique")
    seen_local: set[int] = set()
    seen_upstream: set[int] = set()
    seen_identities: set[str] = set()
    for pair in pairs:
        local_index = pair["local_index"]
        upstream_index = pair["upstream_index"]
        identity = pair["semantic_identity"]
        if local_index in seen_local or upstream_index in seen_upstream:
            raise ValueError("variable correspondence is not one-to-one")
        if identity in seen_identities:
            raise ValueError(f"ambiguous semantic identity: {identity}")
        local = local_by_index.get(local_index)
        upstream = upstream_by_index.get(upstream_index)
        if local is None or upstream is None:
            raise ValueError("mapping references a variable outside the exports")
        if local.get("semantic_identity") != identity:
            raise ValueError(f"local semantic identity mismatch at {local_index}")
        if upstream.get("semantic_identity") != identity:
            raise ValueError(f"upstream semantic identity mismatch at {upstream_index}")
        if local.get("assignment") != upstream.get("assignment"):
            raise ValueError(f"assignment mismatch for semantic identity: {identity}")
        seen_local.add(local_index)
        seen_upstream.add(upstream_index)
        seen_identities.add(identity)
    if seen_local != set(local_by_index) or seen_upstream != set(upstream_by_index):
        raise ValueError("variable correspondence does not cover both exports")


def _semantic_inventory(
    local_variables: list[dict[str, Any]],
    upstream_variables: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    pairs: list[dict[str, Any]] = []

    if len(local_variables) < len(_INPUT_IDENTITIES):
        raise ValueError("local Spend export is missing required input variables")
    if len(upstream_variables) < len(_INPUT_IDENTITIES):
        raise ValueError("Bellman Spend export is missing required inputs")

    for local_name, upstream_label, identity in _INPUT_IDENTITIES:
        local_matches = [v for v in local_variables if v["name"] == local_name]
        upstream_matches = [v for v in upstream_variables if v["annotation"] == upstream_label]
        if len(local_matches) != 1 or len(upstream_matches) != 1:
            raise ValueError(f"public semantic identity is missing or ambiguous: {identity}")
        local = local_matches[0]
        upstream = upstream_matches[0]
        local_assignment = local["assignment"]
        upstream_assignment = _assignment_decimal(upstream["assignment_hex"])
        if local_assignment != upstream_assignment:
            raise ValueError(f"public assignment mismatch for semantic identity: {identity}")
        pairs.append(
            {
                "semantic_identity": identity,
                "local_index": local["index"],
                "upstream_identity": upstream["identity"],
                "upstream_index": _upstream_index(upstream["identity"]),
                "local_assignment": local_assignment,
                "upstream_assignment": upstream_assignment,
                "classification": "matched-public-semantic-identity",
                "local_allocation_event_index": local.get(
                    "allocation_event_index"
                ),
                "upstream_allocation_event_index": upstream.get(
                    "allocation_event_index"
                ),
                "matching_evidence": [
                    "Explicit pinned Spend public-input identity table",
                    "Matching public-input role and label",
                    "Assignments equal as an independent consistency check",
                ],
            }
        )

    return pairs


def _upstream_index(identity: str) -> int:
    kind, raw_index = identity[:-1].split("(")
    index = int(raw_index)
    return index if kind == "Input" else 8 + index


def _provenance_key(value: str) -> str:
    return "/".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _upstream_semantic_allocation_id(variable: dict[str, Any]) -> str | None:
    existing = variable.get("semantic_allocation_id")
    if existing is not None:
        return existing

    namespace = variable.get("allocation_namespace", [])
    if not namespace:
        return None

    if namespace[0] == "g^position":
        if len(namespace) != 3:
            return None
        _, scope, coordinate = namespace
        lookup = re.fullmatch(r"window table lookup (\d+)", scope)
        if lookup is not None:
            if coordinate not in {"x", "y", "precomp"}:
                return None
            expected_label = "and result" if coordinate == "precomp" else "num"
            if variable.get("allocation_label") != expected_label:
                return None
            role = f"window table lookup {lookup.group(1)}/{coordinate}"
        else:
            addition = re.fullmatch(r"addition (\d+)", scope)
            if addition is None or coordinate not in {
                "U",
                "A computation",
                "B computation",
                "C",
                "u3",
                "v3",
            }:
                return None
            expected_label = (
                "product num"
                if coordinate in {"A computation", "B computation"}
                else "num"
            )
            if variable.get("allocation_label") != expected_label:
                return None
            role = f"addition {addition.group(1)}/{coordinate}"
        return (
            "sapling.spend.nullifier-rho|mul:rho-position|"
            f"{_provenance_key(role)}"
        )

    root = namespace[0]
    small_order_roots = {
        "ak not small order": (
            "sapling.spend.randomized-authorization-key",
            "non-small-order:ak",
        ),
        "g_d not small order": (
            "sapling.spend.diversifier-base",
            "non-small-order:g-d",
        ),
    }
    if root in small_order_roots:
        gadget_id, invocation_id = small_order_roots[root]
        if (
            len(namespace) == 2
            and namespace[1] == "check u != 0"
            and variable.get("allocation_label") == "ephemeral inverse"
        ):
            role = "check u != 0/ephemeral inverse"
        else:
            if len(namespace) != 3:
                return None
            stage, item = namespace[1:]
            stage_match = re.fullmatch(
                r"(first|second|third) doubling", stage
            )
            if stage_match is None:
                return None
            expected_label = (
                "product num" if item == "A computation" else "num"
            )
            if item not in {"T", "A computation", "C", "u3", "v3"}:
                return None
            if variable.get("allocation_label") != expected_label:
                return None
            role = f"{stage}/{item}"
        return f"{gadget_id}|{invocation_id}|{_provenance_key(role)}"

    if root == "witness g_d":
        gadget_id = "sapling.spend.diversifier-base"
        invocation_id = "witness:g-d"
        if len(namespace) == 2 and namespace[1] in {"u", "v"}:
            role = namespace[1]
            if variable.get("allocation_label") != "num":
                return None
        elif len(namespace) == 3 and namespace[1] == "point interpretation":
            coordinate = {
                "u^2": "u/2",
                "v^2": "v/2",
                "u^2 v^2": "u/2/v/2",
            }.get(namespace[2])
            expected_label = (
                "product num" if namespace[2] == "u^2 v^2" else "squared num"
            )
            if coordinate is None or variable.get("allocation_label") != expected_label:
                return None
            role = f"point/interpretation/{coordinate}"
        else:
            return None
        return f"{gadget_id}|{invocation_id}|{_provenance_key(role)}"

    if root in {
        "computation of rk",
        "randomization of note commitment",
        "faerie gold prevention",
    } and len(namespace) == 2:
        item = namespace[1]
        item_role = {
            "U": "u",
            "A computation": "a computation",
            "B computation": "b computation",
            "C": "c",
            "u3": "u3",
            "v3": "v3",
        }.get(item)
        if item_role is None:
            return None
        expected_label = (
            "product num" if item in {"A computation", "B computation"} else "num"
        )
        if variable.get("allocation_label") != expected_label:
            return None
        gadget_id, invocation_id, operation = {
            "computation of rk": (
                "sapling.spend.randomized-authorization-key",
                "addition:rk",
                "computation of rk",
            ),
            "randomization of note commitment": (
                "sapling.spend.note-commitment",
                "randomization:note-commitment",
                "",
            ),
            "faerie gold prevention": (
                "sapling.spend.nullifier-rho",
                "faerie-gold-prevention",
                "",
            ),
        }[root]
        role = f"{operation}/{item_role}" if operation else item_role
        return f"{gadget_id}|{invocation_id}|{_provenance_key(role)}"

    return None


def _semantic_role_translation(
    gadget_id: str | None, role: str | None
) -> dict[str, Any] | None:
    if gadget_id in {
        "sapling.spend.ivk.blake2s",
        "sapling.spend.nullifier.blake2s",
    }:
        return {
            "rule": "Map local BLAKE2s compression coordinates to pinned Bellman namespace roles.",
            "details": [
                "Local G indices are translated to Bellman's one-based mixing invocation.",
                "Local alternating add/xor step indices are translated to Bellman's one-based operation step.",
                "Addition carry bits are identified as result bits 32 and 33; XOR outputs use the distinct xor-of-bit role.",
            ],
        }
    if gadget_id in {
        "sapling.spend.ak.representation",
        "sapling.spend.nk.representation",
        "sapling.spend.g-d.representation",
        "sapling.spend.pk-d.representation",
        "sapling.spend.rho.representation",
    }:
        return {
            "rule": "Map local little-endian strict-field bit positions to Bellman's most-significant-bit-first allocation namespaces.",
            "details": [
                "Field bit i maps to the Bellman allocation role bit (254 - i), as shown by pinned AllocatedNum.to_bits_le_strict.",
                "Local zero-based prefix-AND positions map to Bellman's one-based kary_and namespace positions at the corresponding reversed bit index.",
            ],
        }
    if gadget_id in {
        "sapling.spend.pk-d.scalar-multiplication",
        "sapling.spend.nk.fixed-base-multiplication",
        "sapling.spend.randomized-authorization-key",
        "sapling.spend.nullifier-rho",
        "sapling.spend.note-commitment-randomness",
    }:
        return {
            "rule": "Translate local scalar-multiplication allocation roles to pinned Bellman selection, window-table, doubling, and addition roles.",
            "details": [
                "Selected coordinates and lookup-precomputation fields are mapped by their semantic window index and coordinate.",
                "Local base-doubling intermediates map to the matching doubling index; accumulator additions map to matching addition indices and named intermediates.",
                "The operation's gadget ID and invocation distinguish variable-base pk_d from fixed-base nk and randomized authorization-key multiplication.",
            ],
        }
    if (
        gadget_id == "sapling.spend.value-commitment"
        and role
        and (
            role.startswith("compute/the/value/in/the/exponent/")
            or role.startswith("computation/of/rcv/")
        )
    ):
        return {
            "rule": "Translate local value-generator and rcv scalar-multiplication allocations to their pinned exponentiation or rcv roles.",
            "details": [
                "Window lookup and point-addition roles are mapped by operation index and coordinate/intermediate.",
                "The value-commitment gadget and source role distinguish value exponentiation from rcv and note-commitment randomness operations.",
                "Assignments are checked only after a unique semantic role match.",
            ],
        }
    if gadget_id == "sapling.spend.note-content.pedersen":
        return {
            "rule": "Translate local note-content Pedersen segment/window roles to the pinned Bellman note-content hash namespace.",
            "details": [
                "Segment index, window index, and y/precomputation or addition-coordinate role are retained explicitly.",
                "The local note-content invocation is distinguished from the 32 Merkle-level Pedersen calls.",
                "Assignments are checked only after the unique allocation-role match.",
            ],
        }
    if (
        gadget_id == "sapling.spend.merkle-authentication-path"
        and role
        and "/combination/" in role
    ):
        return {
            "rule": "Translate the local Merkle Pedersen accumulator-combination outputs to Bellman's addition-of-segment-to-accumulator roles.",
            "details": [
                "Merkle level, segment number, and U/A/B/C/u3/v3 output role are explicit.",
                "The pinned namespace distinguishes each level and each accumulator addition role.",
                "Assignments are checked only after the unique semantic match.",
            ],
        }
    if (
        gadget_id == "sapling.spend.value-commitment"
        and role
        and (role.startswith("value/bit/") or role.startswith("rcv/bit/"))
    ):
        return {
            "rule": "Map value and rcv range bits by named witness role and bit index to the pinned value-commitment boolean allocations.",
            "details": [
                "The value-versus-rcv namespace and bit index are preserved.",
                "Assignments are independent consistency checks, not identity evidence.",
            ],
        }
    if gadget_id == "sapling.spend.nullifier-rho":
        return {
            "rule": "Translate the local fixed-base nullifier-position multiplication roles to the pinned g^position window and addition namespaces.",
            "details": [
                "Window lookup, precomputation, accumulator, and addition roles are mapped by their semantic operation index.",
                "The local rho-position multiplication call context and the pinned g^position namespace identify the operation.",
                "Six additional local rho/commitment point allocations without matching pinned allocation roles remain unmapped.",
            ],
        }
    if (
        gadget_id == "sapling.spend.merkle-authentication-path"
        and role
        and role.startswith("computation/of/pedersen/hash/")
    ):
        return {
            "rule": "Translate local per-window Pedersen allocation roles to pinned Bellman segment/window namespaces within a specific Merkle level.",
            "details": [
                "Local addition[j] maps to the semantically corresponding Pedersen window j, preserving the lambda/xprime/yprime role.",
                "Local segment conversion coordinates map to Bellman's conversion-of-segment-into-Edwards coordinate roles.",
                "Merkle level is part of every identity, distinguishing the 32 repeated Pedersen invocations.",
            ],
        }
    return None


def match_allocation_provenance(
    local_variables: list[dict[str, Any]],
    upstream_variables: list[dict[str, Any]],
    previously_mapped_pairs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Match only unique, explicit gadget-level semantic allocation identities."""
    local_aux = [v for v in local_variables if v.get("kind") == "private"]
    upstream_aux = [
        v for v in upstream_variables if v.get("identity", "").startswith("Aux(")
    ]
    local_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    upstream_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for variable in local_aux:
        prefix = "Sapling Spend "
        name = variable.get("name", "")
        if not name.startswith(prefix):
            continue
        key = variable.get("semantic_allocation_id")
        if key is None:
            key = _provenance_key(name[len(prefix) :])
        if key and variable.get("allocation_context_frames"):
            local_by_path[key].append(variable)

    for variable in upstream_aux:
        hierarchy = variable.get(
            "namespace_hierarchy", variable.get("allocation_namespace", [])
        )
        if not hierarchy:
            continue
        key = _upstream_semantic_allocation_id(variable)
        if key is None:
            key = _provenance_key("/".join(hierarchy))
        if key:
            upstream_by_path[key].append(variable)

    previous_pairs = {
        (pair["local_index"], pair["upstream_index"])
        for pair in (previously_mapped_pairs or [])
    }
    matched: list[dict[str, Any]] = []
    previously_mapped_count = 0
    ambiguous_local_variables = sum(
        len(variables)
        for key, variables in local_by_path.items()
        if key not in upstream_by_path and len(variables) > 1
    )
    ambiguous_upstream_variables = sum(
        len(variables)
        for key, variables in upstream_by_path.items()
        if key not in local_by_path and len(variables) > 1
    )
    one_to_many_candidate_paths = 0
    many_to_one_candidate_paths = 0
    many_to_many_candidate_paths = 0
    candidate_assignment_mismatches = 0
    shared_paths = set(local_by_path) & set(upstream_by_path)
    for key in sorted(shared_paths):
        locals_for_path = local_by_path[key]
        upstream_for_path = upstream_by_path[key]
        if len(locals_for_path) != 1 or len(upstream_for_path) != 1:
            ambiguous_local_variables += len(locals_for_path)
            ambiguous_upstream_variables += len(upstream_for_path)
            if len(locals_for_path) == 1 and len(upstream_for_path) > 1:
                one_to_many_candidate_paths += 1
            elif len(locals_for_path) > 1 and len(upstream_for_path) == 1:
                many_to_one_candidate_paths += 1
            else:
                many_to_many_candidate_paths += 1
            continue

        local = locals_for_path[0]
        upstream = upstream_for_path[0]
        local_assignment = local.get("assignment")
        upstream_assignment = _assignment_decimal(upstream.get("assignment_hex"))
        if local_assignment != upstream_assignment:
            candidate_assignment_mismatches += 1
            continue

        matched.append(
            {
                "semantic_identity": local.get(
                    "semantic_allocation_id",
                    f"sapling-spend:allocation-path:{key}",
                ),
                "local_index": local["index"],
                "upstream_identity": upstream["identity"],
                "upstream_index": _upstream_index(upstream["identity"]),
                "local_assignment": local_assignment,
                "upstream_assignment": upstream_assignment,
                "classification": (
                    "cross-checked-previous-semantic-mapping"
                    if (local["index"], _upstream_index(upstream["identity"]))
                    in previous_pairs
                    else "new-unique-gadget-allocation-identity"
                ),
                "matching_evidence": [
                    "The local and upstream test-only traces carry the same explicit semantic gadget and allocation-role identity.",
                    "The gadget invocation and parent-child context disambiguate repeated gadget calls.",
                    "Both paths are unique within their respective auxiliary inventories.",
                    "Assignments match as an independent consistency check after semantic selection.",
                ],
                "semantic_role_translation": _semantic_role_translation(
                    local.get("semantic_gadget_id"),
                    local.get("allocation_role"),
                ),
                "semantic_gadget_id": local.get("semantic_gadget_id"),
                "allocation_role": local.get("allocation_role"),
                "parent_gadget_context": local.get("parent_gadget_context"),
                "gadget_invocation_context": local.get(
                    "gadget_invocation_context"
                ),
                "local_allocation_event_index": local.get("allocation_event_index"),
                "local_gadget_scope": local.get("gadget_scope"),
                "upstream_allocation_event_index": upstream.get(
                    "allocation_event_index"
                ),
                "upstream_gadget_scope": upstream.get(
                    "gadget_scope",
                    "/".join(
                        upstream.get(
                            "namespace_hierarchy",
                            upstream.get("allocation_namespace", []),
                        )
                    ),
                ),
                "upstream_allocation_role": upstream.get("allocation_role"),
                "upstream_parent_gadget_context": upstream.get(
                    "parent_gadget_context"
                ),
                "upstream_gadget_invocation_context": upstream.get(
                    "gadget_invocation_context"
                ),
            }
        )
        if (
            local["index"],
            _upstream_index(upstream["identity"]),
        ) in previous_pairs:
            previously_mapped_count += 1

    return {
        "matched_auxiliary_variables": matched,
        "counts": {
            "local_auxiliary_variables": len(local_aux),
            "upstream_auxiliary_variables": len(upstream_aux),
            "shared_semantic_paths": len(shared_paths),
            "unique_candidate_paths": sum(
                len(local_by_path[key]) == 1 and len(upstream_by_path[key]) == 1
                for key in shared_paths
            ),
            "matched_after_assignment_check": len(matched),
            "previously_mapped_and_cross_checked": previously_mapped_count,
            "newly_mapped": len(matched) - previously_mapped_count,
            "ambiguous_local_auxiliary_variables": ambiguous_local_variables,
            "ambiguous_upstream_auxiliary_variables": ambiguous_upstream_variables,
            "one_to_many_candidate_paths": one_to_many_candidate_paths,
            "many_to_one_candidate_paths": many_to_one_candidate_paths,
            "many_to_many_candidate_paths": many_to_many_candidate_paths,
            "candidate_assignment_mismatches": candidate_assignment_mismatches,
        },
        "matching_policy": {
            "identity_source": "shared test-only semantic gadget, invocation, and allocation-role identifiers",
            "allocation_labels_are_sufficient_identity": False,
            "ordinal_positions_used_as_identity": False,
            "assignments_used_as_identity": False,
            "repeated_gadget_calls_disambiguated_by": "semantic invocation context, such as Merkle tree level",
        },
    }


def _allocation_identity(variable: dict[str, Any], upstream: bool) -> str:
    if upstream:
        namespace = "/".join(variable["allocation_namespace"])
        label = variable["allocation_label"]
        return f"bellman:{namespace}/{label}" if namespace else f"bellman:{label}"
    return f"zycoin:{variable['kind']}:{variable['name']}"


def _unresolved_record(variable: dict[str, Any], upstream: bool) -> dict[str, Any]:
    if upstream:
        return {
            "index": _upstream_index(variable["identity"]),
            "variable_identity": variable["identity"],
            "semantic_identity": _allocation_identity(variable, True),
            "allocation_namespace": variable["allocation_namespace"],
            "allocation_label": variable["allocation_label"],
            "assignment": _assignment_decimal(variable["assignment_hex"]),
            "classification": "unresolved-no-cross-system-semantic-identity",
        }
    return {
        "index": variable["index"],
        "variable_identity": f"Local({variable['index']})",
        "semantic_identity": _allocation_identity(variable, False),
        "allocation_namespace": variable["kind"],
        "allocation_label": variable["name"],
        "assignment": variable["assignment"],
        "classification": "unresolved-no-cross-system-semantic-identity",
    }


def build_correspondence_result(
    local_variables: list[dict[str, Any]],
    upstream_variables: list[dict[str, Any]],
    provenance_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build only evidence-backed mappings; never infer identity from indices or values."""
    public_pairs = _semantic_inventory(
        local_variables, upstream_variables
    )
    local_aux = [v for v in local_variables if v["kind"] == "private"]
    upstream_aux = [v for v in upstream_variables if v["identity"].startswith("Aux(")]

    if len(local_aux) != len(upstream_aux):
        raise ValueError("local and upstream Spend auxiliary counts differ")
    provenance_pairs = (
        provenance_result["matched_auxiliary_variables"]
        if provenance_result is not None
        else []
    )
    mapped_local_indices = {pair["local_index"] for pair in provenance_pairs}
    mapped_upstream_indices = {pair["upstream_index"] for pair in provenance_pairs}
    if len(mapped_local_indices) != len(provenance_pairs) or len(
        mapped_upstream_indices
    ) != len(provenance_pairs):
        raise ValueError("allocation provenance correspondence is not one-to-one")
    if not mapped_local_indices.issubset({v["index"] for v in local_aux}):
        raise ValueError("allocation provenance references a non-auxiliary local variable")
    if not mapped_upstream_indices.issubset(
        {_upstream_index(v["identity"]) for v in upstream_aux}
    ):
        raise ValueError("allocation provenance references a non-auxiliary upstream variable")
    local_semantic_ids = [_allocation_identity(v, False) for v in local_aux]
    upstream_semantic_ids = [_allocation_identity(v, True) for v in upstream_aux]
    if len(set(local_semantic_ids)) != len(local_semantic_ids):
        raise ValueError("local auxiliary semantic identities are ambiguous")
    if len(set(upstream_semantic_ids)) != len(upstream_semantic_ids):
        raise ValueError("upstream auxiliary semantic identities are ambiguous")

    normalized_local: dict[str, list[dict[str, Any]]] = defaultdict(list)
    normalized_upstream: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for variable in local_aux:
        normalized_local[_identity_text(variable["name"])].append(variable)
    for variable in upstream_aux:
        normalized_upstream[_identity_text(variable["annotation"])].append(variable)

    # These are labels in separate naming schemes, not cross-system identities.
    shared_label_keys = set(normalized_local) & set(normalized_upstream)
    ambiguous_shared_labels = sorted(
        key
        for key in shared_label_keys
        if len(normalized_local[key]) != 1 or len(normalized_upstream[key]) != 1
    )
    unique_shared_labels = sorted(
        key
        for key in shared_label_keys
        if len(normalized_local[key]) == 1 and len(normalized_upstream[key]) == 1
    )
    if unique_shared_labels:
        raise ValueError(
            "normalized label overlap is not an authoritative semantic identity; "
            "add an independently justified identity rule before pairing"
        )
    local_label_counts = Counter(v["name"] for v in local_aux)
    upstream_label_counts = Counter(v["allocation_label"] for v in upstream_aux)

    local_values = Counter(v["assignment"] for v in local_aux)
    upstream_values = Counter(
        _assignment_decimal(v["assignment_hex"]) for v in upstream_aux
    )
    same_value_candidate_pairs = sum(
        count * upstream_values.get(value, 0)
        for value, count in local_values.items()
    )
    mapping_payload = json.dumps(
        {
            "public": public_pairs,
            "auxiliary": provenance_pairs,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    mapping_fingerprint = hashlib.sha256(
        b"zycoin-sapling-spend-variable-mapping-v2\0" + mapping_payload
    ).hexdigest()

    unresolved_local_aux = [
        v for v in local_aux if v["index"] not in mapped_local_indices
    ]
    unresolved_upstream_aux = [
        v for v in upstream_aux if _upstream_index(v["identity"]) not in mapped_upstream_indices
    ]
    provenance_counts = (
        provenance_result["counts"]
        if provenance_result is not None
        else {
            "ambiguous_local_auxiliary_variables": 0,
            "ambiguous_upstream_auxiliary_variables": 0,
            "candidate_assignment_mismatches": 0,
            "shared_semantic_paths": 0,
            "unique_candidate_paths": 0,
        }
    )
    return {
        "format": "zycoin-sapling-spend-variable-correspondence-v3",
        "status": "blocked-incomplete-semantic-correspondence",
        "complete_one_to_one_coverage": False,
        "counts": {
            "local_variables_including_one": len(local_variables),
            "upstream_variables_including_one": len(upstream_variables),
            "public_variables_mapped": len(public_pairs),
            "auxiliary_variables_mapped": len(provenance_pairs),
            "previously_mapped_auxiliary_variables": provenance_counts.get(
                "previously_mapped_and_cross_checked", 0
            ),
            "newly_mapped_auxiliary_variables": provenance_counts.get(
                "newly_mapped", len(provenance_pairs)
            ),
            "local_auxiliary_unresolved": len(unresolved_local_aux),
            "upstream_auxiliary_unresolved": len(unresolved_upstream_aux),
            "ambiguous_semantic_identities": max(
                provenance_counts["ambiguous_local_auxiliary_variables"],
                provenance_counts["ambiguous_upstream_auxiliary_variables"],
            ),
            "unmatched_local_auxiliary": len(unresolved_local_aux),
            "unmatched_upstream_auxiliary": len(unresolved_upstream_aux),
            "normalized_label_overlap": len(shared_label_keys),
            "ambiguous_normalized_labels": len(ambiguous_shared_labels),
            "repeated_local_allocation_labels": sum(
                count > 1 for count in local_label_counts.values()
            ),
            "repeated_upstream_allocation_labels": sum(
                count > 1 for count in upstream_label_counts.values()
            ),
        },
        "matching_policy": {
            "public_inputs": "Matched by an explicit pinned semantic identity table; assignment equality is a post-match check.",
            "auxiliary_variables": "Mapped only where a unique normalized local allocation name matches the upstream namespace hierarchy; labels, ordinal positions, coefficients, and witness equality do not establish identity.",
            "coefficient_independent_identity": True,
            "witness_values_used_as_identity": False,
        },
        "allocation_provenance_analysis": {
            **provenance_counts,
            "local_source_context_trace_available": provenance_result is not None,
            "upstream_namespace_trace_available": provenance_result is not None,
        },
        "assignment_diagnostics": {
            "same_value_candidate_pairs_if_values_were_used": same_value_candidate_pairs,
            "value_match_is_identity_evidence": False,
            "local_auxiliary_distinct_assignment_values": len(local_values),
            "upstream_auxiliary_distinct_assignment_values": len(upstream_values),
            "local_auxiliary_variables_with_repeated_values": sum(
                count for count in local_values.values() if count > 1
            ),
            "upstream_auxiliary_variables_with_repeated_values": sum(
                count for count in upstream_values.values() if count > 1
            ),
        },
        "matched_public_variables": public_pairs,
        "matched_auxiliary_variables": provenance_pairs,
        "unresolved_local_auxiliary": [
            _unresolved_record(v, False) for v in unresolved_local_aux
        ],
        "unresolved_upstream_auxiliary": [
            _unresolved_record(v, True) for v in unresolved_upstream_aux
        ],
        "mapping_fingerprint_sha256": mapping_fingerprint,
    }


def write_correspondence_artifact(
    local_path: Path,
    upstream_path: Path,
    output_path: Path,
    local_provenance_path: Path | None = None,
    upstream_provenance_path: Path | None = None,
    previous_correspondence_path: Path | None = None,
) -> dict[str, Any]:
    local_document = json.loads(local_path.read_text(encoding="utf-8"))
    upstream_document = json.loads(upstream_path.read_text(encoding="utf-8"))
    upstream_variables = upstream_document["inputs"] + upstream_document["auxiliary_variables"]
    provenance_result = None
    trace_metadata = None
    if local_provenance_path is not None or upstream_provenance_path is not None:
        if local_provenance_path is None or upstream_provenance_path is None:
            raise ValueError("both local and upstream provenance traces are required")
        local_trace = json.loads(
            local_provenance_path.read_text(encoding="utf-8")
        )
        upstream_trace = json.loads(
            upstream_provenance_path.read_text(encoding="utf-8")
        )
        upstream_trace_variables = upstream_trace.get("variables")
        if upstream_trace_variables is None:
            upstream_trace_variables = (
                upstream_trace["inputs"] + upstream_trace["auxiliary_variables"]
            )
        local_variables = local_trace["variables"]
        upstream_variables = upstream_trace_variables
        previous_pairs = []
        if previous_correspondence_path is not None:
            previous_document = json.loads(
                previous_correspondence_path.read_text(encoding="utf-8")
            )
            previous_pairs = previous_document["matched_auxiliary_variables"]
        provenance_result = match_allocation_provenance(
            local_trace["variables"],
            upstream_trace_variables,
            previous_pairs,
        )
        trace_metadata = {
            "local_trace_path": str(local_provenance_path.resolve()),
            "local_trace_sha256": hashlib.sha256(
                local_provenance_path.read_bytes()
            ).hexdigest(),
            "upstream_trace_path": str(upstream_provenance_path.resolve()),
            "upstream_trace_sha256": hashlib.sha256(
                upstream_provenance_path.read_bytes()
            ).hexdigest(),
        }
    else:
        local_variables = local_document["variables"]
    result = build_correspondence_result(
        local_variables, upstream_variables, provenance_result
    )
    if trace_metadata is not None:
        result["provenance_traces"] = trace_metadata
    encoded = json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    output_path.write_bytes(encoded)
    result["artifact_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def build_gadget_crosswalk(correspondence: dict[str, Any]) -> dict[str, Any]:
    pairs = correspondence["matched_auxiliary_variables"]
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for pair in pairs:
        key = (
            pair["semantic_gadget_id"],
            pair["semantic_identity"].split("|", 2)[1],
        )
        grouped[key].append(pair)
    groups = []
    for (gadget_id, invocation), group_pairs in sorted(grouped.items()):
        group_pairs.sort(
            key=lambda pair: (pair["semantic_identity"], pair["local_index"])
        )
        groups.append(
            {
                "semantic_gadget_id": gadget_id,
                "gadget_invocation_context": invocation,
                "parent_gadget_context": group_pairs[0][
                    "parent_gadget_context"
                ],
                "allocation_count": len(group_pairs),
                "previously_mapped": sum(
                    pair["classification"]
                    == "cross-checked-previous-semantic-mapping"
                    for pair in group_pairs
                ),
                "newly_mapped": sum(
                    pair["classification"]
                    == "new-unique-gadget-allocation-identity"
                    for pair in group_pairs
                ),
                "allocations": [
                    {
                        "semantic_allocation_id": pair["semantic_identity"],
                        "allocation_role": pair["allocation_role"],
                        "local_index": pair["local_index"],
                        "upstream_index": pair["upstream_index"],
                        "local_assignment": pair["local_assignment"],
                        "upstream_assignment": pair["upstream_assignment"],
                        "local_allocation_event_index": pair[
                            "local_allocation_event_index"
                        ],
                        "upstream_allocation_event_index": pair[
                            "upstream_allocation_event_index"
                        ],
                        "local_gadget_scope": pair["local_gadget_scope"],
                        "upstream_gadget_scope": pair["upstream_gadget_scope"],
                        "classification": pair["classification"],
                    }
                    for pair in group_pairs
                ],
            }
        )
    semantic_pairs = [
        {
            "semantic_identity": pair["semantic_identity"],
            "local_index": pair["local_index"],
            "upstream_index": pair["upstream_index"],
        }
        for pair in pairs
    ]
    fingerprint = hashlib.sha256(
        b"zycoin-sapling-spend-gadget-crosswalk-v1\0"
        + json.dumps(
            semantic_pairs,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return {
        "format": "zycoin-sapling-spend-gadget-allocation-crosswalk-v1",
        "status": "partial-fail-closed",
        "complete_one_to_one_coverage": correspondence[
            "complete_one_to_one_coverage"
        ],
        "counts": {
            "public_variables_mapped": correspondence["counts"][
                "public_variables_mapped"
            ],
            "auxiliary_variables_mapped": len(pairs),
            "previously_mapped_auxiliary_variables": correspondence["counts"][
                "previously_mapped_auxiliary_variables"
            ],
            "newly_mapped_auxiliary_variables": correspondence["counts"][
                "newly_mapped_auxiliary_variables"
            ],
            "ambiguous_local_auxiliary_variables": correspondence[
                "allocation_provenance_analysis"
            ]["ambiguous_local_auxiliary_variables"],
            "ambiguous_upstream_auxiliary_variables": correspondence[
                "allocation_provenance_analysis"
            ]["ambiguous_upstream_auxiliary_variables"],
            "unresolved_auxiliary_variables_per_side": correspondence["counts"][
                "local_auxiliary_unresolved"
            ],
            "gadget_invocation_groups": len(groups),
        },
        "identity_policy": {
            "semantic_inputs": [
                "source-derived gadget identity",
                "explicit repeated-invocation context",
                "allocation role within that invocation",
            ],
            "variable_ordinal_used_as_identity": False,
            "witness_assignment_used_as_identity": False,
            "generic_allocation_label_sufficient": False,
            "assignment_validation": "Equal assignments are checked only after semantic identities are uniquely paired.",
        },
        "mapping_fingerprint_sha256": fingerprint,
        "gadget_invocation_groups": groups,
    }


def write_gadget_crosswalk(
    correspondence_path: Path, output_path: Path
) -> dict[str, Any]:
    correspondence = json.loads(
        correspondence_path.read_text(encoding="utf-8")
    )
    crosswalk = build_gadget_crosswalk(correspondence)
    encoded = json.dumps(
        crosswalk, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    output_path.write_bytes(encoded)
    crosswalk["artifact_sha256"] = hashlib.sha256(encoded).hexdigest()
    return crosswalk


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--local", required=True, type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--local-provenance", type=Path)
    parser.add_argument("--upstream-provenance", type=Path)
    parser.add_argument("--previous-correspondence", type=Path)
    args = parser.parse_args()
    result = write_correspondence_artifact(
        args.local,
        args.upstream,
        args.output,
        args.local_provenance,
        args.upstream_provenance,
        args.previous_correspondence,
    )
    print(json.dumps({key: result[key] for key in ("status", "counts", "mapping_fingerprint_sha256", "artifact_sha256")}, sort_keys=True))


if __name__ == "__main__":
    main()
