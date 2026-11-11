"""Build a semantic variable correspondence for the pinned Output fixture."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from src.jubjub import Point
from src.r1cs import R1CS
from src.sapling_gadgets import constrain_sapling_output, make_sapling_output_witness

_UPSTREAM_EXPORT_SHA256 = (
    "ea3ca38004d7ddedaf2599f769c71f6b08a0d61e27ce3717f645d1ffddd68afe"
)
_FIXTURE = Path(__file__).parent / "fixtures" / "sapling_output_reference.json"


class CorrespondenceError(ValueError):
    """Raised when a complete, unambiguous semantic mapping cannot be built."""


def _upstream_key(annotation: str, index: int) -> str:
    if annotation == "ONE":
        return "input:ONE"
    input_roles = {
        "value commitment/commitment point/u/input variable": "cv.u",
        "value commitment/commitment point/v/input variable": "cv.v",
        "epk/u/input variable": "epk.u",
        "epk/v/input variable": "epk.v",
        "commitment/input variable": "cmu.u",
    }
    if annotation in input_roles:
        return f"input:{input_roles[annotation]}"

    match = re.fullmatch(
        r"value commitment/value/bit (\d+)/boolean", annotation
    )
    if match:
        return f"scalar:value:{match.group(1)}"
    match = re.fullmatch(r"value commitment/rcv/bit (\d+)/boolean", annotation)
    if match:
        return f"scalar:rcv:{match.group(1)}"
    match = re.fullmatch(r"esk/bit (\d+)/boolean", annotation)
    if match:
        return f"scalar:esk:{match.group(1)}"
    match = re.fullmatch(r"rcm/bit (\d+)/boolean", annotation)
    if match:
        return f"scalar:rcm:{match.group(1)}"

    match = re.fullmatch(r"pk_d bits of v/bit (\d+)/boolean", annotation)
    if match:
        return f"repr:pk_d:v:{match.group(1)}"
    if annotation == "pk_d bit of u/boolean":
        return "repr:pk_d:u"

    match = re.fullmatch(
        r"representation of g_d/unpack ([uv])/bit (\d+)/boolean",
        annotation,
    )
    if match:
        coordinate, bit = match.groups()
        return f"repr:g_d:{coordinate}:bit:{254 - int(bit)}"
    match = re.fullmatch(
        r"representation of g_d/unpack ([uv])/run ending at "
        r"(\d+)/and (\d+)/and result",
        annotation,
    )
    if match:
        coordinate, end, step = match.groups()
        return (
            f"repr:g_d:{coordinate}:and:{254 - int(end)}:{int(step) - 1}"
        )

    match = re.fullmatch(r"witness g_d/([uv])/num", annotation)
    if match:
        return f"g_d:coordinate:{match.group(1)}"
    match = re.fullmatch(
        r"witness g_d/point interpretation/([uv])\^2/squared num",
        annotation,
    )
    if match:
        return f"g_d:curve:{match.group(1)}_squared"
    if annotation == "witness g_d/point interpretation/u^2 v^2/product num":
        return "g_d:curve:coordinate_product"
    match = re.fullmatch(
        r"g_d not small order/(first|second|third) doubling/"
        r"(T/num|A computation/product num|C/num|u3/num|v3/num)",
        annotation,
    )
    if match:
        doubling = {"first": 0, "second": 1, "third": 2}[match.group(1)]
        field = match.group(2)
        role = {
            "T/num": "T",
            "A computation/product num": "A",
            "C/num": "C",
            "u3/num": "u",
            "v3/num": "v",
        }[field]
        return f"g_d:small_order:{doubling}:{role}"
    if annotation == "g_d not small order/check u != 0/ephemeral inverse":
        return "g_d:u_inverse"

    # Fixed-base multiplication allocation names are shared semantically
    # across value, rcv, and rcm; this translates only the source role names.
    fixed_base_prefixes = (
        ("value commitment/compute the value in the exponent/", "value"),
        ("value commitment/computation of rcv/", "rcv"),
        ("computation of commitment randomness/", "rcm"),
    )
    for prefix, component in fixed_base_prefixes:
        if annotation.startswith(prefix):
            suffix = annotation[len(prefix) :]
            match = re.fullmatch(r"window table lookup (\d+)/(.+)", suffix)
            if match:
                window, field = match.groups()
                role = {
                    "x/num": "selected_u",
                    "y/num": "selected_v",
                    "precomp/and result": "lookup_bc",
                }.get(field)
                if role is not None:
                    return f"fixed:{component}:lookup:{window}:{role}"
            match = re.fullmatch(r"addition (\d+)/(.+)", suffix)
            if match:
                window, field = match.groups()
                role = {
                    "U/num": "addition_U",
                    "A computation/product num": "addition_A",
                    "B computation/product num": "addition_B",
                    "C/num": "addition_C",
                    "u3/num": "accumulator_u",
                    "v3/num": "accumulator_v",
                }.get(field)
                if role is not None:
                    return f"fixed:{component}:addition:{window}:{role}"
    match = re.fullmatch(r"value commitment/computation of cv/(.+)", annotation)
    if match:
        field = match.group(1)
        role = {
            "U/num": "addition_U",
            "A computation/product num": "addition_A",
            "B computation/product num": "addition_B",
            "C/num": "addition_C",
            "u3/num": "result_u",
            "v3/num": "result_v",
        }.get(field)
        if role is not None:
            return f"value_commitment:final:{role}"

    match = re.fullmatch(
        r"epk computation/selection (\d+)/([uv])'/num", annotation
    )
    if match:
        index, coordinate = match.groups()
        return f"epk:selection:{index}:{coordinate}"
    match = re.fullmatch(
        r"epk computation/doubling (\d+)/"
        r"(T/num|A computation/product num|C/num|u3/num|v3/num)",
        annotation,
    )
    if match:
        index, field = match.groups()
        role = {
            "T/num": "T",
            "A computation/product num": "A",
            "C/num": "C",
            "u3/num": "u",
            "v3/num": "v",
        }[field]
        return f"epk:doubling:{index}:{role}"
    match = re.fullmatch(r"epk computation/addition (\d+)/(.+)", annotation)
    if match:
        index, field = match.groups()
        role = {
            "U/num": "U",
            "A computation/product num": "A",
            "B computation/product num": "B",
            "C/num": "C",
            "u3/num": "u",
            "v3/num": "v",
        }.get(field)
        if role is not None:
            return f"epk:addition:{index}:{role}"

    match = re.fullmatch(
        r"note content hash/segment (\d+), window (\d+)/(.+)", annotation
    )
    if match:
        segment, window, field = match.groups()
        role = {
            "y/num": "y",
            "precomp/and result": "precomp",
        }.get(field)
        if role is not None:
            return f"pedersen:window:{segment}:{window}:{role}"
    match = re.fullmatch(
        r"note content hash/addition of segment (\d+), window (\d+)/(.+)",
        annotation,
    )
    if match:
        segment, window, field = match.groups()
        role = {
            "lambda/num": "lambda",
            "xprime/num": "xprime",
            "yprime/num": "yprime",
        }.get(field)
        if role is not None:
            return f"pedersen:addition:{segment}:{window}:{role}"
    match = re.fullmatch(
        r"note content hash/conversion of segment (\d+) into edwards/([uv])/num",
        annotation,
    )
    if match:
        segment, coordinate = match.groups()
        return f"pedersen:conversion:{segment}:{coordinate}"
    match = re.fullmatch(
        r"note content hash/addition of segment (\d+) to accumulator/(.+)",
        annotation,
    )
    if match:
        segment, field = match.groups()
        role = {
            "U/num": "U",
            "A computation/product num": "A",
            "B computation/product num": "B",
            "C/num": "C",
            "u3/num": "u",
            "v3/num": "v",
        }.get(field)
        if role is not None:
            return f"pedersen:segment_addition:{segment}:{role}"

    match = re.fullmatch(
        r"computation of commitment randomness/window table lookup "
        r"(\d+)/(.+)",
        annotation,
    )
    if match:
        window, field = match.groups()
        role = {
            "x/num": "selected_u",
            "y/num": "selected_v",
            "precomp/and result": "lookup_bc",
        }.get(field)
        if role is not None:
            return f"fixed:rcm:lookup:{window}:{role}"
    match = re.fullmatch(
        r"computation of commitment randomness/addition (\d+)/(.+)",
        annotation,
    )
    if match:
        window, field = match.groups()
        role = {
            "U/num": "addition_U",
            "A computation/product num": "addition_A",
            "B computation/product num": "addition_B",
            "C/num": "addition_C",
            "u3/num": "accumulator_u",
            "v3/num": "accumulator_v",
        }.get(field)
        if role is not None:
            return f"fixed:rcm:addition:{window}:{role}"

    match = re.fullmatch(r"randomization of note commitment/(.+)", annotation)
    if match:
        field = match.group(1)
        role = {
            "U/num": "addition_U",
            "A computation/product num": "addition_A",
            "B computation/product num": "addition_B",
            "C/num": "addition_C",
            "u3/num": "result_u",
            "v3/num": "result_v",
        }.get(field)
        if role is not None:
            return f"note_randomization:{role}"

    raise CorrespondenceError(
        f"unrecognized upstream variable annotation at Aux({index}): "
        f"{annotation!r}"
    )


def _local_key(name: str, index: int) -> str:
    prefix = "Sapling Output "
    if name == "ONE":
        return "input:ONE"
    if name.startswith(prefix + "public input["):
        public_index = int(name[len(prefix + "public input[") : -1])
        return f"input:{('cv.u', 'cv.v', 'epk.u', 'epk.v', 'cmu.u')[public_index]}"
    name = name.removeprefix(prefix)

    match = re.fullmatch(r"(value|rcv|esk|rcm) bit\[(\d+)\]", name)
    if match:
        component, bit = match.groups()
        return f"scalar:{component}:{bit}"
    match = re.fullmatch(r"pk_d representation\.v bit\[(\d+)\]", name)
    if match:
        bit = int(match.group(1))
        return f"repr:pk_d:{'u' if bit == 255 else f'v:{bit}'}"

    match = re.fullmatch(r"note commitment g_d representation ([uv]) bit\[(\d+)\]", name)
    if match:
        coordinate, bit = match.groups()
        return f"repr:g_d:{coordinate}:bit:{bit}"
    match = re.fullmatch(
        r"note commitment g_d representation ([uv]) bit prefix AND\[(\d+):(\d+)\]",
        name,
    )
    if match:
        coordinate, ending, step = match.groups()
        return f"repr:g_d:{coordinate}:and:{ending}:{step}"

    match = re.fullmatch(r"g_d\.([uv])", name)
    if match:
        return f"g_d:coordinate:{match.group(1)}"
    match = re.fullmatch(r"ephemeral key g_d curve ([uv]) squared", name)
    if match:
        return f"g_d:curve:{match.group(1)}_squared"
    if name == "ephemeral key g_d curve coordinate product":
        return "g_d:curve:coordinate_product"
    match = re.fullmatch(r"ephemeral key g_d double\[(\d+)\]\.([uv])", name)
    if match:
        index, coordinate = match.groups()
        return f"g_d:small_order:{int(index)}:{coordinate}"
    match = re.fullmatch(r"ephemeral key g_d doubling\[(\d+)\] ([TAC])", name)
    if match:
        index, role = match.groups()
        return f"g_d:small_order:{int(index)}:{role}"
    if name == "ephemeral key g_d u inverse":
        return "g_d:u_inverse"

    match = re.fullmatch(
        r"value commitment (value|randomness) multiplication selected\[(\d+)\]\.([uv])",
        name,
    )
    if match:
        which, window, coordinate = match.groups()
        component = "value" if which == "value" else "rcv"
        return f"fixed:{component}:lookup:{window}:selected_{coordinate}"
    match = re.fullmatch(
        r"value commitment (value|randomness) multiplication lookup\[(\d+)\] bc",
        name,
    )
    if match:
        which, window = match.groups()
        component = "value" if which == "value" else "rcv"
        return f"fixed:{component}:lookup:{window}:lookup_bc"
    match = re.fullmatch(
        r"value commitment (value|randomness) multiplication accumulator\[(\d+)\]\.([uv])",
        name,
    )
    if match:
        which, window, coordinate = match.groups()
        component = "value" if which == "value" else "rcv"
        return f"fixed:{component}:addition:{window}:accumulator_{coordinate}"
    match = re.fullmatch(
        r"value commitment (value|randomness) multiplication addition\[(\d+)\] ([UABC])",
        name,
    )
    if match:
        which, window, role = match.groups()
        component = "value" if which == "value" else "rcv"
        return f"fixed:{component}:addition:{window}:addition_{role}"
    match = re.fullmatch(r"value commitment result\.([uv])", name)
    if match:
        return f"value_commitment:final:result_{match.group(1)}"
    match = re.fullmatch(r"value commitment addition ([UABC])", name)
    if match:
        return f"value_commitment:final:addition_{match.group(1)}"

    match = re.fullmatch(r"ephemeral key multiplication selected\[(\d+)\]\.([uv])", name)
    if match:
        index, coordinate = match.groups()
        return f"epk:selection:{index}:{coordinate}"
    match = re.fullmatch(r"ephemeral key multiplication base\[(\d+)\]\.([uv])", name)
    if match:
        index, coordinate = match.groups()
        return f"epk:doubling:{index}:{coordinate}"
    match = re.fullmatch(r"ephemeral key multiplication base doubling\[(\d+)\] ([TAC])", name)
    if match:
        index, role = match.groups()
        return f"epk:doubling:{index}:{role}"
    match = re.fullmatch(r"ephemeral key multiplication accumulator\[(\d+)\]\.([uv])", name)
    if match:
        index, coordinate = match.groups()
        return f"epk:addition:{index}:{coordinate}"
    match = re.fullmatch(r"ephemeral key multiplication accumulation\[(\d+)\] ([UABC])", name)
    if match:
        index, role = match.groups()
        return f"epk:addition:{index}:{role}"

    match = re.fullmatch(
        r"note commitment content hash segment\[(\d+)\] window\[(\d+)\] (y|precomp)",
        name,
    )
    if match:
        segment, window, role = match.groups()
        return f"pedersen:window:{segment}:{window}:{role}"
    match = re.fullmatch(
        r"note commitment content hash segment\[(\d+)\] addition\[(\d+)\] "
        r"(lambda|xprime|yprime)",
        name,
    )
    if match:
        segment, window, role = match.groups()
        return f"pedersen:addition:{segment}:{window}:{role}"
    match = re.fullmatch(
        r"note commitment content hash segment\[(\d+)\] conversion ([uv])",
        name,
    )
    if match:
        segment, coordinate = match.groups()
        return f"pedersen:conversion:{segment}:{coordinate}"
    match = re.fullmatch(
        r"note commitment content hash segment\[(\d+)\] combination ([UABC]|u3|v3)",
        name,
    )
    if match:
        segment, role = match.groups()
        role = {"u3": "u", "v3": "v"}.get(role, role)
        return f"pedersen:segment_addition:{segment}:{role}"

    match = re.fullmatch(
        r"note commitment randomness multiplication selected\[(\d+)\]\.([uv])",
        name,
    )
    if match:
        window, coordinate = match.groups()
        return f"fixed:rcm:lookup:{window}:selected_{coordinate}"
    match = re.fullmatch(
        r"note commitment randomness multiplication lookup\[(\d+)\] bc", name
    )
    if match:
        return f"fixed:rcm:lookup:{match.group(1)}:lookup_bc"
    match = re.fullmatch(
        r"note commitment randomness multiplication accumulator\[(\d+)\]\.([uv])",
        name,
    )
    if match:
        window, coordinate = match.groups()
        return f"fixed:rcm:addition:{window}:accumulator_{coordinate}"
    match = re.fullmatch(
        r"note commitment randomness multiplication addition\[(\d+)\] ([UABC])",
        name,
    )
    if match:
        window, role = match.groups()
        return f"fixed:rcm:addition:{window}:addition_{role}"
    match = re.fullmatch(r"note commitment randomized point\.([uv])", name)
    if match:
        return f"note_randomization:result_{match.group(1)}"
    match = re.fullmatch(r"note commitment randomization ([UABC])", name)
    if match:
        return f"note_randomization:addition_{match.group(1)}"

    raise CorrespondenceError(
        f"unrecognized local variable at column {index}: {name!r}"
    )


def _assignment_hex(value: int) -> str:
    return value.to_bytes(32, "little").hex()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def build_correspondence(export_path: Path) -> dict[str, Any]:
    export_bytes = export_path.read_bytes()
    export_sha256 = hashlib.sha256(export_bytes).hexdigest()
    if export_sha256 != _UPSTREAM_EXPORT_SHA256:
        raise CorrespondenceError(
            f"pinned export SHA-256 mismatch: {export_sha256}"
        )
    upstream = json.loads(export_bytes)
    fixture = json.loads(_FIXTURE.read_text(encoding="utf-8"))["cases"][0]
    witness = make_sapling_output_witness(
        fixture["value"],
        bytes.fromhex(fixture["diversifier"]),
        Point.from_bytes(
            bytes.fromhex(fixture["transmission_key"]), check_subgroup=True
        ),
        int.from_bytes(bytes.fromhex(fixture["rcv"]), "little"),
        int.from_bytes(bytes.fromhex(fixture["rcm"]), "little"),
        int.from_bytes(bytes.fromhex(fixture["esk"]), "little"),
    )
    local = R1CS()
    constrain_sapling_output(local, witness)

    upstream_vars = [
        {
            "identity": item["identity"],
            "annotation": item["annotation"],
            "assignment_hex": item["assignment_hex"],
            "semantic_key": _upstream_key(item["annotation"], index),
        }
        for index, item in enumerate(upstream["inputs"] + upstream["auxiliary_variables"])
    ]
    local_vars = [
        {
            "identity": (
                "Input(0)"
                if index == 0
                else f"Input({index})"
                if variable.kind == "public"
                else f"Aux({index - 6})"
            ),
            "column": index,
            "name": variable.name,
            "assignment_hex": _assignment_hex(local._values[index]),
            "semantic_key": _local_key(variable.name, index),
        }
        for index, variable in enumerate(local.variables)
    ]

    upstream_by_key: dict[str, dict[str, Any]] = {}
    local_by_key: dict[str, dict[str, Any]] = {}
    for variable in upstream_vars:
        key = variable["semantic_key"]
        if key in upstream_by_key:
            raise CorrespondenceError(f"duplicate upstream semantic key {key!r}")
        upstream_by_key[key] = variable
    for variable in local_vars:
        key = variable["semantic_key"]
        if key in local_by_key:
            raise CorrespondenceError(f"duplicate local semantic key {key!r}")
        local_by_key[key] = variable

    upstream_keys = set(upstream_by_key)
    local_keys = set(local_by_key)
    if upstream_keys != local_keys:
        missing_local = sorted(upstream_keys - local_keys)
        missing_upstream = sorted(local_keys - upstream_keys)
        raise CorrespondenceError(
            f"semantic key mismatch: no local match for {missing_local[:10]!r}; "
            f"no upstream match for {missing_upstream[:10]!r}"
        )

    pairs = []
    assignment_mismatches = []
    for key in sorted(upstream_keys, key=lambda item: upstream_by_key[item]["identity"]):
        upstream_variable = upstream_by_key[key]
        local_variable = local_by_key[key]
        if upstream_variable["assignment_hex"] != local_variable["assignment_hex"]:
            assignment_mismatches.append(
                {
                    "semantic_key": key,
                    "upstream": upstream_variable["assignment_hex"],
                    "local": local_variable["assignment_hex"],
                }
            )
        pairs.append(
            {
                "semantic_key": key,
                "upstream_identity": upstream_variable["identity"],
                "upstream_annotation": upstream_variable["annotation"],
                "upstream_assignment_hex": upstream_variable["assignment_hex"],
                "local_identity": local_variable["identity"],
                "local_column": local_variable["column"],
                "local_name": local_variable["name"],
                "local_assignment_hex": local_variable["assignment_hex"],
            }
        )

    if assignment_mismatches:
        raise CorrespondenceError(
            f"{len(assignment_mismatches)} assignment mismatches; "
            f"first: {assignment_mismatches[0]!r}"
        )
    if len(pairs) != 7827 or len({p["upstream_identity"] for p in pairs}) != 7827:
        raise CorrespondenceError("input/auxiliary mapping is not one-to-one")
    if len({p["local_identity"] for p in pairs}) != 7827:
        raise CorrespondenceError("local mapping is not one-to-one")

    mapping_payload = [
        [p["upstream_identity"], p["local_identity"], p["semantic_key"]]
        for p in pairs
    ]
    assignment_payload = [
        [
            p["upstream_identity"],
            p["upstream_assignment_hex"],
            p["local_identity"],
            p["local_assignment_hex"],
        ]
        for p in pairs
    ]
    artifact: dict[str, Any] = {
        "format": "zycoin-bellman-sapling-output-variable-correspondence-v1",
        "pinned_upstream": {
            "format": upstream["format"],
            "sapling_crypto_revision": upstream["sapling_crypto_revision"],
            "bellman_revision": upstream["bellman_revision"],
            "export_sha256": export_sha256,
        },
        "fixture": "tests/fixtures/sapling_output_reference.json case 0",
        "local_output": {
            "rows": local.constraint_count,
            "columns_including_one": len(local.variables),
            "matrix_fingerprint": local.matrix_fingerprint(),
            "satisfied": local.is_satisfied(),
        },
        "counts": {
            "inputs_including_one": 6,
            "auxiliary_variables": 7821,
            "pairs": len(pairs),
            "unmatched_upstream": 0,
            "unmatched_local": 0,
            "ambiguous_upstream_keys": 0,
            "ambiguous_local_keys": 0,
            "assignment_mismatches": 0,
        },
        "mapping_method": (
            "One-to-one semantic role keys derived independently from each "
            "upstream allocation annotation and local variable name. Keys encode "
            "input identity, scalar/bit position, gadget operation, window or "
            "addition index, coordinate, and intermediate role. Witness "
            "assignments are checked after identity mapping; they are not used "
            "to choose a mapping."
        ),
        "mapping_fingerprint_sha256": hashlib.sha256(
            b"zycoin-bellman-output-variable-mapping-v1\0"
            + _canonical_json(mapping_payload)
        ).hexdigest(),
        "assignment_pairs_fingerprint_sha256": hashlib.sha256(
            b"zycoin-bellman-output-assignment-pairs-v1\0"
            + _canonical_json(assignment_payload)
        ).hexdigest(),
        "pairs": pairs,
    }
    artifact["artifact_sha256"] = hashlib.sha256(
        b"zycoin-bellman-output-correspondence-artifact-v1\0"
        + _canonical_json(artifact)
    ).hexdigest()
    return artifact


def write_correspondence(export_path: Path, output_path: Path) -> str:
    artifact = build_correspondence(export_path)
    output_path.write_bytes(_canonical_json(artifact) + b"\n")
    return hashlib.sha256(output_path.read_bytes()).hexdigest()
