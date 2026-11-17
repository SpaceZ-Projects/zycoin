from __future__ import annotations

import hashlib
import json
import os
import unittest
from dataclasses import dataclass
from pathlib import Path

from src.bls12_381 import SCALAR_MODULUS
from src.groth16_qap import QAP
from src.r1cs import (
    _MATRIX_FINGERPRINT_DOMAIN,
    _MATRIX_SERIALIZATION_FORMAT,
    LinearCombination,
    R1CSError,
    Variable,
)
from tests.sapling_spend_reference_port import (
    SpendReferenceR1CS,
)
from tests.sapling_spend_temporal_mapping import (
    SPEND_PUBLIC_INPUT_ANNOTATIONS,
    SpendTemporalCanonicalization,
    canonicalize_spend_reference_r1cs,
)

_REFERENCE_MATRIX_FINGERPRINT = (
    "cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127"
)
_REFERENCE_TRACE_FORMAT = "bellman-sapling-spend-reference-v1"
_REFERENCE_TRACE_HASH = (
    "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89"
)
_SPEND_PUBLIC_INPUT_EVENT_INDICES = (
    1030,
    1031,
    29078,
    29079,
    76811,
    98644,
    98645,
)


class _JsonStreamReader:
    def __init__(self, path: Path) -> None:
        self._file = path.open("r", encoding="utf-8")
        self._decoder = json.JSONDecoder()
        self._buffer = ""
        self._position = 0
        self._eof = False

    def close(self) -> None:
        self._file.close()

    def _fill(self) -> bool:
        self._buffer = self._buffer[self._position :]
        self._position = 0
        chunk = self._file.read(1 << 20)
        if not chunk:
            self._eof = True
            return False
        self._buffer += chunk
        return True

    def _skip_space(self) -> None:
        while True:
            while (
                self._position < len(self._buffer)
                and self._buffer[self._position].isspace()
            ):
                self._position += 1
            if self._position < len(self._buffer) or self._eof:
                return
            self._fill()

    def _peek(self) -> str:
        self._skip_space()
        if self._position >= len(self._buffer):
            raise ValueError("unexpected end of retained Spend trace")
        return self._buffer[self._position]

    def _consume(self, expected: str) -> None:
        actual = self._peek()
        if actual != expected:
            raise ValueError(f"expected {expected!r}, found {actual!r}")
        self._position += 1

    def _read_value(self) -> object:
        self._skip_space()
        while True:
            try:
                value, end = self._decoder.raw_decode(
                    self._buffer, self._position
                )
            except json.JSONDecodeError:
                if not self._fill():
                    raise
                continue
            if end == len(self._buffer) and not self._eof:
                self._fill()
                continue
            self._position = end
            return value

    def _read_array(self):
        self._consume("[")
        if self._peek() == "]":
            self._consume("]")
            return
        while True:
            yield self._read_value()
            separator = self._peek()
            if separator == "]":
                self._consume("]")
                return
            self._consume(",")


def _trace_assignment(record: dict) -> int:
    encoded = record.get("assignment_hex")
    if not isinstance(encoded, str):
        raise TypeError(
            f"trace assignment missing for {record.get('identity')!r}"
        )
    return int.from_bytes(bytes.fromhex(encoded), "little")


def _canonical_column_for_identity(identity: str) -> int:
    if identity.startswith("Input(") and identity.endswith(")"):
        return int(identity[6:-1])
    if identity.startswith("Aux(") and identity.endswith(")"):
        return 8 + int(identity[4:-1])
    raise AssertionError(f"unexpected variable identity {identity!r}")


def _new_reference_matrix_hash(
    public_input_count: int, auxiliary_count: int
) -> tuple[hashlib._Hash, bytes]:
    variable_count = 1 + public_input_count + auxiliary_count
    header = (
        f'{{"auxiliary_variable_count":{auxiliary_count},'
        f'"column_count":{variable_count},"constraints":['
    )
    kinds = ["one"] + ["public"] * public_input_count
    kinds.extend(["private"] * auxiliary_count)
    suffix = (
        '],"field_modulus":'
        + json.dumps(str(SCALAR_MODULUS))
        + ',"format":'
        + json.dumps(_MATRIX_SERIALIZATION_FORMAT)
        + ',"one_column":0,"public_input_count":'
        + str(public_input_count)
        + ',"variable_kinds":'
        + json.dumps(kinds, separators=(",", ":"), ensure_ascii=True)
        + "}"
    ).encode("ascii")
    digest = hashlib.sha256(_MATRIX_FINGERPRINT_DOMAIN)
    digest.update(header.encode("ascii"))
    return digest, suffix


def _canonical_reference_terms(terms: list[dict]) -> list[list[str | int]]:
    combined: dict[int, int] = {}
    for term in terms:
        column = _canonical_column_for_identity(term["identity"])
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        combined[column] = (
            combined.get(column, 0) + coefficient
        ) % SCALAR_MODULUS
    return [
        [column, str(coefficient)]
        for column, coefficient in sorted(combined.items())
        if coefficient
    ]


def _source_expression(
    system: SpendReferenceR1CS, terms: list[dict], variables: dict[str, Variable]
):
    constant = 0
    variable_terms = []
    for term in terms:
        variable = variables[term["identity"]]
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        if variable.index == 0:
            constant += coefficient
        else:
            variable_terms.append((variable, coefficient))
    return system.linear_combination(variable_terms, constant)


def _load_retained_trace(
    path: Path,
) -> tuple[dict, SpendTemporalCanonicalization, dict[str, Variable], str]:
    metadata: dict = {}
    public_records: list[dict] = []
    auxiliary_records: list[dict] = []
    variables: dict[str, Variable] = {}
    system = SpendReferenceR1CS()
    variables["Input(0)"] = system.one
    reference_hash: hashlib._Hash | None = None
    reference_suffix = b""
    row_count = 0
    mapping: SpendTemporalCanonicalization | None = None

    reader = _JsonStreamReader(path)
    try:
        reader._consume("{")
        while True:
            if reader._peek() == "}":
                reader._consume("}")
                break
            key = reader._read_value()
            if not isinstance(key, str):
                raise TypeError("retained trace object has a non-string key")
            reader._consume(":")
            if key in ("inputs", "auxiliary_variables"):
                for raw_record in reader._read_array():
                    if not isinstance(raw_record, dict):
                        raise TypeError(f"{key} contains a non-object record")
                    identity = raw_record["identity"]
                    if key == "inputs":
                        public_records.append(
                            {
                                "identity": identity,
                                "annotation": raw_record["annotation"],
                                "assignment_hex": raw_record["assignment_hex"],
                            }
                        )
                        if identity == "Input(0)" and (
                            raw_record["annotation"] != "ONE"
                            or _trace_assignment(raw_record) != 1
                        ):
                            raise AssertionError("retained ONE allocation is invalid")
                    else:
                        auxiliary_records.append(
                            {
                                "identity": identity,
                                "annotation": raw_record["annotation"],
                                "assignment_hex": raw_record["assignment_hex"],
                            }
                        )
            elif key == "constraints":
                input_count = metadata["num_inputs_including_one"] - 1
                auxiliary_count = metadata["num_auxiliary_variables"]
                if (
                    input_count != 7
                    or len(public_records) != input_count + 1
                    or len(auxiliary_records) != auxiliary_count
                    or tuple(
                        record["annotation"] for record in public_records[1:]
                    )
                    != SPEND_PUBLIC_INPUT_ANNOTATIONS
                    or tuple(
                        record["identity"] for record in public_records
                    )
                    != tuple(f"Input({index})" for index in range(input_count + 1))
                ):
                    raise AssertionError("retained allocation counts/order are invalid")

                public_by_event = dict(
                    zip(
                        _SPEND_PUBLIC_INPUT_EVENT_INDICES,
                        public_records[1:],
                        strict=True,
                    )
                )
                auxiliary_index = 0
                variable_count = 1 + input_count + auxiliary_count
                for event_index in range(1, variable_count):
                    public_record = public_by_event.get(event_index)
                    if public_record is not None:
                        identity = public_record["identity"]
                        variable = system.alloc_public(
                            public_record["annotation"],
                            _trace_assignment(public_record),
                        )
                    else:
                        auxiliary_record = auxiliary_records[auxiliary_index]
                        identity = f"Aux({auxiliary_index})"
                        if auxiliary_record["identity"] != identity:
                            raise AssertionError("retained auxiliary order is invalid")
                        variable = system.alloc_private(
                            auxiliary_record["annotation"],
                            _trace_assignment(auxiliary_record),
                        )
                        auxiliary_index += 1
                    if identity in variables:
                        raise AssertionError(f"duplicate allocation identity {identity}")
                    variables[identity] = variable

                if (
                    len(variables) != variable_count
                    or auxiliary_index != auxiliary_count
                    or tuple(
                        variable.name
                        for variable in system._temporal_public_variables
                    )
                    != SPEND_PUBLIC_INPUT_ANNOTATIONS
                ):
                    raise AssertionError("retained allocation counts/order are invalid")
                mapping = canonicalize_spend_reference_r1cs(system)
                reference_hash, reference_suffix = _new_reference_matrix_hash(
                    input_count, auxiliary_count
                )
                for expected_index, raw_row in enumerate(reader._read_array()):
                    if not isinstance(raw_row, dict) or raw_row["index"] != expected_index:
                        raise AssertionError("constraint row order is invalid")
                    if not isinstance(raw_row.get("annotation"), str):
                        raise TypeError("constraint row label is missing")
                    sides = []
                    for side in ("a", "b", "c"):
                        source_expression = _source_expression(
                            system, raw_row[side], variables
                        )
                        canonical_expression = mapping.remap_linear_combination(
                            source_expression
                        )
                        canonical_terms = [
                            [index, str(coefficient)]
                            for index, coefficient in canonical_expression.terms
                        ]
                        if canonical_terms != _canonical_reference_terms(
                            raw_row[side]
                        ):
                            raise AssertionError(
                                f"{side.upper()} remapping differs at row "
                                f"{expected_index}"
                            )
                        sides.append(canonical_terms)
                    if expected_index:
                        reference_hash.update(b",")
                    reference_hash.update(
                        json.dumps(
                            sides, separators=(",", ":"), ensure_ascii=True
                        ).encode("ascii")
                    )
                    row_count += 1
            else:
                metadata[key] = reader._read_value()
            separator = reader._peek()
            if separator == "}":
                reader._consume("}")
                break
            reader._consume(",")
    finally:
        reader.close()

    if reference_hash is None:
        raise AssertionError("retained trace has no constraints")
    if mapping is None:
        raise AssertionError("retained trace has no allocation mapping")
    reference_hash.update(reference_suffix)
    if row_count != metadata.get("num_constraints"):
        raise AssertionError("retained constraint count is invalid")
    metadata["inputs"] = public_records
    return metadata, mapping, variables, reference_hash.hexdigest()


def _temporal_system(
    public_names: tuple[str, ...] = SPEND_PUBLIC_INPUT_ANNOTATIONS,
) -> tuple[SpendReferenceR1CS, tuple]:
    system = SpendReferenceR1CS()
    before_public = system.alloc_private("auxiliary before public inputs", 5)
    public_variables = tuple(
        system.alloc_public(name, 10 + index)
        for index, name in enumerate(public_names)
    )
    after_public = system.alloc_private("auxiliary after public inputs", 9)
    system.enforce_equal(before_public.lc() + 1, 6, "pre-public relation")
    system.enforce_equal(public_variables[0].lc() + 1, 11, "public relation")
    system.enforce_equal(after_public, 9, "post-public relation")
    return system, (before_public, *public_variables, after_public)


@dataclass(frozen=True)
class _NestedAssemblyResult:
    variable: Variable
    expression: LinearCombination


@dataclass(frozen=True)
class _AssemblyResult:
    nested: _NestedAssemblyResult
    outputs: tuple[Variable, ...]


class SpendTemporalCanonicalMappingTests(unittest.TestCase):
    def test_remaps_temporal_public_and_auxiliary_variables_and_rows(self) -> None:
        source, handles = _temporal_system()
        source_variables = source.variables
        source_constraints = source.constraints

        mapping = canonicalize_spend_reference_r1cs(source)

        self.assertEqual(
            mapping.source_to_canonical_indices,
            (0, 8, 1, 2, 3, 4, 5, 6, 7, 9),
        )
        self.assertEqual(
            [mapping.canonical_index(variable) for variable in handles],
            [8, 1, 2, 3, 4, 5, 6, 7, 9],
        )
        self.assertEqual(
            [variable.name for variable in mapping.system.variables[1:8]],
            list(SPEND_PUBLIC_INPUT_ANNOTATIONS),
        )
        self.assertEqual(
            [variable.name for variable in mapping.system.variables[8:]],
            ["auxiliary before public inputs", "auxiliary after public inputs"],
        )
        self.assertEqual(source.variables, source_variables)
        self.assertEqual(source.constraints, source_constraints)
        self.assertEqual(source.public_inputs(), mapping.system.public_inputs())
        self.assertTrue(source.is_satisfied())
        self.assertTrue(mapping.system.is_satisfied())
        qap = QAP.from_r1cs(mapping.system)
        self.assertEqual(qap.public_input_count, 7)
        self.assertEqual(qap.auxiliary_variable_count, 2)

        for source_row, canonical_row in zip(
            source.constraints, mapping.system.constraints, strict=True
        ):
            self.assertEqual(source_row.label, canonical_row.label)
            self.assertEqual(
                mapping.remap_linear_combination(source_row.left),
                canonical_row.left,
            )
            self.assertEqual(
                mapping.remap_linear_combination(source_row.right),
                canonical_row.right,
            )
            self.assertEqual(
                mapping.remap_linear_combination(source_row.output),
                canonical_row.output,
            )

    def test_remaps_nested_assembly_result_dataclasses(self) -> None:
        source, handles = _temporal_system()
        mapping = canonicalize_spend_reference_r1cs(source)
        expression = source.linear_combination(
            ((handles[0], 2), (handles[1], 3)), constant=4
        )
        assembly = _AssemblyResult(
            nested=_NestedAssemblyResult(handles[1], expression),
            outputs=(handles[0], handles[-1]),
        )

        remapped = mapping.remap_assembly(assembly)

        self.assertIsNot(remapped, assembly)
        self.assertEqual(remapped.nested.variable, mapping.remap_variable(handles[1]))
        self.assertEqual(
            remapped.nested.expression,
            mapping.remap_linear_combination(expression),
        )
        self.assertEqual(
            remapped.outputs,
            tuple(mapping.remap_variable(variable) for variable in assembly.outputs),
        )

    def test_mapping_is_deterministic_for_repeated_construction(self) -> None:
        first_source, _ = _temporal_system()
        second_source, _ = _temporal_system()

        first = canonicalize_spend_reference_r1cs(first_source)
        second = canonicalize_spend_reference_r1cs(second_source)

        self.assertEqual(
            first.source_to_canonical_indices,
            second.source_to_canonical_indices,
        )
        self.assertEqual(first.system.serialize_matrix(), second.system.serialize_matrix())
        self.assertEqual(
            [
                (variable.index, variable.kind, variable.name)
                for variable in first.system.variables
            ],
            [
                (variable.index, variable.kind, variable.name)
                for variable in second.system.variables
            ],
        )

    def test_rejects_duplicate_and_missing_public_allocations(self) -> None:
        duplicate, _ = _temporal_system()
        duplicate._temporal_public_variables.append(
            duplicate._temporal_public_variables[0]
        )
        missing, _ = _temporal_system()
        missing._temporal_public_variables.pop()

        for malformed in (duplicate, missing):
            with (
                self.subTest(
                    public_count=len(malformed._temporal_public_variables)
                ),
                self.assertRaises(R1CSError),
            ):
                canonicalize_spend_reference_r1cs(malformed)

    def test_rejects_duplicate_handles_and_inconsistent_auxiliary_metadata(self) -> None:
        duplicate, _ = _temporal_system()
        duplicate._variables[2] = duplicate._variables[1]
        inconsistent, handles = _temporal_system()
        del inconsistent._auxiliary_indices_by_variable_index[handles[0].index]

        for malformed in (duplicate, inconsistent):
            with self.assertRaises(R1CSError):
                canonicalize_spend_reference_r1cs(malformed)

    def test_rejects_incorrect_public_order_and_one_misplacement(self) -> None:
        wrong_order, _ = _temporal_system(
            (SPEND_PUBLIC_INPUT_ANNOTATIONS[1],)
            + (SPEND_PUBLIC_INPUT_ANNOTATIONS[0],)
            + SPEND_PUBLIC_INPUT_ANNOTATIONS[2:]
        )
        misplaced_one, _ = _temporal_system()
        misplaced_one._variables[0], misplaced_one._variables[1] = (
            misplaced_one._variables[1],
            misplaced_one._variables[0],
        )

        for malformed in (wrong_order, misplaced_one):
            with self.assertRaises(R1CSError):
                canonicalize_spend_reference_r1cs(malformed)

    def test_rejects_foreign_or_missing_variable_handles(self) -> None:
        source, _ = _temporal_system()
        mapping = canonicalize_spend_reference_r1cs(source)
        foreign_system = SpendReferenceR1CS()
        foreign = foreign_system.alloc_private("foreign", 1)

        with self.assertRaises(R1CSError):
            mapping.remap_variable(foreign)
        with self.assertRaises(R1CSError):
            mapping.remap_variable(
                Variable(999, "private", "missing", source._owner)
            )

    @unittest.skipUnless(
        os.environ.get("SAPLING_SPEND_CANONICAL_TRACE"),
        "set SAPLING_SPEND_CANONICAL_TRACE to a retained full Bellman trace",
    )
    def test_retained_bellman_trace_preserves_pinned_canonical_matrix(self) -> None:
        trace_path = Path(os.environ["SAPLING_SPEND_CANONICAL_TRACE"])
        metadata, mapping, variables_by_identity, direct_fingerprint = (
            _load_retained_trace(trace_path)
        )
        source = mapping.source
        self.assertEqual(metadata["format"], _REFERENCE_TRACE_FORMAT)
        self.assertEqual(metadata["sapling_crypto_revision"], "88a7946b4a3066787776e11f0a502654167e022d")
        self.assertEqual(metadata["bellman_revision"], "b726862a4ece8a627e7fea486d77b502a6edbb0b")
        self.assertEqual(metadata["upstream_test_asserted_hash"], _REFERENCE_TRACE_HASH)
        self.assertEqual(metadata["observed_test_constraint_system_hash"], _REFERENCE_TRACE_HASH)
        self.assertTrue(metadata["satisfied"])
        self.assertEqual(metadata["num_inputs_including_one"], 8)
        self.assertEqual(metadata["num_auxiliary_variables"], 98_638)
        self.assertEqual(metadata["num_constraints"], 98_777)
        self.assertEqual(len(source.variables), 98_646)
        self.assertEqual(source.public_input_count, 7)
        self.assertEqual(len(mapping.system.variables), 98_646)
        self.assertEqual(mapping.system.public_input_count, 7)
        self.assertEqual(direct_fingerprint, _REFERENCE_MATRIX_FINGERPRINT)

        expected_temporal_indices = (1030, 1031, 29078, 29079, 76811, 98644, 98645)
        public_records = metadata["inputs"][1:]
        self.assertEqual(
            tuple(record["annotation"] for record in public_records),
            SPEND_PUBLIC_INPUT_ANNOTATIONS,
        )
        for position, (record, temporal_index) in enumerate(
            zip(public_records, expected_temporal_indices, strict=True), start=1
        ):
            temporal = variables_by_identity[record["identity"]]
            self.assertEqual(temporal.index, temporal_index)
            self.assertEqual(mapping.canonical_index(temporal), position)
        for identity, source_variable in variables_by_identity.items():
            canonical_variable = mapping.remap_variable(source_variable)
            self.assertEqual(
                mapping.canonical_index(source_variable),
                _canonical_column_for_identity(identity),
            )
            self.assertEqual(
                source.witness_value(source_variable),
                mapping.system.witness_value(canonical_variable),
            )
        self.assertEqual(
            mapping.system.public_inputs(),
            source.public_inputs(),
        )


if __name__ == "__main__":
    unittest.main()
