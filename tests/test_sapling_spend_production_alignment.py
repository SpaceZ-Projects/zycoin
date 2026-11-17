from __future__ import annotations

import csv
import hashlib
import os
import unittest
from hashlib import blake2s
from pathlib import Path

import tests.test_sapling_spend_reference_port as reference_tests
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import group_hash
from src.r1cs import R1CS
from src.sapling_gadgets import (
    make_merkle_path_witness,
    make_note_commitment_witness,
    make_sapling_nullifier_multipacking_witness,
    make_sapling_nullifier_rho_witness,
    make_sapling_randomized_authorization_key_witness,
    make_sapling_value_commitment_witness,
    sapling_fixed_base_generator,
)
from src.sapling_spend_circuit import (
    SaplingSpendWitness,
    _prepare_witness,
    constrain_sapling_spend,
)
from src.sapling_spend_reference import generate_pinned_test_witness

_VARIABLE_INDEX_MAP = (
    Path(__file__).parent / "fixtures" / "sapling_spend_variable_index_map.csv"
)
# Index-only projection of the separately reviewed v7 semantic allocation map.
_VARIABLE_INDEX_MAP_SHA256 = (
    "b311df0a7ec3e09ddbe8fb56157fc039dd8c747c96af34b4cdb55fc34c38d2f4"
)
_REFERENCE_MATRIX_FINGERPRINT = (
    "cdb472ea319b5a01e36df62560d6a0dd8bc6121991d815ad21514940c929a127"
)
_LOCAL_MATRIX_FINGERPRINT = (
    "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9"
)


@unittest.skipUnless(
    os.environ.get("SAPLING_SPEND_FULL_REFERENCE_ONLY") == "1",
    "requires complete pinned Bellman Spend traces",
)
class ProductionSpendAlignmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = reference_tests._reference_full_spend_trace()
        if cls.reference["sapling_crypto_revision"] != (
            "88a7946b4a3066787776e11f0a502654167e022d"
        ):
            raise AssertionError("unexpected pinned Sapling source revision")
        if cls.reference["bellman_revision"] != (
            "b726862a4ece8a627e7fea486d77b502a6edbb0b"
        ):
            raise AssertionError("unexpected pinned Bellman source revision")
        encoded_map = _VARIABLE_INDEX_MAP.read_bytes()
        if hashlib.sha256(encoded_map).hexdigest() != _VARIABLE_INDEX_MAP_SHA256:
            raise AssertionError("Spend variable index map fixture digest mismatch")
        cls.variable_index_map = tuple(
            (int(record["local_index"]), int(record["upstream_index"]))
            for record in csv.DictReader(
                encoded_map.decode("ascii").splitlines()
            )
        )
        if len(cls.variable_index_map) != 98_637:
            raise AssertionError("unexpected Spend variable index map size")

    def _production_witness_from_reference(
        self, reference: dict
    ) -> SaplingSpendWitness:
        witness = reference_tests._full_spend_reference_witness(reference)
        diversifier_hex = reference["fixture"].get("diversifier_hex")
        if not isinstance(diversifier_hex, str) or len(diversifier_hex) != 22:
            raise AssertionError("Bellman fixture is missing its 11-byte diversifier")
        diversifier = bytes.fromhex(diversifier_hex)
        diversifier_base = group_hash(b"Zcash_gd", diversifier)
        if diversifier_base is None:
            raise AssertionError("exported diversifier does not map to a Jubjub point")

        nullifier_key = sapling_fixed_base_generator(
            "proof_generation_key"
        ).multiply(witness.nsk)
        ivk_digest = blake2s(
            witness.ak.encode() + nullifier_key.encode(),
            digest_size=32,
            person=b"Zcashivk",
        ).digest()
        ivk = int.from_bytes(ivk_digest, "little") & ((1 << 251) - 1)
        transmission_key = diversifier_base.multiply(ivk)
        randomized_key = make_sapling_randomized_authorization_key_witness(
            witness.ak, witness.ar
        ).randomized_key
        value_commitment = make_sapling_value_commitment_witness(
            witness.value, witness.rcv
        ).commitment
        note_commitment = make_note_commitment_witness(
            witness.value,
            diversifier_base,
            transmission_key,
            witness.rcm,
        ).commitment

        position = sum(
            int(direction) << level
            for level, (_, direction) in enumerate(witness.authentication_path)
        )
        siblings = tuple(sibling for sibling, _ in witness.authentication_path)
        merkle_path = make_merkle_path_witness(
            note_commitment.u, siblings, position
        )
        rho = make_sapling_nullifier_rho_witness(
            note_commitment, position
        ).rho
        nullifier = blake2s(
            nullifier_key.encode() + rho.encode(),
            digest_size=32,
            person=b"Zcash_nf",
        ).digest()
        packing = make_sapling_nullifier_multipacking_witness(nullifier)
        public_inputs = (
            randomized_key.u,
            randomized_key.v,
            value_commitment.u,
            value_commitment.v,
            witness.anchor,
            *packing.packed_values,
        )
        trace_public_inputs = tuple(
            reference_tests._full_spend_trace_assignment(record)
            for record in reference["inputs"][1:]
        )
        self.assertEqual(public_inputs, trace_public_inputs)
        self.assertEqual(merkle_path.pedersen_hashes[-1].result.u, witness.anchor)

        return SaplingSpendWitness(
            value=witness.value,
            rcv=witness.rcv,
            ak=witness.ak,
            nsk=witness.nsk,
            nk=nullifier_key,
            ivk=ivk,
            diversifier=diversifier,
            diversifier_base=diversifier_base,
            transmission_key=transmission_key,
            rcm=witness.rcm,
            note_commitment=note_commitment,
            ar=witness.ar,
            randomized_key=randomized_key,
            value_commitment=value_commitment,
            authentication_path=witness.authentication_path,
            position=position,
            anchor=witness.anchor,
            nullifier=nullifier,
            public_inputs=public_inputs,
        )

    def _audit_assignment(
        self,
        system: R1CS,
        reference: dict,
        witness: SaplingSpendWitness,
        *,
        verify_live_assignments: bool = False,
    ) -> dict:
        source_variables = reference["inputs"] + reference["auxiliary_variables"]
        self.assertTrue(reference["satisfied"])
        self.assertEqual(len(system.variables), 98_646)
        self.assertEqual(len(system.constraints), 98_777)
        self.assertEqual(system.public_input_count, 7)
        self.assertEqual(len(reference["inputs"]), 8)
        self.assertEqual(reference["num_auxiliary_variables"], 98_638)
        self.assertEqual(len(source_variables), 98_646)
        self.assertEqual(len(reference["constraints"]), 98_777)
        self.assertEqual(
            reference["observed_test_constraint_system_hash"],
            "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89",
        )

        mapped = self.variable_index_map
        local_indices = {local_index for local_index, _ in mapped}
        upstream_indices = {upstream_index for _, upstream_index in mapped}
        self.assertEqual(len(local_indices), len(mapped))
        self.assertEqual(len(upstream_indices), len(mapped))
        self.assertTrue(all(8 <= index < 98_646 for index in local_indices))
        self.assertTrue(all(8 <= index < 98_646 for index in upstream_indices))
        values: list[int | None] = [None] * len(system.variables)
        values[0] = 1
        for column, source_record in enumerate(reference["inputs"][1:], start=1):
            values[column] = reference_tests._full_spend_trace_assignment(
                source_record
            )
        for local_index, upstream_index in mapped:
            values[local_index] = reference_tests._full_spend_trace_assignment(
                source_variables[upstream_index]
            )
        unmatched_local_indices = set(range(8, len(system.variables))) - local_indices
        unmatched_upstream_indices = (
            set(range(8, len(source_variables))) - upstream_indices
        )
        self.assertEqual(len(unmatched_local_indices), 1)
        self.assertEqual(len(unmatched_upstream_indices), 1)
        unmatched_local_index = next(iter(unmatched_local_indices))
        unmatched_upstream_index = next(iter(unmatched_upstream_indices))
        self.assertEqual(
            system.variables[unmatched_local_index].name,
            "Sapling Spend Merkle path position",
        )
        self.assertEqual(
            source_variables[unmatched_upstream_index]["annotation"],
            "conditional anchor/num",
        )
        self.assertEqual(
            reference_tests._full_spend_trace_assignment(
                source_variables[unmatched_upstream_index]
            ),
            witness.anchor,
        )
        values[unmatched_local_index] = witness.position
        self.assertTrue(all(value is not None for value in values))
        assignment = [int(value) for value in values if value is not None]
        if verify_live_assignments:
            self.assertEqual(
                [
                    system.witness_value(variable)
                    for variable in system.variables
                ],
                assignment,
            )

        local_order = sorted(mapped)
        upstream_order = sorted(mapped, key=lambda pair: pair[1])
        upstream_rank = {
            pair: rank for rank, pair in enumerate(upstream_order)
        }
        order_displacements = sum(
            upstream_rank[pair] != rank
            for rank, pair in enumerate(local_order)
        )
        column_mismatches = sum(
            local_index != upstream_index
            for local_index, upstream_index in mapped
        )
        exact_annotation_matches = sum(
            system.variables[local_index].name
            == source_variables[upstream_index]["annotation"]
            for local_index, upstream_index in mapped
        )
        unmatched_local = [
            {
                "index": unmatched_local_index,
                "name": system.variables[unmatched_local_index].name,
                "assigned_position": witness.position,
            }
        ]
        unmatched_upstream = [
            {
                "index": unmatched_upstream_index,
                "annotation": source_variables[unmatched_upstream_index][
                    "annotation"
                ],
                "assignment": witness.anchor,
            }
        ]
        rows_satisfied = self._rows_satisfied(system, assignment)
        self.assertEqual(rows_satisfied, len(system.constraints))
        self.assertEqual(
            tuple(assignment[1:8]),
            tuple(
                reference_tests._full_spend_trace_assignment(record)
                for record in reference["inputs"][1:]
            ),
        )
        summary = {
            "fixture": reference["fixture"]["name"],
            "production_fingerprint": _LOCAL_MATRIX_FINGERPRINT,
            "reference_fingerprint": _REFERENCE_MATRIX_FINGERPRINT,
            "mapped_public_variables": 8,
            "mapped_auxiliary_variables": len(mapped),
            "unmatched_local": unmatched_local,
            "unmatched_upstream": unmatched_upstream,
            "auxiliary_order_displaced_variables": order_displacements,
            "mapped_column_index_mismatches": column_mismatches,
            "exact_allocation_annotation_matches": exact_annotation_matches,
            "production_rows_satisfied": rows_satisfied,
        }
        print(summary)
        return summary

    @staticmethod
    def _rows_satisfied(system: R1CS, values: list[int]) -> int:
        def evaluate(terms: tuple[tuple[int, int], ...]) -> int:
            return sum(
                coefficient * values[index] for index, coefficient in terms
            ) % SCALAR_MODULUS

        return sum(
            evaluate(row.left.terms) * evaluate(row.right.terms) % SCALAR_MODULUS
            == evaluate(row.output.terms)
            for row in system.constraints
        )

    def test_production_assignments_and_matrices_match_audit_baseline(self) -> None:
        baseline_reference = self.reference
        baseline_generated = generate_pinned_test_witness(0)
        baseline_witness = SaplingSpendWitness(
            value=baseline_generated.value,
            rcv=baseline_generated.rcv,
            ak=baseline_generated.ak,
            nsk=baseline_generated.nsk,
            nk=baseline_generated.nk,
            ivk=baseline_generated.ivk,
            diversifier=baseline_generated.diversifier,
            diversifier_base=baseline_generated.diversifier_base,
            transmission_key=baseline_generated.transmission_key,
            rcm=baseline_generated.rcm,
            note_commitment=baseline_generated.note_commitment,
            ar=baseline_generated.ar,
            randomized_key=baseline_generated.randomized_key,
            value_commitment=baseline_generated.value_commitment,
            authentication_path=baseline_generated.authentication_path,
            position=baseline_generated.position,
            anchor=baseline_generated.anchor,
            nullifier=baseline_generated.nullifier,
            public_inputs=baseline_generated.public_inputs,
        )
        baseline_source = reference_tests._full_spend_reference_witness(
            baseline_reference
        )
        self.assertEqual(baseline_witness.ak, baseline_source.ak)
        self.assertEqual(baseline_witness.nsk, baseline_source.nsk)
        self.assertEqual(baseline_witness.diversifier_base, baseline_source.g_d)
        self.assertEqual(baseline_witness.authentication_path, baseline_source.authentication_path)
        self.assertEqual(baseline_witness.anchor, baseline_source.anchor)

        system = R1CS()
        constrain_sapling_spend(system, baseline_witness)
        self.assertTrue(system.is_satisfied())
        self.assertEqual(system.matrix_fingerprint(), _LOCAL_MATRIX_FINGERPRINT)
        self._audit_assignment(
            system,
            baseline_reference,
            baseline_witness,
            verify_live_assignments=True,
        )

        for variant in ("zero-value-alternating", "max-value-all-right"):
            reference, _ = reference_tests._reference_full_spend_variant_trace(variant)
            witness = self._production_witness_from_reference(reference)
            _prepare_witness(witness)
            self._audit_assignment(system, reference, witness)


if __name__ == "__main__":
    unittest.main()
