import hashlib
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from src.blake2s_gadget import _NegatedBit
from src.bls12_381 import (
    G1_GENERATOR,
    G1_INFINITY,
    G2_GENERATOR,
    G2_INFINITY,
    SCALAR_MODULUS,
)
from src.groth16_proof import (
    Groth16ProvingQueries,
    assemble_proof_elements,
)
from src.groth16_qap import QAP, QAPAssignment
from src.groth16_queries import (
    G1Query,
    G2Query,
    ValidatedG1Point,
    ValidatedG2Point,
)
from src.jubjub import IDENTITY, Point, group_hash
from src.r1cs import R1CS, R1CSError, Variable
from src.sapling_spend_circuit import (
    SPEND_PUBLIC_INPUT_ORDER,
    SaplingSpendWitness,
    constrain_sapling_spend,
)
from src.sapling_spend_reference import generate_pinned_test_witness
from tests.bellman_blake2s_reference import (
    _Negated as BellmanNegatedBit,
)
from tests.bellman_blake2s_reference import (
    bellman_bits_to_bytes,
    constrain_bellman_blake2s_reference,
)
from tests.bellman_pedersen_reference import (
    synthesize_pedersen_hash as synthesize_bellman_pedersen_reference,
)
from tests.sapling_spend_independent_reference import (
    generate_pinned_test_witness as generate_independent_witness,
)


def _point(point) -> Point:
    return Point.from_bytes(point.encode(), check_subgroup=True)


def _circuit_witness(reference) -> SaplingSpendWitness:
    value_commitment = getattr(reference, "value_commitment", None)
    if value_commitment is None:
        value_commitment = reference.cv
    return SaplingSpendWitness(
        value=reference.value,
        rcv=reference.rcv,
        ak=_point(reference.ak),
        nsk=reference.nsk,
        nk=_point(reference.nk),
        ivk=reference.ivk,
        diversifier=reference.diversifier,
        diversifier_base=_point(reference.diversifier_base),
        transmission_key=_point(reference.transmission_key),
        rcm=reference.rcm,
        note_commitment=_point(reference.note_commitment),
        ar=reference.ar,
        randomized_key=_point(reference.randomized_key),
        value_commitment=_point(value_commitment),
        authentication_path=reference.authentication_path,
        position=reference.position,
        anchor=reference.anchor,
        nullifier=reference.nullifier,
        public_inputs=reference.public_inputs,
    )


class SaplingSpendCircuitTests(unittest.TestCase):
    def test_spend_witness_builds_and_divides_its_qap_without_parameters(self):
        witness = _circuit_witness(generate_pinned_test_witness(0))
        system = R1CS()
        constrain_sapling_spend(system, witness)

        qap = QAP.from_r1cs(system)
        auxiliary_values = []
        for variable in system.variables[system.public_input_count + 1 :]:
            value = system._witness_value(variable)
            if value is None:
                raise AssertionError("Spend fixture contains an unassigned variable")
            auxiliary_values.append(value)
        assignment = QAPAssignment(
            system.public_inputs(),
            auxiliary_values,
        )
        self.assertEqual(system.constraint_count, 98_777)
        self.assertEqual(qap.domain.row_count, 98_785)
        self.assertEqual(qap.domain.size, 131_072)

        # Identity query points exercise full Spend-sized lengths without
        # loading CRS material or performing expensive secret-bearing MSMs.
        g1_identity = ValidatedG1Point(G1_INFINITY)
        g2_identity = ValidatedG2Point(G2_INFINITY)
        queries = Groth16ProvingQueries(
            g1_identity,
            g1_identity,
            g2_identity,
            ValidatedG1Point(G1_GENERATOR),
            ValidatedG2Point(G2_GENERATOR),
            G1Query((g1_identity,) * qap.variable_count),
            G1Query((g1_identity,) * qap.variable_count),
            G2Query((g2_identity,) * qap.variable_count),
            G1Query((g1_identity,) * qap.auxiliary_variable_count),
            G1Query((g1_identity,) * (qap.domain.size - 1)),
        )
        proof_elements = assemble_proof_elements(qap, assignment, queries, 0, 0)
        self.assertEqual(proof_elements.a, G1_INFINITY)
        self.assertEqual(proof_elements.b, G2_INFINITY)
        self.assertEqual(proof_elements.c, G1_INFINITY)

    def test_seeded_independent_witness_satisfies_complete_spend_r1cs(self):
        independent = generate_independent_witness(0)
        source_reference = generate_pinned_test_witness(0)
        self.assertEqual(independent.as_dict(), source_reference.as_dict())

        witness = _circuit_witness(independent)
        system = R1CS()
        assembly = constrain_sapling_spend(system, witness)

        self.assertEqual(
            tuple(variable.name for variable in assembly.public_inputs),
            tuple(
                f"Sapling Spend public {name}"
                for name in SPEND_PUBLIC_INPUT_ORDER
            ),
        )
        self.assertEqual(system.public_input_count, 7)
        self.assertEqual(system.public_inputs(), witness.public_inputs)
        self.assertEqual(system.variables[0].kind, "one")
        upstream_input_names = (
            "ONE",
            "rk.u",
            "rk.v",
            "cv.u",
            "cv.v",
            "anchor",
            "nullifier_chunk_0",
            "nullifier_chunk_1",
        )
        upstream_input_mapping = tuple(
            (variable.index, ("Input", variable.index), upstream_name)
            for variable, upstream_name in zip(
                system.variables[:8], upstream_input_names
            )
        )
        self.assertEqual(
            upstream_input_mapping,
            tuple(
                (index, ("Input", index), name)
                for index, name in enumerate(upstream_input_names)
            ),
        )
        self.assertEqual(
            tuple(variable.name.removeprefix("Sapling Spend public ")
                  if variable.kind == "public" else variable.name
                  for variable in system.variables[:8]),
            upstream_input_names,
        )
        self.assertEqual(
            tuple((variable.index, variable.kind) for variable in system.variables[:8]),
            ((0, "one"),) + tuple((index, "public") for index in range(1, 8)),
        )
        self.assertEqual(
            len(system.variables) - 1 - system.public_input_count, 98_638
        )
        variable_manifest = [
            (variable.kind, variable.name) for variable in system.variables
        ]
        self.assertEqual(
            hashlib.sha256(
                json.dumps(variable_manifest, separators=(",", ":")).encode()
            ).hexdigest(),
            "cc8289461de9acb811ff5ceacb239d035e00483d7c5d6227b7887e0cbc5f2be7",
        )
        allocation_ranges = (
            ("Sapling Spend ak.", 2, 8, 9),
            ("Sapling Spend ar bit[", 252, 10, 261),
            ("Sapling Spend randomized authorization key", 775, 262, 1036),
            ("Sapling Spend nsk bit[", 252, 1037, 1288),
            ("Sapling Spend nk multiplication", 750, 1289, 2038),
            ("Sapling Spend ak representation", 774, 2039, 2812),
            ("Sapling Spend nk representation", 774, 2813, 3586),
            ("Sapling Spend ivk", 20_960, 3587, 24546),
            ("Sapling Spend g_d", 21, 24547, 24567),
            ("Sapling Spend pk_d multiplication", 3252, 24568, 27819),
            ("Sapling Spend pk_d representation", 774, 27820, 28593),
            ("Sapling Spend value bit[", 64, 28594, 28657),
            ("Sapling Spend rcv bit[", 252, 28658, 28909),
            ("Sapling Spend value commitment", 947, 28910, 29856),
            ("Sapling Spend rcm bit[", 252, 29857, 30108),
            ("Sapling Spend note commitment", 2512, 30109, 32620),
            ("Sapling Spend Merkle path", 44_193, 32621, 76813),
            ("Sapling Spend rho", 872, 76814, 77685),
            ("Sapling Spend nullifier PRF", 20_960, 77686, 98645),
        )
        allocated_indices = []
        for prefix, expected_count, expected_first, expected_last in (
            allocation_ranges
        ):
            variables = tuple(
                variable
                for variable in system.variables
                if variable.index > system.public_input_count
                and variable.name.startswith(prefix)
            )
            with self.subTest(allocation=prefix):
                self.assertEqual(len(variables), expected_count)
                self.assertEqual(
                    (variables[0].index, variables[-1].index),
                    (expected_first, expected_last),
                )
                self.assertEqual(
                    tuple(variable.index for variable in variables),
                    tuple(range(expected_first, expected_last + 1)),
                )
            allocated_indices.extend(variable.index for variable in variables)
        self.assertEqual(
            tuple(sorted(allocated_indices)),
            tuple(range(system.public_input_count + 1, len(system.variables))),
        )
        self.assertEqual(
            tuple(
                (variable.index, variable.name)
                for variable in system.variables
                if variable.name
                in (
                    "Sapling Spend ak.u",
                    "Sapling Spend ak.v",
                    "Sapling Spend ar bit[0]",
                    "Sapling Spend ar bit[251]",
                    "Sapling Spend nsk bit[0]",
                    "Sapling Spend nsk bit[251]",
                    "Sapling Spend value bit[0]",
                    "Sapling Spend rcv bit[0]",
                    "Sapling Spend rcm bit[0]",
                    "Sapling Spend Merkle path position",
                    "Sapling Spend Merkle path position bit[0]",
                )
            ),
            (
                (8, "Sapling Spend ak.u"),
                (9, "Sapling Spend ak.v"),
                (10, "Sapling Spend ar bit[0]"),
                (261, "Sapling Spend ar bit[251]"),
                (1037, "Sapling Spend nsk bit[0]"),
                (1288, "Sapling Spend nsk bit[251]"),
                (28594, "Sapling Spend value bit[0]"),
                (28658, "Sapling Spend rcv bit[0]"),
                (29857, "Sapling Spend rcm bit[0]"),
                (32621, "Sapling Spend Merkle path position"),
                (32622, "Sapling Spend Merkle path position bit[0]"),
            ),
        )
        position_variable = next(
            variable
            for variable in system.variables
            if variable.name == "Sapling Spend Merkle path position"
        )
        position_reconstruction = next(
            constraint
            for constraint in system.constraints
            if constraint.label == "Sapling Spend Merkle path position bit reconstruction"
        )
        self.assertEqual(
            position_reconstruction.left.terms,
            tuple(
                sorted(
                    ((position_variable.index, 1),)
                    + tuple(
                        (bit.index, -(1 << index) % SCALAR_MODULUS)
                        for index, bit in enumerate(assembly.merkle_path.position_bits)
                    )
                )
            ),
        )
        self.assertEqual(position_reconstruction.right.terms, ((0, 1),))
        self.assertEqual(position_reconstruction.output.terms, ())
        conditional_anchor = next(
            constraint
            for constraint in system.constraints
            if constraint.label == "Sapling Spend Merkle path conditional anchor"
        )
        self.assertIn(
            assembly.public_inputs[4].index,
            dict(conditional_anchor.left.terms),
        )
        self.assertFalse(
            any(
                variable.kind == "private"
                and "conditional anchor" in variable.name
                for variable in system.variables
            )
        )
        self.assertEqual(
            assembly.constraint_count,
            system.constraint_count,
        )
        self.assertEqual(
            assembly.relation_constraint_counts,
            (
                ("ak and randomized authorization key", 1030),
                ("nsk, nk, point representations, and ivk", 23560),
                ("g_d and pk_d", 4048),
                ("value commitment and note commitment", 4031),
                ("Merkle path, position, and conditional anchor", 44226),
                ("rho, nullifier PRF, and multipacking", 21882),
            ),
        )
        self.assertEqual(system.constraint_count, 98777)
        self.assertEqual(len(system.variables), 98646)
        matrix = json.loads(system.serialize_matrix())
        self.assertEqual(matrix["field_modulus"], str(SCALAR_MODULUS))
        self.assertEqual(matrix["public_input_count"], 7)
        self.assertEqual(
            matrix["variable_kinds"][:8],
            ["one"] + ["public"] * 7,
        )
        self.assertEqual(
            system.matrix_fingerprint(),
            "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9",
        )
        self.assertEqual(len(matrix["constraints"]), system.constraint_count)
        self.assertNotIn("witness", system.serialize_matrix().decode())
        self.assertEqual(len(assembly.authorization_randomizer_bits), 252)
        self.assertEqual(
            assembly.value.terms,
            tuple(
                (bit.index, 1 << index)
                for index, bit in enumerate(assembly.value_bits)
            ),
        )
        self.assertFalse(
            any(variable.name == "Sapling Spend ar" for variable in system.variables)
        )
        self.assertFalse(
            any(variable.name == "Sapling Spend value" for variable in system.variables)
        )
        self.assertFalse(
            any(
                constraint.label in (
                    "Sapling Spend randomized authorization key ar bit reconstruction",
                    "Sapling Spend note commitment value encoding",
                )
                for constraint in system.constraints
            )
        )
        self.assertFalse(
            any(
                constraint.label.endswith(" complement")
                and (
                    " ivk output bit[" in constraint.label.lower()
                    or " nullifier prf output bit[" in constraint.label.lower()
                )
                for constraint in system.constraints
            )
        )
        self.assertTrue(
            all(count > 0 for _, count in assembly.relation_constraint_counts)
        )
        self.assertTrue(system.is_satisfied())

        public_relation_labels = (
            "Sapling Spend randomized authorization key public rk.u",
            "Sapling Spend randomized authorization key public rk.v",
            "Sapling Spend value commitment public commitment u",
            "Sapling Spend value commitment public commitment v",
            "Sapling Spend Merkle path conditional anchor",
            "Sapling Spend nullifier multipacking public chunk[0]",
            "Sapling Spend nullifier multipacking public chunk[1]",
        )
        for public_index, expected_label in enumerate(public_relation_labels, 1):
            with self.subTest(public_relation=expected_label):
                self.assertTrue(
                    any(
                        constraint.label == expected_label
                        and any(
                            column == public_index
                            for expression in (
                                constraint.left,
                                constraint.right,
                                constraint.output,
                            )
                            for column, _ in expression.terms
                        )
                        for constraint in system.constraints
                    )
                )

        values = [int(value) for value in system._values]
        incident_rows = [[] for _ in values]
        for constraint in system.constraints:
            left = constraint.left
            right = constraint.right
            output = constraint.output
            left_value = system._evaluate(left, values)
            right_value = system._evaluate(right, values)
            output_value = system._evaluate(output, values)
            coefficients = (
                dict(left.terms),
                dict(right.terms),
                dict(output.terms),
            )
            for column in set().union(*(set(row) for row in coefficients)):
                incident_rows[column].append(
                    (
                        coefficients[0].get(column, 0),
                        coefficients[1].get(column, 0),
                        coefficients[2].get(column, 0),
                        left_value,
                        right_value,
                        output_value,
                    )
                )

        for variable in system.variables[1:]:
            for delta in (-1, 1):
                self.assertTrue(
                    any(
                        (
                            delta * (a_coefficient * right_value
                                     + b_coefficient * left_value
                                     - c_coefficient)
                            + delta * delta * a_coefficient * b_coefficient
                        )
                        % SCALAR_MODULUS
                        != 0
                        for (
                            a_coefficient,
                            b_coefficient,
                            c_coefficient,
                            left_value,
                            right_value,
                            _,
                        ) in incident_rows[variable.index]
                    ),
                    f"{variable.name} mutation did not break an incident constraint",
                )

        for index, variable in enumerate(assembly.public_inputs):
            with self.subTest(public_input=SPEND_PUBLIC_INPUT_ORDER[index]):
                current = witness.public_inputs[index]
                self.assertFalse(
                    system.is_satisfied(
                        {variable.index: current + 1}
                    )
                )

        tamper_cases = (
            (assembly.authorization_key[0], None),
            (
                assembly.authorization_randomizer_bits[0],
                1 - (witness.ar & 1),
            ),
            (assembly.nsk_bits[0], 1 - witness.nsk % 2),
            (assembly.nullifier_key[0], None),
            (assembly.ivk_bits[0], None),
            (assembly.diversifier_base[0], None),
            (assembly.transmission_key_repr_bits[0], None),
            (assembly.value_bits[0], 1 - witness.value % 2),
            (
                assembly.value_commitment_randomness_bits[0],
                1 - witness.rcv % 2,
            ),
            (
                assembly.commitment_randomness_bits[0],
                1 - witness.rcm % 2,
            ),
            (assembly.note_commitment[0], None),
            (assembly.merkle_path.siblings[0], None),
            (
                assembly.merkle_path.position_bits[0],
                1 - (witness.position & 1),
            ),
            (assembly.rho[0], None),
            (assembly.rho_repr_bits[0], None),
            (assembly.nullifier_bits[0], None),
        )
        for variable, replacement in tamper_cases:
            backing = (
                variable.variable
                if isinstance(variable, _NegatedBit)
                else variable
            )
            with self.subTest(witness_category=backing.name):
                current = system._witness_value(backing)
                assigned = (
                    1 - current
                    if replacement is None and current in (0, 1)
                    else current + 1
                    if replacement is None
                    else replacement
                )
                self.assertFalse(
                    system.is_satisfied({backing.index: assigned})
                )

    def test_complete_spend_matrix_is_unchanged_by_component_reference_substitutions(self):
        witness = _circuit_witness(generate_independent_witness(0))
        local_system = R1CS()
        local_assembly = constrain_sapling_spend(local_system, witness)

        pedersen_personalizations = []
        blake2s_personalizations = []

        def constrain_reference_pedersen(
            system,
            personalization_bits,
            message_bits,
            pedersen_witness,
            label,
            *,
            message_bits_preconstrained=False,
            representation="edwards",
        ):
            self.assertTrue(message_bits_preconstrained)
            self.assertEqual(representation, "montgomery")
            self.assertTrue(
                all(
                    type(bit) is int and bit in (0, 1)
                    for bit in personalization_bits
                )
            )
            pedersen_personalizations.append(tuple(personalization_bits))
            result = synthesize_bellman_pedersen_reference(
                system,
                tuple(personalization_bits),
                tuple(message_bits),
                label,
            )
            self.assertEqual(
                tuple(system._witness_value(coordinate) for coordinate in result),
                (pedersen_witness.result.u, pedersen_witness.result.v),
            )
            return result

        def constrain_reference_blake2s(
            system,
            input_bits,
            personalization,
            blake2s_witness,
            label,
            *,
            input_bits_preconstrained=False,
        ):
            if not input_bits_preconstrained:
                for index, bit in enumerate(input_bits):
                    if isinstance(bit, Variable):
                        system.boolean(bit, f"{label} input bit[{index}]")
            blake2s_personalizations.append(personalization)
            digest = constrain_bellman_blake2s_reference(
                system, tuple(input_bits), personalization
            )
            self.assertEqual(
                bellman_bits_to_bytes(system, digest),
                blake2s_witness.digest,
            )
            return tuple(
                _NegatedBit(bit.variable)
                if isinstance(bit, BellmanNegatedBit)
                else bit
                for bit in digest
            )

        composed_system = R1CS()
        with (
            patch(
                "src.sapling_gadgets.constrain_pedersen_hash",
                constrain_reference_pedersen,
            ),
            patch(
                "src.blake2s_gadget.constrain_blake2s",
                constrain_reference_blake2s,
            ),
        ):
            composed_assembly = constrain_sapling_spend(composed_system, witness)

        self.assertEqual(
            pedersen_personalizations,
            [(1,) * 6]
            + [
                tuple((level >> bit) & 1 for bit in range(6))
                for level in range(32)
            ],
        )
        self.assertEqual(
            blake2s_personalizations,
            [b"Zcashivk", b"Zcash_nf"],
        )
        self.assertEqual(
            composed_assembly.relation_constraint_counts,
            local_assembly.relation_constraint_counts,
        )
        self.assertEqual(composed_system.constraint_count, 98_777)
        self.assertEqual(len(composed_system.variables), 98_646)
        self.assertEqual(composed_system.public_input_count, 7)
        self.assertEqual(len(composed_system.variables) - 1 - 7, 98_638)
        self.assertEqual(composed_system.variables[0].kind, "one")
        self.assertEqual(
            tuple(variable.kind for variable in composed_system.variables[:8]),
            ("one",) + ("public",) * 7,
        )
        self.assertEqual(
            composed_system.serialize_matrix(),
            local_system.serialize_matrix(),
        )
        self.assertEqual(
            composed_system.matrix_fingerprint(),
            "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9",
        )
        self.assertTrue(local_system.is_satisfied())
        self.assertTrue(composed_system.is_satisfied())

    def test_spend_assembly_rejects_nonfresh_system(self):
        reference = generate_pinned_test_witness(0)
        witness = _circuit_witness(reference)
        system = R1CS()
        system.alloc_public("occupied", 0)
        with self.assertRaisesRegex(ValueError, "fresh R1CS"):
            constrain_sapling_spend(system, witness)

    def test_spend_assembly_rejects_malformed_host_witness_encodings(self):
        reference = generate_pinned_test_witness(0)
        witness = _circuit_witness(reference)
        invalid_witnesses = (
            replace(witness, value=1 << 64),
            replace(witness, rcv=SCALAR_MODULUS),
            replace(witness, nsk=SCALAR_MODULUS),
            replace(witness, rcm=SCALAR_MODULUS),
            replace(witness, ar=SCALAR_MODULUS),
            replace(witness, ivk=1 << 251),
            replace(witness, position=witness.position ^ 1),
            replace(witness, anchor=-1),
            replace(witness, nullifier=b"\x00"),
            replace(
                witness,
                public_inputs=(
                    witness.public_inputs[0],
                    witness.public_inputs[1],
                    witness.public_inputs[2],
                    witness.public_inputs[3],
                    witness.public_inputs[4],
                    witness.public_inputs[5],
                    -1,
                ),
            ),
        )
        for index, invalid in enumerate(invalid_witnesses):
            with self.subTest(invalid_field=index), self.assertRaises(R1CSError):
                constrain_sapling_spend(R1CS(), invalid)

    def test_spend_admission_rejects_invalid_upstream_host_preconditions(self):
        reference = generate_pinned_test_witness(0)
        witness = _circuit_witness(reference)
        non_subgroup_ak = Point.from_bytes(bytes.fromhex("03" + "00" * 31))
        self.assertTrue(non_subgroup_ak.is_on_curve())
        self.assertNotEqual(non_subgroup_ak.multiply(8), IDENTITY)
        self.assertFalse(non_subgroup_ak.is_in_subgroup())

        invalid_diversifier = bytes.fromhex("01" + "00" * 10)
        self.assertIsNone(group_hash(b"Zcash_gd", invalid_diversifier))
        valid_mismatched_diversifier = bytes(11)
        mismatched_g_d = group_hash(
            b"Zcash_gd", valid_mismatched_diversifier
        )
        self.assertIsNotNone(mismatched_g_d)
        self.assertNotEqual(mismatched_g_d, witness.diversifier_base)

        invalid_witnesses = (
            ("off-curve ak", replace(witness, ak=Point(1, 1))),
            ("small-order ak", replace(witness, ak=IDENTITY)),
            ("non-subgroup ak", replace(witness, ak=non_subgroup_ak)),
            (
                "invalid diversifier",
                replace(witness, diversifier=invalid_diversifier),
            ),
            (
                "valid but mismatched diversifier",
                replace(witness, diversifier=valid_mismatched_diversifier),
            ),
        )
        for field in ("rcv", "nsk", "rcm", "ar"):
            for value in (SCALAR_MODULUS, -1, True):
                invalid_witnesses += (
                    (f"{field}={value!r}", replace(witness, **{field: value})),
                )

        for case, invalid in invalid_witnesses:
            system = R1CS()
            with self.subTest(case=case), self.assertRaises(R1CSError):
                constrain_sapling_spend(system, invalid)
            self.assertEqual(len(system.variables), 1)
            self.assertEqual(system.constraint_count, 0)


if __name__ == "__main__":
    unittest.main()
