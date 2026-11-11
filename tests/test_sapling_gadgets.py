import hashlib
import json
import unittest
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast
from unittest.mock import patch

from src.bellman_synthesis import (
    BellmanRecorderError,
    BellmanSynthesisRecorder,
    RecorderSynthesisBackend,
)
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import (
    FIELD_MODULUS,
    Point,
    find_group_hash,
    group_hash,
    spending_key_base,
)
from src.jubjub import (
    SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS,
)
from src.r1cs import R1CS, R1CSError
from src.sapling_gadgets import (
    FixedBaseJubjubWitness,
    MerklePathWitness,
    SaplingNullifierMultipackingWitness,
    SaplingOutputWitness,
    CircuitBit,
    _allocate_jubjub_scalar_bits,
    _constrain_fixed_base_jubjub_mul,
    _constrain_fixed_base_scalar,
    _constrain_fixed_base_windows,
    _constrain_lookup3_point,
    _constrain_note_commitment,
    _constrain_sapling_value_commitment,
    _constrain_signed_lookup3_point,
    _constrain_strict_field_bits,
    _fixed_base_tables,
    _pedersen_montgomery_tables,
    _pedersen_tables,
    allocate_jubjub_point,
    allocate_unchecked_jubjub_repr,
    constrain_fixed_base_jubjub_mul,
    constrain_jubjub_add,
    constrain_jubjub_double,
    constrain_jubjub_not_small_order,
    constrain_jubjub_point,
    constrain_jubjub_repr,
    constrain_jubjub_scalar_mul,
    constrain_merkle_authentication_path,
    constrain_note_commitment,
    constrain_pedersen_hash,
    constrain_sapling_conditional_anchor,
    constrain_sapling_ephemeral_key,
    constrain_sapling_nullifier_multipacking,
    constrain_sapling_output,
    constrain_sapling_randomized_authorization_key,
    constrain_sapling_value_commitment,
    jubjub_add_witness,
    jubjub_double_witness,
    make_fixed_base_jubjub_witness,
    make_jubjub_scalar_mul_witness,
    make_merkle_path_witness,
    make_note_commitment_witness,
    make_pedersen_witness,
    make_sapling_ephemeral_key_witness,
    make_sapling_nullifier_multipacking_witness,
    make_sapling_output_witness,
    make_sapling_randomized_authorization_key_witness,
    make_sapling_value_commitment_witness,
    sapling_fixed_base_generator,
)
from src.synthesis import SynthesisBackend, VariableLike
from src.sapling_spend_reference import (
    _pedersen_generators,
    _pedersen_hash,
    generate_pinned_test_witness,
)
from tests.bellman_pedersen_reference import (
    _pedersen_montgomery_tables as reference_pedersen_montgomery_tables,
)
from tests.bellman_pedersen_reference import (
    synthesize_pedersen_hash,
)

FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_merkle_tree_reference.json"
)
NULLIFIER_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_reference.json"
)
SPEND_PARTIAL_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_spend_partial_reference.json"
)
VALUE_COMMITMENT_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_value_commitment_reference.json"
)
OUTPUT_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_output_reference.json"
)
EPHEMERAL_KEY_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_ephemeral_key_reference.json"
)
NULLIFIER_MULTIPACKING_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_multipacking_reference.json"
)
IVK_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_ivk_blake2s_reference.json"
)
RANDOMIZED_AUTHORIZATION_KEY_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_randomized_authorization_key_reference.json"
)


def bits_le(value, width):
    return tuple((value >> index) & 1 for index in range(width))


FIXED_BASE_REFERENCE_LIMBS = {
    "proof_generation_key": (
        (0x3AF2DBEFB96E2571, 0xADF2D038F2FBB820, 0x704303F1E8906081, 0x1457A50231CDE2DF),
        (0x467AF9F7E05DE8E7, 0x50DF51EAF5A149D2, 0xDEC901840F4948CC, 0x54B6D10718DF2A7A),
    ),
    "note_commitment_randomness": (
        (0xA5143B34A8E36462, 0xF0919D06FFB1ECDA, 0xA1409AA1F33BEC2C, 0x26EB9F8A9EC72A8C),
        (0xD4FC6365796C77AC, 0x96B78BEAFA9CC44C, 0x949D77476E262C95, 0x114B7501AD104C57),
    ),
    "nullifier_position": (
        (0x2CE33921888D30DB, 0xE81CEE09A561229E, 0xDB56B6DB8D8075ED, 0x2400C2E2E3362644),
        (0xA3F7FA36C72B0065, 0xE155B8E8FFFF2E42, 0xFC9E8A15A096BA8F, 0x61369D5440BF84A5),
    ),
    "value_commitment_value": (
        (0x36183B2CB4D7EF51, 0x9472C89AC043042D, 0xD8618ED1D15FEF4E, 0x273F910D9ECC1615),
        (0xA77A81F50667C8D7, 0xBC3332D0FA1CCD18, 0xD32294FD89774AD6, 0x466A7E3A82F67AB1),
    ),
    "value_commitment_randomness": (
        (0x3BCE3B7793664337, 0xD1D8DA41AF03744E, 0x7FF6826AD58004B4, 0x6800F4FA0F001CFC),
        (0x3CAEFAB9380B6A8B, 0xAD46F1B0473B803B, 0xE6FB2A6E1E22AB50, 0x6D81D3A9CB45DEDB),
    ),
    "spending_key": (
        (0x47BF46920A95A753, 0xD5B9A7D3EF8E2827, 0xD418A7FF26753B6A, 0x0926D4F32059C712),
        (0x305632ADAAF2B530, 0x6D65674DCEDBDDBC, 0x53BB37D0C21CFD05, 0x57A1019E6DE9B675),
    ),
}


class SaplingGadgetTests(unittest.TestCase):
    def test_strict_field_range_and_bit_packing(self):
        system = R1CS()
        field_value = system.alloc_private("field", 123456)
        bits = system.range_check(
            field_value, 255, "field bit", upper_bound=SCALAR_MODULUS
        )
        packed = system.pack_bits(bits[:8], "packed")
        self.assertEqual(system._witness_value(packed), 64)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({bits[0].index: 1}))
        with self.assertRaises(R1CSError):
            system.pack_bits(bits, "too wide")

        alias_system = R1CS()
        one = alias_system.alloc_private("one", 1)
        alias_bits = alias_system.range_check(
            one, 255, "alias bit", upper_bound=SCALAR_MODULUS
        )
        field_alias = SCALAR_MODULUS + 1
        self.assertFalse(
            alias_system.is_satisfied(
                {
                    bit.index: (field_alias >> index) & 1
                    for index, bit in enumerate(alias_bits)
                }
            )
        )

    def test_jubjub_curve_membership_and_repr(self):
        point_value = spending_key_base()
        system = R1CS()
        point = allocate_jubjub_point(system, "point", point_value)
        constrain_jubjub_point(system, point)
        representation = constrain_jubjub_repr(system, point)
        self.assertEqual(len(representation), 256)
        self.assertEqual(
            tuple(system._witness_value(bit) for bit in representation),
            bits_le(point_value.v, 255) + (point_value.u & 1,),
        )
        self.assertTrue(system.is_satisfied())

        invalid_system = R1CS()
        invalid = allocate_jubjub_point(invalid_system, "invalid", Point(1, 1))
        constrain_jubjub_point(invalid_system, invalid)
        self.assertFalse(invalid_system.is_satisfied())

    def test_jubjub_repr_uses_strict_prefix_comparator_without_aliases(self):
        system = R1CS()
        u = system.alloc_private("u", 1)
        v = system.alloc_private("v", SCALAR_MODULUS - 1)
        representation = constrain_jubjub_repr(system, (u, v))

        self.assertEqual(len(representation), 256)
        self.assertEqual(system.constraint_count, 776)
        self.assertTrue(system.is_satisfied())

        noncanonical_system = R1CS()
        value = noncanonical_system.alloc_private("value", 1)
        strict_bits = _constrain_strict_field_bits(
            noncanonical_system, value, "value bit"
        )
        self.assertTrue(noncanonical_system.is_satisfied())
        self.assertFalse(
            noncanonical_system.is_satisfied(
                {
                    bit.index: ((SCALAR_MODULUS + 1) >> index) & 1
                    for index, bit in enumerate(strict_bits)
                }
            )
        )

        zero_alias_system = R1CS()
        zero = zero_alias_system.alloc_private("zero", 0)
        zero_bits = _constrain_strict_field_bits(
            zero_alias_system, zero, "zero bit"
        )
        self.assertTrue(zero_alias_system.is_satisfied())
        self.assertFalse(
            zero_alias_system.is_satisfied(
                {
                    bit.index: (SCALAR_MODULUS >> index) & 1
                    for index, bit in enumerate(zero_bits)
                }
            )
        )

    def test_upstream_affine_addition_and_doubling_constraints(self):
        left_value = spending_key_base()
        right_value = find_group_hash(b"Zcash_G_", b"gadgets")

        add_system = R1CS()
        left = allocate_jubjub_point(add_system, "left", left_value)
        right = allocate_jubjub_point(add_system, "right", right_value)
        result_value = jubjub_add_witness(left_value, right_value)
        result = allocate_jubjub_point(add_system, "result", result_value)
        constrain_jubjub_add(add_system, left, right, result)
        self.assertEqual(add_system.constraint_count, 6)
        constrain_jubjub_point(add_system, left, "left curve")
        constrain_jubjub_point(add_system, right, "right curve")
        constrain_jubjub_point(add_system, result, "result curve")
        self.assertEqual(add_system.constraint_count, 18)
        self.assertTrue(add_system.is_satisfied())
        self.assertFalse(
            add_system.is_satisfied({result[0].index: (result_value.u + 1)})
        )

        double_system = R1CS()
        point = allocate_jubjub_point(double_system, "point", left_value)
        doubled_value = jubjub_double_witness(left_value)
        doubled = allocate_jubjub_point(double_system, "doubled", doubled_value)
        constrain_jubjub_double(double_system, point, doubled)
        self.assertEqual(double_system.constraint_count, 5)
        self.assertTrue(double_system.is_satisfied())
        self.assertFalse(
            double_system.is_satisfied(
                {doubled[1].index: (doubled_value.v + 1) % SCALAR_MODULUS}
            )
        )

        for label, lhs_value, rhs_value, expected in (
            ("identity left", Point(0, 1), left_value, left_value),
            ("identity right", left_value, Point(0, 1), left_value),
            ("inverse pair", left_value, Point(-left_value.u, left_value.v), Point(0, 1)),
        ):
            with self.subTest(edge_case=label):
                edge_system = R1CS()
                left = allocate_jubjub_point(edge_system, f"{label} left", lhs_value)
                right = allocate_jubjub_point(edge_system, f"{label} right", rhs_value)
                result_value = jubjub_add_witness(lhs_value, rhs_value)
                self.assertEqual(result_value, expected)
                result = allocate_jubjub_point(
                    edge_system, f"{label} result", result_value
                )
                constrain_jubjub_add(
                    edge_system, left, right, result, f"{label} addition"
                )
                for point_index, point in enumerate((left, right, result)):
                    constrain_jubjub_point(
                        edge_system, point, f"{label} point[{point_index}]"
                    )
                self.assertTrue(edge_system.is_satisfied())
                self.assertFalse(
                    edge_system.is_satisfied(
                        {
                            result[0].index:
                            (result_value.u + 1) % SCALAR_MODULUS
                        }
                    )
                )

    def test_little_endian_variable_base_scalar_multiplication(self):
        base_value = spending_key_base()
        bit_values = (1, 0, 1, 1, 0)
        witness = make_jubjub_scalar_mul_witness(base_value, bit_values)
        system = R1CS()
        base = allocate_jubjub_point(system, "base", base_value)
        constrain_jubjub_point(system, base)
        bits = tuple(
            system.alloc_private(f"scalar bit[{index}]", bit)
            for index, bit in enumerate(bit_values)
        )
        result = constrain_jubjub_scalar_mul(system, base, bits, witness)
        self.assertEqual(
            (system._witness_value(result[0]), system._witness_value(result[1])),
            (witness.result.u, witness.result.v),
        )
        self.assertEqual(system.constraint_count, 63)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({bits[0].index: 0}))

    def test_sapling_ephemeral_key_matches_reference_and_constraints(self):
        vector = json.loads(EPHEMERAL_KEY_FIXTURE.read_text(encoding="utf-8"))[
            "case"
        ]
        diversifier = bytes.fromhex(vector["default_d"])
        diversifier_base = group_hash(b"Zcash_gd", diversifier)
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")
        expected_epk = Point.from_bytes(bytes.fromhex(vector["epk"]))
        self.assertIsNotNone(diversifier_base)
        self.assertEqual(expected_epk.encode().hex(), vector["epk"])
        witness = make_sapling_ephemeral_key_witness(diversifier_base, esk)
        self.assertEqual(witness.esk_bits, bits_le(esk, 252))
        self.assertEqual(witness.ephemeral_key, expected_epk)

        system = R1CS()
        public_inputs = tuple(
            system.alloc_public(f"Output public[{index}]", value)
            for index, value in enumerate(
                (17, 18, expected_epk.u, expected_epk.v, 19)
            )
        )
        base = allocate_jubjub_point(system, "g_d", diversifier_base)
        esk_bits = tuple(
            system.alloc_private(f"esk bit[{index}]", bit)
            for index, bit in enumerate(witness.esk_bits)
        )
        result = constrain_sapling_ephemeral_key(
            system, base, esk_bits, public_inputs[2:4], witness
        )
        self.assertEqual(
            system.public_inputs(),
            (17, 18, expected_epk.u, expected_epk.v, 19),
        )
        self.assertEqual(
            (
                system._witness_value(result[0]),
                system._witness_value(result[1]),
            ),
            (expected_epk.u, expected_epk.v),
        )
        self.assertEqual(system.constraint_count, 3539)
        self.assertTrue(system.is_satisfied())

        intermediate = next(
            variable
            for variable in system.variables
            if variable.name
            == "Sapling Output ephemeral key multiplication accumulator[100].u"
        )
        tamper_cases = (
            ("esk", {esk_bits[0].index: 1 - witness.esk_bits[0]}),
            (
                "reversed esk byte/bit order",
                {
                    bit.index: value
                    for bit, value in zip(esk_bits, reversed(witness.esk_bits))
                },
            ),
            ("g_d", {base[0].index: diversifier_base.u + 1}),
            (
                "intermediate multiplication point",
                {
                    intermediate.index: system._witness_value(intermediate) + 1
                },
            ),
            ("epk.u", {public_inputs[2].index: expected_epk.u + 1}),
            ("epk.v", {public_inputs[3].index: expected_epk.v + 1}),
        )
        for label, assignment in tamper_cases:
            with self.subTest(tamper=label):
                self.assertFalse(system.is_satisfied(assignment))

    def test_sapling_ephemeral_key_scalar_boundaries_and_invalid_inputs(self):
        vector = json.loads(EPHEMERAL_KEY_FIXTURE.read_text(encoding="utf-8"))[
            "case"
        ]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        self.assertIsNotNone(diversifier_base)

        for esk in (0, 1, JUBJUB_SCALAR_MODULUS - 1):
            with self.subTest(esk=esk):
                witness = make_sapling_ephemeral_key_witness(
                    diversifier_base, esk
                )
                public_epk = witness.ephemeral_key
                system = R1CS()
                public = tuple(
                    system.alloc_public(f"epk.{coordinate}", value)
                    for coordinate, value in (
                        ("u", public_epk.u),
                        ("v", public_epk.v),
                    )
                )
                base = allocate_jubjub_point(
                    system, "g_d", diversifier_base
                )
                bits = tuple(
                    system.alloc_private(f"esk bit[{index}]", bit)
                    for index, bit in enumerate(witness.esk_bits)
                )
                constrain_sapling_ephemeral_key(
                    system, base, bits, public, witness
                )
                self.assertTrue(system.is_satisfied())
                self.assertEqual(system.constraint_count, 3539)
                self.assertEqual(public_epk, diversifier_base.multiply(esk))

        with self.assertRaises(R1CSError):
            make_sapling_ephemeral_key_witness(
                diversifier_base, JUBJUB_SCALAR_MODULUS
            )
        with self.assertRaises(R1CSError):
            make_sapling_ephemeral_key_witness(Point(1, 1), 1)
        with self.assertRaises(R1CSError):
            make_sapling_ephemeral_key_witness(Point(0, 1), 1)
        with self.assertRaises(ValueError):
            Point.from_bytes(FIELD_MODULUS.to_bytes(32, "little"))

        invalid_diversifier = next(
            bytes((counter,)) * 11
            for counter in range(256)
            if group_hash(b"Zcash_gd", bytes((counter,)) * 11) is None
        )
        self.assertIsNone(group_hash(b"Zcash_gd", invalid_diversifier))

        malformed_system = R1CS()
        public = (
            malformed_system.alloc_public("epk.u", 0),
            malformed_system.alloc_public("epk.v", 1),
        )
        base = allocate_jubjub_point(
            malformed_system, "g_d", diversifier_base
        )
        short_bits = tuple(
            malformed_system.alloc_private(f"esk bit[{index}]", 0)
            for index in range(251)
        )
        valid_witness = make_sapling_ephemeral_key_witness(
            diversifier_base, 0
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_ephemeral_key(
                malformed_system,
                base,
                short_bits,
                public,
                valid_witness,
            )

    def test_sapling_ephemeral_key_matches_production_and_recorder(self):
        vector = json.loads(EPHEMERAL_KEY_FIXTURE.read_text(encoding="utf-8"))[
            "case"
        ]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")
        witness = make_sapling_ephemeral_key_witness(diversifier_base, esk)

        def synthesize(system):
            public = tuple(
                system.alloc_public(f"Output public[{index}]", value)
                for index, value in enumerate(
                    (17, 18, witness.ephemeral_key.u, witness.ephemeral_key.v, 19)
                )
            )
            base = allocate_jubjub_point(
                system, "g_d", diversifier_base
            )
            bits = tuple(
                system.alloc_private(f"esk bit[{index}]", bit)
                for index, bit in enumerate(witness.esk_bits)
            )
            result = constrain_sapling_ephemeral_key(
                system, base, bits, public[2:4], witness
            )
            if isinstance(system, R1CS):
                variables = system.variables[1:]
                matrix = system.serialize_matrix()
                labels = tuple(row.label for row in system.constraints)
                values = tuple(system.witness_value(v) for v in variables)
                result_values = tuple(system.witness_value(v) for v in result)
                rows = system.constraint_count
                columns = len(system.variables)
            else:
                variables = system.recorder.inputs[1:] + system.recorder.auxiliary_variables
                matrix = system.recorder.serialize_local_matrix()
                labels = tuple(
                    row.name.replace("/", " ")
                    for row in system.recorder.constraints
                )
                values = tuple(system.witness_value(v) for v in variables)
                result_values = tuple(system.witness_value(v) for v in result)
                rows = system.recorder.constraint_count
                columns = len(system.recorder.inputs) + len(
                    system.recorder.auxiliary_variables
                )
            return matrix, labels, variables, values, result_values, rows, columns

        production = R1CS()
        production_result = synthesize(production)
        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorder_result = synthesize(recorder_backend)

        self.assertEqual(production_result[5:], (3539, 3544))
        self.assertEqual(recorder_result[5:], (3539, 3544))
        self.assertEqual(production_result[0], recorder_result[0])
        self.assertEqual(production_result[1], recorder_result[1])
        self.assertEqual(
            tuple(variable.name for variable in production_result[2]),
            tuple(
                variable.name.replace("/", " ")
                for variable in recorder_result[2]
            ),
        )
        self.assertEqual(
            tuple(variable.index for variable in production_result[2]),
            tuple(
                variable.index.index
                if variable.index.kind == "input"
                else len(recorder.inputs) + variable.index.index
                for variable in recorder_result[2]
            ),
        )
        self.assertEqual(production_result[3], recorder_result[3])
        self.assertEqual(production_result[4], recorder_result[4])
        self.assertEqual(
            hashlib.sha256(production_result[0]).hexdigest(),
            "c70a14e6c311b6b029651659ff03a7fec711bd2c4333ccecca138280c65d0a1b",
        )
        self.assertEqual(
            production_result[4],
            (witness.ephemeral_key.u, witness.ephemeral_key.v),
        )
        self.assertTrue(production.is_satisfied())

    def test_sapling_ephemeral_key_scalar_boundaries_match_recorder(self):
        vector = json.loads(EPHEMERAL_KEY_FIXTURE.read_text(encoding="utf-8"))[
            "case"
        ]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )

        for esk in (0, 1, JUBJUB_SCALAR_MODULUS - 1):
            with self.subTest(esk=esk):
                witness = make_sapling_ephemeral_key_witness(
                    diversifier_base, esk
                )
                production = R1CS()
                recorder = BellmanSynthesisRecorder()
                recorder_backend = RecorderSynthesisBackend(recorder)
                results = []
                for system in (production, recorder_backend):
                    public = (
                        system.alloc_public("epk.u", witness.ephemeral_key.u),
                        system.alloc_public("epk.v", witness.ephemeral_key.v),
                    )
                    base = allocate_jubjub_point(
                        system, "g_d", diversifier_base
                    )
                    bits = tuple(
                        system.alloc_private(f"esk bit[{index}]", bit)
                        for index, bit in enumerate(witness.esk_bits)
                    )
                    result = constrain_sapling_ephemeral_key(
                        system, base, bits, public, witness
                    )
                    if isinstance(system, R1CS):
                        variables = system.variables[1:]
                        matrix = system.serialize_matrix()
                        values = tuple(
                            system.witness_value(variable)
                            for variable in variables
                        )
                    else:
                        variables = (
                            recorder.inputs[1:] + recorder.auxiliary_variables
                        )
                        matrix = recorder.serialize_local_matrix()
                        values = tuple(
                            system.witness_value(variable)
                            for variable in variables
                        )
                    result_values = tuple(
                        system.witness_value(variable) for variable in result
                    )
                    results.append((matrix, values, result_values))

                self.assertEqual(results[0], results[1])
                self.assertEqual(production.constraint_count, 3539)
                self.assertTrue(production.is_satisfied())
                self.assertEqual(
                    results[0][2],
                    (witness.ephemeral_key.u, witness.ephemeral_key.v),
                )

    def test_sapling_ephemeral_key_rejects_invalid_witness_before_mutation(self):
        vector = json.loads(EPHEMERAL_KEY_FIXTURE.read_text(encoding="utf-8"))[
            "case"
        ]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")
        witness = make_sapling_ephemeral_key_witness(diversifier_base, esk)
        out_of_range_bits = bits_le(
            JUBJUB_SCALAR_MODULUS, JUBJUB_SCALAR_MODULUS.bit_length()
        )
        out_of_range_mul = make_jubjub_scalar_mul_witness(
            diversifier_base, out_of_range_bits
        )
        out_of_range_witness = replace(
            witness,
            esk=JUBJUB_SCALAR_MODULUS,
            esk_bits=out_of_range_bits,
            multiplication=out_of_range_mul,
            ephemeral_key=out_of_range_mul.result,
        )

        def expect_rejection(backend_factory, invalid_kind):
            backend, snapshot = backend_factory()
            public = tuple(
                backend.alloc_public(f"epk.{coordinate}", value)
                for coordinate, value in (
                    ("u", witness.ephemeral_key.u),
                    ("v", witness.ephemeral_key.v),
                )
            )
            base = allocate_jubjub_point(
                backend, "g_d", diversifier_base
            )
            assigned_bits = (
                out_of_range_bits
                if invalid_kind == "out-of-range"
                else witness.esk_bits
            )
            bits = tuple(
                backend.alloc_private(
                    f"esk bit[{index}]",
                    2 if invalid_kind == "non-boolean" and index == 0
                    else None if invalid_kind == "unassigned" and index == 0
                    else bit,
                )
                for index, bit in enumerate(assigned_bits)
            )
            supplied_bits = bits
            supplied_witness = witness
            if invalid_kind == "foreign":
                foreign = backend_factory()[0]
                supplied_bits = tuple(
                    foreign.alloc_private(f"foreign esk bit[{index}]", bit)
                    for index, bit in enumerate(witness.esk_bits)
                )
            elif invalid_kind == "out-of-range":
                supplied_witness = out_of_range_witness
            elif invalid_kind == "mismatched":
                supplied_witness = make_sapling_ephemeral_key_witness(
                    diversifier_base, 1
                )
            before = snapshot(backend)
            with self.assertRaises((R1CSError, BellmanRecorderError)):
                constrain_sapling_ephemeral_key(
                    backend, base, supplied_bits, public, supplied_witness
                )
            self.assertEqual(snapshot(backend), before)

        def r1cs_factory():
            backend = R1CS()
            return backend, lambda target: target.serialize()

        def recorder_factory():
            recorder = BellmanSynthesisRecorder()
            backend = RecorderSynthesisBackend(recorder)
            return backend, lambda target: target.recorder.serialize()

        for factory in (r1cs_factory, recorder_factory):
            for kind in (
                "non-boolean",
                "unassigned",
                "foreign",
                "out-of-range",
                "mismatched",
            ):
                with self.subTest(backend=factory.__name__, invalid=kind):
                    expect_rejection(factory, kind)

    def test_fixed_base_generators_match_pinned_upstream_constants(self):
        for name, coordinates in FIXED_BASE_REFERENCE_LIMBS.items():
            with self.subTest(generator=name):
                point = sapling_fixed_base_generator(name)
                expected = tuple(
                    sum(limb << (64 * index) for index, limb in enumerate(limbs))
                    for limbs in coordinates
                )
                self.assertEqual((point.u, point.v), expected)
                self.assertTrue(point.is_in_subgroup())
                scalar_bits = bits_le(1, JUBJUB_SCALAR_MODULUS.bit_length())
                witness = make_fixed_base_jubjub_witness(point, scalar_bits)
                system = R1CS()
                bits = tuple(
                    system.alloc_private(f"{name} bit[{index}]", bit)
                    for index, bit in enumerate(scalar_bits)
                )
                result = constrain_fixed_base_jubjub_mul(
                    system, point, bits, witness, name
                )
                self.assertEqual(system.constraint_count, 1626)
                self.assertEqual(witness.result, point)
                self.assertEqual(
                    (
                        system._witness_value(result[0]),
                        system._witness_value(result[1]),
                    ),
                    expected,
                )
                self.assertTrue(system.is_satisfied())

    def test_fixed_base_three_bit_lookup_all_patterns_and_ordered_rows(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        table = _fixed_base_tables(base)[0]

        for pattern in range(8):
            with self.subTest(pattern=pattern):
                system = R1CS()
                bit_values = tuple((pattern >> index) & 1 for index in range(3))
                bits = tuple(
                    system.alloc_private(f"lookup input bit[{index}]", value)
                    for index, value in enumerate(bit_values)
                )
                for index, bit in enumerate(bits):
                    system.boolean(bit, f"lookup input bit[{index}] boolean")

                selected = allocate_jubjub_point(
                    system,
                    "lookup selected",
                    table[pattern],
                )
                _constrain_lookup3_point(
                    system,
                    bits,
                    table,
                    selected,
                    "lookup",
                )

                self.assertEqual(
                    [row.label for row in system.constraints],
                    [
                        "lookup input bit[0] boolean",
                        "lookup input bit[1] boolean",
                        "lookup input bit[2] boolean",
                        "lookup bc multiplication",
                        "lookup coordinate[0]",
                        "lookup coordinate[1]",
                    ],
                )
                bc = system.variables[-1]
                self.assertEqual(system.constraints[3].left, bits[1].lc())
                self.assertEqual(system.constraints[3].right, bits[2].lc())
                self.assertEqual(system.constraints[3].output, bc.lc())

                for coordinate, name in enumerate(("u", "v")):
                    values = tuple(getattr(point, name) for point in table)
                    base_expression = system.linear_combination(
                        (
                            (bits[1], values[2] - values[0]),
                            (bits[2], values[4] - values[0]),
                            (
                                bc,
                                values[6] - values[4] - values[2] + values[0],
                            ),
                        ),
                        values[0],
                    )
                    factor_expression = system.linear_combination(
                        (
                            (
                                bits[1],
                                values[3] - values[2] - values[1] + values[0],
                            ),
                            (
                                bits[2],
                                values[5] - values[4] - values[1] + values[0],
                            ),
                            (
                                bc,
                                values[7] - values[6] - values[5] + values[4]
                                - values[3] + values[2] + values[1] - values[0],
                            ),
                        ),
                        values[1] - values[0],
                    )
                    row = system.constraints[4 + coordinate]
                    self.assertEqual(row.left, factor_expression)
                    self.assertEqual(row.right, bits[0].lc())
                    self.assertEqual(
                        row.output,
                        selected[coordinate].lc() - base_expression,
                    )

                self.assertTrue(system.is_satisfied())
                self.assertEqual(
                    (
                        system._witness_value(selected[0]),
                        system._witness_value(selected[1]),
                    ),
                    (table[pattern].u, table[pattern].v),
                )

    def test_fixed_base_three_bit_lookup_matches_recorder_for_all_patterns(self):
        table = _fixed_base_tables(
            sapling_fixed_base_generator("value_commitment_value")
        )[0]
        for pattern in range(8):
            with self.subTest(pattern=pattern):
                values = tuple((pattern >> index) & 1 for index in range(3))
                production = R1CS()
                production_scope = production.namespace("outer").namespace("nested")
                production_bits = tuple(
                    production_scope.alloc_private(f"input bit[{index}]", value)
                    for index, value in enumerate(values)
                )
                for index, bit in enumerate(production_bits):
                    production_scope.enforce(
                        bit,
                        bit.lc() - 1,
                        0,
                        f"input bit[{index}] boolean",
                    )
                production_selected = allocate_jubjub_point(
                    production_scope, "lookup selected", table[pattern]
                )
                _constrain_lookup3_point(
                    production_scope,
                    production_bits,
                    table,
                    production_selected,
                    "lookup",
                )

                recorder = BellmanSynthesisRecorder()
                recorder_backend = RecorderSynthesisBackend(recorder)
                recorder_scope = recorder_backend.namespace("outer").namespace(
                    "nested"
                )
                recorded_bits = tuple(
                    recorder_scope.alloc_private(f"input bit[{index}]", value)
                    for index, value in enumerate(values)
                )
                for index, bit in enumerate(recorded_bits):
                    recorder_scope.enforce(
                        bit.lc(),
                        bit.lc() - 1,
                        0,
                        f"input bit[{index}] boolean",
                    )
                recorded_selected = allocate_jubjub_point(
                    recorder_scope, "lookup selected", table[pattern]
                )
                _constrain_lookup3_point(
                    recorder_scope,
                    recorded_bits,
                    table,
                    recorded_selected,
                    "lookup",
                )

                self.assertEqual(production.constraint_count, 6)
                self.assertEqual(recorder.constraint_count, 6)
                self.assertEqual(len(production.variables), 7)
                self.assertEqual(
                    len(recorder.inputs) + len(recorder.auxiliary_variables), 7
                )
                self.assertEqual(
                    tuple(row.label for row in production.constraints),
                    tuple(
                        f"outer nested input bit[{index}] boolean"
                        for index in range(3)
                    )
                    + (
                        "outer nested lookup bc multiplication",
                        "outer nested lookup coordinate[0]",
                        "outer nested lookup coordinate[1]",
                    ),
                )
                self.assertEqual(
                    tuple(row.name for row in recorder.constraints),
                    tuple(
                        f"outer/nested/input bit[{index}] boolean"
                        for index in range(3)
                    )
                    + (
                        "outer/nested/lookup bc multiplication",
                        "outer/nested/lookup coordinate[0]",
                        "outer/nested/lookup coordinate[1]",
                    ),
                )
                self.assertEqual(
                    production.serialize_matrix(),
                    recorder.serialize_local_matrix(),
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production_bits),
                    tuple(variable.index.index for variable in recorded_bits),
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production_selected),
                    tuple(variable.index.index for variable in recorded_selected),
                )
                production_bc = production.variables[-1]
                recorder_bc = recorder.auxiliary_variables[-1]
                self.assertEqual(
                    production_bc.name,
                    recorder_bc.name.replace("/", " "),
                )
                self.assertEqual(
                    production_bc.index - 1,
                    recorder_bc.index.index,
                )
                self.assertEqual(
                    production.witness_value(production_bc),
                    recorder_backend.witness_value(recorder_bc),
                )
                self.assertEqual(
                    tuple(production.witness_value(variable) for variable in production_selected),
                    (table[pattern].u, table[pattern].v),
                )
                self.assertEqual(
                    tuple(recorder_backend.witness_value(variable) for variable in recorded_selected),
                    (table[pattern].u, table[pattern].v),
                )
                self.assertTrue(production.is_satisfied())

    def test_fixed_base_three_bit_lookup_recorder_partial_window_padding(self):
        table = _fixed_base_tables(
            sapling_fixed_base_generator("value_commitment_value")
        )[0]
        production = R1CS()
        production_bit = production.alloc_private("partial bit", 1)
        production.boolean(production_bit, "partial bit boolean")
        production_selected = allocate_jubjub_point(
            production, "partial selected", table[1]
        )
        _constrain_lookup3_point(
            production,
            (production_bit, 0, 0),
            table,
            production_selected,
            "partial lookup",
        )

        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorded_bit = recorder_backend.alloc_private("partial bit", 1)
        recorder_backend.enforce(
            recorded_bit.lc(),
            recorded_bit.lc() - 1,
            0,
            "partial bit boolean",
        )
        recorded_selected = allocate_jubjub_point(
            recorder_backend, "partial selected", table[1]
        )
        _constrain_lookup3_point(
            recorder_backend,
            (recorded_bit, 0, 0),
            table,
            recorded_selected,
            "partial lookup",
        )

        self.assertEqual(production.constraint_count, 3)
        self.assertEqual(recorder.constraint_count, 3)
        self.assertEqual(len(production.variables), 4)
        self.assertEqual(len(recorder.inputs) + len(recorder.auxiliary_variables), 4)
        self.assertEqual(
            tuple(row.label for row in production.constraints),
            (
                "partial bit boolean",
                "partial lookup coordinate[0]",
                "partial lookup coordinate[1]",
            ),
        )
        self.assertEqual(
            tuple(row.name for row in recorder.constraints),
            (
                "partial bit boolean",
                "partial lookup coordinate[0]",
                "partial lookup coordinate[1]",
            ),
        )
        self.assertEqual(
            production.serialize_matrix(), recorder.serialize_local_matrix()
        )
        self.assertFalse(any("bc" in variable.name for variable in production.variables))
        self.assertEqual(
            tuple(production.witness_value(variable) for variable in production_selected),
            (table[1].u, table[1].v),
        )
        self.assertEqual(
            tuple(recorder_backend.witness_value(variable) for variable in recorded_selected),
            (table[1].u, table[1].v),
        )
        self.assertTrue(production.is_satisfied())

    def test_fixed_base_three_bit_lookup_rejects_foreign_variables_before_mutation(self):
        table = _fixed_base_tables(
            sapling_fixed_base_generator("value_commitment_value")
        )[0]
        for backend_name in ("production", "recorder"):
            with self.subTest(backend=backend_name):
                if backend_name == "production":
                    system = R1CS()
                    bits = tuple(
                        system.alloc_private(f"input bit[{index}]", 0)
                        for index in range(3)
                    )
                    selected = allocate_jubjub_point(system, "selected", table[0])
                    foreign = R1CS().alloc_private("foreign bit", 0)
                    before = system.serialize()
                    with self.assertRaises(R1CSError):
                        _constrain_lookup3_point(
                            system, (bits[0], foreign, bits[2]), table, selected, "lookup"
                        )
                    self.assertEqual(system.serialize(), before)
                    foreign_recorder = RecorderSynthesisBackend(
                        BellmanSynthesisRecorder()
                    ).alloc_private("foreign recorder bit", 0)
                    with self.assertRaises(R1CSError):
                        _constrain_lookup3_point(
                            system,
                            (bits[0], foreign_recorder, bits[2]),
                            table,
                            selected,
                            "lookup",
                        )
                    self.assertEqual(system.serialize(), before)
                    foreign_system = R1CS()
                    foreign_selected = allocate_jubjub_point(
                        foreign_system, "foreign selected", table[0]
                    )
                    with self.assertRaises(R1CSError):
                        _constrain_lookup3_point(
                            system, bits, table, foreign_selected, "lookup"
                        )
                    self.assertEqual(system.serialize(), before)
                else:
                    recorder = BellmanSynthesisRecorder()
                    backend = RecorderSynthesisBackend(recorder)
                    bits = tuple(
                        backend.alloc_private(f"input bit[{index}]", 0)
                        for index in range(3)
                    )
                    selected = allocate_jubjub_point(backend, "selected", table[0])
                    foreign = RecorderSynthesisBackend(
                        BellmanSynthesisRecorder()
                    ).alloc_private("foreign bit", 0)
                    before = recorder.serialize()
                    with self.assertRaises(BellmanRecorderError):
                        _constrain_lookup3_point(
                            backend,
                            (bits[0], foreign, bits[2]),
                            table,
                            selected,
                            "lookup",
                        )
                    self.assertEqual(recorder.serialize(), before)
                    foreign_variable = R1CS().alloc_private(
                        "foreign production bit", 0
                    )
                    with self.assertRaises(BellmanRecorderError):
                        _constrain_lookup3_point(
                            backend,
                            (bits[0], foreign_variable, bits[2]),
                            table,
                            selected,
                            "lookup",
                        )
                    self.assertEqual(recorder.serialize(), before)
                    foreign_recorder = BellmanSynthesisRecorder()
                    foreign_backend = RecorderSynthesisBackend(foreign_recorder)
                    foreign_selected = allocate_jubjub_point(
                        foreign_backend, "foreign selected", table[0]
                    )
                    with self.assertRaises(BellmanRecorderError):
                        _constrain_lookup3_point(
                            backend, bits, table, foreign_selected, "lookup"
                        )
                    self.assertEqual(recorder.serialize(), before)

    def test_fixed_base_three_bit_lookup_preserves_invalid_witness_behavior(self):
        table = _fixed_base_tables(
            sapling_fixed_base_generator("value_commitment_value")
        )[0]
        for value in (None, 2):
            with self.subTest(value=value):
                production = R1CS()
                bits = tuple(
                    production.alloc_private(
                        f"input bit[{index}]", value if index == 1 else 0
                    )
                    for index in range(3)
                )
                for index, bit in enumerate(bits):
                    production.boolean(bit, f"input bit[{index}] boolean")
                selected = allocate_jubjub_point(production, "selected", table[0])
                _constrain_lookup3_point(production, bits, table, selected, "lookup")

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_bits = tuple(
                    backend.alloc_private(
                        f"input bit[{index}]", value if index == 1 else 0
                    )
                    for index in range(3)
                )
                for index, bit in enumerate(recorded_bits):
                    backend.enforce(
                        bit.lc(),
                        bit.lc() - 1,
                        0,
                        f"input bit[{index}] boolean",
                    )
                recorded_selected = allocate_jubjub_point(
                    backend, "selected", table[0]
                )
                _constrain_lookup3_point(
                    backend, recorded_bits, table, recorded_selected, "lookup"
                )

                self.assertEqual(
                    production.serialize_matrix(),
                    recorder.serialize_local_matrix(),
                )
                self.assertEqual(
                    production.witness_value(production.variables[-1]),
                    backend.witness_value(recorder.auxiliary_variables[-1]),
                )
                if value is None:
                    self.assertIsNone(production.witness_value(production.variables[-1]))
                    with self.assertRaisesRegex(
                        R1CSError, "constraint system has unassigned variables"
                    ):
                        production.is_satisfied()
                else:
                    self.assertEqual(production.witness_value(production.variables[-1]), 0)
                    self.assertFalse(production.is_satisfied())

    def test_fixed_base_window_orchestration_matches_across_backends(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        bit_values = (1, 0, 1, 1)
        witness = make_fixed_base_jubjub_witness(base, bit_values)

        production = R1CS()
        production_scope = production.namespace("outer").namespace("fixed")
        production_bits = tuple(
            production_scope.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bit_values)
        )
        production_result = _constrain_fixed_base_windows(
            production_scope, base, production_bits, witness, "windows"
        )

        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorder_scope = recorder_backend.namespace("outer").namespace("fixed")
        recorded_bits = tuple(
            recorder_scope.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bit_values)
        )
        recorded_result = _constrain_fixed_base_windows(
            recorder_scope, base, recorded_bits, witness, "windows"
        )

        self.assertEqual(production.constraint_count, 11)
        self.assertEqual(recorder.constraint_count, 11)
        self.assertEqual(len(production.variables), 16)
        self.assertEqual(
            len(recorder.inputs) + len(recorder.auxiliary_variables), 16
        )
        production_matrix = production.serialize_matrix()
        recorder_matrix = recorder.serialize_local_matrix()
        self.assertEqual(production_matrix, recorder_matrix)
        self.assertEqual(
            hashlib.sha256(production_matrix).digest(),
            hashlib.sha256(recorder_matrix).digest(),
        )
        self.assertEqual(
            hashlib.sha256(production_matrix).hexdigest(),
            "d0bb18f6a9dbb97594fb879fd6946be554b9f68cb35acefe59f829319e0f8d72",
        )
        self.assertEqual(
            tuple(row.label for row in production.constraints),
            (
                "outer fixed windows lookup[0] bc multiplication",
                "outer fixed windows lookup[0] coordinate[0]",
                "outer fixed windows lookup[0] coordinate[1]",
                "outer fixed windows lookup[1] coordinate[0]",
                "outer fixed windows lookup[1] coordinate[1]",
                "outer fixed windows addition[1] U multiplication",
                "outer fixed windows addition[1] A multiplication",
                "outer fixed windows addition[1] B multiplication",
                "outer fixed windows addition[1] C multiplication",
                "outer fixed windows addition[1] u division relation",
                "outer fixed windows addition[1] v division relation",
            ),
        )
        self.assertEqual(
            tuple(row.name for row in recorder.constraints),
            tuple(
                row.label.replace("outer fixed ", "outer/fixed/", 1)
                for row in production.constraints
            ),
        )
        production_variables = production.variables[1:]
        recorder_variables = (
            recorder.inputs[1:] + recorder.auxiliary_variables
        )
        self.assertEqual(len(production_variables), len(recorder_variables))
        self.assertEqual(
            tuple(variable.index - 1 for variable in production_variables),
            tuple(range(len(recorder_variables))),
        )
        self.assertEqual(
            tuple(variable.name for variable in production_variables),
            tuple(variable.name.replace("/", " ") for variable in recorder_variables),
        )
        self.assertEqual(
            tuple(production.witness_value(variable) for variable in production_variables),
            tuple(recorder_backend.witness_value(variable) for variable in recorder_variables),
        )
        self.assertEqual(
            tuple(production.witness_value(variable) for variable in production_result),
            (witness.result.u, witness.result.v),
        )
        self.assertEqual(
            tuple(recorder_backend.witness_value(variable) for variable in recorded_result),
            (witness.result.u, witness.result.v),
        )
        self.assertTrue(production.is_satisfied())

    def test_fixed_base_window_orchestration_rejects_foreign_bits_before_mutation(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        bit_values = (1, 0, 1, 1)
        witness = make_fixed_base_jubjub_witness(base, bit_values)

        production = R1CS()
        production_bits = tuple(
            production.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bit_values)
        )
        foreign_production = R1CS().alloc_private("foreign scalar bit", 1)
        before_production = production.serialize()
        with self.assertRaises(R1CSError):
            _constrain_fixed_base_windows(
                production,
                base,
                (*production_bits[:3], foreign_production),
                witness,
                "windows",
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_bits = tuple(
            backend.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bit_values)
        )
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign scalar bit", 1)
        before_recorder = recorder.serialize()
        with self.assertRaises(BellmanRecorderError):
            _constrain_fixed_base_windows(
                backend,
                base,
                (*recorded_bits[:3], foreign_recorder),
                witness,
                "windows",
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_fixed_base_scalar_validation_matches_across_backends(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        for scalar in (0, 1, JUBJUB_SCALAR_MODULUS - 1):
            with self.subTest(scalar=scalar):
                bits_le = tuple(
                    (scalar >> index) & 1
                    for index in range(JUBJUB_SCALAR_MODULUS.bit_length())
                )
                witness = make_fixed_base_jubjub_witness(base, bits_le)

                production = R1CS()
                production_scope = production.namespace("outer").namespace(
                    "validation"
                )
                production_bits = tuple(
                    production_scope.alloc_private(
                        f"scalar bit[{index}]", bit
                    )
                    for index, bit in enumerate(bits_le)
                )
                production_values = _constrain_fixed_base_scalar(
                    production_scope,
                    production_bits,
                    witness,
                    "scalar",
                    True,
                    False,
                )

                recorder = BellmanSynthesisRecorder()
                recorder_backend = RecorderSynthesisBackend(recorder)
                recorder_scope = recorder_backend.namespace("outer").namespace(
                    "validation"
                )
                recorded_bits = tuple(
                    recorder_scope.alloc_private(
                        f"scalar bit[{index}]", bit
                    )
                    for index, bit in enumerate(bits_le)
                )
                recorded_values = _constrain_fixed_base_scalar(
                    recorder_scope,
                    recorded_bits,
                    witness,
                    "scalar",
                    True,
                    False,
                )

                self.assertEqual(production_values, bits_le)
                self.assertEqual(recorded_values, bits_le)
                self.assertEqual(
                    production.serialize_matrix(),
                    recorder.serialize_local_matrix(),
                )
                self.assertEqual(
                    hashlib.sha256(production.serialize_matrix()).hexdigest(),
                    hashlib.sha256(
                        recorder.serialize_local_matrix()
                    ).hexdigest(),
                )
                self.assertEqual(
                    tuple(row.label for row in production.constraints),
                    tuple(
                        row.name.replace("/", " ")
                        for row in recorder.constraints
                    ),
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production_bits),
                    tuple(variable.index.index for variable in recorded_bits),
                )
                self.assertEqual(
                    tuple(
                        variable.name for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.name.replace("/", " ")
                        for variable in (
                            recorder.inputs[1:] + recorder.auxiliary_variables
                        )
                    ),
                )
                self.assertEqual(
                    tuple(
                        production.witness_value(variable)
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        recorder_backend.witness_value(variable)
                        for variable in (
                            recorder.inputs[1:] + recorder.auxiliary_variables
                        )
                    ),
                )
                self.assertEqual(
                    production.constraint_count,
                    recorder.constraint_count,
                )
                self.assertEqual(production.constraint_count, 876)
                self.assertEqual(len(production.variables), 875)
                self.assertEqual(
                    hashlib.sha256(
                        production.serialize_matrix()
                    ).hexdigest(),
                    "22dd60e383842b4500b7bfb1a0664af072fd14b4b5df420ffb68100d83997ad5",
                )
                self.assertTrue(production.is_satisfied())

    def test_fixed_base_scalar_validation_rejects_invalid_and_foreign_bits_before_mutation(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        zero_bits = (0,) * JUBJUB_SCALAR_MODULUS.bit_length()
        witness = make_fixed_base_jubjub_witness(base, zero_bits)

        production = R1CS()
        production_bits = _allocate_jubjub_scalar_bits(
            production, zero_bits, "scalar bit"
        )
        foreign_production = R1CS().alloc_private("foreign scalar bit", 0)
        before_production = production.serialize()
        with self.assertRaises(R1CSError):
            _constrain_fixed_base_scalar(
                production,
                (*production_bits[:-1], foreign_production),
                witness,
                "scalar",
                True,
                False,
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorded_bits = _allocate_jubjub_scalar_bits(
            recorder_backend, zero_bits, "scalar bit"
        )
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign scalar bit", 0)
        before_recorder = recorder.serialize()
        with self.assertRaises(BellmanRecorderError):
            _constrain_fixed_base_scalar(
                recorder_backend,
                (*recorded_bits[:-1], foreign_recorder),
                witness,
                "scalar",
                True,
                False,
            )
        self.assertEqual(recorder.serialize(), before_recorder)

        for invalid_value in (None, 2):
            with self.subTest(invalid_value=invalid_value):
                invalid_bits = (invalid_value,) + (0,) * (
                    len(zero_bits) - 1
                )
                invalid_witness = replace(witness, bit_values=invalid_bits)
                production_invalid = R1CS()
                invalid_variables = _allocate_jubjub_scalar_bits(
                    production_invalid, invalid_bits, "invalid scalar bit"
                )
                before_invalid = production_invalid.serialize()
                with self.assertRaises(R1CSError):
                    _constrain_fixed_base_scalar(
                        production_invalid,
                        invalid_variables,
                        invalid_witness,
                        "invalid scalar",
                        False,
                        False,
                    )
                self.assertEqual(production_invalid.serialize(), before_invalid)
                recorder_invalid = BellmanSynthesisRecorder()
                recorder_invalid_backend = RecorderSynthesisBackend(
                    recorder_invalid
                )
                invalid_recorded_variables = _allocate_jubjub_scalar_bits(
                    recorder_invalid_backend,
                    invalid_bits,
                    "invalid scalar bit",
                )
                before_recorded_invalid = recorder_invalid.serialize()
                with self.assertRaises(R1CSError):
                    _constrain_fixed_base_scalar(
                        recorder_invalid_backend,
                        invalid_recorded_variables,
                        invalid_witness,
                        "invalid scalar",
                        False,
                        False,
                    )
                self.assertEqual(
                    recorder_invalid.serialize(), before_recorded_invalid
                )

        out_of_range_value = JUBJUB_SCALAR_MODULUS
        out_of_range_bits = tuple(
            (out_of_range_value >> index) & 1
            for index in range(JUBJUB_SCALAR_MODULUS.bit_length())
        )
        out_of_range_witness = replace(witness, bit_values=out_of_range_bits)
        out_of_range_system = R1CS()
        out_of_range_variables = _allocate_jubjub_scalar_bits(
            out_of_range_system,
            out_of_range_bits,
            "out-of-range scalar bit",
        )
        before_out_of_range = out_of_range_system.serialize()
        with self.assertRaisesRegex(R1CSError, "outside the Jubjub scalar field"):
            _constrain_fixed_base_scalar(
                out_of_range_system,
                out_of_range_variables,
                out_of_range_witness,
                "out-of-range scalar",
                True,
                False,
            )
        self.assertEqual(out_of_range_system.serialize(), before_out_of_range)
        out_of_range_recorder = BellmanSynthesisRecorder()
        out_of_range_backend = RecorderSynthesisBackend(out_of_range_recorder)
        out_of_range_recorded_variables = _allocate_jubjub_scalar_bits(
            out_of_range_backend,
            out_of_range_bits,
            "out-of-range scalar bit",
        )
        before_out_of_range_recorder = out_of_range_recorder.serialize()
        with self.assertRaisesRegex(
            R1CSError, "outside the Jubjub scalar field"
        ):
            _constrain_fixed_base_scalar(
                out_of_range_backend,
                out_of_range_recorded_variables,
                out_of_range_witness,
                "out-of-range scalar",
                True,
                False,
            )
        self.assertEqual(
            out_of_range_recorder.serialize(), before_out_of_range_recorder
        )

        one_bits = (1,) + (0,) * (len(zero_bits) - 1)
        one_witness = make_fixed_base_jubjub_witness(base, one_bits)
        for backend_name in ("production", "recorder"):
            with self.subTest(backend=backend_name, case="mismatched witness"):
                if backend_name == "production":
                    system = R1CS()
                    variables = _allocate_jubjub_scalar_bits(
                        system, zero_bits, "mismatched scalar bit"
                    )
                    before = system.serialize()
                else:
                    recorder = BellmanSynthesisRecorder()
                    system = RecorderSynthesisBackend(recorder)
                    variables = _allocate_jubjub_scalar_bits(
                        system, zero_bits, "mismatched scalar bit"
                    )
                    before = recorder.serialize()
                with self.assertRaisesRegex(
                    R1CSError, "does not match the assigned scalar bits"
                ):
                    _constrain_fixed_base_scalar(
                        system,
                        variables,
                        one_witness,
                        "mismatched scalar",
                        False,
                        False,
                    )
                self.assertEqual(
                    system.serialize() if backend_name == "production" else recorder.serialize(),
                    before,
                )

    def test_fixed_base_scalar_validation_preserves_preconstrained_branch(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        bits_le = (1, 0, 1, 1)
        witness = make_fixed_base_jubjub_witness(base, bits_le)
        production = R1CS()
        production_bits = tuple(
            production.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bits_le)
        )
        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_bits = tuple(
            backend.alloc_private(f"scalar bit[{index}]", value)
            for index, value in enumerate(bits_le)
        )
        self.assertEqual(
            _constrain_fixed_base_scalar(
                production, production_bits, witness, "scalar", False, True
            ),
            bits_le,
        )
        self.assertEqual(
            _constrain_fixed_base_scalar(
                backend, recorded_bits, witness, "scalar", False, True
            ),
            bits_le,
        )
        self.assertEqual(production.constraint_count, 0)
        self.assertEqual(recorder.constraint_count, 0)
        self.assertEqual(
            production.serialize_matrix(), recorder.serialize_local_matrix()
        )

    def test_fixed_base_scalar_validation_and_windows_integrate_across_backends(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        bits_le = (0,) * JUBJUB_SCALAR_MODULUS.bit_length()
        witness = make_fixed_base_jubjub_witness(base, bits_le)

        production = R1CS()
        production_bits = _allocate_jubjub_scalar_bits(
            production, bits_le, "scalar bit"
        )
        production_result = _constrain_fixed_base_jubjub_mul(
            production,
            base,
            production_bits,
            witness,
            "fixed-base",
            True,
            False,
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_bits = _allocate_jubjub_scalar_bits(
            backend, bits_le, "scalar bit"
        )
        recorded_result = _constrain_fixed_base_jubjub_mul(
            backend,
            base,
            recorded_bits,
            witness,
            "fixed-base",
            True,
            False,
        )

        self.assertEqual(production.constraint_count, 1626)
        self.assertEqual(recorder.constraint_count, 1626)
        self.assertEqual(len(production.variables), 1625)
        self.assertEqual(
            len(recorder.inputs) + len(recorder.auxiliary_variables), 1625
        )
        production_matrix = production.serialize_matrix()
        recorder_matrix = recorder.serialize_local_matrix()
        self.assertEqual(production_matrix, recorder_matrix)
        self.assertEqual(
            hashlib.sha256(production_matrix).hexdigest(),
            hashlib.sha256(recorder_matrix).hexdigest(),
        )
        self.assertEqual(
            hashlib.sha256(production_matrix).hexdigest(),
            "aadef2e1b28c133bb86798085aa92f66525af7eac38d46e673f8f003bfb401f0",
        )
        self.assertEqual(
            tuple(row.label for row in production.constraints),
            tuple(
                row.name.replace("/", " ")
                for row in recorder.constraints
            ),
        )
        self.assertEqual(
            tuple(variable.index - 1 for variable in production.variables[1:]),
            tuple(
                variable.index.index
                for variable in (
                    recorder.inputs[1:] + recorder.auxiliary_variables
                )
            ),
        )
        self.assertEqual(
            tuple(
                production.witness_value(variable)
                for variable in production.variables[1:]
            ),
            tuple(
                backend.witness_value(variable)
                for variable in (
                    recorder.inputs[1:] + recorder.auxiliary_variables
                )
            ),
        )
        self.assertEqual(
            tuple(production.witness_value(variable) for variable in production_result),
            tuple(backend.witness_value(variable) for variable in recorded_result),
        )
        self.assertTrue(production.is_satisfied())

    def test_fixed_base_jubjub_multiplication_constraints_and_tampering(self):
        base = sapling_fixed_base_generator("spending_key")
        scalar_bits = bits_le(5, JUBJUB_SCALAR_MODULUS.bit_length())
        witness = make_fixed_base_jubjub_witness(base, scalar_bits)
        system = R1CS()
        bits = tuple(
            system.alloc_private(f"fixed scalar bit[{index}]", bit)
            for index, bit in enumerate(scalar_bits)
        )
        result = constrain_fixed_base_jubjub_mul(system, base, bits, witness)

        self.assertEqual(
            (system._witness_value(result[0]), system._witness_value(result[1])),
            (witness.result.u, witness.result.v),
        )
        self.assertEqual(system.constraint_count, 1626)
        self.assertTrue(
            any(
                constraint.label.startswith(
                    "Sapling fixed-base Jubjub multiplication scalar range"
                )
                for constraint in system.constraints
            )
        )
        scalar_bit_labels = [
            constraint.label
            for constraint in system.constraints
            if constraint.label.startswith(
                "Sapling fixed-base Jubjub multiplication scalar bit["
            )
        ]
        self.assertEqual(len(scalar_bit_labels), len(scalar_bits))
        self.assertEqual(
            scalar_bit_labels,
            [
                f"Sapling fixed-base Jubjub multiplication scalar bit[{index}]"
                for index in range(len(scalar_bits))
            ],
        )
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({bits[0].index: 0}))

        altered_selections = list(witness.selected_points)
        altered_selections[0] = Point(
            altered_selections[0].u + 1, altered_selections[0].v
        )
        altered_witness = replace(
            witness, selected_points=tuple(altered_selections)
        )
        altered_system = R1CS()
        altered_bits = tuple(
            altered_system.alloc_private(f"altered scalar bit[{index}]", bit)
            for index, bit in enumerate(scalar_bits)
        )
        constrain_fixed_base_jubjub_mul(
            altered_system, base, altered_bits, altered_witness
        )
        self.assertFalse(altered_system.is_satisfied())

        altered_accumulators = list(witness.accumulators)
        altered_accumulators[-1] = Point(
            altered_accumulators[-1].u + 1, altered_accumulators[-1].v
        )
        altered_witness = replace(
            witness,
            accumulators=tuple(altered_accumulators),
            result=altered_accumulators[-1],
        )
        altered_system = R1CS()
        altered_bits = tuple(
            altered_system.alloc_private(f"altered output bit[{index}]", bit)
            for index, bit in enumerate(scalar_bits)
        )
        constrain_fixed_base_jubjub_mul(
            altered_system, base, altered_bits, altered_witness
        )
        self.assertFalse(altered_system.is_satisfied())

    def test_fixed_base_witness_boundaries_and_malformed_scalars(self):
        base = sapling_fixed_base_generator("value_commitment_value")
        width = JUBJUB_SCALAR_MODULUS.bit_length()
        zero = make_fixed_base_jubjub_witness(base, bits_le(0, width))
        one = make_fixed_base_jubjub_witness(base, bits_le(1, width))
        maximum = make_fixed_base_jubjub_witness(
            base, bits_le(JUBJUB_SCALAR_MODULUS - 1, width)
        )
        self.assertEqual(zero.result, Point(0, 1))
        self.assertEqual(one.result, base)
        self.assertEqual(maximum.result, Point(-base.u, base.v))
        with self.assertRaises(R1CSError):
            make_fixed_base_jubjub_witness(
                base, bits_le(JUBJUB_SCALAR_MODULUS, width)
            )
        with self.assertRaises(R1CSError):
            make_fixed_base_jubjub_witness(base, bits_le(1, 0))
        with self.assertRaises(R1CSError):
            make_fixed_base_jubjub_witness(base, bits_le(1, width + 1))
        with self.assertRaises(R1CSError):
            make_fixed_base_jubjub_witness(Point(1, 1), bits_le(1, width))
        with self.assertRaises(R1CSError):
            make_fixed_base_jubjub_witness(
                Point(0, FIELD_MODULUS - 1), bits_le(1, width)
            )
        with self.assertRaises(ValueError):
            sapling_fixed_base_generator("unrecognized")

    def test_fixed_base_supports_upstream_u64_and_position_widths(self):
        base = sapling_fixed_base_generator("nullifier_position")
        for width, expected_constraints in ((32, 124), (64, 255)):
            with self.subTest(width=width):
                scalar_bits = bits_le(5, width)
                witness = make_fixed_base_jubjub_witness(base, scalar_bits)
                system = R1CS()
                bits = tuple(
                    system.alloc_private(f"scalar bit[{index}]", bit)
                    for index, bit in enumerate(scalar_bits)
                )
                result = constrain_fixed_base_jubjub_mul(
                    system, base, bits, witness
                )
                self.assertEqual(system.constraint_count, expected_constraints)
                self.assertEqual(
                    (
                        system._witness_value(result[0]),
                        system._witness_value(result[1]),
                    ),
                    (base.multiply(5).u, base.multiply(5).v),
                )
                self.assertTrue(system.is_satisfied())

    def test_pedersen_constraints_match_pinned_merkle_vector(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        vector = fixture["pedersen_merkle_crh_vector"]
        depth = vector["level"]
        left_value = int.from_bytes(bytes.fromhex(vector["left"]), "little")
        right_value = int.from_bytes(bytes.fromhex(vector["right"]), "little")
        depth_values = bits_le(depth, 6)

        reference_point = _pedersen_hash(
            list(depth_values)
            + list(bits_le(left_value, 255))
            + list(bits_le(right_value, 255)),
            _pedersen_generators(6),
        )

        system = R1CS()
        personalization = tuple(
            system.alloc_private(f"personalization[{index}]", bit)
            for index, bit in enumerate(depth_values)
        )
        left = system.alloc_private("left field", left_value)
        right = system.alloc_private("right field", right_value)
        left_bits = system.range_check(
            left, 255, "left bit", upper_bound=SCALAR_MODULUS
        )
        right_bits = system.range_check(
            right, 255, "right bit", upper_bound=SCALAR_MODULUS
        )
        message_bits = left_bits + right_bits
        witness = make_pedersen_witness(
            depth_values,
            bits_le(left_value, 255) + bits_le(right_value, 255),
        )
        result = constrain_pedersen_hash(
            system, personalization, message_bits, witness
        )
        expected = int.from_bytes(bytes.fromhex(vector["expected"]), "little")
        self.assertEqual(system._witness_value(result[0]), expected)
        self.assertEqual(system._witness_value(result[1]), reference_point.v)
        self.assertEqual(expected, reference_point.u)
        self.assertEqual(system.constraint_count, 3350)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(
            system.is_satisfied(
                {
                    message_bits[0].index: 1
                    - system._witness_value(message_bits[0])
                }
            )
        )

    def test_pedersen_montgomery_relation_matches_production_and_recorder(self):
        vector = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))[
            "cases"
        ][0]
        witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(vector["transmission_key"]),
                check_subgroup=True,
            ),
            int.from_bytes(bytes.fromhex(vector["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(vector["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(vector["esk"]), "little"),
        ).note_commitment.note_hash
        message_values = witness.bit_values[6:]

        def capture(system, representation):
            bits = tuple(
                system.alloc_private(f"Pedersen input[{index}]", value)
                for index, value in enumerate(message_values)
            )
            for index, bit in enumerate(bits):
                if isinstance(system, R1CS):
                    system.boolean(bit, f"Pedersen input Boolean[{index}]")
                else:
                    system.enforce(
                        bit,
                        bit.lc() - 1,
                        0,
                        f"Pedersen input Boolean[{index}]",
                    )
            result = constrain_pedersen_hash(
                cast(SynthesisBackend, system),
                (1,) * 6,
                cast(Sequence[CircuitBit | VariableLike], bits),
                witness,
                "Output isolated Pedersen",
                message_bits_preconstrained=True,
                representation=representation,
            )
            if isinstance(system, R1CS):
                variables = system.variables[1:]
                rows = system.constraints
                matrix = system.serialize_matrix()
                labels = tuple(row.label for row in rows)
                names = tuple(variable.name for variable in variables)
                assignments = tuple(
                    system.witness_value(variable) for variable in variables
                )
                mappings = tuple(variable.index for variable in variables)
                satisfied = system.is_satisfied()
            else:
                variables = (
                    system.recorder.inputs[1:]
                    + system.recorder.auxiliary_variables
                )
                rows = system.recorder.constraints
                matrix = system.recorder.serialize_local_matrix()
                labels = tuple(row.name.replace("/", " ") for row in rows)
                names = tuple(
                    variable.name.replace("/", " ") for variable in variables
                )
                assignments = tuple(
                    system.witness_value(variable) for variable in variables
                )
                mappings = tuple(
                    variable.index.index
                    if variable.index.kind == "input"
                    else len(system.recorder.inputs) + variable.index.index
                    for variable in variables
                )

                def evaluate(expression):
                    value = 0
                    for variable, coefficient in expression.terms:
                        self.assertIsNotNone(variable.value)
                        value += variable.value * coefficient
                    return value % SCALAR_MODULUS

                satisfied = all(
                    evaluate(row.a) * evaluate(row.b) % SCALAR_MODULUS
                    == evaluate(row.c)
                    for row in rows
                )
            return (
                len(rows),
                len(variables) + 1,
                matrix,
                labels,
                names,
                assignments,
                mappings,
                tuple(system.witness_value(point) for point in result),
                satisfied,
            )

        for representation, expected_rows in (
            ("edwards", 2314),
            ("montgomery", 1558),
        ):
            with self.subTest(representation=representation):
                production_result = capture(R1CS(), representation)
                recorder = BellmanSynthesisRecorder()
                recorder_result = capture(
                    RecorderSynthesisBackend(recorder), representation
                )

                self.assertEqual(production_result[:8], recorder_result[:8])
                self.assertEqual(
                    production_result[0:2], (expected_rows, expected_rows + 1)
                )
                self.assertEqual(
                    production_result[7], (witness.result.u, witness.result.v)
                )
                self.assertTrue(production_result[8])
                self.assertTrue(recorder_result[8])

    def test_pedersen_rejects_bad_bits_before_backend_mutation(self):
        witness = make_pedersen_witness((1,) * 6, (0, 0, 0))
        for backend_name in ("production", "recorder"):
            for invalid_kind in (
                "out-of-range",
                "unassigned",
                "foreign",
                "malformed",
            ):
                with self.subTest(backend=backend_name, invalid=invalid_kind):
                    if backend_name == "production":
                        system = R1CS()
                        bits = tuple(
                            system.alloc_private(
                                f"Pedersen input[{index}]",
                                2 if invalid_kind == "out-of-range"
                                and index == 0 else
                                None if invalid_kind == "unassigned"
                                and index == 0 else 0,
                            )
                            for index in range(3)
                        )
                        if invalid_kind == "foreign":
                            bits = (
                                R1CS().alloc_private("foreign bit", 0),
                                bits[1],
                                bits[2],
                            )
                        if invalid_kind == "malformed":
                            bits = (object(), bits[1], bits[2])
                        before = system.serialize()
                    else:
                        recorder = BellmanSynthesisRecorder()
                        system = RecorderSynthesisBackend(recorder)
                        bits = tuple(
                            system.alloc_private(
                                f"Pedersen input[{index}]",
                                2 if invalid_kind == "out-of-range"
                                and index == 0 else
                                None if invalid_kind == "unassigned"
                                and index == 0 else 0,
                            )
                            for index in range(3)
                        )
                        if invalid_kind == "foreign":
                            foreign_backend = RecorderSynthesisBackend(
                                BellmanSynthesisRecorder()
                            )
                            bits = (
                                foreign_backend.alloc_private("foreign bit", 0),
                                bits[1],
                                bits[2],
                            )
                        if invalid_kind == "malformed":
                            bits = ("0", bits[1], bits[2])
                        before = recorder.serialize()
                    with self.assertRaises((R1CSError, BellmanRecorderError, TypeError)):
                        constrain_pedersen_hash(
                            cast(SynthesisBackend, system),
                            (1,) * 6,
                            cast(Sequence[CircuitBit | VariableLike], bits),
                            witness,
                            "invalid Pedersen",
                            representation="montgomery",
                        )
                    after = (
                        system.serialize()
                        if backend_name == "production"
                        else recorder.serialize()
                    )
                    self.assertEqual(after, before)

    def test_pedersen_segment_boundary_counts_match_pinned_formula(self):
        upstream_hash_rows = {
            183: 312,
            184: 321,
            185: 322,
            510: 867,
            576: 982,
        }
        local_hash_rows = {
            183: 559,
            184: 567,
            185: 568,
            510: 1540,
            576: 1738,
        }

        for message_length, upstream_rows in upstream_hash_rows.items():
            with self.subTest(message_length=message_length):
                message_values = (0,) * message_length
                witness = make_pedersen_witness((1,) * 6, message_values)
                expected_point = _pedersen_hash(
                    [1] * 6 + list(message_values),
                    _pedersen_generators(6),
                )
                self.assertEqual(witness.result, expected_point)

                system = R1CS()
                message_bits = tuple(
                    system.alloc_private(f"boundary bit[{index}]", bit)
                    for index, bit in enumerate(message_values)
                )
                constrain_pedersen_hash(
                    system, (1,) * 6, message_bits, witness
                )
                self.assertEqual(
                    system.constraint_count - message_length,
                    local_hash_rows[message_length],
                )
                self.assertEqual(
                    system.constraint_count,
                    message_length + local_hash_rows[message_length],
                )
                self.assertTrue(system.is_satisfied())
                self.assertGreater(
                    local_hash_rows[message_length], upstream_rows
                )

                reference_system = R1CS()
                reference_bits = tuple(
                    reference_system.alloc_private(
                        f"reference boundary bit[{index}]", bit
                    )
                    for index, bit in enumerate(message_values)
                )
                for index, bit in enumerate(reference_bits):
                    reference_system.boolean(
                        bit, f"reference boundary Boolean[{index}]"
                    )
                reference_result = synthesize_pedersen_hash(
                    reference_system, (1,) * 6, reference_bits
                )
                self.assertEqual(
                    reference_system.constraint_count,
                    message_length + upstream_rows,
                )
                self.assertEqual(
                    len(reference_system.variables),
                    1 + message_length + upstream_rows,
                )
                self.assertEqual(
                    tuple(
                        reference_system._witness_value(point)
                        for point in reference_result
                    ),
                    (expected_point.u, expected_point.v),
                )
                self.assertTrue(reference_system.is_satisfied())
                if message_length in (510, 576):
                    repeat_system = R1CS()
                    repeat_bits = tuple(
                        repeat_system.alloc_private(
                            f"repeat boundary bit[{index}]", bit
                        )
                        for index, bit in enumerate(message_values)
                    )
                    for index, bit in enumerate(repeat_bits):
                        repeat_system.boolean(
                            bit, f"repeat boundary Boolean[{index}]"
                        )
                    synthesize_pedersen_hash(
                        repeat_system, (1,) * 6, repeat_bits
                    )
                    self.assertEqual(
                        repeat_system.serialize_matrix(),
                        reference_system.serialize_matrix(),
                    )
                    self.assertEqual(
                        repeat_system.matrix_fingerprint(),
                        reference_system.matrix_fingerprint(),
                    )

    def test_spend_pedersen_matrices_match_reference_outputs_at_all_consumers(self):
        source_witness = generate_pinned_test_witness(0)
        self.assertEqual(
            _pedersen_montgomery_tables(),
            reference_pedersen_montgomery_tables(),
        )
        note_witness = make_note_commitment_witness(
            source_witness.value,
            source_witness.diversifier_base,
            source_witness.transmission_key,
            source_witness.rcm,
        )
        cases = [
            (
                "note",
                (1,) * 6,
                note_witness.note_hash.bit_values[6:],
                note_witness.note_hash.result,
            )
        ]
        path_witness = make_merkle_path_witness(
            source_witness.note_commitment.u,
            tuple(sibling for sibling, _ in source_witness.authentication_path),
            source_witness.position,
        )
        for depth, pedersen_witness in enumerate(path_witness.pedersen_hashes):
            cases.append(
                (
                    f"merkle depth {depth}",
                    pedersen_witness.bit_values[:6],
                    pedersen_witness.bit_values[6:],
                    pedersen_witness.result,
                )
            )

        reference_fingerprints = set()
        local_fingerprints = set()
        for name, personalization, message, expected in cases:
            with self.subTest(configuration=name):
                pedersen_witness = make_pedersen_witness(
                    personalization, message
                )
                self.assertEqual(pedersen_witness.result, expected)
                matrices = {}
                for implementation in (
                    "edwards",
                    "montgomery",
                    "bellman-reference",
                ):
                    system = R1CS()
                    input_bits = tuple(
                        system.alloc_private(f"{name} input[{index}]", bit)
                        for index, bit in enumerate(message)
                    )
                    for index, bit in enumerate(input_bits):
                        system.boolean(bit, f"{name} input Boolean[{index}]")
                    if implementation in ("edwards", "montgomery"):
                        result = constrain_pedersen_hash(
                            system,
                            personalization,
                            input_bits,
                            pedersen_witness,
                            f"{name} {implementation}",
                            message_bits_preconstrained=True,
                            representation=(
                                "montgomery"
                                if implementation == "montgomery"
                                else "edwards"
                            ),
                        )
                    else:
                        result = synthesize_pedersen_hash(
                            system,
                            personalization,
                            input_bits,
                            f"{name} Bellman reference",
                        )
                    self.assertEqual(
                        tuple(system._witness_value(point) for point in result),
                        (expected.u, expected.v),
                    )
                    self.assertTrue(system.is_satisfied())
                    matrices[implementation] = (
                        system,
                        system.serialize_matrix(),
                        system.matrix_fingerprint(),
                        result,
                    )

                (
                    local_system,
                    local_matrix,
                    local_fingerprint,
                    _,
                ) = matrices["edwards"]
                montgomery_system, montgomery_matrix, montgomery_fingerprint, (
                    montgomery_u,
                    _,
                ) = matrices["montgomery"]
                reference_system, reference_matrix, reference_fingerprint = (
                    matrices["bellman-reference"][:3]
                )
                self.assertNotEqual(local_matrix, reference_matrix)
                self.assertEqual(montgomery_matrix, reference_matrix)
                self.assertEqual(montgomery_fingerprint, reference_fingerprint)
                self.assertEqual(
                    montgomery_system.constraint_count,
                    reference_system.constraint_count,
                )
                self.assertEqual(
                    len(montgomery_system.variables),
                    len(reference_system.variables),
                )
                self.assertTrue(montgomery_system.is_satisfied())
                windows = (6 + len(message) + 2) // 3
                segments = (windows + 62) // 63
                expected_structure_delta = 4 * windows - 5 * segments
                self.assertEqual(
                    local_system.constraint_count
                    - reference_system.constraint_count,
                    expected_structure_delta,
                )
                self.assertEqual(
                    len(local_system.variables) - len(reference_system.variables),
                    expected_structure_delta,
                )
                if name == "note":
                    self.assertEqual(local_system.constraint_count, 2314)
                    self.assertEqual(len(local_system.variables), 2315)
                    self.assertEqual(reference_system.constraint_count, 1558)
                    self.assertEqual(len(reference_system.variables), 1559)
                    self.assertEqual(
                        local_fingerprint,
                        "94febbae8187b627cc2fc95f6d923f3ce25ff45946d738d4310a9e14274b79d2",
                    )
                    self.assertEqual(
                        reference_fingerprint,
                        "b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76",
                    )
                    self.assertFalse(
                        reference_system.is_satisfied(
                            {
                                reference_system.variables[1].index:
                                    1 - reference_system._witness_value(
                                        reference_system.variables[1]
                                    )
                            }
                        )
                    )
                    reference_result = matrices["bellman-reference"][3]
                    self.assertFalse(
                        reference_system.is_satisfied(
                            {
                                reference_result[0].index:
                                    reference_system._witness_value(
                                        reference_result[0]
                                    ) + 1
                            }
                        )
                    )
                    self.assertEqual(
                        reference_system.matrix_fingerprint(),
                        reference_fingerprint,
                    )
                    self.assertFalse(
                        montgomery_system.is_satisfied(
                            {
                                montgomery_system.variables[1].index:
                                    1 - montgomery_system._witness_value(
                                        montgomery_system.variables[1]
                                    )
                            }
                        )
                    )
                    self.assertFalse(
                        montgomery_system.is_satisfied(
                            {
                                montgomery_system.variables[3].index:
                                    1 - montgomery_system._witness_value(
                                        montgomery_system.variables[3]
                                    )
                            }
                        )
                    )
                    for variable_name in (
                        "note montgomery segment[0] window[3] y",
                        "note montgomery segment[0] addition[3] lambda",
                        "note montgomery segment[0] conversion u",
                        "note montgomery segment[1] combination U",
                    ):
                        variable = next(
                            variable
                            for variable in montgomery_system.variables
                            if variable.name == variable_name
                        )
                        self.assertFalse(
                            montgomery_system.is_satisfied(
                                {
                                    variable.index:
                                        montgomery_system._witness_value(variable)
                                        + 1
                                }
                            )
                        )
                    self.assertFalse(
                        montgomery_system.is_satisfied(
                            {
                                montgomery_u.index:
                                    montgomery_system._witness_value(montgomery_u)
                                    + 1
                            }
                        )
                    )
                else:
                    self.assertEqual(local_system.constraint_count, 2050)
                    self.assertEqual(len(local_system.variables), 2051)
                    self.assertEqual(reference_system.constraint_count, 1377)
                    self.assertEqual(len(reference_system.variables), 1378)
                    if name == "merkle depth 25":
                        self.assertEqual(
                            local_fingerprint,
                            "686c70259fd8cbf046c4cde6eee4510a0b84d0ab6dd7888107a157be10254185",
                        )
                        self.assertEqual(
                            reference_fingerprint,
                            "706c8e1c013c93d98a05a0c47f43dc048d67bb3817e8623001bfc79b7b7c8c86",
                        )
                    reference_fingerprints.add(reference_fingerprint)
                    local_fingerprints.add(local_fingerprint)

        self.assertEqual(len(reference_fingerprints), 32)
        self.assertEqual(len(local_fingerprints), 32)

    def test_signed_pedersen_lookup_uses_three_rows_and_binds_all_patterns(self):
        table = _pedersen_tables()[0][0]
        for pattern in range(8):
            with self.subTest(pattern=pattern):
                bit_values = tuple((pattern >> index) & 1 for index in range(3))
                system = R1CS()
                bits = tuple(
                    system.alloc_private(f"lookup bit[{index}]", value)
                    for index, value in enumerate(bit_values)
                )
                for index, bit in enumerate(bits):
                    system.boolean(bit, f"lookup bit[{index}]")
                selected = allocate_jubjub_point(
                    system, "selected", table[pattern]
                )
                before = system.constraint_count
                _constrain_signed_lookup3_point(
                    system, bits, table, selected, "signed lookup"
                )

                self.assertEqual(system.constraint_count - before, 3)
                self.assertTrue(system.is_satisfied())
                for index in range(3):
                    self.assertFalse(
                        system.is_satisfied(
                            {bits[index].index: 1 - bit_values[index]}
                        )
                    )
                self.assertFalse(
                    system.is_satisfied(
                        {selected[0].index: table[pattern].u + 1}
                    )
                )
                self.assertFalse(
                    system.is_satisfied(
                        {selected[1].index: table[pattern].v + 1}
                    )
                )

    def test_pedersen_matches_pinned_upstream_boundary_vectors(self):
        fixture_path = (
            Path(__file__).parent
            / "fixtures"
            / "sapling_pedersen_upstream_vectors.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(
            fixture["reference_revision"],
            "88a7946b4a3066787776e11f0a502654167e022d",
        )
        personalization = (1,) * 6

        for vector in fixture["vectors"]:
            with self.subTest(message_bits=vector["message_bits"]):
                values = tuple(vector["message_bits"])
                witness = make_pedersen_witness(personalization, values)
                expected = Point(
                    int(vector["hash_u"], 16),
                    int(vector["hash_v"], 16),
                )
                self.assertEqual(witness.result, expected)

                system = R1CS()
                message_bits = tuple(
                    system.alloc_private(f"message bit[{index}]", bit)
                    for index, bit in enumerate(values)
                )
                result = constrain_pedersen_hash(
                    system, personalization, message_bits, witness
                )
                self.assertEqual(
                    (
                        system._witness_value(result[0]),
                        system._witness_value(result[1]),
                    ),
                    (expected.u, expected.v),
                )
                self.assertTrue(system.is_satisfied())

                reference_system = R1CS()
                reference_bits = tuple(
                    reference_system.alloc_private(
                        f"reference message bit[{index}]", bit
                    )
                    for index, bit in enumerate(values)
                )
                for index, bit in enumerate(reference_bits):
                    reference_system.boolean(
                        bit, f"reference message Boolean[{index}]"
                    )
                reference_result = synthesize_pedersen_hash(
                    reference_system, personalization, reference_bits
                )
                self.assertEqual(
                    (
                        reference_system._witness_value(reference_result[0]),
                        reference_system._witness_value(reference_result[1]),
                    ),
                    (expected.u, expected.v),
                )
                self.assertTrue(reference_system.is_satisfied())

    def test_note_commitment_matches_pinned_upstream_vector(self):
        fixture_path = (
            Path(__file__).parent
            / "fixtures"
            / "sapling_nullifier_reference.json"
        )
        vector = json.loads(fixture_path.read_text(encoding="utf-8"))["cases"][0]
        diversifier = bytes.fromhex(vector["default_d"])
        diversifier_base = group_hash(b"Zcash_gd", diversifier)
        transmission_key = Point.from_bytes(bytes.fromhex(vector["default_pk_d"]))
        randomness = int.from_bytes(bytes.fromhex(vector["note_r"]), "little")
        witness = make_note_commitment_witness(
            vector["note_v"],
            diversifier_base,
            transmission_key,
            randomness,
        )
        expected_u = int.from_bytes(bytes.fromhex(vector["note_cmu"]), "little")

        system = R1CS()
        public = tuple(
            system.alloc_public(f"output public[{index}]", value)
            for index, value in enumerate((0, 0, 0, 0, expected_u))
        )
        value = system.alloc_private("note value", vector["note_v"])
        gd = allocate_jubjub_point(system, "g_d", diversifier_base)
        pkd_repr = allocate_unchecked_jubjub_repr(
            system, "pk_d representation", transmission_key
        )
        rcm_bits = tuple(
            system.alloc_private(f"rcm bit[{index}]", bit)
            for index, bit in enumerate(witness.rcm_bits)
        )
        with self.assertRaises(R1CSError):
            constrain_note_commitment(
                system,
                value,
                gd,
                pkd_repr,
                rcm_bits,
                replace(witness, value=witness.value + 1),
                public[4],
            )
        commitment = constrain_note_commitment(
            system,
            value,
            gd,
            pkd_repr,
            rcm_bits,
            witness,
            public[4],
        )
        self.assertEqual(system.public_inputs(), (0, 0, 0, 0, expected_u))
        self.assertEqual(system.constraint_count, 4740)
        self.assertEqual(system._witness_value(commitment[0]), expected_u)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(
            system.is_satisfied({public[4].index: expected_u + 1})
        )
        self.assertFalse(
            system.is_satisfied({rcm_bits[0].index: 1 - witness.rcm_bits[0]})
        )
        self.assertFalse(system.is_satisfied({value.index: 1}))

    def test_output_reuses_shared_note_and_value_commitment_primitives(self):
        fixture = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))
        vector = fixture["cases"][0]
        diversifier = bytes.fromhex(vector["diversifier"])
        diversifier_base = group_hash(b"Zcash_gd", diversifier)
        transmission_key = Point.from_bytes(
            bytes.fromhex(vector["transmission_key"]), check_subgroup=True
        )
        rcv = int.from_bytes(bytes.fromhex(vector["rcv"]), "little")
        rcm = int.from_bytes(bytes.fromhex(vector["rcm"]), "little")
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")

        output = make_sapling_output_witness(
            vector["value"], diversifier, transmission_key, rcv, rcm, esk
        )
        value_commitment = make_sapling_value_commitment_witness(
            vector["value"], rcv
        )
        note_commitment = make_note_commitment_witness(
            vector["value"], diversifier_base, transmission_key, rcm
        )

        self.assertEqual(FIELD_MODULUS, SCALAR_MODULUS)
        self.assertNotEqual(JUBJUB_SCALAR_MODULUS, SCALAR_MODULUS)
        self.assertEqual(JUBJUB_SCALAR_MODULUS.bit_length(), 252)
        self.assertEqual(output.value_commitment, value_commitment)
        self.assertEqual(output.note_commitment, note_commitment)
        self.assertEqual(value_commitment.commitment.encode().hex(), vector["cv"])
        self.assertEqual(note_commitment.commitment.u.to_bytes(32, "little").hex(), vector["cmu"])

        max_scalar = JUBJUB_SCALAR_MODULUS - 1
        for value, scalar in ((0, 0), ((1 << 64) - 1, max_scalar)):
            with self.subTest(value=value, scalar=scalar):
                boundary_commitment = make_sapling_value_commitment_witness(
                    value, scalar
                )
                self.assertEqual(
                    sum(bit << index for index, bit in enumerate(boundary_commitment.value_bits)),
                    value,
                )
                self.assertEqual(
                    sum(bit << index for index, bit in enumerate(boundary_commitment.randomness_bits)),
                    scalar,
                )
        for invalid_scalar in (-1, JUBJUB_SCALAR_MODULUS, True):
            with self.subTest(invalid_scalar=invalid_scalar), self.assertRaises(
                R1CSError
            ):
                make_sapling_value_commitment_witness(0, invalid_scalar)

    def test_sapling_output_assembles_public_inputs_and_constrained_witness(self):
        reference = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))
        vector = reference["cases"][0]
        diversifier = bytes.fromhex(vector["diversifier"])
        transmission_key = Point.from_bytes(
            bytes.fromhex(vector["transmission_key"]), check_subgroup=True
        )
        value_randomness = int.from_bytes(bytes.fromhex(vector["rcv"]), "little")
        commitment_randomness = int.from_bytes(
            bytes.fromhex(vector["rcm"]), "little"
        )
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")
        expected_cv = Point.from_bytes(bytes.fromhex(vector["cv"]), check_subgroup=True)
        expected_epk = Point.from_bytes(
            bytes.fromhex(vector["epk"]), check_subgroup=True
        )
        expected_cmu_bytes = bytes.fromhex(vector["cmu"])
        expected_cmu = int.from_bytes(expected_cmu_bytes, "little")
        self.assertEqual(len(diversifier), 11)
        self.assertEqual(vector["value"], 100000000)
        self.assertEqual(len(bytes.fromhex(vector["rcv"])), 32)
        self.assertEqual(len(bytes.fromhex(vector["rcm"])), 32)
        self.assertEqual(len(bytes.fromhex(vector["esk"])), 32)
        self.assertGreater(esk, 0)
        self.assertLess(value_randomness, JUBJUB_SCALAR_MODULUS)
        self.assertLess(commitment_randomness, JUBJUB_SCALAR_MODULUS)
        self.assertLess(esk, JUBJUB_SCALAR_MODULUS)
        self.assertLess(expected_cmu, FIELD_MODULUS)
        self.assertEqual(value_randomness, commitment_randomness)
        self.assertEqual(transmission_key.encode().hex(), vector["transmission_key"])
        self.assertEqual(expected_cv.encode().hex(), vector["cv"])
        self.assertEqual(expected_epk.encode().hex(), vector["epk"])
        self.assertEqual(
            value_randomness.to_bytes(32, "little"), bytes.fromhex(vector["rcv"])
        )
        self.assertEqual(
            commitment_randomness.to_bytes(32, "little"),
            bytes.fromhex(vector["rcm"]),
        )
        self.assertEqual(esk.to_bytes(32, "little"), bytes.fromhex(vector["esk"]))
        self.assertEqual(expected_cmu.to_bytes(32, "little"), expected_cmu_bytes)

        witness = make_sapling_output_witness(
            vector["value"],
            diversifier,
            transmission_key,
            value_randomness,
            commitment_randomness,
            esk,
        )
        self.assertIsInstance(witness, SaplingOutputWitness)
        self.assertEqual(witness.diversifier_base, group_hash(b"Zcash_gd", diversifier))
        self.assertEqual(
            expected_epk.multiply(pow(esk, -1, JUBJUB_SCALAR_MODULUS)),
            witness.diversifier_base,
        )
        self.assertEqual(witness.value_commitment.commitment, expected_cv)
        self.assertEqual(witness.ephemeral_key.ephemeral_key, expected_epk)
        self.assertEqual(witness.note_commitment.commitment.u, expected_cmu)
        self.assertEqual(witness.value_commitment_randomness, value_randomness)
        self.assertEqual(witness.commitment_randomness, commitment_randomness)
        self.assertEqual(witness.esk, esk)
        self.assertEqual(witness.note_commitment.commitment.u, expected_cmu)

        system = R1CS()
        result = constrain_sapling_output(system, witness)
        expected_public_inputs = (
            expected_cv.u,
            expected_cv.v,
            expected_epk.u,
            expected_epk.v,
            expected_cmu,
        )
        self.assertEqual(system.public_inputs(), expected_public_inputs)
        self.assertEqual(
            tuple(variable.index for variable in result.public_inputs),
            (1, 2, 3, 4, 5),
        )
        self.assertEqual(
            tuple(system.variables[index].name for index in range(1, 6)),
            tuple(
                f"Sapling Output public input[{index}]"
                for index in range(5)
            ),
        )
        self.assertEqual(
            system._witness_value(result.note_commitment[0]), expected_cmu
        )
        self.assertTrue(system.is_satisfied())
        self.assertEqual(system.constraint_count, 7827)
        self.assertEqual(len(system.variables), 7827)
        self.assertEqual(
            len(system.variables) - 1 - system.public_input_count,
            7821,
        )
        variable_manifest = [
            (variable.kind, variable.name) for variable in system.variables
        ]
        self.assertEqual(
            hashlib.sha256(
                json.dumps(variable_manifest, separators=(",", ":")).encode()
            ).hexdigest(),
            "79eafdadcecc6d4abee556c4fac67d2e1e7e36072502ae1303e342995ee8fb28",
        )
        self.assertEqual(
            tuple(variable.index for variable in system.variables),
            tuple(range(7827)),
        )
        for prefix, expected_count in (
            ("Sapling Output value commitment", 1265),
            ("Sapling Output ephemeral key", 3539),
            ("Sapling Output note commitment g_d representation", 776),
            ("Sapling Output note commitment pk_d representation", 256),
            ("Sapling Output note commitment content hash", 982),
        ):
            with self.subTest(component=prefix):
                self.assertEqual(
                    sum(
                        constraint.label.startswith(prefix)
                        for constraint in system.constraints
                    ),
                    expected_count,
                )
        boolean_rows = {
            "Sapling Output value commitment value multiplication scalar bit[": 64,
            "Sapling Output value commitment randomness multiplication scalar bit[": 252,
            "Sapling Output note commitment pk_d representation[": 256,
            "Sapling Output note commitment rcm bit[": 252,
        }
        for prefix, expected_count in boolean_rows.items():
            with self.subTest(boolean_owner=prefix):
                labels = tuple(
                    constraint.label
                    for constraint in system.constraints
                    if constraint.label.startswith(prefix)
                )
                self.assertEqual(len(labels), expected_count)
                self.assertEqual(
                    labels,
                    tuple(f"{prefix}{index}]" for index in range(expected_count)),
                )
        rcm_variables = tuple(
            variable
            for variable in system.variables
            if variable.name.startswith("Sapling Output rcm bit[")
        )
        value_variables = tuple(
            variable
            for variable in system.variables
            if variable.name.startswith("Sapling Output value bit[")
        )
        rcv_variables = tuple(
            variable
            for variable in system.variables
            if variable.name.startswith("Sapling Output rcv bit[")
        )
        self.assertEqual(len(value_variables), 64)
        self.assertEqual(
            tuple(variable.name for variable in value_variables),
            tuple(f"Sapling Output value bit[{index}]" for index in range(64)),
        )
        self.assertEqual(
            tuple(system.witness_value(variable) for variable in value_variables),
            witness.value_commitment.value_bits,
        )
        self.assertEqual(len(rcv_variables), 252)
        self.assertEqual(
            tuple(variable.name for variable in rcv_variables),
            tuple(f"Sapling Output rcv bit[{index}]" for index in range(252)),
        )
        self.assertEqual(
            tuple(system.witness_value(variable) for variable in rcv_variables),
            witness.value_commitment.randomness_bits,
        )
        value_boolean_indices = tuple(
            index
            for index, constraint in enumerate(system.constraints)
            if constraint.label.startswith(
                "Sapling Output value commitment value multiplication scalar bit["
            )
        )
        rcv_boolean_indices = tuple(
            index
            for index, constraint in enumerate(system.constraints)
            if constraint.label.startswith(
                "Sapling Output value commitment randomness multiplication scalar bit["
            )
        )
        self.assertEqual(
            value_boolean_indices,
            tuple(range(value_boolean_indices[0], value_boolean_indices[0] + 64)),
        )
        self.assertEqual(
            rcv_boolean_indices,
            tuple(range(rcv_boolean_indices[0], rcv_boolean_indices[0] + 252)),
        )
        self.assertEqual(value_boolean_indices[0], 0)
        self.assertTrue(
            system.constraints[value_boolean_indices[-1] + 1].label.startswith(
                "Sapling Output value commitment value multiplication lookup[0]"
            )
        )
        self.assertTrue(
            system.constraints[rcv_boolean_indices[0] - 1].label.startswith(
                "Sapling Output value commitment value multiplication"
            )
        )
        self.assertTrue(
            system.constraints[rcv_boolean_indices[-1] + 1].label.startswith(
                "Sapling Output value commitment randomness multiplication lookup[0]"
            )
        )
        for label, window_count, partial_final_window, expected_rows in (
            (
                "Sapling Output value commitment value multiplication",
                22,
                True,
                65,
            ),
            (
                "Sapling Output value commitment randomness multiplication",
                84,
                False,
                252,
            ),
        ):
            expected_labels = tuple(
                constraint_label
                for window in range(window_count)
                for constraint_label in (
                    (
                        f"{label} lookup[{window}] bc multiplication",
                        f"{label} lookup[{window}] coordinate[0]",
                        f"{label} lookup[{window}] coordinate[1]",
                    )
                    if not (window == window_count - 1 and partial_final_window)
                    else (
                        f"{label} lookup[{window}] coordinate[0]",
                        f"{label} lookup[{window}] coordinate[1]",
                    )
                )
            )
            actual_labels = tuple(
                constraint.label
                for constraint in system.constraints
                if constraint.label.startswith(f"{label} lookup[")
            )
            with self.subTest(fixed_base_lookup=label):
                self.assertEqual(len(actual_labels), expected_rows)
                self.assertEqual(actual_labels, expected_labels)
        self.assertEqual(len(rcm_variables), 252)
        self.assertEqual(
            tuple(variable.name for variable in rcm_variables),
            tuple(f"Sapling Output rcm bit[{index}]" for index in range(252)),
        )
        self.assertEqual(
            tuple(system.witness_value(variable) for variable in rcm_variables),
            witness.note_commitment.rcm_bits,
        )
        rcm_constraint_indices = tuple(
            index
            for index, constraint in enumerate(system.constraints)
            if constraint.label.startswith(
                "Sapling Output note commitment rcm bit["
            )
        )
        pk_d_constraint_indices = tuple(
            index
            for index, constraint in enumerate(system.constraints)
            if constraint.label.startswith(
                "Sapling Output note commitment pk_d representation["
            )
        )
        self.assertEqual(
            rcm_constraint_indices,
            tuple(range(rcm_constraint_indices[0], rcm_constraint_indices[0] + 252)),
        )
        content_hash_constraint_indices = tuple(
            index
            for index, constraint in enumerate(system.constraints)
            if constraint.label.startswith(
                "Sapling Output note commitment content hash"
            )
        )
        self.assertEqual(
            content_hash_constraint_indices[0],
            pk_d_constraint_indices[-1] + 1,
        )
        self.assertEqual(
            rcm_constraint_indices[0],
            content_hash_constraint_indices[-1] + 1,
        )
        self.assertTrue(
            system.constraints[rcm_constraint_indices[-1] + 1].label.startswith(
                "Sapling Output note commitment randomness multiplication lookup[0]"
            )
        )
        self.assertFalse(
            any(
                constraint.label.startswith(
                    "Sapling Output note commitment shared value bit["
                )
                or constraint.label.startswith(
                    "Sapling Output note commitment content hash input bit["
                )
                or constraint.label.startswith(
                    "Sapling Output note commitment randomness multiplication scalar bit["
                )
                for constraint in system.constraints
            )
        )
        self.assertFalse(
            any(
                constraint.label.startswith(
                    "Sapling Output note commitment randomness multiplication scalar"
                )
                for constraint in system.constraints
            )
        )
        self.assertEqual(
            sum(
                constraint.label.startswith(
                    "Sapling Output note commitment randomness multiplication"
                )
                for constraint in system.constraints
            ),
            750,
        )
        self.assertNotIn(
            "Sapling Output value",
            {variable.name for variable in system.variables},
        )
        self.assertNotIn(
            "Sapling Output note commitment value encoding",
            {constraint.label for constraint in system.constraints},
        )
        matrix = system.serialize_matrix()
        self.assertEqual(system.serialize_matrix(), matrix)
        self.assertEqual(
            system.matrix_fingerprint(),
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertNotIn(b"witness", matrix.lower())
        self.assertNotIn(b"assignment", matrix.lower())

        def reference_pedersen(
            reference_system,
            personalization_bits,
            message_bits,
            _pedersen_witness,
            label,
            *,
            message_bits_preconstrained,
            representation,
        ):
            self.assertTrue(message_bits_preconstrained)
            self.assertEqual(representation, "montgomery")
            self.assertEqual(
                _pedersen_witness.bit_values,
                witness.note_commitment.note_hash.bit_values,
            )
            return synthesize_pedersen_hash(
                reference_system,
                tuple(personalization_bits),
                tuple(message_bits),
                label,
            )

        with patch(
            "src.sapling_gadgets.constrain_pedersen_hash",
            side_effect=reference_pedersen,
        ):
            reference_system = R1CS()
            reference_result = constrain_sapling_output(
                reference_system, witness
            )
        self.assertEqual(reference_system.serialize_matrix(), matrix)
        self.assertEqual(
            reference_system.matrix_fingerprint(), system.matrix_fingerprint()
        )

        self.assertEqual(reference_system.constraint_count, 7827)
        self.assertEqual(len(reference_system.variables), 7827)
        self.assertTrue(reference_system.is_satisfied())
        self.assertEqual(
            reference_system.public_inputs(), expected_public_inputs
        )
        self.assertEqual(
            tuple(
                reference_system._witness_value(variable)
                for variable in reference_result.note_commitment
            ),
            tuple(
                system._witness_value(variable)
                for variable in result.note_commitment
            ),
        )

        def find_variable(name):
            return next(variable for variable in system.variables if variable.name == name)

        tamper_cases = [
            (
                f"Sapling Output public input[{index}]",
                expected_public_inputs[index] + 1,
            )
            for index in range(5)
        ] + [
            ("Sapling Output value bit[0]", None),
            ("Sapling Output rcv bit[0]", None),
            ("Sapling Output esk bit[0]", None),
            ("Sapling Output rcm bit[0]", None),
            ("Sapling Output g_d.u", witness.diversifier_base.u + 1),
            ("Sapling Output pk_d representation.v bit[0]", None),
            (
                "Sapling Output note commitment content hash segment[0] window[0] y",
                None,
            ),
            (
                "Sapling Output note commitment content hash segment[0] addition[1] lambda",
                None,
            ),
            (
                "Sapling Output note commitment content hash segment[0] conversion u",
                None,
            ),
            (
                "Sapling Output ephemeral key multiplication accumulator[100].u",
                None,
            ),
        ]
        for name, assigned_value in tamper_cases:
            variable = find_variable(name)
            if assigned_value is None:
                assigned_value = 1 - system._witness_value(variable)
            for candidate, implementation in (
                (system, "Output Montgomery path"),
                (reference_system, "independent Bellman transcription"),
            ):
                with self.subTest(tamper=name, implementation=implementation):
                    self.assertFalse(
                        candidate.is_satisfied(
                            {variable.index: assigned_value}
                        )
                    )

        with self.assertRaises(R1CSError):
            constrain_sapling_output(system, witness)
        with self.assertRaises(R1CSError):
            make_sapling_output_witness(
                witness.value,
                b"\x00" * 10,
                transmission_key,
                value_randomness,
                commitment_randomness,
                witness.esk,
            )
        with self.assertRaises(R1CSError):
            constrain_sapling_output(
                R1CS(), replace(witness, diversifier_base=Point(1, 1))
            )

        alternate_witness = make_sapling_output_witness(
            vector["value"] + 1,
            diversifier,
            transmission_key,
            value_randomness,
            commitment_randomness,
            esk,
        )
        alternate_system = R1CS()
        constrain_sapling_output(alternate_system, alternate_witness)
        self.assertTrue(alternate_system.is_satisfied())
        self.assertEqual(alternate_system.serialize_matrix(), matrix)
        self.assertEqual(
            alternate_system.matrix_fingerprint(),
            system.matrix_fingerprint(),
        )

    def test_output_entrypoint_recorder_completes_synthesis(self):
        vector = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))[
            "cases"
        ][0]
        output_witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(vector["transmission_key"]),
                check_subgroup=True,
            ),
            int.from_bytes(bytes.fromhex(vector["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(vector["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(vector["esk"]), "little"),
        )

        def capture(system):
            constrain_sapling_output(system, output_witness)
            if isinstance(system, R1CS):
                variables = system.variables
                rows = system.constraints
                return (
                    system.constraint_count,
                    len(variables),
                    system.serialize_matrix(),
                    tuple(row.label for row in rows),
                    tuple(variable.name for variable in variables[1:]),
                    tuple(
                        system.witness_value(variable)
                        for variable in variables[1:]
                    ),
                    tuple(variable.index for variable in variables),
                    system.is_satisfied(),
                )

            variables = (
                system.recorder.inputs
                + system.recorder.auxiliary_variables
            )
            rows = system.recorder.constraints

            def evaluate(expression):
                value = 0
                for variable, coefficient in expression.terms:
                    self.assertIsNotNone(variable.value)
                    value += variable.value * coefficient
                return value % SCALAR_MODULUS

            recorder_satisfied = all(
                evaluate(row.a) * evaluate(row.b) % SCALAR_MODULUS
                == evaluate(row.c)
                for row in rows
            )
            return (
                system.recorder.constraint_count,
                len(variables),
                system.recorder.serialize_local_matrix(),
                tuple(row.name.replace("/", " ") for row in rows),
                tuple(variable.name.replace("/", " ") for variable in variables[1:]),
                tuple(system.witness_value(variable) for variable in variables[1:]),
                tuple(
                    variable.index.index
                    if variable.index.kind == "input"
                    else len(system.recorder.inputs) + variable.index.index
                    for variable in variables
                ),
                recorder_satisfied,
            )

        production = R1CS()
        production_result = capture(production)
        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_result = capture(backend)

        self.assertEqual(production_result[:7], recorder_result[:7])
        self.assertEqual(production_result[:2], (7827, 7827))
        self.assertEqual(
            production.matrix_fingerprint(),
            "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368",
        )
        self.assertTrue(production_result[7])
        self.assertTrue(recorder_result[7])
        self.assertFalse(backend.is_fresh)

        invalid_recorder = BellmanSynthesisRecorder()
        invalid_backend = RecorderSynthesisBackend(invalid_recorder)
        with self.assertRaises(R1CSError):
            constrain_sapling_output(
                invalid_backend,
                replace(output_witness, value=output_witness.value + 1),
            )
        self.assertEqual(len(invalid_recorder.inputs), 1)
        self.assertEqual(invalid_recorder.auxiliary_variables, ())
        self.assertEqual(invalid_recorder.constraints, ())

        nonfresh_recorder = BellmanSynthesisRecorder()
        nonfresh_backend = RecorderSynthesisBackend(nonfresh_recorder)
        nonfresh_backend.alloc_private("existing allocation", 0)
        before = nonfresh_recorder.serialize()
        with self.assertRaisesRegex(R1CSError, "requires a fresh backend"):
            constrain_sapling_output(nonfresh_backend, output_witness)
        self.assertEqual(nonfresh_recorder.serialize(), before)

    def test_output_note_commitment_pre_pedersen_prefix_matches_backends(self):
        vector = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))[
            "cases"
        ][0]
        output_witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(vector["transmission_key"]),
                check_subgroup=True,
            ),
            int.from_bytes(bytes.fromhex(vector["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(vector["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(vector["esk"]), "little"),
        )

        class PedersenBoundaryReached(Exception):
            pass

        def capture(system):
            with patch(
                "src.sapling_gadgets.constrain_pedersen_hash",
                side_effect=PedersenBoundaryReached,
            ) as pedersen:
                with self.assertRaises(PedersenBoundaryReached):
                    constrain_sapling_output(system, output_witness)
            self.assertEqual(pedersen.call_count, 1)
            if isinstance(system, R1CS):
                variables = system.variables[1:]
                rows = system.constraint_count
                columns = len(system.variables)
                matrix = system.serialize_matrix()
                labels = tuple(row.label for row in system.constraints)
                names = tuple(variable.name for variable in variables)
                assignments = tuple(
                    system.witness_value(variable) for variable in variables
                )
                satisfied = system.is_satisfied()
                mappings = tuple(variable.index for variable in variables)
            else:
                variables = (
                    system.recorder.inputs[1:]
                    + system.recorder.auxiliary_variables
                )
                rows = system.recorder.constraint_count
                columns = (
                    len(system.recorder.inputs)
                    + len(system.recorder.auxiliary_variables)
                )
                matrix = system.recorder.serialize_local_matrix()
                labels = tuple(
                    row.name.replace("/", " ")
                    for row in system.recorder.constraints
                )
                names = tuple(
                    variable.name.replace("/", " ") for variable in variables
                )
                assignments = tuple(
                    system.witness_value(variable) for variable in variables
                )
                satisfied = None
                mappings = tuple(
                    variable.index.index
                    if variable.index.kind == "input"
                    else len(system.recorder.inputs) + variable.index.index
                    for variable in variables
                )
            return rows, columns, matrix, labels, names, assignments, mappings, satisfied

        production = R1CS()
        production_result = capture(production)
        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorder_result = capture(recorder_backend)

        self.assertEqual(production_result[:2], recorder_result[:2])
        self.assertEqual(production_result[2], recorder_result[2])
        self.assertEqual(production_result[3], recorder_result[3])
        self.assertEqual(production_result[4], recorder_result[4])
        self.assertEqual(production_result[5], recorder_result[5])
        self.assertEqual(production_result[6], recorder_result[6])
        self.assertTrue(production_result[7])
        self.assertEqual(production_result[:2], (5836, 5837))
        self.assertEqual(
            hashlib.sha256(production_result[2]).hexdigest(),
            "e16e2e03cdc5b966c9b76576852cb7a4b5b8597b8ce84c7d4ac9049d7ae3a1e6",
        )

    def test_note_commitment_rejects_bad_value_inputs_before_mutation(self):
        vector = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))[
            "cases"
        ][0]
        output_witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(vector["transmission_key"]),
                check_subgroup=True,
            ),
            int.from_bytes(bytes.fromhex(vector["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(vector["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(vector["esk"]), "little"),
        )
        witness = output_witness.note_commitment

        def setup(system, value, note_witness):
            public = tuple(
                system.alloc_public(f"public[{index}]", 0)
                for index in range(5)
            )
            value_variable = system.alloc_private("note value", value)
            base = allocate_jubjub_point(
                system, "g_d", output_witness.diversifier_base
            )
            transmission_repr = allocate_unchecked_jubjub_repr(
                system, "pk_d representation", output_witness.transmission_key
            )
            randomness = tuple(
                system.alloc_private(f"rcm bit[{index}]", bit)
                for index, bit in enumerate(note_witness.rcm_bits)
            )
            return public[4], value_variable, base, transmission_repr, randomness

        def snapshot(system):
            return (
                system.serialize()
                if isinstance(system, R1CS)
                else system.recorder.serialize()
            )

        for backend_name in ("production", "recorder"):
            for case in ("invalid-type", "unassigned", "foreign", "out-of-range"):
                with self.subTest(backend=backend_name, case=case):
                    if backend_name == "production":
                        system = R1CS()
                        foreign_system = R1CS()
                    else:
                        recorder = BellmanSynthesisRecorder()
                        system = RecorderSynthesisBackend(recorder)
                        foreign_system = RecorderSynthesisBackend(
                            BellmanSynthesisRecorder()
                        )
                    value = witness.value
                    note_witness = witness
                    if case == "unassigned":
                        value = None
                    elif case == "out-of-range":
                        value = 1 << 64
                        note_witness = replace(witness, value=value)
                    (
                        commitment_u,
                        value_variable,
                        base,
                        transmission_repr,
                        randomness,
                    ) = setup(system, value, note_witness)
                    supplied_value = value_variable
                    if case == "invalid-type":
                        supplied_value = object()
                    elif case == "foreign":
                        supplied_value = foreign_system.alloc_private(
                            "foreign note value", witness.value
                        )
                    before = snapshot(system)
                    with self.assertRaises((R1CSError, TypeError, BellmanRecorderError)):
                        _constrain_note_commitment(
                            system,
                            supplied_value,
                            base,
                            transmission_repr,
                            randomness,
                            note_witness,
                            commitment_u,
                            "test note commitment",
                            validate_diversifier_base=False,
                        )
                    self.assertEqual(snapshot(system), before)

    def test_output_note_pedersen_matrix_matches_bellman_transcription(self):
        reference = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))
        vector = reference["cases"][0]
        witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            Point.from_bytes(
                bytes.fromhex(vector["transmission_key"]),
                check_subgroup=True,
            ),
            int.from_bytes(bytes.fromhex(vector["rcv"]), "little"),
            int.from_bytes(bytes.fromhex(vector["rcm"]), "little"),
            int.from_bytes(bytes.fromhex(vector["esk"]), "little"),
        )
        message = witness.note_commitment.note_hash.bit_values[6:]
        matrices = {}
        for implementation in ("montgomery", "bellman-reference"):
            system = R1CS()
            bits = tuple(
                system.alloc_private(f"Output note bit[{index}]", bit)
                for index, bit in enumerate(message)
            )
            for index, bit in enumerate(bits):
                system.boolean(bit, f"Output note input Boolean[{index}]")
            if implementation == "montgomery":
                result = constrain_pedersen_hash(
                    system,
                    (1,) * 6,
                    bits,
                    witness.note_commitment.note_hash,
                    "Output note hash",
                    message_bits_preconstrained=True,
                    representation="montgomery",
                )
            else:
                result = synthesize_pedersen_hash(
                    system,
                    (1,) * 6,
                    bits,
                    "Output note hash reference",
                )
            matrices[implementation] = (
                system,
                system.serialize_matrix(),
                system.matrix_fingerprint(),
                result,
            )

        local, local_matrix, local_fingerprint, local_result = matrices[
            "montgomery"
        ]
        upstream, upstream_matrix, upstream_fingerprint, upstream_result = (
            matrices["bellman-reference"]
        )
        self.assertEqual(local.constraint_count, 1558)
        self.assertEqual(len(local.variables), 1559)
        self.assertEqual(
            local_fingerprint,
            "b72dc6da89fc978cf68052a92424fb8eec133a1488ddb3333a858df19021da76",
        )
        self.assertEqual(local_matrix, upstream_matrix)
        self.assertEqual(local_fingerprint, upstream_fingerprint)
        self.assertEqual(
            tuple(local._witness_value(point) for point in local_result),
            tuple(upstream._witness_value(point) for point in upstream_result),
        )
        self.assertEqual(
            tuple(local._witness_value(point) for point in local_result),
            (witness.note_commitment.note_hash.result.u,
             witness.note_commitment.note_hash.result.v),
        )
        self.assertTrue(local.is_satisfied())
        self.assertTrue(upstream.is_satisfied())

        for system in (local, upstream):
            point = local_result if system is local else upstream_result
            variable = next(
                item for item in system.variables
                if item.name.endswith("segment[0] addition[1] lambda")
            )
            with self.subTest(matrix="local" if system is local else "reference"):
                self.assertFalse(
                    system.is_satisfied(
                        {variable.index: system._witness_value(variable) + 1}
                    )
                )
                self.assertEqual(
                    tuple(system._witness_value(item) for item in point),
                    (
                        witness.note_commitment.note_hash.result.u,
                        witness.note_commitment.note_hash.result.v,
                    ),
                )

    def test_fixed_base_output_randomness_allows_noncanonical_scalar_alias(self):
        base = sapling_fixed_base_generator("note_commitment_randomness")
        scalar = JUBJUB_SCALAR_MODULUS + 1
        bits = tuple(
            (scalar >> index) & 1
            for index in range(JUBJUB_SCALAR_MODULUS.bit_length())
        )
        selected_points = []
        accumulators = []
        accumulator = None
        for window, table in enumerate(_fixed_base_tables(base)):
            start = window * 3
            pattern = sum(
                bits[start + offset] << offset
                for offset in range(3)
                if start + offset < len(bits)
            )
            selected = table[pattern]
            selected_points.append(selected)
            accumulator = (
                selected if accumulator is None else accumulator + selected
            )
            accumulators.append(accumulator)
        witness = FixedBaseJubjubWitness(
            bits,
            tuple(selected_points),
            tuple(accumulators),
            accumulator,
        )
        self.assertEqual(accumulator, base)

        system = R1CS()
        bit_variables = tuple(
            system.alloc_private(f"rcm alias bit[{index}]", bit)
            for index, bit in enumerate(bits)
        )
        result = constrain_fixed_base_jubjub_mul(
            system,
            base,
            bit_variables,
            witness,
            "Output rcm",
            enforce_scalar_range=False,
        )
        self.assertTrue(system.is_satisfied())
        self.assertEqual(system._witness_value(result[0]), base.u)
        self.assertEqual(system._witness_value(result[1]), base.v)
        self.assertFalse(
            any("scalar range" in constraint.label for constraint in system.constraints)
        )

        strict_system = R1CS()
        strict_bits = tuple(
            strict_system.alloc_private(f"rcm alias bit[{index}]", bit)
            for index, bit in enumerate(bits)
        )
        with self.assertRaises(R1CSError):
            constrain_fixed_base_jubjub_mul(
                strict_system,
                base,
                strict_bits,
                witness,
                "Strict rcm",
                enforce_scalar_range=True,
            )

    def test_sapling_output_rejects_invalid_host_witness_before_allocation(self):
        reference = json.loads(OUTPUT_FIXTURE.read_text(encoding="utf-8"))
        vector = reference["cases"][0]
        transmission_key = Point.from_bytes(
            bytes.fromhex(vector["transmission_key"]), check_subgroup=True
        )
        randomness = int.from_bytes(bytes.fromhex(vector["rcm"]), "little")
        esk = int.from_bytes(bytes.fromhex(vector["esk"]), "little")
        witness = make_sapling_output_witness(
            vector["value"],
            bytes.fromhex(vector["diversifier"]),
            transmission_key,
            randomness,
            randomness,
            esk,
        )

        invalid_witnesses = [
            ("invalid value", replace(witness, value=1 << 64)),
            ("Boolean value", replace(witness, value=True)),
            (
                "invalid diversifier",
                replace(witness, diversifier=b"\x01" + bytes(10)),
            ),
            ("valid but mismatched diversifier", replace(witness, diversifier=bytes(11))),
            ("mismatched diversifier base", replace(witness, diversifier_base=Point(1, 1))),
            ("off-curve transmission key", replace(witness, transmission_key=Point(1, 1))),
            ("identity transmission key", replace(witness, transmission_key=Point(0, 1))),
            (
                "non-subgroup transmission key",
                replace(
                    witness,
                    transmission_key=Point.from_bytes(
                        bytes.fromhex("03" + "00" * 31)
                    ),
                ),
            ),
            (
                "inconsistent value commitment",
                replace(witness, value_commitment=replace(
                    witness.value_commitment, value=witness.value + 1
                )),
            ),
            (
                "inconsistent note commitment",
                replace(witness, note_commitment=replace(
                    witness.note_commitment, value=witness.value + 1
                )),
            ),
            (
                "inconsistent ephemeral key trace",
                replace(
                    witness,
                    ephemeral_key=replace(
                        witness.ephemeral_key,
                        esk_bits=(1 - witness.ephemeral_key.esk_bits[0],)
                        + witness.ephemeral_key.esk_bits[1:],
                    ),
                ),
            ),
        ]
        for field in (
            "value_commitment_randomness",
            "commitment_randomness",
            "esk",
        ):
            for value in (JUBJUB_SCALAR_MODULUS, -1, True):
                invalid_witnesses.append(
                    (f"{field}={value!r}", replace(witness, **{field: value}))
                )

        for case, invalid in invalid_witnesses:
            system = R1CS()
            with self.subTest(case=case), self.assertRaises(
                (R1CSError, TypeError)
            ):
                constrain_sapling_output(system, invalid)
            self.assertEqual(len(system.variables), 1)
            self.assertEqual(system.public_input_count, 0)
            self.assertEqual(system.constraint_count, 0)

        for kwargs in (
            {"value": True},
            {"value_commitment_randomness": JUBJUB_SCALAR_MODULUS},
            {"commitment_randomness": JUBJUB_SCALAR_MODULUS},
            {"esk": JUBJUB_SCALAR_MODULUS},
        ):
            inputs = {
                "value": witness.value,
                "diversifier": witness.diversifier,
                "transmission_key": witness.transmission_key,
                "value_commitment_randomness": witness.value_commitment_randomness,
                "commitment_randomness": witness.commitment_randomness,
                "esk": witness.esk,
            }
            inputs.update(kwargs)
            with self.subTest(maker_input=kwargs), self.assertRaises(R1CSError):
                make_sapling_output_witness(**inputs)

        with self.assertRaises(R1CSError):
            make_sapling_output_witness(
                witness.value,
                witness.diversifier,
                Point(0, 1),
                witness.value_commitment_randomness,
                witness.commitment_randomness,
                witness.esk,
            )

    def test_randomized_authorization_key_binds_pinned_ak_vector(self):
        fixture = json.loads(IVK_FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("sapling_zip32.json", fixture["source"])
        authorization_key = Point.from_bytes(
            bytes.fromhex(fixture["case"]["ak"]), check_subgroup=True
        )
        witness = make_sapling_randomized_authorization_key_witness(
            authorization_key, 0
        )
        self.assertEqual(witness.randomized_key, authorization_key)

        system = R1CS()
        randomized_key = (
            system.alloc_public("Spend rk.u", authorization_key.u),
            system.alloc_public("Spend rk.v", authorization_key.v),
        )
        tuple(
            system.alloc_public(f"Spend remaining public[{index}]", index)
            for index in range(5)
        )
        circuit_ak = allocate_jubjub_point(
            system, "Spend ak", authorization_key
        )
        ar = system.alloc_private("Spend ar", 0)
        constrain_sapling_randomized_authorization_key(
            system,
            circuit_ak,
            ar,
            randomized_key,
            witness,
        )
        self.assertEqual(
            system.public_inputs(),
            (authorization_key.u, authorization_key.v) + tuple(range(5)),
        )
        self.assertTrue(system.is_satisfied())

        tamper_cases = (
            (randomized_key[0], authorization_key.u + 1),
            (randomized_key[1], authorization_key.v + 1),
            (circuit_ak[0], authorization_key.u + 1),
            (circuit_ak[1], authorization_key.v + 1),
            (ar, 1),
            (ar, JUBJUB_SCALAR_MODULUS),
        )
        for variable, value in tamper_cases:
            with self.subTest(variable=variable.name):
                self.assertFalse(system.is_satisfied({variable.index: value}))

        scalar_boundaries = (
            0,
            1,
            JUBJUB_SCALAR_MODULUS - 1,
        )
        for scalar in scalar_boundaries:
            with self.subTest(ar=scalar):
                boundary_witness = (
                    make_sapling_randomized_authorization_key_witness(
                        authorization_key, scalar
                    )
                )
                expected_bits = tuple(
                    (scalar >> index) & 1
                    for index in range(JUBJUB_SCALAR_MODULUS.bit_length())
                )
                self.assertEqual(
                    len(boundary_witness.ar_bits),
                    JUBJUB_SCALAR_MODULUS.bit_length(),
                )
                self.assertEqual(boundary_witness.ar_bits, expected_bits)
                self.assertEqual(
                    sum(bit << index for index, bit in enumerate(expected_bits)),
                    scalar,
                )
                self.assertEqual(
                    boundary_witness.multiplication.bit_values,
                    expected_bits,
                )
                self.assertEqual(
                    boundary_witness.randomized_key,
                    authorization_key
                    + sapling_fixed_base_generator("spending_key").multiply(
                        sum(
                            bit << index
                            for index, bit in enumerate(expected_bits)
                        )
                    ),
                )
        for invalid_scalar in (
            -1,
            JUBJUB_SCALAR_MODULUS,
            SCALAR_MODULUS - 1,
            SCALAR_MODULUS,
            True,
        ):
            with self.subTest(invalid_ar=invalid_scalar), self.assertRaises(
                R1CSError
            ):
                make_sapling_randomized_authorization_key_witness(
                    authorization_key, invalid_scalar
                )
        non_subgroup_key = Point.from_bytes(bytes.fromhex(
            "0300000000000000000000000000000000000000000000000000000000000000"
        ))
        self.assertTrue(non_subgroup_key.is_on_curve())
        self.assertNotEqual(non_subgroup_key.multiply(8), Point(0, 1))
        self.assertFalse(non_subgroup_key.is_in_subgroup())
        for invalid_key in (
            Point(0, 1),
            Point(1, 1),
            non_subgroup_key,
        ):
            with self.subTest(invalid_ak=invalid_key), self.assertRaises(
                R1CSError
            ):
                make_sapling_randomized_authorization_key_witness(
                    invalid_key, 0
                )
        with self.assertRaises(ValueError):
            Point.from_bytes(FIELD_MODULUS.to_bytes(32, "little"))

        wrong_order_system = R1CS()
        first = wrong_order_system.alloc_public("Spend rk.v", authorization_key.v)
        second = wrong_order_system.alloc_public("Spend rk.u", authorization_key.u)
        for index in range(5):
            wrong_order_system.alloc_public(f"Spend public[{index}]", index)
        wrong_ak = allocate_jubjub_point(
            wrong_order_system, "Spend ak", authorization_key
        )
        wrong_ar = wrong_order_system.alloc_private("Spend ar", 0)
        constrain_sapling_randomized_authorization_key(
            wrong_order_system,
            wrong_ak,
            wrong_ar,
            (first, second),
            witness,
        )
        self.assertFalse(wrong_order_system.is_satisfied())

    def test_randomized_authorization_key_matches_independent_nonzero_vector(self):
        fixture = json.loads(
            RANDOMIZED_AUTHORIZATION_KEY_FIXTURE.read_text(encoding="utf-8")
        )
        self.assertIn("sapling_signatures.json", fixture["source"])
        self.assertEqual(
            fixture["generator_revision"],
            "78321beacb0e0477e33cd002b56585a107c2708c",
        )
        vector = fixture["case"]
        authorization_key = Point.from_bytes(
            bytes.fromhex(vector["ak"]), check_subgroup=True
        )
        ar_bytes = bytes.fromhex(vector["ar"])
        ar = int.from_bytes(ar_bytes, "little")
        expected_randomized_key = Point.from_bytes(
            bytes.fromhex(vector["rk"]), check_subgroup=True
        )
        self.assertGreater(ar, 0)
        self.assertLess(ar, JUBJUB_SCALAR_MODULUS)
        self.assertLess(ar, SCALAR_MODULUS)
        self.assertEqual(len(ar_bytes), 32)
        self.assertEqual(
            spending_key_base(),
            sapling_fixed_base_generator("spending_key"),
        )

        witness = make_sapling_randomized_authorization_key_witness(
            authorization_key, ar
        )
        self.assertEqual(witness.randomized_key, expected_randomized_key)
        self.assertEqual(
            witness.randomized_key.encode().hex(), vector["rk"]
        )

        system = R1CS()
        randomized_key = (
            system.alloc_public("Spend rk.u", expected_randomized_key.u),
            system.alloc_public("Spend rk.v", expected_randomized_key.v),
        )
        for index in range(5):
            system.alloc_public(f"Spend remaining public[{index}]", index)
        circuit_ak = allocate_jubjub_point(
            system, "Spend ak", authorization_key
        )
        ar_variable = system.alloc_private("Spend ar", ar)
        constrain_sapling_randomized_authorization_key(
            system,
            circuit_ak,
            ar_variable,
            randomized_key,
            witness,
        )
        self.assertEqual(
            system.public_inputs(),
            (expected_randomized_key.u, expected_randomized_key.v)
            + tuple(range(5)),
        )
        self.assertTrue(system.is_satisfied())

        tamper_cases = (
            (randomized_key[0], expected_randomized_key.u + 1),
            (randomized_key[1], expected_randomized_key.v + 1),
            (circuit_ak[0], system._witness_value(circuit_ak[0]) + 1),
            (circuit_ak[1], system._witness_value(circuit_ak[1]) + 1),
            (ar_variable, ar + 1),
        )
        for variable, value in tamper_cases:
            with self.subTest(variable=variable.name):
                self.assertFalse(
                    system.is_satisfied({variable.index: value})
                )

    def test_value_commitment_matches_pinned_upstream_vector_and_constraints(self):
        vector = json.loads(VALUE_COMMITMENT_FIXTURE.read_text(encoding="utf-8"))[
            "cases"
        ][0]
        value = vector["value"]
        randomness = int.from_bytes(bytes.fromhex(vector["randomness"]), "little")
        expected = Point.from_bytes(bytes.fromhex(vector["commitment"]))
        witness = make_sapling_value_commitment_witness(value, randomness)
        self.assertEqual(witness.commitment, expected)

        system = R1CS()
        commitment = (
            system.alloc_public("cv.u", expected.u),
            system.alloc_public("cv.v", expected.v),
        )
        value_bits = tuple(
            system.alloc_private(f"value bit[{index}]", bit)
            for index, bit in enumerate(witness.value_bits)
        )
        randomness_bits = tuple(
            system.alloc_private(f"rcv bit[{index}]", bit)
            for index, bit in enumerate(witness.randomness_bits)
        )
        result = constrain_sapling_value_commitment(
            system, value_bits, randomness_bits, commitment, witness
        )
        self.assertEqual(system.public_inputs(), (expected.u, expected.v))
        self.assertEqual(system.constraint_count, 1889)
        self.assertEqual(
            (system._witness_value(result[0]), system._witness_value(result[1])),
            (expected.u, expected.v),
        )
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({commitment[0].index: expected.u + 1}))
        self.assertFalse(system.is_satisfied({commitment[1].index: expected.v + 1}))
        self.assertFalse(
            system.is_satisfied(
                {value_bits[0].index: 1 - witness.value_bits[0]}
            )
        )
        self.assertFalse(
            system.is_satisfied(
                {randomness_bits[0].index: 1 - witness.randomness_bits[0]}
            )
        )

        corrupted_value_mul = replace(
            witness.value_mul,
            selected_points=(
                Point(
                    witness.value_mul.selected_points[0].u + 1,
                    witness.value_mul.selected_points[0].v,
                ),
            )
            + witness.value_mul.selected_points[1:],
        )
        corrupted_randomness_mul = replace(
            witness.randomness_mul,
            accumulators=(
                witness.randomness_mul.accumulators[:1]
                + (
                    Point(
                        witness.randomness_mul.accumulators[1].u + 1,
                        witness.randomness_mul.accumulators[1].v,
                    ),
                )
                + witness.randomness_mul.accumulators[2:]
            ),
        )
        for label, corrupted_witness in (
            (
                "value lookup selection",
                replace(witness, value_mul=corrupted_value_mul),
            ),
            (
                "randomness accumulator",
                replace(witness, randomness_mul=corrupted_randomness_mul),
            ),
        ):
            with self.subTest(label=label):
                corrupted_system = R1CS()
                corrupted_public = (
                    corrupted_system.alloc_public("cv.u", expected.u),
                    corrupted_system.alloc_public("cv.v", expected.v),
                )
                corrupted_value_bits = tuple(
                    corrupted_system.alloc_private(f"value bit[{index}]", bit)
                    for index, bit in enumerate(witness.value_bits)
                )
                corrupted_randomness_bits = tuple(
                    corrupted_system.alloc_private(f"rcv bit[{index}]", bit)
                    for index, bit in enumerate(witness.randomness_bits)
                )
                constrain_sapling_value_commitment(
                    corrupted_system,
                    corrupted_value_bits,
                    corrupted_randomness_bits,
                    corrupted_public,
                    corrupted_witness,
                )
                self.assertFalse(corrupted_system.is_satisfied())

    def test_value_commitment_boundaries_and_malformed_inputs(self):
        cases = (
            (0, 0, Point(0, 1)),
            (
                (1 << 64) - 1,
                JUBJUB_SCALAR_MODULUS - 1,
                sapling_fixed_base_generator("value_commitment_value")
                .multiply((1 << 64) - 1)
                + sapling_fixed_base_generator(
                    "value_commitment_randomness"
                ).multiply(JUBJUB_SCALAR_MODULUS - 1),
            ),
        )
        for value, randomness, expected in cases:
            with self.subTest(value=value, randomness=randomness):
                witness = make_sapling_value_commitment_witness(
                    value, randomness
                )
                self.assertEqual(witness.commitment, expected)
                system = R1CS()
                public = (
                    system.alloc_public("cv.u", expected.u),
                    system.alloc_public("cv.v", expected.v),
                )
                value_bits = tuple(
                    system.alloc_private(f"value bit[{index}]", bit)
                    for index, bit in enumerate(witness.value_bits)
                )
                randomness_bits = tuple(
                    system.alloc_private(f"rcv bit[{index}]", bit)
                    for index, bit in enumerate(witness.randomness_bits)
                )
                constrain_sapling_value_commitment(
                    system, value_bits, randomness_bits, public, witness
                )
                self.assertTrue(system.is_satisfied())

        with self.assertRaises(R1CSError):
            make_sapling_value_commitment_witness(1 << 64, 0)
        with self.assertRaises(R1CSError):
            make_sapling_value_commitment_witness(0, JUBJUB_SCALAR_MODULUS)

    def test_nullifier_multipacking_matches_pinned_reference(self):
        fixture = json.loads(
            NULLIFIER_MULTIPACKING_FIXTURE.read_text(encoding="utf-8")
        )
        vector = fixture["case"]
        digest = bytes.fromhex(vector["nullifier_digest_hex"])
        witness = make_sapling_nullifier_multipacking_witness(digest)
        expected = tuple(
            int(value) for value in vector["packed_public_inputs_decimal"]
        )
        self.assertEqual(tuple(vector["chunk_widths"]), (254, 2))
        self.assertEqual(witness.packed_values, expected)

        system = R1CS()
        tuple(
            system.alloc_public(f"Spend public[{index}]", index + 10)
            for index in range(5)
        )
        public_chunks = tuple(
            system.alloc_public(f"nullifier chunk[{index}]", value)
            for index, value in enumerate(expected)
        )
        bits = tuple(
            system.alloc_private(f"nullifier bit[{index}]", bit)
            for index, bit in enumerate(witness.digest_bits)
        )
        outputs = constrain_sapling_nullifier_multipacking(
            system, bits, public_chunks, witness
        )
        self.assertEqual(tuple(output.index for output in outputs), (6, 7))
        self.assertEqual(system.public_inputs(), tuple(range(10, 15)) + expected)
        self.assertEqual(system.constraint_count, 258)
        self.assertTrue(system.is_satisfied())

        for variable, bad_value in (
            (public_chunks[0], expected[0] + 1),
            (public_chunks[1], expected[1] ^ 1),
            (bits[0], 1 - witness.digest_bits[0]),
        ):
            with self.subTest(variable=variable.name):
                self.assertFalse(system.is_satisfied({variable.index: bad_value}))

        reversed_bits = tuple(reversed(witness.digest_bits))
        first_reversed = sum(
            bit << index for index, bit in enumerate(reversed_bits[:254])
        )
        second_reversed = sum(
            bit << index for index, bit in enumerate(reversed_bits[254:])
        )
        reversed_witness = SaplingNullifierMultipackingWitness(
            reversed_bits, (first_reversed, second_reversed)
        )
        reversed_system = R1CS()
        for index in range(5):
            reversed_system.alloc_public(f"Spend public[{index}]", index + 10)
        reversed_public = tuple(
            reversed_system.alloc_public(f"nullifier chunk[{index}]", value)
            for index, value in enumerate(expected)
        )
        reversed_variables = tuple(
            reversed_system.alloc_private(f"reversed nullifier bit[{index}]", bit)
            for index, bit in enumerate(reversed_bits)
        )
        constrain_sapling_nullifier_multipacking(
            reversed_system,
            reversed_variables,
            reversed_public,
            reversed_witness,
        )
        self.assertFalse(reversed_system.is_satisfied())

    def test_nullifier_multipacking_boundaries_and_invalid_inputs(self):
        zero = make_sapling_nullifier_multipacking_witness(bytes(32))
        maximum = make_sapling_nullifier_multipacking_witness(bytes([0xFF]) * 32)
        self.assertEqual(zero.packed_values, (0, 0))
        self.assertEqual(maximum.packed_values, ((1 << 254) - 1, 3))
        self.assertLess(maximum.packed_values[0], SCALAR_MODULUS)
        for label, witness in (("zero", zero), ("maximum", maximum)):
            with self.subTest(label=label):
                system = R1CS()
                for index in range(5):
                    system.alloc_public(f"Spend public[{index}]", index)
                public = tuple(
                    system.alloc_public(f"nullifier chunk[{index}]", value)
                    for index, value in enumerate(witness.packed_values)
                )
                bits = tuple(
                    system.alloc_private(f"nullifier bit[{index}]", bit)
                    for index, bit in enumerate(witness.digest_bits)
                )
                constrain_sapling_nullifier_multipacking(
                    system, bits, public, witness
                )
                self.assertEqual(system.constraint_count, 258)
                self.assertTrue(system.is_satisfied())

        for malformed_digest in (b"", bytes(31), bytes(33)):
            with (
                self.subTest(length=len(malformed_digest)),
                self.assertRaises(R1CSError),
            ):
                make_sapling_nullifier_multipacking_witness(malformed_digest)

        witness = zero
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                R1CS(), (), (), witness
            )

        malformed_width_system = R1CS()
        for index in range(5):
            malformed_width_system.alloc_public(f"Spend public[{index}]", index)
        malformed_public = tuple(
            malformed_width_system.alloc_public(f"nullifier chunk[{index}]", 0)
            for index in range(2)
        )
        malformed_bits = tuple(
            malformed_width_system.alloc_private("malformed digest bit", 0)
            for _ in range(255)
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                malformed_width_system,
                malformed_bits,
                malformed_public,
                witness,
            )
        correctly_sized_system = R1CS()
        for index in range(5):
            correctly_sized_system.alloc_public(f"Spend public[{index}]", index)
        correctly_sized_public = tuple(
            correctly_sized_system.alloc_public(f"nullifier chunk[{index}]", 0)
            for index in range(2)
        )
        correctly_sized_bits = tuple(
            correctly_sized_system.alloc_private(f"nullifier bit[{index}]", bit)
            for index, bit in enumerate(witness.digest_bits)
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                correctly_sized_system,
                correctly_sized_bits,
                correctly_sized_public,
                replace(witness, digest_bits=(0,) * 255),
            )
        with self.assertRaises(R1CSError):
            make_sapling_nullifier_multipacking_witness(b"\x00" * 31)

        noncanonical_system = R1CS()
        for index in range(5):
            noncanonical_system.alloc_public(f"Spend public[{index}]", index)
        noncanonical_public = tuple(
            noncanonical_system.alloc_public(f"nullifier chunk[{index}]", 0)
            for index in range(2)
        )
        noncanonical_bits = tuple(
            noncanonical_system.alloc_private(f"nullifier bit[{index}]", bit)
            for index, bit in enumerate(witness.digest_bits)
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                noncanonical_system,
                noncanonical_bits,
                noncanonical_public,
                replace(witness, packed_values=(SCALAR_MODULUS, 0)),
            )

        wrong_position = R1CS()
        public = tuple(
            wrong_position.alloc_public(f"public[{index}]", 0)
            for index in range(7)
        )
        bits = tuple(
            wrong_position.alloc_private(f"nullifier bit[{index}]", bit)
            for index, bit in enumerate(witness.digest_bits)
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                wrong_position, bits, public[4:6], witness
            )

        non_boolean_system = R1CS()
        non_boolean_public = tuple(
            non_boolean_system.alloc_public(f"public[{index}]", 0)
            for index in range(7)
        )
        non_boolean_bits = tuple(
            non_boolean_system.alloc_private(
                f"nullifier bit[{index}]", 2 if index == 0 else bit
            )
            for index, bit in enumerate(witness.digest_bits)
        )
        with self.assertRaises(R1CSError):
            constrain_sapling_nullifier_multipacking(
                non_boolean_system,
                non_boolean_bits,
                non_boolean_public[5:],
                witness,
            )

    def test_value_commitment_relation_matches_production_and_recorder(self):
        vector = json.loads(
            VALUE_COMMITMENT_FIXTURE.read_text(encoding="utf-8")
        )["cases"][0]
        witness = make_sapling_value_commitment_witness(
            vector["value"],
            int.from_bytes(bytes.fromhex(vector["randomness"]), "little"),
        )

        production = R1CS()
        production_commitment = (
            production.alloc_public("cv.u", witness.commitment.u),
            production.alloc_public("cv.v", witness.commitment.v),
        )
        production_value_bits = tuple(
            production.alloc_private(f"value bit[{index}]", bit)
            for index, bit in enumerate(witness.value_bits)
        )
        production_randomness_bits = tuple(
            production.alloc_private(f"rcv bit[{index}]", bit)
            for index, bit in enumerate(witness.randomness_bits)
        )
        production_result = _constrain_sapling_value_commitment(
            production,
            production_value_bits,
            production_randomness_bits,
            production_commitment,
            witness,
            "Sapling value commitment",
            True,
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_commitment = (
            backend.alloc_public("cv.u", witness.commitment.u),
            backend.alloc_public("cv.v", witness.commitment.v),
        )
        recorder_value_bits = tuple(
            backend.alloc_private(f"value bit[{index}]", bit)
            for index, bit in enumerate(witness.value_bits)
        )
        recorder_randomness_bits = tuple(
            backend.alloc_private(f"rcv bit[{index}]", bit)
            for index, bit in enumerate(witness.randomness_bits)
        )
        recorder_result = _constrain_sapling_value_commitment(
            backend,
            recorder_value_bits,
            recorder_randomness_bits,
            recorder_commitment,
            witness,
            "Sapling value commitment",
            True,
        )

        self.assertEqual(production.constraint_count, 1889)
        self.assertEqual(recorder.constraint_count, 1889)
        self.assertEqual(len(production.variables), 1888)
        self.assertEqual(
            len(recorder.inputs) + len(recorder.auxiliary_variables), 1888
        )
        production_matrix = production.serialize_matrix()
        recorder_matrix = recorder.serialize_local_matrix()
        self.assertEqual(production_matrix, recorder_matrix)
        self.assertEqual(
            hashlib.sha256(production_matrix).hexdigest(),
            "885b7d51797f2d65e89e4ada3e8bdd5ca8fc3187eef421fbe4f7463bbc65d592",
        )
        self.assertEqual(
            tuple(row.name for row in recorder.constraints),
            tuple(row.label for row in production.constraints),
        )
        production_variables = production.variables[1:]
        recorder_variables = (
            recorder.inputs[1:] + recorder.auxiliary_variables
        )
        self.assertEqual(
            tuple(variable.index - 1 for variable in production_variables),
            tuple(range(len(recorder_variables))),
        )
        self.assertEqual(
            tuple(variable.name for variable in production_variables),
            tuple(variable.name for variable in recorder_variables),
        )
        self.assertEqual(
            tuple(
                production.witness_value(variable)
                for variable in production_variables
            ),
            tuple(
                backend.witness_value(variable)
                for variable in recorder_variables
            ),
        )
        self.assertEqual(
            tuple(
                production.witness_value(variable)
                for variable in production_result
            ),
            tuple(
                backend.witness_value(variable)
                for variable in recorder_result
            ),
        )
        self.assertTrue(production.is_satisfied())

        rejected_recorder = BellmanSynthesisRecorder()
        rejected_backend = RecorderSynthesisBackend(rejected_recorder)
        rejected_commitment = (
            rejected_backend.alloc_public("cv.u", witness.commitment.u),
            rejected_backend.alloc_public("cv.v", witness.commitment.v),
        )
        rejected_value_bits = tuple(
            rejected_backend.alloc_private(f"value bit[{index}]", bit)
            for index, bit in enumerate(witness.value_bits)
        )
        rejected_randomness_bits = tuple(
            rejected_backend.alloc_private(f"rcv bit[{index}]", bit)
            for index, bit in enumerate(witness.randomness_bits)
        )
        foreign_backend = RecorderSynthesisBackend(BellmanSynthesisRecorder())
        foreign_value_bit = foreign_backend.alloc_private(
            "foreign value bit", witness.value_bits[-1]
        )
        before_rejection = rejected_recorder.serialize()
        with self.assertRaises(BellmanRecorderError):
            _constrain_sapling_value_commitment(
                rejected_backend,
                (*rejected_value_bits[:-1], foreign_value_bit),
                rejected_randomness_bits,
                rejected_commitment,
                witness,
                "Sapling value commitment",
                True,
            )
        self.assertEqual(rejected_recorder.serialize(), before_rejection)

    def test_merkle_path_constraints_match_pinned_reference(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        path_case = fixture["witnesses"][3]
        leaf = int.from_bytes(
            bytes.fromhex(path_case["note_commitment"]), "little"
        )
        anchor_value = int.from_bytes(bytes.fromhex(path_case["anchor"]), "little")
        siblings = tuple(
            int.from_bytes(bytes.fromhex(node), "little")
            for node in path_case["authentication_path"]
        )
        witness = make_merkle_path_witness(leaf, siblings, path_case["position"])

        def constrain_path(path_witness, anchor):
            system = R1CS()
            public_values = (11, 12, 13, 14, anchor, 15, 16)
            public = tuple(
                system.alloc_public(f"spend public[{index}]", value)
                for index, value in enumerate(public_values)
            )
            leaf_variable = system.alloc_private("note commitment u", leaf)
            result = constrain_merkle_authentication_path(
                system, leaf_variable, public[4], path_witness
            )
            return system, public, leaf_variable, result, public_values

        system, public, leaf_variable, result, public_values = constrain_path(
            witness, anchor_value
        )
        self.assertEqual(system.public_inputs(), public_values)
        self.assertEqual(system._witness_value(result.root), anchor_value)
        self.assertEqual(len(result.position_bits), 32)
        self.assertEqual(len(result.siblings), 32)
        self.assertEqual(len(result.intermediate_roots), 32)
        self.assertEqual(system.constraint_count, 65762)
        self.assertEqual(
            tuple(system._witness_value(bit) for bit in result.position_bits),
            tuple((path_case["position"] >> level) & 1 for level in range(32)),
        )
        self.assertTrue(system.is_satisfied())

        variables = {variable.name: variable for variable in system.variables}
        self.assertEqual(
            system._witness_value(variables[
                "Sapling Merkle authentication path left[0]"
            ]),
            siblings[0],
        )
        self.assertEqual(
            system._witness_value(variables[
                "Sapling Merkle authentication path right[0]"
            ]),
            leaf,
        )
        self.assertEqual(
            system._witness_value(variables[
                "Sapling Merkle authentication path left[2]"
            ]),
            system._witness_value(result.intermediate_roots[1]),
        )
        self.assertEqual(
            system._witness_value(variables[
                "Sapling Merkle authentication path right[2]"
            ]),
            siblings[2],
        )

        position_variable = variables["Sapling Merkle authentication path position"]
        for level, bit in enumerate(result.position_bits):
            bit_value = (path_case["position"] >> level) & 1
            changed_position = path_case["position"] ^ (1 << level)
            with self.subTest(direction_level=level):
                self.assertFalse(
                    system.is_satisfied({bit.index: 1 - bit_value})
                )
                self.assertFalse(
                    system.is_satisfied(
                        {
                            position_variable.index: changed_position,
                            bit.index: 1 - bit_value,
                        }
                    )
                )

        self.assertFalse(
            system.is_satisfied({public[4].index: anchor_value + 1})
        )
        self.assertFalse(
            system.is_satisfied({leaf_variable.index: leaf + 1})
        )
        for level in (0, 1, 31):
            sibling = result.siblings[level]
            with self.subTest(changed_sibling_level=level):
                self.assertFalse(
                    system.is_satisfied(
                        {
                            sibling.index:
                            (siblings[level] + 1) % SCALAR_MODULUS
                        }
                    )
                )
        for level in (0, 15, 31):
            intermediate = result.intermediate_roots[level]
            value = system._witness_value(intermediate)
            with self.subTest(changed_intermediate_level=level):
                self.assertFalse(
                    system.is_satisfied(
                        {intermediate.index: (value + 1) % SCALAR_MODULUS}
                    )
                )

        malformed_witness = MerklePathWitness(
            witness.position,
            witness.siblings,
            witness.pedersen_hashes[:-1],
        )
        malformed_system = R1CS()
        malformed_anchor = malformed_system.alloc_public(
            "malformed path anchor", anchor_value
        )
        malformed_leaf = malformed_system.alloc_private(
            "malformed path leaf", leaf
        )
        with self.assertRaises(R1CSError):
            constrain_merkle_authentication_path(
                malformed_system,
                malformed_leaf,
                malformed_anchor,
                malformed_witness,
            )

        with self.assertRaises(R1CSError):
            make_merkle_path_witness(leaf, siblings[:-1], 0)
        with self.assertRaises(R1CSError):
            make_merkle_path_witness(leaf, siblings, 1 << 32)

        maximum_position = (1 << 32) - 1
        maximum_witness = make_merkle_path_witness(
            leaf, siblings, maximum_position
        )
        maximum_root = maximum_witness.pedersen_hashes[-1].result.u
        max_system, max_public, _, max_result, max_public_values = constrain_path(
            maximum_witness, maximum_root
        )
        self.assertEqual(
            tuple(max_system._witness_value(bit) for bit in max_result.position_bits),
            (1,) * 32,
        )
        self.assertEqual(max_system.public_inputs(), max_public_values)
        self.assertTrue(max_system.is_satisfied())
        self.assertFalse(
            max_system.is_satisfied(
                {max_public[4].index: (maximum_root + 1) % SCALAR_MODULUS}
            )
        )
        max_position = {
            variable.name: variable
            for variable in max_system.variables
        }["Sapling Merkle authentication path position"]
        self.assertFalse(
            max_system.is_satisfied(
                {max_position.index: maximum_position + 1}
            )
        )

    def test_sapling_conditional_anchor_matches_upstream_zero_value_rule(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        path_case = fixture["witnesses"][0]
        leaf = int.from_bytes(
            bytes.fromhex(path_case["note_commitment"]), "little"
        )
        anchor_value = int.from_bytes(
            bytes.fromhex(path_case["anchor"]), "little"
        )
        siblings = tuple(
            int.from_bytes(bytes.fromhex(node), "little")
            for node in path_case["authentication_path"]
        )
        witness = make_merkle_path_witness(
            leaf, siblings, path_case["position"]
        )
        self.assertEqual(path_case["position"], 0)
        self.assertEqual(
            path_case["note_commitment"],
            json.loads(NULLIFIER_FIXTURE.read_text(encoding="utf-8"))[
                "cases"
            ][0]["note_cmu"],
        )
        self.assertEqual(
            json.loads(NULLIFIER_FIXTURE.read_text(encoding="utf-8"))[
                "cases"
            ][0]["note_v"],
            0,
        )

        wrong_anchor = (anchor_value + 1) % SCALAR_MODULUS
        system = R1CS()
        public = tuple(
            system.alloc_public(
                f"Spend public[{index}]",
                wrong_anchor if index == 4 else index,
            )
            for index in range(7)
        )
        note_value = system.alloc_private("note value", 0)
        value_bits = system.range_check(note_value, 64, "note value bit")
        leaf_variable = system.alloc_private("note commitment u", leaf)
        result = constrain_merkle_authentication_path(
            system,
            leaf_variable,
            public[4],
            witness,
            note_value=note_value,
        )
        self.assertEqual(system._witness_value(result.root), anchor_value)
        self.assertTrue(system.is_satisfied())

        # A zero-valued note permits an unrelated public anchor, but changing
        # the same constrained value to nonzero activates the root equality.
        nonzero_value = {
            note_value.index: 1,
            value_bits[0].index: 1,
        }
        self.assertFalse(system.is_satisfied(nonzero_value))
        self.assertTrue(
            system.is_satisfied(
                nonzero_value | {public[4].index: anchor_value}
            )
        )
        self.assertFalse(
            system.is_satisfied(
                nonzero_value | {public[4].index: wrong_anchor}
            )
        )
        self.assertFalse(
            system.is_satisfied({leaf_variable.index: leaf + 1})
        )
        self.assertFalse(
            system.is_satisfied(
                {
                    result.siblings[0].index:
                    (siblings[0] + 1) % SCALAR_MODULUS
                }
            )
        )

        malformed_system = R1CS()
        malformed_anchor = malformed_system.alloc_public("anchor", 1)
        malformed_public_value = malformed_system.alloc_public("value", 0)
        malformed_root = malformed_system.alloc_private("computed root", 1)
        with self.assertRaises(R1CSError):
            constrain_sapling_conditional_anchor(
                malformed_system,
                malformed_root,
                malformed_anchor,
                malformed_public_value,
            )
        foreign_system = R1CS()
        foreign_value = foreign_system.alloc_private("foreign value", 0)
        with self.assertRaises(R1CSError):
            constrain_sapling_conditional_anchor(
                malformed_system,
                malformed_root,
                malformed_anchor,
                foreign_value,
            )
        malformed_root_system = R1CS()
        public_root = malformed_root_system.alloc_public("root", 1)
        public_anchor = malformed_root_system.alloc_public("anchor", 1)
        private_value = malformed_root_system.alloc_private("value", 1)
        with self.assertRaises(R1CSError):
            constrain_sapling_conditional_anchor(
                malformed_root_system,
                public_root,
                public_anchor,
                private_value,
            )


    def test_spend_note_and_merkle_reference_vectors_are_aligned(self):
        partial_reference = json.loads(
            SPEND_PARTIAL_FIXTURE.read_text(encoding="utf-8")
        )
        self.assertFalse(
            partial_reference["complete_spend_relation_vector"]
        )
        self.assertEqual(
            partial_reference["source_revisions"]["zcash_test_vectors"][
                "commit"
            ],
            "78321beacb0e0477e33cd002b56585a107c2708c",
        )
        nullifier_case = json.loads(
            NULLIFIER_FIXTURE.read_text(encoding="utf-8")
        )["cases"][
            partial_reference["case_join"]["key_components_case_index"]
        ]
        path_case = json.loads(FIXTURE.read_text(encoding="utf-8"))[
            "witnesses"
        ][partial_reference["case_join"]["merkle_witness_index"]]
        for field_mapping in partial_reference["case_join"][
            "matching_fields"
        ]:
            self.assertEqual(
                nullifier_case[field_mapping["key_components"]],
                path_case[field_mapping["merkle_path"]],
            )
        self.assertEqual(nullifier_case["note_v"], 0)

        leaf = int.from_bytes(
            bytes.fromhex(nullifier_case["note_cmu"]), "little"
        )
        siblings = tuple(
            int.from_bytes(bytes.fromhex(node), "little")
            for node in path_case["authentication_path"]
        )
        for position in (0, (1 << 32) - 1):
            with self.subTest(position=position):
                witness = make_merkle_path_witness(
                    leaf, siblings, position
                )
                self.assertEqual(witness.position, position)
                self.assertEqual(len(witness.pedersen_hashes), 32)

    def test_small_order_jubjub_points_fail_the_circuit_constraint(self):
        system = R1CS()
        identity = allocate_jubjub_point(system, "identity", Point(0, 1))
        constrain_jubjub_point(system, identity)
        constrain_jubjub_not_small_order(system, identity)
        self.assertFalse(system.is_satisfied())

        with self.assertRaises(R1CSError):
            make_note_commitment_witness(0, Point(0, 1), Point(0, 1), 0)


if __name__ == "__main__":
    unittest.main()
