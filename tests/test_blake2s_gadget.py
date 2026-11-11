import json
import unittest
from hashlib import blake2s
from pathlib import Path

from src.blake2s_gadget import (
    _NegatedBit,
    _xor_bit,
    _word_xor,
    bits_to_bytes_le,
    bytes_to_bits_le,
    constrain_blake2s,
    constrain_sapling_ivk,
    constrain_sapling_nullifier_hash,
    make_blake2s_witness,
)
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import Point, group_hash
from src.nullifiers import SaplingNote, _note_position_base
from src.r1cs import R1CS, R1CSError, Variable
from src.sapling_gadgets import (
    allocate_jubjub_point,
    constrain_jubjub_point,
    constrain_jubjub_repr,
    constrain_merkle_authentication_path,
    constrain_note_commitment,
    constrain_sapling_nullifier_multipacking,
    constrain_sapling_nullifier_rho,
    constrain_sapling_randomized_authorization_key,
    constrain_sapling_value_commitment,
    make_merkle_path_witness,
    make_note_commitment_witness,
    make_sapling_nullifier_multipacking_witness,
    make_sapling_nullifier_rho_witness,
    make_sapling_randomized_authorization_key_witness,
    make_sapling_value_commitment_witness,
)
from tests.bellman_blake2s_reference import (
    bellman_bits_to_bytes,
    build_bellman_compression_reference,
    constrain_bellman_blake2s_reference,
)

IVK_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_ivk_blake2s_reference.json"
)
NULLIFIER_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_reference.json"
)
NULLIFIER_MULTIPACKING_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_nullifier_multipacking_reference.json"
)
MERKLE_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_merkle_tree_reference.json"
)
RANDOMIZED_AUTHORIZATION_KEY_FIXTURE = (
    Path(__file__).parent
    / "fixtures"
    / "sapling_randomized_authorization_key_reference.json"
)


def allocate_bits(system, name, data):
    return tuple(
        system.alloc_private(f"{name}[{index}]", bit)
        for index, bit in enumerate(bytes_to_bits_le(data))
    )


def compare_full_hash_matrix(test_case, message, personalization):
    bits = bytes_to_bits_le(message)
    local = R1CS()
    local_bits = allocate_bits(local, "message", message)
    witness = make_blake2s_witness(bits, personalization)
    local_digest = constrain_blake2s(
        local, local_bits, personalization, witness
    )

    reference = R1CS()
    reference_bits = allocate_bits(reference, "message", message)
    for bit in reference_bits:
        reference.enforce(1 - bit.lc(), bit, 0, "upstream input Boolean")
    reference_digest = constrain_bellman_blake2s_reference(
        reference, reference_bits, personalization
    )

    test_case.assertEqual(local.serialize_matrix(), reference.serialize_matrix())
    test_case.assertEqual(local.matrix_fingerprint(), reference.matrix_fingerprint())
    test_case.assertEqual(
        bits_to_bytes_le(local_digest, local),
        bellman_bits_to_bytes(reference, reference_digest),
    )
    test_case.assertTrue(local.is_satisfied())
    test_case.assertTrue(reference.is_satisfied())
    return local, bits_to_bytes_le(local_digest, local)


class Blake2sGadgetTests(unittest.TestCase):
    def test_bellman_015_xor_truth_table_and_exact_r1cs_row(self):
        for left_value in (0, 1):
            for right_value in (0, 1):
                with self.subTest(left=left_value, right=right_value):
                    system = R1CS()
                    left = system.alloc_private("left", left_value)
                    right = system.alloc_private("right", right_value)
                    system.boolean(left, "left boolean")
                    system.boolean(right, "right boolean")

                    output = _xor_bit(system, left, right, "xor")

                    self.assertIsInstance(output, type(left))
                    self.assertIsInstance(output, Variable)
                    assert isinstance(output, Variable)
                    self.assertEqual(output.index, 3)
                    self.assertEqual(
                        system._witness_value(output),
                        left_value ^ right_value,
                    )
                    self.assertTrue(system.is_satisfied())
                    relation = next(
                        constraint
                        for constraint in system.constraints
                        if constraint.label == "xor XOR relation"
                    )
                    self.assertEqual(relation.left.terms, ((left.index, 2),))
                    self.assertEqual(relation.right.terms, ((right.index, 1),))
                    self.assertEqual(
                        relation.output.terms,
                        (
                            (left.index, 1),
                            (right.index, 1),
                            (output.index, SCALAR_MODULUS - 1),
                        ),
                    )

    def test_bellman_xor_matches_exhaustive_is_and_not_aliases(self):
        for left_value in (0, 1):
            for right_value in (0, 1):
                for left_negated in (False, True):
                    for right_negated in (False, True):
                        with self.subTest(
                            left=left_value,
                            right=right_value,
                            left_negated=left_negated,
                            right_negated=right_negated,
                        ):
                            system = R1CS()
                            left_variable = system.alloc_private(
                                "left", left_value
                            )
                            right_variable = system.alloc_private(
                                "right", right_value
                            )
                            system.boolean(left_variable, "left boolean")
                            system.boolean(right_variable, "right boolean")
                            left = (
                                _NegatedBit(left_variable)
                                if left_negated
                                else left_variable
                            )
                            right = (
                                _NegatedBit(right_variable)
                                if right_negated
                                else right_variable
                            )

                            output = _xor_bit(system, left, right, "xor")
                            expected = (
                                (left_value ^ int(left_negated))
                                ^ (right_value ^ int(right_negated))
                            )

                            self.assertEqual(
                                int(system._witness_value(output.variable))
                                if isinstance(output, _NegatedBit)
                                else system._witness_value(output),
                                (left_value ^ right_value),
                            )
                            actual = (
                                1 - system._witness_value(output.variable)
                                if isinstance(output, _NegatedBit)
                                else system._witness_value(output)
                            )
                            self.assertEqual(actual, expected)
                            self.assertEqual(
                                isinstance(output, _NegatedBit),
                                left_negated != right_negated,
                            )
                            output_variable = (
                                output.variable
                                if isinstance(output, _NegatedBit)
                                else output
                            )
                            assert isinstance(output_variable, Variable)
                            self.assertEqual(output_variable.index, 3)
                            self.assertTrue(system.is_satisfied())
                            relation = next(
                                constraint
                                for constraint in system.constraints
                                if constraint.label == "xor XOR relation"
                            )
                            output_variable = (
                                output.variable
                                if isinstance(output, _NegatedBit)
                                else output
                            )
                            self.assertEqual(
                                relation.left.terms,
                                ((left_variable.index, 2),),
                            )
                            self.assertEqual(
                                relation.right.terms,
                                ((right_variable.index, 1),),
                            )
                            self.assertEqual(
                                relation.output.terms,
                                (
                                    (left_variable.index, 1),
                                    (right_variable.index, 1),
                                    (output_variable.index, SCALAR_MODULUS - 1),
                                ),
                            )

    def test_multi_bit_xor_matches_bitwise_reference_and_upstream_rows(self):
        system = R1CS()
        left_values = tuple((index * 7 + 1) & 1 for index in range(32))
        right_values = tuple((index * 11 + 1) & 1 for index in range(32))
        left = tuple(
            system.alloc_private(f"left[{index}]", bit)
            for index, bit in enumerate(left_values)
        )
        right_variables = tuple(
            system.alloc_private(f"right[{index}]", bit)
            for index, bit in enumerate(right_values)
        )
        for variable in left + right_variables:
            system.boolean(variable, f"{variable.name} boolean")
        right = tuple(
            _NegatedBit(variable) if index % 2 else variable
            for index, variable in enumerate(right_variables)
        )

        result = _word_xor(system, left, right, "word xor")

        expected = tuple(
            left_values[index] ^ right_values[index] ^ (index % 2)
            for index in range(32)
        )
        self.assertEqual(
            tuple(
                1 - system._witness_value(bit.variable)
                if isinstance(bit, _NegatedBit)
                else system._witness_value(bit)
                for bit in result
            ),
            expected,
        )
        self.assertEqual(
            sum(constraint.label.endswith("XOR relation") for constraint in system.constraints),
            32,
        )
        self.assertTrue(system.is_satisfied())

    def test_xor_rejects_non_boolean_inputs_and_output_mutation(self):
        system = R1CS()
        left = system.alloc_private("left", 1)
        right = system.alloc_private("right", 0)
        system.boolean(left, "left boolean")
        system.boolean(right, "right boolean")
        output = _xor_bit(system, left, right, "xor")
        self.assertTrue(system.is_satisfied())

        self.assertFalse(system.is_satisfied({left.index: 2}))
        self.assertFalse(system.is_satisfied({right.index: 2}))
        self.assertFalse(system.is_satisfied({output.index: 2}))

    def test_bit_serialization_is_little_endian_within_each_byte(self):
        self.assertEqual(
            bytes_to_bits_le(b"\x01\x80"),
            (1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
        )

    def test_blake2s_official_unpersonalized_kat(self):
        message = b"\x00"
        system = R1CS()
        input_bits = allocate_bits(system, "input", message)
        witness = make_blake2s_witness(
            bytes_to_bits_le(message), b"\x00" * 8
        )
        output = constrain_blake2s(
            system, input_bits, b"\x00" * 8, witness
        )
        self.assertEqual(
            bits_to_bytes_le(output, system).hex(),
            "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea",
        )
        self.assertTrue(system.is_satisfied())

    def test_upstream_blank_hash_personalization_vector(self):
        system = R1CS()
        witness = make_blake2s_witness((), b"12345678")
        digest = constrain_blake2s(
            system, (), b"12345678", witness
        )
        self.assertEqual(
            bits_to_bytes_le(digest, system).hex(),
            "c59f682376d137f3f255e671e207d1f2374ebe504e9314208a52d9f88d69e8c8",
        )
        self.assertEqual(system.constraint_count, 0)
        self.assertTrue(system.is_satisfied())

    def test_boundary_lengths_match_independent_hashlib(self):
        for length in (0, 1, 3, 63, 64, 65):
            message = bytes(index % 256 for index in range(length))
            personalization = b"Zcashivk"
            system = R1CS()
            input_bits = allocate_bits(system, "input", message)
            witness = make_blake2s_witness(
                bytes_to_bits_le(message), personalization
            )
            output = constrain_blake2s(
                system,
                input_bits,
                personalization,
                witness,
                f"boundary[{length}]",
            )
            self.assertTrue(system.is_satisfied(), f"length={length}")
            self.assertEqual(
                bits_to_bytes_le(output, system),
                blake2s(message, digest_size=32, person=personalization).digest(),
            )
            if length == 64:
                self.assertEqual(system.constraint_count, 21518)

    def test_full_block_constraint_profile_matches_pinned_bellman(self):
        message = bytes([0xFF]) * 64
        personalization = b"12345678"
        system = R1CS()
        input_bits = allocate_bits(system, "input", message)
        witness = make_blake2s_witness(
            bytes_to_bits_le(message), personalization
        )
        digest = constrain_blake2s(system, input_bits, personalization, witness)

        labels = tuple(constraint.label for constraint in system.constraints)
        self.assertEqual(system.constraint_count, 21518)
        self.assertEqual(
            bits_to_bytes_le(digest, system).hex(),
            "36a9a0bbcfc4e31b22a6e0d9cc4e2d37153950bda51aff8cd904d77057da5b65",
        )
        self.assertEqual(sum("input bit[" in label for label in labels), 512)
        self.assertEqual(
            sum("add[" in label and " boolean" in label for label in labels),
            10720,
        )
        self.assertEqual(
            sum("packed additions[" in label for label in labels), 46
        )
        self.assertEqual(
            sum("XOR relation" in label for label in labels), 10240
        )
        self.assertEqual(
            [
                sum(f"round[{index}]" in label for label in labels)
                for index in range(10)
            ],
            [1845, 2101, 2100, 2101, 2100, 2101, 2100, 2101, 2101, 2100],
        )
        reference = build_bellman_compression_reference()
        matrix = system.serialize_matrix()
        self.assertEqual(matrix, reference.serialize_matrix())
        self.assertEqual(
            system.matrix_fingerprint(), reference.matrix_fingerprint()
        )
        matrix_document = json.loads(matrix)
        self.assertEqual(matrix_document["column_count"], 21473)
        self.assertEqual(matrix_document["auxiliary_variable_count"], 21472)
        self.assertEqual(matrix_document["public_input_count"], 0)
        input_boolean = next(
            constraint
            for constraint in system.constraints
            if constraint.label.endswith("input bit[0]")
        )
        self.assertEqual(
            input_boolean.left.terms,
            ((0, 1), (input_bits[0].index, SCALAR_MODULUS - 1)),
        )
        self.assertEqual(
            input_boolean.right.terms, ((input_bits[0].index, 1),)
        )
        packed_addition = next(
            constraint
            for constraint in system.constraints
            if "packed additions[0]" in constraint.label
        )
        self.assertEqual(packed_addition.right.terms, ((0, 1),))
        self.assertEqual(matrix, system.serialize_matrix())
        repeated = R1CS()
        repeated_input = allocate_bits(repeated, "input", message)
        repeated_witness = make_blake2s_witness(
            bytes_to_bits_le(message), personalization
        )
        constrain_blake2s(
            repeated, repeated_input, personalization, repeated_witness
        )
        self.assertEqual(matrix, repeated.serialize_matrix())
        self.assertEqual(
            system.matrix_fingerprint(),
            "fbbf17336107591b69f01d1a4cb74635a659851aaec627d5dce2e8e31aba9785",
        )
        self.assertTrue(system.is_satisfied())
        self.assertTrue(reference.is_satisfied())

    def test_complete_hash_matrix_matches_reference_at_block_boundaries(self):
        for length in (0, 1, 63, 64, 65, 127, 128, 129):
            with self.subTest(length=length):
                message = bytes(index % 251 for index in range(length))
                _, digest = compare_full_hash_matrix(
                    self, message, b"Zcash_nf"
                )
                self.assertEqual(
                    digest,
                    blake2s(message, digest_size=32, person=b"Zcash_nf").digest(),
                )

    def test_sapling_ivk_hash_matrix_matches_pinned_personalization(self):
        vector = json.loads(IVK_FIXTURE.read_text(encoding="utf-8"))["case"]
        preimage = bytes.fromhex(vector["ak"] + vector["nk"])
        system, digest = compare_full_hash_matrix(self, preimage, b"Zcashivk")
        expected = int.from_bytes(bytes.fromhex(vector["ivk"]), "little")
        self.assertEqual(int.from_bytes(digest[:32], "little") & ((1 << 251) - 1), expected)
        self.assertEqual(system.constraint_count, 21518)
        self.assertEqual(len(system.variables), 21473)
        self.assertEqual(
            system.matrix_fingerprint(),
            "1ec15b1eb11bc673d71aa761acb8e396a4bb74a5945940d302cfbfa6a429cc0d",
        )

    def test_sapling_nullifier_hash_matrix_matches_pinned_personalization(self):
        vector = json.loads(NULLIFIER_FIXTURE.read_text(encoding="utf-8"))["cases"][0]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        self.assertIsNotNone(diversifier_base)
        note = SaplingNote(
            bytes.fromhex(vector["note_cmu"]),
            diversifier_base.encode(),
            bytes.fromhex(vector["default_pk_d"]),
            vector["note_v"],
            int.from_bytes(bytes.fromhex(vector["note_r"]), "little"),
            1,
        )
        nk = Point.from_bytes(bytes.fromhex(vector["nk"]), check_subgroup=True)
        rho = note._commitment_point + _note_position_base().multiply(
            vector["note_pos"]
        )
        system, digest = compare_full_hash_matrix(
            self, nk.encode() + rho.encode(), b"Zcash_nf"
        )
        self.assertEqual(digest.hex(), vector["note_nf"])
        self.assertEqual(system.constraint_count, 21518)
        self.assertEqual(len(system.variables), 21473)
        self.assertEqual(
            system.matrix_fingerprint(),
            "701c5a72f19a024a3f7b436f5364820efa4a824364b00753c9a06ef04d2ef569",
        )

    def test_variable_input_and_output_tampering_break_constraints(self):
        message = bytes(range(64))
        system = R1CS()
        input_bits = allocate_bits(system, "message", message)
        witness = make_blake2s_witness(bytes_to_bits_le(message), b"Zcash_nf")
        output = constrain_blake2s(
            system, input_bits, b"Zcash_nf", witness, "tamper test"
        )
        self.assertTrue(system.is_satisfied())
        self.assertFalse(
            system.is_satisfied({input_bits[0].index: 1 - message[0] % 2})
        )
        output_variable = (
            output[0].variable
            if isinstance(output[0], _NegatedBit)
            else output[0]
        )
        output_value = system._witness_value(output_variable)
        self.assertIn(output_value, (0, 1))
        self.assertFalse(
            system.is_satisfied(
                {output_variable.index: 1 - output_value}
            )
        )
        intermediate = next(
            variable
            for variable in system.variables
            if variable.name.endswith("add[0] bit[0]")
        )
        intermediate_value = system._witness_value(intermediate)
        self.assertIn(intermediate_value, (0, 1))
        self.assertFalse(
            system.is_satisfied({intermediate.index: 1 - intermediate_value})
        )
        carry = next(
            variable
            for variable in system.variables
            if variable.name.endswith("add[0] carry[0]")
        )
        carry_value = system._witness_value(carry)
        self.assertIn(carry_value, (0, 1))
        self.assertFalse(
            system.is_satisfied({carry.index: 1 - carry_value})
        )

    def test_malformed_bits_personalization_and_witness_are_rejected(self):
        with self.assertRaises(R1CSError):
            make_blake2s_witness((0, 1, 0), b"Zcash_nf")
        with self.assertRaises(R1CSError):
            make_blake2s_witness((0,) * 8, b"short")
        with self.assertRaises(R1CSError):
            make_blake2s_witness((0, 1, 2, 0, 0, 0, 0, 0), b"Zcash_nf")

        message = bytes_to_bits_le(b"x")
        system = R1CS()
        input_bits = allocate_bits(system, "message", b"x")
        witness = make_blake2s_witness(message, b"Zcash_nf")
        with self.assertRaises(R1CSError):
            constrain_blake2s(system, input_bits, b"Zcashivk", witness)
        wrong_input_witness = make_blake2s_witness(
            bytes_to_bits_le(b"y"), b"Zcash_nf"
        )
        with self.assertRaises(R1CSError):
            constrain_blake2s(
                system, input_bits, b"Zcash_nf", wrong_input_witness
            )

    def test_sapling_ivk_matches_pinned_zip32_vector(self):
        vector = json.loads(IVK_FIXTURE.read_text(encoding="utf-8"))["case"]
        ak = Point.from_bytes(bytes.fromhex(vector["ak"]), check_subgroup=True)
        nk = Point.from_bytes(bytes.fromhex(vector["nk"]), check_subgroup=True)
        self.assertEqual(ak.encode().hex(), vector["ak"])
        self.assertEqual(nk.encode().hex(), vector["nk"])

        system = R1CS()
        ak_bits = allocate_bits(system, "ak repr", ak.encode())
        nk_bits = allocate_bits(system, "nk repr", nk.encode())
        ivk_bits = constrain_sapling_ivk(system, ak_bits, nk_bits)
        actual = sum(
            system._witness_value(bit) << index
            for index, bit in enumerate(ivk_bits)
        )
        self.assertEqual(actual, int.from_bytes(bytes.fromhex(vector["ivk"]), "little"))
        self.assertTrue(system.is_satisfied())
        self.assertEqual(len(ivk_bits), 251)

    def test_sapling_nullifier_hash_matches_pinned_note_vector(self):
        vector = json.loads(NULLIFIER_FIXTURE.read_text(encoding="utf-8"))["cases"][0]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        self.assertIsNotNone(diversifier_base)
        note = SaplingNote(
            bytes.fromhex(vector["note_cmu"]),
            diversifier_base.encode(),
            bytes.fromhex(vector["default_pk_d"]),
            vector["note_v"],
            int.from_bytes(bytes.fromhex(vector["note_r"]), "little"),
            1,
        )
        nk = Point.from_bytes(bytes.fromhex(vector["nk"]), check_subgroup=True)
        rho = note._commitment_point + _note_position_base().multiply(
            vector["note_pos"]
        )

        packing_vector = json.loads(
            NULLIFIER_MULTIPACKING_FIXTURE.read_text(encoding="utf-8")
        )["case"]
        packing_witness = make_sapling_nullifier_multipacking_witness(
            bytes.fromhex(packing_vector["nullifier_digest_hex"])
        )
        expected_chunks = tuple(
            int(value)
            for value in packing_vector["packed_public_inputs_decimal"]
        )

        system = R1CS()
        for index, value in enumerate((11, 12, 13, 14, 15)):
            system.alloc_public(f"Spend public[{index}]", value)
        public_chunks = tuple(
            system.alloc_public(f"nullifier chunk[{index}]", value)
            for index, value in enumerate(expected_chunks)
        )
        nk_bits = allocate_bits(system, "nk repr", nk.encode())
        rho_bits = allocate_bits(system, "rho repr", rho.encode())
        nullifier_bits = constrain_sapling_nullifier_hash(
            system, nk_bits, rho_bits
        )
        actual = bits_to_bytes_le(nullifier_bits, system)
        self.assertEqual(actual.hex(), vector["note_nf"])
        constrain_sapling_nullifier_multipacking(
            system,
            nullifier_bits,
            public_chunks,
            packing_witness,
        )
        self.assertEqual(
            system.public_inputs(), (11, 12, 13, 14, 15) + expected_chunks
        )
        self.assertEqual(system.constraint_count, 21912)
        self.assertTrue(system.is_satisfied())
        self.assertEqual(len(nullifier_bits), 256)
        self.assertFalse(
            system.is_satisfied(
                {public_chunks[0].index: expected_chunks[0] + 1}
            )
        )

    def test_sapling_nullifier_rho_relation_matches_pinned_note_vector(self):
        fixture = json.loads(NULLIFIER_FIXTURE.read_text(encoding="utf-8"))
        self.assertIn("sapling_key_components.json", fixture["source"])
        vector = fixture["cases"][1]
        diversifier_base = group_hash(
            b"Zcash_gd", bytes.fromhex(vector["default_d"])
        )
        self.assertIsNotNone(diversifier_base)
        transmission_key = Point.from_bytes(
            bytes.fromhex(vector["default_pk_d"]), check_subgroup=True
        )
        commitment_randomness = int.from_bytes(
            bytes.fromhex(vector["note_r"]), "little"
        )
        note_witness = make_note_commitment_witness(
            vector["note_v"],
            diversifier_base,
            transmission_key,
            commitment_randomness,
        )
        self.assertEqual(
            note_witness.commitment.u.to_bytes(32, "little").hex(),
            vector["note_cmu"],
        )
        rho_witness = make_sapling_nullifier_rho_witness(
            note_witness.commitment, vector["note_pos"]
        )
        self.assertEqual(rho_witness.position, vector["note_pos"])

        expected_nullifier = bytes.fromhex(vector["note_nf"])
        expected_nullifier_integer = int.from_bytes(
            expected_nullifier, "little"
        )
        expected_chunks = (
            expected_nullifier_integer & ((1 << 254) - 1),
            expected_nullifier_integer >> 254,
        )
        packing_witness = make_sapling_nullifier_multipacking_witness(
            expected_nullifier
        )
        self.assertEqual(packing_witness.packed_values, expected_chunks)

        system = R1CS()
        for index in range(5):
            system.alloc_public(f"Spend public input[{index}]", 0)
        public_chunks = tuple(
            system.alloc_public(f"Spend public input[{index + 5}]", value)
            for index, value in enumerate(expected_chunks)
        )
        value = system.alloc_private("note value", vector["note_v"])
        circuit_base = allocate_jubjub_point(
            system, "note diversifier base", diversifier_base
        )
        pkd_bits = allocate_bits(
            system, "note transmission key", transmission_key.encode()
        )
        randomness_bits = tuple(
            system.alloc_private(f"note rcm bit[{index}]", bit)
            for index, bit in enumerate(note_witness.rcm_bits)
        )
        note_commitment = constrain_note_commitment(
            system,
            value,
            circuit_base,
            pkd_bits,
            randomness_bits,
            note_witness,
        )
        position_bits = tuple(
            system.alloc_private(f"position bit[{index}]", bit)
            for index, bit in enumerate(rho_witness.position_bits)
        )
        rho = constrain_sapling_nullifier_rho(
            system,
            note_commitment,
            position_bits,
            rho_witness,
        )
        rho_bits = constrain_jubjub_repr(system, rho, "rho representation")
        nk = Point.from_bytes(bytes.fromhex(vector["nk"]), check_subgroup=True)
        nk_bits = allocate_bits(system, "nullifier key", nk.encode())
        nullifier_bits = constrain_sapling_nullifier_hash(
            system, nk_bits, rho_bits
        )
        self.assertEqual(
            bits_to_bytes_le(nullifier_bits, system), expected_nullifier
        )
        constrain_sapling_nullifier_multipacking(
            system, nullifier_bits, public_chunks, packing_witness
        )
        self.assertEqual(
            system.public_inputs(), (0, 0, 0, 0, 0) + expected_chunks
        )
        self.assertEqual(
            bits_to_bytes_le(rho_bits, system), rho_witness.rho.encode()
        )
        self.assertTrue(system.is_satisfied())

        tamper_cases = (
            (position_bits[0], 1 - rho_witness.position_bits[0]),
            (
                randomness_bits[0],
                1 - note_witness.rcm_bits[0],
            ),
            (
                rho[0],
                (system._witness_value(rho[0]) + 1),
            ),
            (rho_bits[0], 1 - system._witness_value(rho_bits[0])),
            (
                public_chunks[0],
                expected_chunks[0] + 1,
            ),
        )
        for variable, assigned_value in tamper_cases:
            with self.subTest(variable=variable.name):
                self.assertFalse(
                    system.is_satisfied({variable.index: assigned_value})
                )

    def test_spend_component_relations_share_note_value_path_and_position(self):
        nullifier_fixture = json.loads(
            NULLIFIER_FIXTURE.read_text(encoding="utf-8")
        )
        vector = nullifier_fixture["cases"][0]
        merkle_fixture = json.loads(MERKLE_FIXTURE.read_text(encoding="utf-8"))
        path_case = merkle_fixture["witnesses"][0]
        self.assertEqual(path_case["position"], vector["note_pos"])
        self.assertEqual(path_case["note_commitment"], vector["note_cmu"])
        self.assertEqual(vector["note_v"], 0)

        diversifier = bytes.fromhex(vector["default_d"])
        diversifier_base = group_hash(b"Zcash_gd", diversifier)
        self.assertIsNotNone(diversifier_base)
        transmission_key = Point.from_bytes(
            bytes.fromhex(vector["default_pk_d"]), check_subgroup=True
        )
        note_witness = make_note_commitment_witness(
            vector["note_v"],
            diversifier_base,
            transmission_key,
            int.from_bytes(bytes.fromhex(vector["note_r"]), "little"),
        )
        self.assertEqual(
            note_witness.commitment.u.to_bytes(32, "little").hex(),
            vector["note_cmu"],
        )

        siblings = tuple(
            int.from_bytes(bytes.fromhex(node), "little")
            for node in path_case["authentication_path"]
        )
        path_witness = make_merkle_path_witness(
            note_witness.commitment.u,
            siblings,
            vector["note_pos"],
        )
        anchor = int.from_bytes(bytes.fromhex(path_case["anchor"]), "little")
        self.assertEqual(path_witness.pedersen_hashes[-1].result.u, anchor)

        expected_nullifier = bytes.fromhex(vector["note_nf"])
        expected_nullifier_integer = int.from_bytes(
            expected_nullifier, "little"
        )
        expected_chunks = (
            expected_nullifier_integer & ((1 << 254) - 1),
            expected_nullifier_integer >> 254,
        )
        packing_witness = make_sapling_nullifier_multipacking_witness(
            expected_nullifier
        )
        value_commitment_witness = make_sapling_value_commitment_witness(
            vector["note_v"], 1
        )
        randomized_key_fixture = json.loads(
            RANDOMIZED_AUTHORIZATION_KEY_FIXTURE.read_text(encoding="utf-8")
        )
        randomized_key_vector = randomized_key_fixture["case"]
        authorization_key = Point.from_bytes(
            bytes.fromhex(randomized_key_vector["ak"]), check_subgroup=True
        )
        ar = int.from_bytes(
            bytes.fromhex(randomized_key_vector["ar"]), "little"
        )
        ar_witness = make_sapling_randomized_authorization_key_witness(
            authorization_key, ar
        )
        self.assertEqual(
            ar_witness.randomized_key.encode().hex(),
            randomized_key_vector["rk"],
        )

        system = R1CS()
        public = (
            system.alloc_public("Spend rk.u", ar_witness.randomized_key.u),
            system.alloc_public("Spend rk.v", ar_witness.randomized_key.v),
            system.alloc_public(
                "Spend cv.u", value_commitment_witness.commitment.u
            ),
            system.alloc_public(
                "Spend cv.v", value_commitment_witness.commitment.v
            ),
            system.alloc_public("Spend anchor", anchor),
            system.alloc_public("Spend nullifier chunk[0]", expected_chunks[0]),
            system.alloc_public("Spend nullifier chunk[1]", expected_chunks[1]),
        )

        circuit_ak = allocate_jubjub_point(
            system, "Spend ak", authorization_key
        )
        ar_variable = system.alloc_private("Spend ar", ar_witness.ar)
        constrain_sapling_randomized_authorization_key(
            system,
            circuit_ak,
            ar_variable,
            public[:2],
            ar_witness,
        )

        value = system.alloc_private("shared Spend note value", vector["note_v"])
        value_bits = system.range_check(value, 64, "shared Spend value bit")
        value_randomness_bits = tuple(
            system.alloc_private(f"Spend rcv bit[{index}]", bit)
            for index, bit in enumerate(value_commitment_witness.randomness_bits)
        )
        value_commitment = constrain_sapling_value_commitment(
            system,
            value_bits,
            value_randomness_bits,
            public[2:4],
            value_commitment_witness,
        )
        self.assertEqual(value_commitment[0].kind, "private")

        circuit_base = allocate_jubjub_point(
            system, "Spend note diversifier base", diversifier_base
        )
        transmission_key_bits = allocate_bits(
            system, "Spend note transmission key", transmission_key.encode()
        )
        commitment_randomness_bits = tuple(
            system.alloc_private(f"Spend rcm bit[{index}]", bit)
            for index, bit in enumerate(note_witness.rcm_bits)
        )
        note_commitment = constrain_note_commitment(
            system,
            value,
            circuit_base,
            transmission_key_bits,
            commitment_randomness_bits,
            note_witness,
            label="Spend note commitment",
            value_bits=value_bits,
        )
        self.assertEqual(
            system._witness_value(note_commitment[0]),
            int.from_bytes(bytes.fromhex(vector["note_cmu"]), "little"),
        )
        merkle_leaf = system.alloc_private(
            "Spend Merkle leaf", note_witness.commitment.u
        )
        system.enforce_equal(
            merkle_leaf,
            note_commitment[0],
            "Spend note commitment to Merkle leaf binding",
        )

        path_result = constrain_merkle_authentication_path(
            system,
            merkle_leaf,
            public[4],
            path_witness,
            note_value=value,
        )
        rho_witness = make_sapling_nullifier_rho_witness(
            note_witness.commitment, vector["note_pos"]
        )
        shared_position_bits = path_result.position_bits
        rho = constrain_sapling_nullifier_rho(
            system,
            note_commitment,
            shared_position_bits,
            rho_witness,
        )
        rho_bits = constrain_jubjub_repr(system, rho, "Spend rho representation")
        nk = Point.from_bytes(bytes.fromhex(vector["nk"]), check_subgroup=True)
        nk_bits = allocate_bits(system, "Spend nullifier key", nk.encode())
        nullifier_bits = constrain_sapling_nullifier_hash(
            system, nk_bits, rho_bits
        )
        self.assertEqual(
            bits_to_bytes_le(nullifier_bits, system), expected_nullifier
        )
        constrain_sapling_nullifier_multipacking(
            system, nullifier_bits, public[5:7], packing_witness
        )

        self.assertEqual(
            tuple(variable.index for variable in public),
            tuple(range(1, 8)),
        )
        self.assertEqual(
            system.public_inputs(),
            (ar_witness.randomized_key.u, ar_witness.randomized_key.v)
            + (
                value_commitment_witness.commitment.u,
                value_commitment_witness.commitment.v,
                anchor,
            )
            + expected_chunks,
        )
        self.assertTrue(system.is_satisfied())

        for bit in shared_position_bits:
            labels = {
                constraint.label
                for constraint in system.constraints
                if any(
                    index == bit.index
                    for expression in (
                        constraint.left,
                        constraint.right,
                        constraint.output,
                    )
                    for index, _ in expression.terms
                )
            }
            self.assertTrue(
                any(
                    label.startswith(
                        "Sapling Merkle authentication path position bit["
                    )
                    for label in labels
                )
            )
            self.assertTrue(
                any(
                    label.startswith(
                        "Sapling nullifier rho position multiplication lookup["
                    )
                    for label in labels
                )
            )

        constrained_indices = {
            index
            for constraint in system.constraints
            for expression in (constraint.left, constraint.right, constraint.output)
            for index, _ in expression.terms
        }
        self.assertTrue(
            {public[0].index, public[1].index}.issubset(constrained_indices)
        )
        unconstrained_private = [
            variable.name
            for variable in system.variables
            if variable.kind == "private"
            and variable.index not in constrained_indices
        ]
        self.assertEqual(unconstrained_private, [])

        tamper_cases = (
            (public[0], ar_witness.randomized_key.u + 1),
            (public[1], ar_witness.randomized_key.v + 1),
            (circuit_ak[0], system._witness_value(circuit_ak[0]) + 1),
            (circuit_ak[1], system._witness_value(circuit_ak[1]) + 1),
            (ar_variable, ar_witness.ar + 1),
            (value, 1),
            (value_bits[0], 1),
            (note_commitment[0], system._witness_value(note_commitment[0]) + 1),
            (
                merkle_leaf,
                system._witness_value(merkle_leaf) + 1,
            ),
            (
                shared_position_bits[0],
                1 - system._witness_value(shared_position_bits[0]),
            ),
            (rho[0], system._witness_value(rho[0]) + 1),
            (rho_bits[0], 1 - system._witness_value(rho_bits[0])),
            (nullifier_bits[0], 1 - system._witness_value(nullifier_bits[0])),
            (public[5], expected_chunks[0] + 1),
        )
        for variable, assigned_value in tamper_cases:
            with self.subTest(variable=variable.name):
                self.assertFalse(
                    system.is_satisfied({variable.index: assigned_value})
                )

    def test_sapling_nullifier_rho_position_boundaries(self):
        note_commitment = Point(0, 1)
        for position in (0, (1 << 32) - 1):
            with self.subTest(position=position):
                witness = make_sapling_nullifier_rho_witness(
                    note_commitment, position
                )
                system = R1CS()
                circuit_note = allocate_jubjub_point(
                    system, "note commitment", note_commitment
                )
                constrain_jubjub_point(system, circuit_note)
                position_bits = tuple(
                    system.alloc_private(f"position bit[{index}]", bit)
                    for index, bit in enumerate(witness.position_bits)
                )
                rho = constrain_sapling_nullifier_rho(
                    system, circuit_note, position_bits, witness
                )
                rho_bits = constrain_jubjub_repr(
                    system, rho, "rho representation"
                )
                self.assertEqual(
                    bits_to_bytes_le(rho_bits, system), witness.rho.encode()
                )
                self.assertTrue(system.is_satisfied())
                changed_bit = position_bits[31]
                self.assertFalse(
                    system.is_satisfied(
                        {
                            changed_bit.index: 1 - witness.position_bits[31]
                        }
                    )
                )

        for invalid_position in (True, -1, 1 << 32):
            with self.subTest(invalid_position=invalid_position), self.assertRaises(
                R1CSError
            ):
                make_sapling_nullifier_rho_witness(
                    note_commitment, invalid_position
                )


if __name__ == "__main__":
    unittest.main()
