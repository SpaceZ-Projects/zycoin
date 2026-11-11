import unittest

from src.blake2s_gadget import (
    _NegatedBit,
    _read_bit,
    constrain_sapling_ivk,
    constrain_sapling_nullifier_hash,
    make_blake2s_witness,
)
from src.jubjub import SCALAR_MODULUS
from src.r1cs import R1CS
from src.sapling_gadgets import (
    allocate_jubjub_point,
    constrain_fixed_base_jubjub_mul,
    constrain_sapling_conditional_anchor,
    constrain_sapling_nullifier_multipacking,
    constrain_sapling_randomized_authorization_key,
    make_fixed_base_jubjub_witness,
    make_sapling_nullifier_multipacking_witness,
    make_sapling_randomized_authorization_key_witness,
    sapling_fixed_base_generator,
)
from tests.bellman_blake2s_reference import (
    _Negated as BellmanNegatedBit,
)
from tests.bellman_blake2s_reference import (
    bellman_bits_to_bytes,
    constrain_bellman_blake2s_reference,
)


def _localize_bellman_bit(bit):
    if isinstance(bit, BellmanNegatedBit):
        return _NegatedBit(bit.variable)
    return bit


def _allocate_boolean_message(system, label, values):
    variables = tuple(
        system.alloc_private(f"{label}[{index}]", bit)
        for index, bit in enumerate(values)
    )
    for bit in variables:
        system.boolean(bit)
    return variables


class SaplingSpendBindingTests(unittest.TestCase):
    def test_ar_scalar_binding_is_replaced_by_direct_boolean_bits(self):
        authorization_key = sapling_fixed_base_generator("spending_key")
        ar = 37
        witness = make_sapling_randomized_authorization_key_witness(
            authorization_key, ar
        )

        def assemble(use_direct_bits):
            system = R1CS()
            randomized_key = (
                system.alloc_public("Spend rk.u", witness.randomized_key.u),
                system.alloc_public("Spend rk.v", witness.randomized_key.v),
            )
            for index in range(5):
                system.alloc_public(f"Spend public[{index}]", index)
            circuit_ak = allocate_jubjub_point(
                system, "Spend ak", authorization_key
            )
            if use_direct_bits:
                ar_input = tuple(
                    system.alloc_private(f"Spend ar bit[{index}]", bit)
                    for index, bit in enumerate(witness.ar_bits)
                )
            else:
                ar_input = system.alloc_private("Spend ar", ar)
            constrain_sapling_randomized_authorization_key(
                system,
                circuit_ak,
                ar_input,
                randomized_key,
                witness,
            )
            return system, ar_input, randomized_key

        legacy, legacy_ar, _ = assemble(False)
        direct, direct_ar_bits, direct_randomized_key = assemble(True)
        repeated, _, _ = assemble(True)

        self.assertTrue(legacy.is_satisfied())
        self.assertTrue(direct.is_satisfied())
        self.assertEqual(legacy.constraint_count, direct.constraint_count + 1)
        self.assertEqual(len(legacy.variables), len(direct.variables) + 1)
        self.assertEqual(len(direct_ar_bits), SCALAR_MODULUS.bit_length())
        self.assertEqual(direct.serialize_matrix(), repeated.serialize_matrix())
        self.assertFalse(
            legacy.is_satisfied(
                {legacy_ar.index: ar + 1}
            )
        )
        self.assertFalse(
            direct.is_satisfied(
                {
                    direct_ar_bits[0].index: 1 - witness.ar_bits[0]
                }
            )
        )
        self.assertFalse(
            direct.is_satisfied(
                {
                    direct_randomized_key[0].index:
                    witness.randomized_key.u + 1
                }
            )
        )

    def test_ivk_aliases_feed_fixed_base_without_materialization_rows(self):
        values = tuple((index * 13 + 5) >> 2 & 1 for index in range(512))
        base = sapling_fixed_base_generator("spending_key")

        def assemble(materialize, reference=False):
            system = R1CS()
            message = _allocate_boolean_message(system, "IVK input", values)
            if reference:
                reference_output = constrain_bellman_blake2s_reference(
                    system, message, b"Zcashivk"
                )
                output = tuple(
                    _localize_bellman_bit(bit)
                    for bit in reference_output[:251]
                )
            else:
                output = constrain_sapling_ivk(
                    system,
                    message[:256],
                    message[256:],
                    input_bits_preconstrained=True,
                    materialize_output=materialize,
                )
            scalar_bits = tuple(_read_bit(system, bit) for bit in output)
            witness = make_fixed_base_jubjub_witness(base, scalar_bits)
            result = constrain_fixed_base_jubjub_mul(
                system,
                base,
                output,
                witness,
                "IVK fixed-base consumer",
                enforce_scalar_range=False,
                bits_preconstrained=True,
            )
            return system, output, result

        adapted, _, adapted_point = assemble(True)
        direct, direct_bits, direct_point = assemble(False)
        reference, _, reference_point = assemble(False, reference=True)
        repeated, _, _ = assemble(False)

        self.assertTrue(adapted.is_satisfied())
        self.assertTrue(direct.is_satisfied())
        self.assertEqual(
            tuple(adapted._witness_value(bit) for bit in adapted_point),
            tuple(direct._witness_value(bit) for bit in direct_point),
        )
        self.assertEqual(
            tuple(direct._witness_value(bit) for bit in direct_point),
            tuple(reference._witness_value(bit) for bit in reference_point),
        )
        self.assertEqual(direct.serialize_matrix(), reference.serialize_matrix())
        self.assertEqual(
            adapted.constraint_count - direct.constraint_count, 130
        )
        self.assertEqual(len(adapted.variables) - len(direct.variables), 130)
        self.assertEqual(
            sum(isinstance(bit, _NegatedBit) for bit in direct_bits), 130
        )
        self.assertEqual(direct.serialize_matrix(), repeated.serialize_matrix())
        alias = next(bit for bit in direct_bits if isinstance(bit, _NegatedBit))
        current = direct._witness_value(alias.variable)
        self.assertFalse(
            direct.is_satisfied({alias.variable.index: 1 - current})
        )

    def test_nullifier_aliases_pack_public_chunks_without_materialization(self):
        values = tuple((index * 17 + 3) >> 1 & 1 for index in range(512))
        hash_witness = make_blake2s_witness(values, b"Zcash_nf")
        packing_witness = make_sapling_nullifier_multipacking_witness(
            hash_witness.digest
        )

        def assemble(materialize, reference=False):
            system = R1CS()
            public = tuple(
                system.alloc_public(f"Spend public[{index}]", index)
                for index in range(5)
            )
            chunks = tuple(
                system.alloc_public(
                    f"nullifier chunk[{index}]", value
                )
                for index, value in enumerate(packing_witness.packed_values)
            )
            message = _allocate_boolean_message(system, "nullifier input", values)
            if reference:
                reference_output = constrain_bellman_blake2s_reference(
                    system, message, b"Zcash_nf"
                )
                output = tuple(
                    _localize_bellman_bit(bit) for bit in reference_output
                )
                self.assertEqual(
                    bellman_bits_to_bytes(system, reference_output),
                    hash_witness.digest,
                )
            else:
                output = constrain_sapling_nullifier_hash(
                    system,
                    message[:256],
                    message[256:],
                    input_bits_preconstrained=True,
                    materialize_output=materialize,
                )
            constrain_sapling_nullifier_multipacking(
                system,
                output,
                chunks,
                packing_witness,
                digest_bits_preconstrained=True,
            )
            return system, output, public, chunks

        adapted, _, _, _ = assemble(True)
        direct, direct_bits, _, direct_chunks = assemble(False)
        reference, _, _, _ = assemble(False, reference=True)
        repeated, _, _, _ = assemble(False)

        self.assertTrue(adapted.is_satisfied())
        self.assertTrue(direct.is_satisfied())
        self.assertEqual(adapted.public_inputs(), direct.public_inputs())
        self.assertEqual(direct.serialize_matrix(), reference.serialize_matrix())
        self.assertEqual(
            adapted.constraint_count - direct.constraint_count, 136
        )
        self.assertEqual(len(adapted.variables) - len(direct.variables), 136)
        self.assertEqual(
            sum(isinstance(bit, _NegatedBit) for bit in direct_bits), 136
        )
        self.assertEqual(direct.serialize_matrix(), repeated.serialize_matrix())
        self.assertFalse(
            direct.is_satisfied(
                {direct_chunks[0].index: packing_witness.packed_values[0] + 1}
            )
        )
        alias = next(bit for bit in direct_bits if isinstance(bit, _NegatedBit))
        current = direct._witness_value(alias.variable)
        self.assertFalse(
            direct.is_satisfied({alias.variable.index: 1 - current})
        )

    def test_note_value_binding_is_needed_only_for_a_separate_scalar(self):
        value = 3
        value_bits = tuple((value >> index) & 1 for index in range(64))

        def assemble(with_scalar, bind_scalar, root_value, scalar_value, bits):
            system = R1CS()
            anchor = system.alloc_public("anchor", 9)
            root = system.alloc_private("root", root_value)
            bit_variables = tuple(
                system.alloc_private(f"value bit[{index}]", bit)
                for index, bit in enumerate(bits)
            )
            for index, bit in enumerate(bit_variables):
                system.boolean(bit, f"value bit[{index}] Boolean")
            value_expression = system.linear_combination(
                tuple(
                    (bit, 1 << index)
                    for index, bit in enumerate(bit_variables)
                )
            )
            if with_scalar:
                scalar = system.alloc_private("note value", scalar_value)
                if bind_scalar:
                    system.enforce_equal(
                        scalar, value_expression, "note value binding"
                    )
                conditional_value = scalar
            else:
                conditional_value = value_expression
            constrain_sapling_conditional_anchor(
                system, root, anchor, conditional_value
            )
            return system, bit_variables

        bound, _ = assemble(True, True, 9, value, value_bits)
        missing_binding, _ = assemble(True, False, 8, 0, value_bits)
        linked_valid, _ = assemble(False, False, 9, 0, value_bits)
        linked, linked_bits = assemble(False, False, 8, 0, value_bits)
        repeated, _ = assemble(False, False, 8, 0, value_bits)

        self.assertTrue(bound.is_satisfied())
        self.assertTrue(linked_valid.is_satisfied())
        self.assertTrue(
            missing_binding.is_satisfied(),
            "an unbound scalar can be changed to zero despite nonzero value bits",
        )
        self.assertFalse(
            linked.is_satisfied(),
            "the bit-derived value must keep the conditional anchor active",
        )
        self.assertEqual(linked.constraint_count, bound.constraint_count - 1)
        self.assertEqual(len(linked.variables), len(bound.variables) - 1)
        self.assertEqual(linked.serialize_matrix(), repeated.serialize_matrix())
        self.assertFalse(
            linked.is_satisfied(
                {linked_bits[0].index: 1 - value_bits[0]}
            )
        )

        zero_bits = (0,) * 64
        zero_value, _ = assemble(False, False, 8, 0, zero_bits)
        self.assertTrue(zero_value.is_satisfied())


if __name__ == "__main__":
    unittest.main()
