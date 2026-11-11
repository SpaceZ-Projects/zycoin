import unittest

from src.jubjub import IDENTITY
from src.r1cs import R1CS
from src.sapling_gadgets import allocate_jubjub_point
from tests.sapling_spend_allocation_provenance import (
    AllocationTraceR1CS,
    _semantic_provenance,
    _blake2s_allocation_identity,
)


class SaplingSpendAllocationProvenanceTests(unittest.TestCase):
    def test_local_trace_records_order_and_callsite_without_changing_allocation(self):
        traced = AllocationTraceR1CS()
        traced_point = allocate_jubjub_point(
            traced, "Sapling Spend ak", IDENTITY
        )

        baseline = R1CS()
        baseline_point = allocate_jubjub_point(
            baseline, "Sapling Spend ak", IDENTITY
        )

        self.assertEqual(
            [(variable.index, variable.kind, variable.name) for variable in traced.variables],
            [
                (variable.index, variable.kind, variable.name)
                for variable in baseline.variables
            ],
        )
        self.assertEqual(
            [variable.index for variable in traced_point],
            [variable.index for variable in baseline_point],
        )
        self.assertEqual(
            [event["allocation_event_index"] for event in traced.allocation_events],
            [0, 1, 2],
        )
        self.assertEqual(
            traced.allocation_events[1]["gadget_scope"],
            "src/sapling_gadgets.py:allocate_jubjub_point",
        )
        self.assertTrue(
            traced.allocation_events[1]["allocation_context_frames"]
        )
        self.assertEqual(
            traced.allocation_events[1]["allocation_context_frames"][0]["function"],
            "allocate_jubjub_point",
        )

    def test_merkle_gadget_identity_includes_semantic_level_and_role(self):
        first = _semantic_provenance(
            "Sapling Spend Merkle path position bit[3]",
            [{"file": "src/sapling_gadgets.py", "function": "constrain_merkle_authentication_path"}],
        )
        second = _semantic_provenance(
            "Sapling Spend Merkle path position bit[4]",
            [{"file": "src/sapling_gadgets.py", "function": "constrain_merkle_authentication_path"}],
        )
        self.assertEqual(first[0], "sapling.spend.merkle-authentication-path")
        self.assertEqual(first[3], "position/bit")
        self.assertEqual(first[4], "sapling.spend.merkle-authentication-path|level:3|position/bit")
        self.assertNotEqual(first[4], second[4])

    def test_unmatched_gadget_gets_provenance_but_no_cross_system_identity(self):
        provenance = _semantic_provenance(
            "Sapling Spend ivk block[2] round[4] g[1] xor[3]",
            [{"file": "src/blake2s_gadget.py", "function": "constrain_blake2s"}],
        )
        self.assertEqual(provenance[0], "sapling.spend.ivk.blake2s")
        self.assertIn("block:2", provenance[2])
        self.assertIn("round:4", provenance[2])
        self.assertIsNone(provenance[4])

    def test_blake2s_roles_translate_operation_coordinates_not_ordinals(self):
        add = _semantic_provenance(
            "Sapling Spend ivk block[0] final round[0] g[0] add[0] bit[0]"
        )
        carry = _semantic_provenance(
            "Sapling Spend ivk block[0] final round[0] g[0] add[0] carry[0]"
        )
        xor = _semantic_provenance(
            "Sapling Spend ivk block[0] final round[0] g[0] xor[0] bit[0]"
        )
        final_hash = _semantic_provenance(
            "Sapling Spend nullifier PRF block[0] final hash xor b[0] bit[0]"
        )

        self.assertEqual(add[0], "sapling.spend.ivk.blake2s")
        self.assertEqual(
            add[4],
            "sapling.spend.ivk.blake2s|hash:ivk|final/block/round/0/"
            "mixing/invocation/1/mixing/step/1/result/bit/0",
        )
        self.assertTrue(carry[4].endswith("mixing/step/1/result/bit/32"))
        self.assertTrue(xor[4].endswith("mixing/step/2/xor/of/bit/0"))
        self.assertEqual(
            final_hash[4],
            "sapling.spend.nullifier.blake2s|hash:nullifier|final/block/"
            "h/0/v/0/v/0/8/second/xor/xor/of/bit/0",
        )
        self.assertNotEqual(add[4], xor[4])
        self.assertEqual(add[2][-4:], ["final-block:", "round:0", "mixing-invocation:1", "mixing-step:1"])
        self.assertEqual(xor[2][-1], "mixing-step:2")

    def test_unknown_blake2s_role_is_not_promoted_to_a_shared_identity(self):
        self.assertIsNone(
            _blake2s_allocation_identity("ivk undocumented operation bit[0]")
        )

    def test_strict_representation_uses_pinned_most_significant_first_bit_roles(self):
        bit = _semantic_provenance(
            "Sapling Spend ak representation u bit[0]"
        )
        prefix = _semantic_provenance(
            "Sapling Spend note commitment g_d representation "
            "v bit prefix AND[251:0]"
        )
        self.assertEqual(
            bit[4], "sapling.spend.ak.representation|repr:ak|unpack/u/bit/254"
        )
        self.assertEqual(
            prefix[4],
            "sapling.spend.g-d.representation|repr:g-d|"
            "unpack/v/run/ending/at/3/and/1",
        )
        self.assertEqual(prefix[0], "sapling.spend.g-d.representation")

    def test_merkle_pedersen_roles_translate_to_pinned_segment_window_names(self):
        addition = _semantic_provenance(
            "Sapling Spend Merkle path hash[7] segment[2] "
            "addition[9] lambda"
        )
        conversion = _semantic_provenance(
            "Sapling Spend Merkle path hash[7] segment[2] conversion v"
        )
        self.assertEqual(
            addition[4],
            "sapling.spend.merkle-authentication-path|level:7|"
            "computation/of/pedersen/hash/addition/of/segment/2/window/9/lambda",
        )
        self.assertEqual(
            conversion[4],
            "sapling.spend.merkle-authentication-path|level:7|"
            "computation/of/pedersen/hash/conversion/of/segment/2/"
            "into/edwards/v",
        )
        self.assertIn("level:7", addition[2])
        self.assertIn("sapling.pedersen-hash", addition[2])

    def test_scalar_multiplication_roles_preserve_gadget_and_operation_index(self):
        variable_base = _semantic_provenance(
            "Sapling Spend pk_d multiplication base doubling[7] A"
        )
        fixed_base = _semantic_provenance(
            "Sapling Spend nk multiplication addition[4] B"
        )
        randomized_key = _semantic_provenance(
            "Sapling Spend randomized authorization key "
            "ar multiplication selected[0].u"
        )
        self.assertEqual(
            variable_base[4],
            "sapling.spend.pk-d.scalar-multiplication|mul:pk-d|"
            "doubling/7/a/computation",
        )
        self.assertEqual(
            fixed_base[4],
            "sapling.spend.nk.fixed-base-multiplication|mul:nk|"
            "addition/4/b/computation",
        )
        self.assertEqual(
            randomized_key[4],
            "sapling.spend.randomized-authorization-key|mul:ar|"
            "window/table/lookup/0/x",
        )
        self.assertNotEqual(variable_base[4], fixed_base[4])

    def test_note_content_pedersen_roles_preserve_segment_and_window(self):
        y = _semantic_provenance(
            "Sapling Spend note commitment content hash "
            "segment[2] window[17] y"
        )
        addition = _semantic_provenance(
            "Sapling Spend note commitment content hash "
            "segment[2] addition[17] lambda"
        )
        conversion = _semantic_provenance(
            "Sapling Spend note commitment content hash "
            "segment[2] conversion v"
        )
        combination = _semantic_provenance(
            "Sapling Spend note commitment content hash "
            "segment[2] combination B"
        )
        self.assertEqual(y[0], "sapling.spend.note-content.pedersen")
        self.assertEqual(y[4], "sapling.spend.note-content.pedersen|hash:note-content|segment/2/window/17/y")
        self.assertEqual(
            addition[4],
            "sapling.spend.note-content.pedersen|hash:note-content|"
            "addition/of/segment/2/window/17/lambda",
        )
        self.assertEqual(
            conversion[4],
            "sapling.spend.note-content.pedersen|hash:note-content|"
            "conversion/of/segment/2/into/edwards/v",
        )
        self.assertEqual(
            combination[4],
            "sapling.spend.note-content.pedersen|hash:note-content|"
            "addition/of/segment/2/to/accumulator/b/computation",
        )

    def test_merkle_accumulator_combination_roles_include_level_and_coordinate(self):
        output = _semantic_provenance(
            "Sapling Spend Merkle path hash[9] segment[2] combination A"
        )
        self.assertEqual(
            output[4],
            "sapling.spend.merkle-authentication-path|level:9|"
            "computation/of/pedersen/hash/addition/of/segment/2/to/"
            "accumulator/a/computation",
        )

    def test_value_and_rcv_bits_have_distinct_named_witness_identities(self):
        value = _semantic_provenance("Sapling Spend value bit[31]")
        randomness = _semantic_provenance("Sapling Spend rcv bit[31]")
        self.assertEqual(
            value[4],
            "sapling.spend.value-commitment|relation:value-commitment|"
            "value/bit/31",
        )
        self.assertEqual(
            randomness[4],
            "sapling.spend.value-commitment|relation:value-commitment|"
            "rcv/bit/31",
        )
        self.assertNotEqual(value[4], randomness[4])

    def test_rho_position_multiplication_role_is_operation_indexed(self):
        lookup = _semantic_provenance(
            "Sapling Spend rho position multiplication lookup[3] bc"
        )
        addition = _semantic_provenance(
            "Sapling Spend rho position multiplication addition[3] B"
        )
        self.assertEqual(
            lookup[4],
            "sapling.spend.nullifier-rho|mul:rho-position|"
            "window/table/lookup/3/precomp",
        )
        self.assertEqual(
            addition[4],
            "sapling.spend.nullifier-rho|mul:rho-position|"
            "addition/3/b/computation",
        )

    def test_value_and_rcm_multiplication_roles_keep_distinct_semantic_scopes(self):
        value = _semantic_provenance(
            "Sapling Spend value commitment value multiplication "
            "selected[5].u"
        )
        rcm = _semantic_provenance(
            "Sapling Spend note commitment randomness multiplication "
            "addition[5] B"
        )
        rcv = _semantic_provenance(
            "Sapling Spend value commitment randomness multiplication "
            "lookup[5] bc"
        )
        self.assertEqual(
            value[4],
            "sapling.spend.value-commitment|relation:value-commitment|"
            "compute/the/value/in/the/exponent/window/table/lookup/5/x",
        )
        self.assertEqual(
            rcm[4],
            "sapling.spend.note-commitment-randomness|mul:rcm|"
            "addition/5/b/computation",
        )
        self.assertEqual(
            rcv[4],
            "sapling.spend.value-commitment|relation:value-commitment|"
            "computation/of/rcv/window/table/lookup/5/precomp",
        )

    def test_remaining_jubjub_relations_use_gadget_and_named_output_roles(self):
        cases = {
            "Sapling Spend randomized authorization key ak doubling[0] A":
                "sapling.spend.randomized-authorization-key|"
                "non-small-order:ak|first/doubling/a/computation",
            "Sapling Spend randomized authorization key ak double[2].v":
                "sapling.spend.randomized-authorization-key|"
                "non-small-order:ak|third/doubling/v3",
            "Sapling Spend g_d curve coordinate product":
                "sapling.spend.diversifier-base|witness:g-d|"
                "point/interpretation/u/2/v/2",
            "Sapling Spend g_d u inverse":
                "sapling.spend.diversifier-base|"
                "non-small-order:g-d|check/u/0/ephemeral/inverse",
            "Sapling Spend randomized authorization key ak u inverse":
                "sapling.spend.randomized-authorization-key|"
                "non-small-order:ak|check/u/0/ephemeral/inverse",
            "Sapling Spend randomized authorization key result.u":
                "sapling.spend.randomized-authorization-key|addition:rk|"
                "computation/of/rk/u3",
            "Sapling Spend value commitment result.v":
                "sapling.spend.value-commitment|relation:value-commitment|"
                "computation/of/cv/v3",
            "Sapling Spend note commitment randomization B":
                "sapling.spend.note-commitment|"
                "randomization:note-commitment|b/computation",
            "Sapling Spend rho point.u":
                "sapling.spend.nullifier-rho|faerie-gold-prevention|u3",
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(_semantic_provenance(name)[4], expected)


if __name__ == "__main__":
    unittest.main()
