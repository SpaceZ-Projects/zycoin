from __future__ import annotations

import unittest
from types import SimpleNamespace

from src.r1cs import R1CS
from tests.sapling_spend_groth16_adapter import (
    SpendGroth16AdapterError,
    _validate_component_public_inputs,
    adapt_source_faithful_spend,
)
from tests.sapling_spend_reference_port import (
    SpendReferenceAssembly,
    SpendReferenceR1CS,
)
from tests.sapling_spend_temporal_mapping import SPEND_PUBLIC_INPUT_ANNOTATIONS


def _public_only_source() -> tuple[SpendReferenceR1CS, tuple]:
    source = SpendReferenceR1CS()
    public_inputs = tuple(
        source.alloc_public(name, index)
        for index, name in enumerate(SPEND_PUBLIC_INPUT_ANNOTATIONS, start=1)
    )
    return source, public_inputs


def _assembly_shell(public_inputs: tuple) -> SpendReferenceAssembly:
    return SpendReferenceAssembly(
        public_inputs=public_inputs,
        randomized_key=None,
        nullifier_key=None,
        ak_repr_bits=(),
        nk_repr_bits=(),
        ivk_bits=(),
        diversifier_base=None,
        transmission_key=None,
        transmission_key_repr_bits=(),
        value_commitment=None,
        note_commitment=None,
        merkle_path=None,
        conditional_anchor=None,
        rho=None,
        rho_repr_bits=(),
        nullifier_hash=None,
        nullifier_multipacking=None,
    )


class SpendGroth16AdapterBoundaryTests(unittest.TestCase):
    def test_rejects_non_reference_api_inputs(self) -> None:
        with self.assertRaises(TypeError):
            adapt_source_faithful_spend(R1CS(), None)
        with self.assertRaises(TypeError):
            adapt_source_faithful_spend(SpendReferenceR1CS(), object())

    def test_rejects_duplicate_or_misordered_public_handles(self) -> None:
        source, public_inputs = _public_only_source()
        duplicate = (
            public_inputs[0],
            *public_inputs[1:6],
            public_inputs[0],
        )
        misordered = (public_inputs[1], public_inputs[0], *public_inputs[2:])

        for candidate in (duplicate, misordered):
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(SpendGroth16AdapterError),
            ):
                adapt_source_faithful_spend(
                    source,
                    _assembly_shell(candidate),
                )

        self.assertEqual(source.constraint_count, 0)
        self.assertEqual(len(source.variables), 8)

    def test_rejects_foreign_public_handle(self) -> None:
        source, public_inputs = _public_only_source()
        foreign_source, _ = _public_only_source()
        candidate = (*public_inputs[:6], foreign_source.variables[1])

        with self.assertRaisesRegex(SpendGroth16AdapterError, "another R1CS"):
            adapt_source_faithful_spend(
                source,
                _assembly_shell(candidate),
            )

    def test_rejects_incomplete_assembly_result(self) -> None:
        source, public_inputs = _public_only_source()

        with self.assertRaisesRegex(SpendGroth16AdapterError, "component"):
            adapt_source_faithful_spend(
                source,
                _assembly_shell(public_inputs),
            )

    def test_rejects_component_public_input_mismatch(self) -> None:
        _, public_inputs = _public_only_source()
        assembly = SimpleNamespace(
            public_inputs=public_inputs,
            value_commitment=SimpleNamespace(
                input_variables=public_inputs[1:3]
            ),
            conditional_anchor=SimpleNamespace(
                anchor_variable=public_inputs[4]
            ),
            nullifier_multipacking=SimpleNamespace(
                input_variables=public_inputs[5:7]
            ),
        )

        with self.assertRaisesRegex(SpendGroth16AdapterError, "disagree"):
            _validate_component_public_inputs(assembly)


if __name__ == "__main__":
    unittest.main()
