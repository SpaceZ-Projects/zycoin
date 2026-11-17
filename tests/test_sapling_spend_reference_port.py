from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import ExitStack
from hashlib import blake2s, sha256
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import patch

import sapling_spend_reference_port
from sapling_spend_reference_port import (
    EdwardsPointWitnessVariables,
    SpendReferenceR1CS,
    SpendReferenceWitness,
    allocate_spend_fixed_base_scalar_bits,
    allocate_spend_montgomery_point,
    constrain_source_faithful_spend,
    constrain_spend_conditional_anchor,
    constrain_spend_edwards_point_add,
    constrain_spend_edwards_point_double,
    constrain_spend_edwards_point_mul,
    constrain_spend_edwards_point_not_small_order,
    constrain_spend_edwards_point_repr,
    constrain_spend_edwards_point_witness,
    constrain_spend_fixed_base_mul,
    constrain_spend_ivk_blake2s,
    constrain_spend_merkle_authentication_path,
    constrain_spend_montgomery_add,
    constrain_spend_montgomery_into_edwards,
    constrain_spend_note_commitment,
    constrain_spend_nullifier_blake2s,
    constrain_spend_nullifier_multipacking,
    constrain_spend_pedersen_hash,
    constrain_spend_signed_montgomery_lookup,
    constrain_spend_value_commitment,
    spend_edwards_to_montgomery_coordinates,
    spend_fixed_base_tables,
    spend_pedersen_montgomery_tables,
)

from src.blake2s_gadget import _NegatedBit, _read_bit
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import (
    CURVE_D,
    IDENTITY,
    Point,
)
from src.jubjub import SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS
from src.r1cs import (
    _MATRIX_FINGERPRINT_DOMAIN,
    _MATRIX_SERIALIZATION_FORMAT,
    R1CS,
    R1CSError,
    Variable,
)
from src.sapling_gadgets import (
    _pedersen_montgomery_tables,
    sapling_fixed_base_generator,
)
from tests.bellman_blake2s_reference import _add as _bellman_add
from tests.bellman_blake2s_reference import (
    _constant_word,
    constrain_bellman_blake2s_reference,
)
from tests.bellman_blake2s_reference import _MultiEq as _BellmanMultiEq
from tests.bellman_blake2s_reference import _Negated as _BellmanNegated
from tests.bellman_blake2s_reference import _xor_bit as _bellman_xor_bit

ROOT = Path(__file__).resolve().parents[1]
REFERENCE_MANIFEST = (
    ROOT / "tests" / "reference" / "sapling-output-qap" / "Cargo.toml"
)


class SpendReferenceCompositionBoundaryTests(unittest.TestCase):
    def test_fixed_base_and_preserves_source_boolean_allocations(self) -> None:
        system = R1CS()
        bits = allocate_spend_fixed_base_scalar_bits(system, 0, 3)
        base = sapling_spend_reference_port.sapling_fixed_base_generator(
            "spending_key"
        )

        constrain_spend_fixed_base_mul(system, bits, base)

        self.assertIn(
            "fixed base multiplication/window table lookup 0/precomp/and result",
            [variable.name for variable in system.variables],
        )
        self.assertIn(
            "fixed base multiplication/window table lookup 0/precomp/and constraint",
            [row.label for row in system.constraints],
        )
        self.assertTrue(system.is_satisfied())

    def test_fixed_base_and_matches_bellman_negated_boolean_forms(self) -> None:
        system = R1CS()
        positive = system.alloc_private("positive bit", 1)
        first_negated = sapling_spend_reference_port._NegatedBit(positive)
        not_variable = system.alloc_private("not bit backing", 0)
        second_negated = sapling_spend_reference_port._NegatedBit(
            not_variable
        )

        nor_result = sapling_spend_reference_port._spend_boolean_and(
            system,
            first_negated,
            second_negated,
            "nor",
        )

        self.assertIsInstance(nor_result, Variable)
        self.assertEqual(system.witness_value(nor_result), 0)
        self.assertEqual(system.variables[-1].name, "nor/nor result")
        self.assertEqual(system.constraints[-1].label, "nor/nor constraint")
        self.assertTrue(system.is_satisfied())

    def test_value_commitment_continues_after_prior_public_inputs(self) -> None:
        system = SpendReferenceR1CS()
        for name in ("rk/u", "rk/v", "prior/cv/u", "prior/cv/v"):
            system.alloc_public(name, 0)

        def fake_fixed_base(
            target: SpendReferenceR1CS,
            bits: tuple[Variable, ...],
            base: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            return EdwardsPointWitnessVariables(
                target.alloc_private(f"{label}/u/num", IDENTITY.u),
                target.alloc_private(f"{label}/v/num", IDENTITY.v),
            )

        def fake_add(
            target: SpendReferenceR1CS,
            left_variables: EdwardsPointWitnessVariables,
            left_witness: Point,
            right_variables: EdwardsPointWitnessVariables,
            right_witness: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            return EdwardsPointWitnessVariables(
                target.alloc_private(f"{label}/u3/num", IDENTITY.u),
                target.alloc_private(f"{label}/v3/num", IDENTITY.v),
            )

        with (
            patch.object(
                sapling_spend_reference_port,
                "constrain_spend_fixed_base_mul",
                side_effect=fake_fixed_base,
            ),
            patch.object(
                sapling_spend_reference_port,
                "constrain_spend_edwards_point_add",
                side_effect=fake_add,
            ),
        ):
            result = constrain_spend_value_commitment(system, 0, 0)

        self.assertEqual(
            [system.public_input_position(variable) for variable in result.input_variables],
            [5, 6],
        )
        self.assertEqual(system.public_input_count, 6)

    def test_note_commitment_reuses_preallocated_source_bits(self) -> None:
        system = SpendReferenceR1CS()
        g_d_variables = EdwardsPointWitnessVariables(
            system.alloc_private("g_d/u", IDENTITY.u),
            system.alloc_private("g_d/v", IDENTITY.v),
        )
        pk_d_variables = EdwardsPointWitnessVariables(
            system.alloc_private("pk_d/u", IDENTITY.u),
            system.alloc_private("pk_d/v", IDENTITY.v),
        )
        value = 5
        value_bits = tuple(
            system.alloc_private(
                f"value commitment/value/bit {index}/boolean",
                (value >> index) & 1,
            )
            for index in range(64)
        )

        def allocate_repr(label: str) -> tuple[Variable, ...]:
            expected = (1,) + (0,) * 254 + (0,)
            return tuple(
                system.alloc_private(f"{label}/bit {index}", bit)
                for index, bit in enumerate(expected)
            )

        g_d_repr_bits = allocate_repr("representation of g_d")
        pk_d_repr_bits = allocate_repr("representation of pk_d")
        variables_before_note = len(system.variables)
        pedersen_inputs: list[tuple] = []

        def fake_pedersen(
            target: SpendReferenceR1CS,
            bits: tuple[Variable, ...],
            label: str,
            personalization: tuple[bool, ...] = (),
        ) -> SimpleNamespace:
            self.assertEqual(len(target.variables), variables_before_note)
            pedersen_inputs.append(bits)
            commitment_variables = EdwardsPointWitnessVariables(
                target.alloc_private("note hash/u", IDENTITY.u),
                target.alloc_private("note hash/v", IDENTITY.v),
            )
            return SimpleNamespace(
                variables=commitment_variables,
                witness=IDENTITY,
            )

        def fake_scalar_bits(
            target: SpendReferenceR1CS, scalar: int, width: int, label: str
        ) -> tuple[Variable, ...]:
            return tuple(
                target.alloc_private(f"{label}/bit {index}", 0)
                for index in range(width)
            )

        def fake_fixed_base(
            target: SpendReferenceR1CS,
            bits: tuple[Variable, ...],
            base: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            return EdwardsPointWitnessVariables(
                target.alloc_private(f"{label}/u/num", IDENTITY.u),
                target.alloc_private(f"{label}/v/num", IDENTITY.v),
            )

        def fake_add(
            target: SpendReferenceR1CS,
            left_variables: EdwardsPointWitnessVariables,
            left_witness: Point,
            right_variables: EdwardsPointWitnessVariables,
            right_witness: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            return EdwardsPointWitnessVariables(
                target.alloc_private(f"{label}/u3/num", IDENTITY.u),
                target.alloc_private(f"{label}/v3/num", IDENTITY.v),
            )

        with (
            patch.object(
                sapling_spend_reference_port,
                "constrain_spend_pedersen_hash",
                side_effect=fake_pedersen,
            ),
            patch.object(
                sapling_spend_reference_port,
                "allocate_spend_fixed_base_scalar_bits",
                side_effect=fake_scalar_bits,
            ),
            patch.object(
                sapling_spend_reference_port,
                "constrain_spend_fixed_base_mul",
                side_effect=fake_fixed_base,
            ),
            patch.object(
                sapling_spend_reference_port,
                "constrain_spend_edwards_point_add",
                side_effect=fake_add,
            ),
        ):
            result = constrain_spend_note_commitment(
                system,
                value,
                g_d_variables,
                IDENTITY,
                pk_d_variables,
                IDENTITY,
                0,
                value_bits=value_bits,
                g_d_repr_bits=g_d_repr_bits,
                pk_d_repr_bits=pk_d_repr_bits,
            )

        self.assertEqual(len(pedersen_inputs), 1)
        self.assertEqual(
            pedersen_inputs[0],
            value_bits + g_d_repr_bits + pk_d_repr_bits,
        )
        self.assertEqual(
            result.note_contents,
            value_bits + g_d_repr_bits + pk_d_repr_bits,
        )
        self.assertEqual(
            len(system.variables),
            variables_before_note + 2 + 252 + 2 + 2,
        )

    def test_source_order_anchor_uses_value_linear_combination_and_late_input(
        self,
    ) -> None:
        system = SpendReferenceR1CS()
        for name in ("rk/u", "rk/v", "cv/u", "cv/v"):
            system.alloc_public(name, 0)
        note_value = 5
        value_bits = tuple(
            system.alloc_private(
                f"value bit {index}", (note_value >> index) & 1
            )
            for index in range(64)
        )
        root_value = 77
        root = system.alloc_private("merkle root", root_value)
        variables_before_anchor = len(system.variables)

        result = sapling_spend_reference_port.constrain_spend_source_order_conditional_anchor(
            system,
            root,
            root_value,
            value_bits,
            note_value,
            root_value,
        )

        expected_value_num = system.linear_combination(
            tuple((bit, 1 << index) for index, bit in enumerate(value_bits))
        )
        self.assertEqual(result.value_num, expected_value_num)
        self.assertEqual(
            result.conditional_anchor_variable.index,
            variables_before_anchor,
        )
        self.assertGreater(
            result.anchor_variable.index,
            result.conditional_anchor_variable.index,
        )
        self.assertEqual(system.public_input_position(result.anchor_variable), 5)
        self.assertEqual(
            [row.label for row in system.constraints],
            [
                "conditionally enforce correct root",
                "anchor/enforce input is correct",
            ],
        )
        self.assertEqual(
            system.constraints[0].left,
            root.lc() - result.conditional_anchor_variable.lc(),
        )
        self.assertEqual(system.constraints[0].right, expected_value_num)
        self.assertEqual(
            system.constraints[1].left, result.anchor_variable.lc()
        )
        self.assertEqual(system.constraints[1].output, result.conditional_anchor_variable.lc())
        self.assertTrue(system.is_satisfied())

    def test_variable_base_multiplication_accepts_bellman_negated_ivk_bit(
        self,
    ) -> None:
        system = SpendReferenceR1CS()
        generator = sapling_fixed_base_generator("proof_generation_key")
        point_variables = constrain_spend_edwards_point_witness(
            system, generator, "negated IVK base"
        )
        raw_bit = system.alloc_private("negated IVK raw bit", 0)
        negated_bit = sapling_spend_reference_port._BellmanNegated(raw_bit)

        result = constrain_spend_edwards_point_mul(
            system,
            point_variables,
            generator,
            (negated_bit,),
            "negated IVK multiplication",
        )

        self.assertEqual(
            (
                system.witness_value(result.u),
                system.witness_value(result.v),
            ),
            (generator.u, generator.v),
        )
        self.assertTrue(system.is_satisfied())

    def test_source_stage_handoffs_without_full_synthesis(self) -> None:
        system = SpendReferenceR1CS()
        witness = SpendReferenceWitness(
            IDENTITY,
            0,
            0,
            IDENTITY,
            0,
            0,
            0,
            tuple((0, False) for _ in range(32)),
            0,
        )
        events: list[str] = []
        observed: dict[str, object] = {}

        def allocate_point(
            target: SpendReferenceR1CS, point: Point, label: str
        ) -> EdwardsPointWitnessVariables:
            return EdwardsPointWitnessVariables(
                target.alloc_private(f"{label}/u/num", point.u),
                target.alloc_private(f"{label}/v/num", point.v),
            )

        def fake_point_witness(
            target: SpendReferenceR1CS, point: Point, label: str
        ) -> EdwardsPointWitnessVariables:
            events.append(f"point:{label}")
            return allocate_point(target, point, label)

        def fake_non_small_order(
            target: SpendReferenceR1CS,
            variables: EdwardsPointWitnessVariables,
            point: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            events.append(f"small-order:{label}")
            return variables

        def fake_scalar_bits(
            target: SpendReferenceR1CS, scalar: int, width: int, label: str
        ) -> tuple[Variable, ...]:
            events.append(f"bits:{label}")
            return tuple(
                target.alloc_private(
                    f"{label}/bit {index}/boolean", (scalar >> index) & 1
                )
                for index in range(width)
            )

        def fake_fixed_base(
            target: SpendReferenceR1CS,
            bits: tuple,
            base: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            events.append(f"fixed:{label}")
            if label == "g^position":
                observed["position_bits"] = bits
            variables = allocate_point(target, IDENTITY, label)
            if label == "g^position":
                observed["position_variables"] = variables
            return variables

        def fake_add(
            target: SpendReferenceR1CS,
            left_variables: EdwardsPointWitnessVariables,
            left_witness: Point,
            right_variables: EdwardsPointWitnessVariables,
            right_witness: Point,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            events.append(f"add:{label}")
            if label == "faerie gold prevention":
                observed["rho_left"] = left_variables
                observed["rho_right"] = right_variables
            return allocate_point(target, left_witness + right_witness, label)

        def fake_repr(
            target: SpendReferenceR1CS,
            variables: EdwardsPointWitnessVariables,
            point: Point,
            label: str,
        ) -> tuple[Variable, ...]:
            events.append(f"repr:{label}")
            values = tuple((point.v >> index) & 1 for index in range(255)) + (
                point.u & 1,
            )
            result = tuple(
                target.alloc_private(f"{label}/bit {index}", value)
                for index, value in enumerate(values)
            )
            if label == "representation of ak":
                observed["ak_repr"] = result
            elif label == "representation of nk":
                observed["nk_repr"] = result
            elif label == "representation of g_d":
                observed["g_d_repr"] = result
            elif label == "representation of pk_d":
                observed["pk_d_repr"] = result
            elif label == "representation of rho":
                observed["rho_repr"] = result
            return result

        def fake_ivk(
            target: SpendReferenceR1CS,
            ak_bits: tuple[Variable, ...],
            nk_bits: tuple[Variable, ...],
        ) -> SimpleNamespace:
            events.append("ivk")
            raw_bits = tuple(
                target.alloc_private(f"ivk bit {index}", index & 1)
                for index in range(251)
            )
            ivk_bits = tuple(
                sapling_spend_reference_port._BellmanNegated(bit)
                for bit in raw_bits
            )
            observed["ivk_bits"] = ivk_bits
            return SimpleNamespace(ivk_bits=ivk_bits)

        def fake_variable_base(
            target: SpendReferenceR1CS,
            variables: EdwardsPointWitnessVariables,
            point: Point,
            bits: tuple,
            label: str,
        ) -> EdwardsPointWitnessVariables:
            events.append(f"variable-base:{label}")
            observed["pk_d_bits"] = bits
            return allocate_point(target, IDENTITY, label)

        def fake_value_commitment(
            target: SpendReferenceR1CS, value: int, randomness: int
        ) -> SimpleNamespace:
            events.append("value commitment")
            value_bits = tuple(
                target.alloc_private(
                    f"value commitment/value/bit {index}/boolean",
                    (value >> index) & 1,
                )
                for index in range(64)
            )
            cv_variables = allocate_point(
                target, IDENTITY, "value commitment/commitment point"
            )
            inputs = sapling_spend_reference_port._inputize_spend_point(
                target,
                cv_variables,
                IDENTITY,
                "value commitment/commitment point",
            )
            observed["value_bits"] = value_bits
            return SimpleNamespace(
                value_bits=value_bits,
                input_variables=inputs,
                commitment_variables=cv_variables,
                commitment_witness=IDENTITY,
            )

        def fake_note_commitment(
            target: SpendReferenceR1CS,
            value: int,
            g_d_variables: EdwardsPointWitnessVariables,
            g_d_witness: Point,
            pk_d_variables: EdwardsPointWitnessVariables,
            pk_d_witness: Point,
            rcm: int,
            **kwargs,
        ) -> SimpleNamespace:
            events.append("note commitment")
            observed["note_value_bits"] = kwargs["value_bits"]
            observed["note_g_d_bits"] = kwargs["g_d_repr_bits"]
            observed["note_pk_d_bits"] = kwargs["pk_d_repr_bits"]
            variables = allocate_point(
                target, IDENTITY, "randomization of note commitment"
            )
            return SimpleNamespace(
                commitment_variables=variables,
                commitment_witness=IDENTITY,
            )

        def fake_merkle(
            target: SpendReferenceR1CS,
            leaf: Variable,
            leaf_value: int,
            authentication_path: tuple[tuple[int, bool], ...],
        ) -> SimpleNamespace:
            events.append("merkle")
            observed["merkle_leaf"] = leaf
            observed["merkle_path"] = authentication_path
            position_bits = tuple(
                target.alloc_private(f"merkle position bit {index}", 0)
                for index in range(32)
            )
            root = target.alloc_private("merkle root", 0)
            observed["merkle_position_bits"] = position_bits
            return SimpleNamespace(
                leaf_variable=leaf,
                position_bits=position_bits,
                root_variable=root,
                root_value=0,
            )

        def fake_nullifier_hash(
            target: SpendReferenceR1CS,
            nk_bits: tuple[Variable, ...],
            rho_bits: tuple[Variable, ...],
        ) -> SimpleNamespace:
            events.append("nullifier hash")
            observed["nf_nk_bits"] = nk_bits
            observed["nf_rho_bits"] = rho_bits
            digest_bits = tuple(False for _ in range(256))
            observed["digest_bits"] = digest_bits
            return SimpleNamespace(digest_bits=digest_bits)

        def fake_multipacking(
            target: SpendReferenceR1CS, digest_bits: tuple[bool, ...]
        ) -> SimpleNamespace:
            events.append("multipacking")
            observed["packing_bits"] = digest_bits
            inputs = []
            for index in range(2):
                variable = target.alloc_public(
                    f"pack nullifier/input {index}", 0
                )
                target.enforce(
                    target.linear_combination(()),
                    target.one,
                    variable,
                    f"pack nullifier/packing constraint {index}",
                )
                inputs.append(variable)
            return SimpleNamespace(input_variables=tuple(inputs))

        replacements = {
            "constrain_spend_edwards_point_witness": fake_point_witness,
            "constrain_spend_edwards_point_not_small_order": fake_non_small_order,
            "allocate_spend_fixed_base_scalar_bits": fake_scalar_bits,
            "constrain_spend_fixed_base_mul": fake_fixed_base,
            "constrain_spend_edwards_point_add": fake_add,
            "constrain_spend_edwards_point_repr": fake_repr,
            "constrain_spend_ivk_blake2s": fake_ivk,
            "constrain_spend_edwards_point_mul": fake_variable_base,
            "constrain_spend_value_commitment": fake_value_commitment,
            "constrain_spend_note_commitment": fake_note_commitment,
            "constrain_spend_merkle_authentication_path": fake_merkle,
            "constrain_spend_nullifier_blake2s": fake_nullifier_hash,
            "constrain_spend_nullifier_multipacking": fake_multipacking,
        }
        with ExitStack() as stack:
            for name, replacement in replacements.items():
                stack.enter_context(
                    patch.object(
                        sapling_spend_reference_port,
                        name,
                        side_effect=replacement,
                    )
                )
            assembly = constrain_source_faithful_spend(system, witness)

        self.assertEqual(
            events,
            [
                "point:ak",
                "small-order:ak not small order",
                "bits:ar",
                "fixed:computation of randomization for the signing key",
                "add:computation of rk",
                "bits:nsk",
                "fixed:computation of nk",
                "repr:representation of ak",
                "repr:representation of nk",
                "ivk",
                "point:witness g_d",
                "small-order:g_d not small order",
                "variable-base:compute pk_d",
                "value commitment",
                "repr:representation of g_d",
                "repr:representation of pk_d",
                "note commitment",
                "merkle",
                "fixed:g^position",
                "add:faerie gold prevention",
                "repr:representation of rho",
                "nullifier hash",
                "multipacking",
            ],
        )
        self.assertIs(observed["pk_d_bits"], observed["ivk_bits"])
        self.assertIs(observed["note_value_bits"], observed["value_bits"])
        self.assertIs(observed["note_g_d_bits"], observed["g_d_repr"])
        self.assertIs(observed["note_pk_d_bits"], observed["pk_d_repr"])
        self.assertIs(assembly.merkle_path.leaf_variable, observed["merkle_leaf"])
        self.assertIs(observed["merkle_path"], witness.authentication_path)
        self.assertIs(
            observed["position_bits"], assembly.merkle_path.position_bits
        )
        self.assertIs(observed["rho_left"], assembly.note_commitment.commitment_variables)
        self.assertIs(observed["rho_right"], observed["position_variables"])
        self.assertIs(observed["nf_nk_bits"], assembly.nk_repr_bits)
        self.assertIs(observed["nf_rho_bits"], assembly.rho_repr_bits)
        self.assertIs(observed["packing_bits"], observed["digest_bits"])
        self.assertEqual(
            [system.public_input_position(variable) for variable in assembly.public_inputs],
            list(range(1, 8)),
        )
        self.assertEqual(
            [variable.name for variable in assembly.public_inputs],
            [
                "rk/u/input variable",
                "rk/v/input variable",
                "value commitment/commitment point/u/input variable",
                "value commitment/commitment point/v/input variable",
                "anchor/input variable",
                "pack nullifier/input 0",
                "pack nullifier/input 1",
            ],
        )
        self.assertLess(system.constraint_count, 20)


def _reference_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_ivk_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
        "--",
        "--ivk-only",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_nullifier_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
        "--",
        "--nullifier-only",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_nullifier_multipacking_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
        "--",
        "--nullifier-multipacking-only",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_value_commitment_cases() -> dict:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(REFERENCE_MANIFEST),
        "--bin",
        "sapling_spend_edwards_point_reference",
        "--",
        "--value-commitment-only",
    ]
    environment = os.environ.copy()
    environment["CARGO_TERM_COLOR"] = "never"
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    return json.loads(completed.stdout)


def _reference_full_spend_trace() -> dict:
    persisted_trace = os.environ.get("SAPLING_SPEND_REFERENCE_TRACE")
    if persisted_trace:
        return json.loads(Path(persisted_trace).read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="sapling-spend-reference-") as directory:
        trace_path = Path(directory) / "spend-reference.json"
        command = [
            "cargo",
            "test",
            "--quiet",
            "--manifest-path",
            str(REFERENCE_MANIFEST),
            "--test",
            "export_spend",
            "export_pinned_spend_fixture",
            "--",
            "--exact",
        ]
        environment = os.environ.copy()
        environment["CARGO_TERM_COLOR"] = "never"
        environment["SAPLING_SPEND_EXPORT"] = str(trace_path)
        subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=900,
            env=environment,
        )
        return json.loads(trace_path.read_text(encoding="utf-8"))


def _reference_spend_assignment_variant(name: str) -> dict:
    with tempfile.TemporaryDirectory(
        prefix="sapling-spend-assignment-reference-"
    ) as directory:
        trace_path = Path(directory) / "spend-assignments.json"
        command = [
            "cargo",
            "test",
            "--quiet",
            "--manifest-path",
            str(REFERENCE_MANIFEST),
            "--test",
            "export_spend",
            "export_spend_assignment_variant",
            "--",
            "--exact",
        ]
        environment = os.environ.copy()
        environment["CARGO_TERM_COLOR"] = "never"
        environment["SAPLING_SPEND_ASSIGNMENT_VARIANT"] = name
        environment["SAPLING_SPEND_ASSIGNMENT_EXPORT"] = str(trace_path)
        subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=900,
            env=environment,
        )
        return json.loads(trace_path.read_text(encoding="utf-8"))


def _full_spend_trace_assignment(record: dict) -> int:
    assignment_hex = record.get("assignment_hex")
    if not isinstance(assignment_hex, str):
        raise TypeError(
            f"Bellman trace variable {record.get('identity')!r} is unassigned"
        )
    return int.from_bytes(bytes.fromhex(assignment_hex), "little")


def _full_spend_reference_witness(reference: dict) -> SpendReferenceWitness:
    auxiliary = {
        record["annotation"]: record for record in reference["auxiliary_variables"]
    }

    def assigned(annotation: str) -> int:
        try:
            record = auxiliary[annotation]
        except KeyError as error:
            raise AssertionError(
                f"missing Bellman witness annotation {annotation!r}"
            ) from error
        return _full_spend_trace_assignment(record)

    def bits(prefix: str, width: int) -> int:
        return sum(
            assigned(f"{prefix}/bit {index}/boolean") << index
            for index in range(width)
        )

    authentication_path = tuple(
        (
            assigned(f"merkle tree hash {level}/path element/num"),
            bool(assigned(f"merkle tree hash {level}/position bit/boolean")),
        )
        for level in range(32)
    )
    anchor_record = next(
        record
        for record in reference["inputs"]
        if record["annotation"] == "anchor/input variable"
    )
    return SpendReferenceWitness(
        ak=Point(assigned("ak/u/num"), assigned("ak/v/num")),
        ar=bits("ar", 252),
        nsk=bits("nsk", 252),
        g_d=Point(assigned("witness g_d/u/num"), assigned("witness g_d/v/num")),
        value=bits("value commitment/value", 64),
        rcv=bits("value commitment/rcv", 252),
        rcm=bits("rcm", 252),
        authentication_path=authentication_path,
        anchor=_full_spend_trace_assignment(anchor_record),
    )


def _full_spend_reference_failed_rows(
    reference: dict, replacements: dict[str, int]
) -> tuple[int, ...]:
    return _full_spend_reference_failed_rows_with_assignments(
        reference, reference, replacements
    )


def _full_spend_reference_failed_rows_with_assignments(
    matrix_reference: dict,
    assignment_reference: dict,
    replacements: dict[str, int] | None = None,
) -> tuple[int, ...]:
    assignments = {
        record["identity"]: _full_spend_trace_assignment(record)
        for record in (
            *assignment_reference["inputs"],
            *assignment_reference["auxiliary_variables"],
        )
    }
    assignments.update(
        {
            identity: value % SCALAR_MODULUS
            for identity, value in (replacements or {}).items()
        }
    )

    def evaluate(terms: list[dict]) -> int:
        return sum(
            int.from_bytes(
                bytes.fromhex(term["coefficient_hex"]), "little"
            )
            * assignments[term["identity"]]
            for term in terms
        ) % SCALAR_MODULUS

    return tuple(
        row["index"]
        for row in matrix_reference["constraints"]
        if evaluate(row["a"]) * evaluate(row["b"]) % SCALAR_MODULUS
        != evaluate(row["c"])
    )


@unittest.skipUnless(
    os.environ.get("SAPLING_SPEND_FULL_REFERENCE_ONLY") == "1",
    "requires one complete pinned Bellman Spend trace",
)
class SpendFullCompositionReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reference = _reference_full_spend_trace()
        if cls.reference["format"] != "bellman-sapling-spend-reference-v1":
            raise AssertionError("unexpected full Spend reference format")
        if cls.reference["sapling_crypto_revision"] != (
            "88a7946b4a3066787776e11f0a502654167e022d"
        ):
            raise AssertionError("unexpected pinned Sapling source revision")
        if cls.reference["bellman_revision"] != (
            "b726862a4ece8a627e7fea486d77b502a6edbb0b"
        ):
            raise AssertionError("unexpected pinned Bellman source revision")
        if cls.reference["upstream_test_asserted_hash"] != (
            "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89"
        ):
            raise AssertionError("unexpected upstream Spend matrix hash")
        if (
            cls.reference["observed_test_constraint_system_hash"]
            != cls.reference["upstream_test_asserted_hash"]
            or cls.reference["num_inputs_including_one"] != 8
            or cls.reference["num_auxiliary_variables"] != 98_638
            or cls.reference["num_constraints"] != 98_777
            or len(cls.reference["inputs"]) != 8
            or len(cls.reference["auxiliary_variables"]) != 98_638
            or len(cls.reference["constraints"]) != 98_777
            or not cls.reference["satisfied"]
        ):
            raise AssertionError("Bellman Spend trace failed metadata validation")
        cls.witness = _full_spend_reference_witness(cls.reference)

    def _assert_assignment_variant_matches(self, assignment_reference: dict):
        self.assertEqual(
            assignment_reference["format"],
            "bellman-sapling-spend-assignment-reference-v1",
        )
        self.assertEqual(assignment_reference["full_synthesis_count"], 1)
        self.assertFalse(assignment_reference["constraints_recorded"])
        self.assertEqual(
            assignment_reference["sapling_crypto_revision"],
            self.reference["sapling_crypto_revision"],
        )
        self.assertEqual(
            assignment_reference["bellman_revision"],
            self.reference["bellman_revision"],
        )
        self.assertEqual(assignment_reference["num_inputs_including_one"], 8)
        self.assertEqual(assignment_reference["num_auxiliary_variables"], 98_638)

        witness = _full_spend_reference_witness(assignment_reference)
        system = SpendReferenceR1CS()
        started = time.perf_counter()
        assembly = constrain_source_faithful_spend(system, witness)
        synthesis_seconds = time.perf_counter() - started
        print(
            f"{assignment_reference['fixture']['name']}: "
            f"Python full synthesis {synthesis_seconds:.3f}s"
        )

        matrix_reference = self.reference
        expected_allocations = (
            *assignment_reference["inputs"],
            *assignment_reference["auxiliary_variables"],
        )
        self.assertEqual(len(system.constraints), matrix_reference["num_constraints"])
        self.assertEqual(len(system.variables), len(expected_allocations))
        self.assertTrue(system.is_satisfied())
        self.assertEqual(
            _full_spend_reference_failed_rows_with_assignments(
                matrix_reference, assignment_reference
            ),
            (),
        )
        self.assertEqual(
            system.witness_value(system.variables[0]),
            _full_spend_trace_assignment(assignment_reference["inputs"][0]),
        )

        expected_by_identity = {
            record["identity"]: record
            for record in expected_allocations
        }
        expected_events = sorted(
            (
                record
                for record in expected_allocations
                if record["identity"] != "Input(0)"
            ),
            key=lambda record: record["allocation_event_index"],
        )
        actual_identities: list[str] = []
        local_variables_by_identity = {"Input(0)": system.variables[0]}
        auxiliary_index = 0
        for event_index, actual in enumerate(system.variables[1:]):
            if actual.kind == "private":
                identity = f"Aux({auxiliary_index})"
                auxiliary_index += 1
            else:
                position = system.public_input_position(actual)
                self.assertIsNotNone(position)
                identity = f"Input({position})"
            actual_identities.append(identity)
            local_variables_by_identity[identity] = actual
            expected = expected_by_identity[identity]
            self.assertEqual(actual.name, expected["annotation"], f"allocation {event_index}")
            self.assertEqual(
                system.witness_value(actual),
                _full_spend_trace_assignment(expected),
                f"assignment {event_index} ({identity})",
            )
        self.assertEqual(
            actual_identities,
            [record["identity"] for record in expected_events],
        )
        self.assertEqual(auxiliary_index, len(assignment_reference["auxiliary_variables"]))

        public_records = assignment_reference["inputs"][1:]
        self.assertEqual(len(assembly.public_inputs), 7)
        self.assertEqual(
            [system.public_input_position(variable) for variable in assembly.public_inputs],
            list(range(1, 8)),
        )
        self.assertEqual(
            [variable.name for variable in assembly.public_inputs],
            [record["annotation"] for record in public_records],
        )
        self.assertEqual(
            system.public_inputs(),
            tuple(_full_spend_trace_assignment(record) for record in public_records),
        )

        self.assertEqual(
            len(system.constraints),
            len(matrix_reference["constraints"]),
        )
        expected_public_inputs = matrix_reference["inputs"][1:]
        for row_index, (actual, expected) in enumerate(
            zip(system.constraints, matrix_reference["constraints"], strict=True)
        ):
            self.assertEqual(expected["index"], row_index)
            self.assertEqual(actual.label, expected["annotation"], f"row {row_index}")
            for side, local_terms in (
                ("a", actual.left.terms),
                ("b", actual.right.terms),
                ("c", actual.output.terms),
            ):
                expected_terms = tuple(
                    (int(column), int(coefficient))
                    for column, coefficient in _canonical_reference_terms_with_inputs(
                        expected[side], len(expected_public_inputs)
                    )
                )
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_terms),
                    expected_terms,
                    f"ordered {side.upper()} expression at row {row_index}",
                )

        self.assertEqual(
            system.matrix_fingerprint(),
            _reference_matrix_fingerprint_with_inputs(
                {
                    "inputs": expected_public_inputs,
                    "variables": matrix_reference["auxiliary_variables"],
                    "constraints": matrix_reference["constraints"],
                }
            ),
        )

        replacements = (
            ("Input(5)", (witness.anchor + 1) % SCALAR_MODULUS),
            (
                next(
                    record["identity"]
                    for record in assignment_reference["auxiliary_variables"]
                    if record["annotation"] == "ak/u/num"
                ),
                (witness.ak.u + 1) % SCALAR_MODULUS,
            ),
            (
                next(
                    record["identity"]
                    for record in assignment_reference["auxiliary_variables"]
                    if record["annotation"]
                    == "merkle tree hash 0/path element/num"
                ),
                (witness.authentication_path[0][0] + 1) % SCALAR_MODULUS,
            ),
        )
        for identity, replacement in replacements:
            local_variable = local_variables_by_identity[identity]
            local_failures = _local_failed_rows_with_assignments(
                system, {local_variable.index: replacement}
            )
            reference_failures = _full_spend_reference_failed_rows_with_assignments(
                matrix_reference,
                assignment_reference,
                {identity: replacement},
            )
            self.assertEqual(local_failures, reference_failures)
            self.assertTrue(local_failures, identity)
            if identity == "Input(5)":
                self.assertEqual(local_failures, (76_894,))

        conditional_anchor_identity = next(
            record["identity"]
            for record in assignment_reference["auxiliary_variables"]
            if record["annotation"] == "conditional anchor/num"
        )
        conditional_anchor_value = (witness.anchor + 1) % SCALAR_MODULUS
        conditional_anchor_replacements = {
            "Input(5)": conditional_anchor_value,
            conditional_anchor_identity: conditional_anchor_value,
        }
        local_failures = _local_failed_rows_with_assignments(
            system,
            {
                local_variables_by_identity[identity].index: replacement
                for identity, replacement in conditional_anchor_replacements.items()
            },
        )
        reference_failures = _full_spend_reference_failed_rows_with_assignments(
            matrix_reference,
            assignment_reference,
            conditional_anchor_replacements,
        )
        self.assertEqual(local_failures, reference_failures)
        if witness.value == 0:
            self.assertEqual(local_failures, ())
        else:
            self.assertEqual(local_failures, (76_893,))
        return system, assembly, synthesis_seconds

    def test_zero_value_alternating_path_witness_matches_bellman(self) -> None:
        assignment_reference = _reference_spend_assignment_variant(
            "zero-value-alternating"
        )
        witness = _full_spend_reference_witness(assignment_reference)
        self.assertEqual(witness.value, 0)
        self.assertEqual(
            tuple(direction for _, direction in witness.authentication_path),
            tuple(level % 2 == 0 for level in range(32)),
        )
        self.assertNotEqual(witness.ak, self.witness.ak)
        self.assertNotEqual(witness.nsk, self.witness.nsk)
        self.assertNotEqual(witness.g_d, self.witness.g_d)
        self.assertNotEqual(witness.rcv, self.witness.rcv)

        for prefix in (
            "computation of ivk",
            "nf computation",
            "note content hash",
            "representation of nk",
        ):
            baseline_values = tuple(
                record["assignment_hex"]
                for record in self.reference["auxiliary_variables"]
                if record["annotation"].startswith(prefix)
            )
            variant_values = tuple(
                record["assignment_hex"]
                for record in assignment_reference["auxiliary_variables"]
                if record["annotation"].startswith(prefix)
            )
            self.assertEqual(len(variant_values), len(baseline_values), prefix)
            self.assertNotEqual(variant_values, baseline_values, prefix)

        self._assert_assignment_variant_matches(assignment_reference)

    def test_max_value_all_right_path_witness_matches_bellman(self) -> None:
        assignment_reference = _reference_spend_assignment_variant(
            "max-value-all-right"
        )
        witness = _full_spend_reference_witness(assignment_reference)
        self.assertEqual(witness.value, (1 << 64) - 1)
        self.assertEqual(
            tuple(direction for _, direction in witness.authentication_path),
            (True,) * 32,
        )
        self.assertNotEqual(witness.ak, self.witness.ak)
        self.assertNotEqual(witness.nsk, self.witness.nsk)
        self.assertNotEqual(witness.g_d, self.witness.g_d)
        self.assertNotEqual(witness.rcv, self.witness.rcv)

        for prefix in (
            "computation of ivk",
            "nf computation",
            "note content hash",
            "representation of nk",
        ):
            baseline_values = tuple(
                record["assignment_hex"]
                for record in self.reference["auxiliary_variables"]
                if record["annotation"].startswith(prefix)
            )
            variant_values = tuple(
                record["assignment_hex"]
                for record in assignment_reference["auxiliary_variables"]
                if record["annotation"].startswith(prefix)
            )
            self.assertEqual(len(variant_values), len(baseline_values), prefix)
            self.assertNotEqual(variant_values, baseline_values, prefix)

        self._assert_assignment_variant_matches(assignment_reference)

    def test_complete_composition_matches_bellman_trace_and_failure_row(
        self,
    ) -> None:
        system = SpendReferenceR1CS()
        with patch(
            __name__ + ".constrain_source_faithful_spend",
            wraps=constrain_source_faithful_spend,
        ) as python_syntheses:
            assembly = constrain_source_faithful_spend(system, self.witness)
            python_syntheses.assert_called_once()

        reference = self.reference
        self.assertTrue(system.is_satisfied())
        self.assertEqual(len(system.constraints), reference["num_constraints"])
        self.assertEqual(
            len(system.variables),
            len(reference["inputs"]) + len(reference["auxiliary_variables"]),
        )
        self.assertEqual(system.public_input_count, len(reference["inputs"]) - 1)
        self.assertEqual(
            system.witness_value(system.variables[0]),
            _full_spend_trace_assignment(reference["inputs"][0]),
        )

        auxiliary_records = reference["auxiliary_variables"]
        public_records = reference["inputs"][1:]
        public_positions_by_auxiliary_count = {
            1: 1_029,
            2: 1_029,
            3: 29_075,
            4: 29_075,
            5: 76_806,
            6: 98_638,
            7: 98_638,
        }
        auxiliary_index = 0
        for event_index, actual in enumerate(system.variables[1:]):
            if actual.kind == "private":
                expected = auxiliary_records[auxiliary_index]
                identity = f"Aux({auxiliary_index})"
                self.assertEqual(expected["identity"], identity)
                self.assertEqual(
                    system.auxiliary_index(actual), auxiliary_index
                )
                auxiliary_index += 1
            else:
                position = system.public_input_position(actual)
                assert position is not None
                expected = public_records[position - 1]
                identity = f"Input({position})"
                self.assertEqual(expected["identity"], identity)
                self.assertEqual(
                    auxiliary_index,
                    public_positions_by_auxiliary_count[position],
                    f"public input allocation boundary at event {event_index}",
                )
            self.assertEqual(
                actual.name, expected["annotation"], f"allocation {event_index}"
            )
            self.assertEqual(
                system.witness_value(actual),
                _full_spend_trace_assignment(expected),
                f"assignment {event_index} ({identity})",
            )
        self.assertEqual(auxiliary_index, len(auxiliary_records))

        if all(
            "allocation_event_index" in record
            for record in (*reference["inputs"], *auxiliary_records)
        ):
            expected_events = sorted(
                (
                    record
                    for record in (
                        *reference["inputs"],
                        *auxiliary_records,
                    )
                    if record["identity"] != "Input(0)"
                ),
                key=lambda record: record["allocation_event_index"],
            )
            actual_identities = []
            seen_auxiliaries = 0
            for actual in system.variables[1:]:
                if actual.kind == "private":
                    actual_identities.append(f"Aux({seen_auxiliaries})")
                    seen_auxiliaries += 1
                else:
                    position = system.public_input_position(actual)
                    assert position is not None
                    actual_identities.append(f"Input({position})")
            self.assertEqual(
                actual_identities,
                [record["identity"] for record in expected_events],
            )

        expected_public_inputs = reference["inputs"][1:]
        self.assertEqual(len(assembly.public_inputs), 7)
        self.assertEqual(
            [system.public_input_position(variable) for variable in assembly.public_inputs],
            list(range(1, 8)),
        )
        self.assertEqual(
            [variable.name for variable in assembly.public_inputs],
            [record["annotation"] for record in expected_public_inputs],
        )
        self.assertEqual(
            system.public_inputs(),
            tuple(
                _full_spend_trace_assignment(record)
                for record in expected_public_inputs
            ),
        )

        self.assertEqual(len(system.constraints), len(reference["constraints"]))
        for row_index, (actual, expected) in enumerate(
            zip(system.constraints, reference["constraints"], strict=True)
        ):
            if expected["index"] != row_index:
                raise AssertionError(f"Bellman row index changed at {row_index}")
            if actual.label != expected["annotation"]:
                raise AssertionError(f"row label differs at {row_index}")
            for side, local_terms in (
                ("a", actual.left.terms),
                ("b", actual.right.terms),
                ("c", actual.output.terms),
            ):
                expected_terms = tuple(
                    (int(column), int(coefficient))
                    for column, coefficient in _canonical_reference_terms_with_inputs(
                        expected[side], len(expected_public_inputs)
                    )
                )
                actual_terms = _canonical_local_terms_with_inputs(
                    system, local_terms
                )
                if actual_terms != expected_terms:
                    raise AssertionError(
                        f"ordered {side.upper()} expression differs at row {row_index}"
                    )

        self.assertEqual(
            system.matrix_fingerprint(),
            _reference_matrix_fingerprint_with_inputs(
                {
                    "inputs": expected_public_inputs,
                    "variables": reference["auxiliary_variables"],
                    "constraints": reference["constraints"],
                }
            ),
        )

        anchor_variable = assembly.conditional_anchor.anchor_variable
        anchor_value = system.witness_value(anchor_variable)
        self.assertIsNotNone(anchor_value)
        replacement = (int(anchor_value) + 1) % SCALAR_MODULUS
        local_failures = _local_failed_rows_with_assignments(
            system, {anchor_variable.index: replacement}
        )
        reference_failures = _full_spend_reference_failed_rows(
            reference, {"Input(5)": replacement}
        )
        self.assertEqual(local_failures, reference_failures)
        self.assertEqual(len(local_failures), 1)

def _reference_index(identity: str) -> int:
    if identity == "Input(0)":
        return 0
    if identity.startswith("Aux(") and identity.endswith(")"):
        return int(identity[4:-1]) + 1
    raise AssertionError(f"unexpected isolated reference variable {identity!r}")


def _input_reference_column(identity: str, input_count: int) -> int:
    if identity == "Input(0)":
        return 0
    if identity.startswith("Input(") and identity.endswith(")"):
        return int(identity[6:-1])
    if identity.startswith("Aux(") and identity.endswith(")"):
        return input_count + 1 + int(identity[4:-1])
    raise AssertionError(f"unexpected value-commitment variable {identity!r}")


def _canonical_reference_terms_with_inputs(
    terms: list[dict], input_count: int
) -> list[list[str | int]]:
    combined: dict[int, int] = {}
    for term in terms:
        column = _input_reference_column(term["identity"], input_count)
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


def _reference_matrix_fingerprint_with_inputs(reference: dict) -> str:
    input_count = len(reference["inputs"])
    auxiliary_count = len(reference["variables"])
    document = {
        "format": _MATRIX_SERIALIZATION_FORMAT,
        "field_modulus": str(SCALAR_MODULUS),
        "column_count": 1 + input_count + auxiliary_count,
        "one_column": 0,
        "public_input_count": input_count,
        "auxiliary_variable_count": auxiliary_count,
        "variable_kinds": (
            ["one"] + ["public"] * input_count + ["private"] * auxiliary_count
        ),
        "constraints": [
            [
                _canonical_reference_terms_with_inputs(row[side], input_count)
                for side in ("a", "b", "c")
            ]
            for row in reference["constraints"]
        ],
    }
    serialized = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return sha256(_MATRIX_FINGERPRINT_DOMAIN + serialized).hexdigest()


def _canonical_local_terms_with_inputs(
    system: SpendReferenceR1CS,
    terms: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = {}
    for variable_index, coefficient in terms:
        column = system.canonical_column(variable_index)
        combined[column] = (
            combined.get(column, 0) + coefficient
        ) % SCALAR_MODULUS
    return tuple(
        (column, coefficient)
        for column, coefficient in sorted(combined.items())
        if coefficient
    )


def _canonical_terms(terms: list[dict]) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = {}
    for term in terms:
        index = _reference_index(term["identity"])
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        combined[index] = (combined.get(index, 0) + coefficient) % SCALAR_MODULUS
    return tuple(
        (index, coefficient)
        for index, coefficient in sorted(combined.items())
        if coefficient
    )


def _reference_failed_rows(
    reference: dict, variable_index: int, replacement: int
) -> tuple[int, ...]:
    return _reference_failed_rows_with_assignments(
        reference, {variable_index: replacement}
    )


def _reference_failed_rows_with_assignments(
    reference: dict, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = [1] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["variables"]
    ]
    for variable_index, replacement in replacements.items():
        assignments[variable_index] = replacement % SCALAR_MODULUS

    def evaluate(terms: list[dict]) -> int:
        return sum(
            int.from_bytes(
                bytes.fromhex(term["coefficient_hex"]), "little"
            )
            * assignments[_reference_index(term["identity"])]
            for term in terms
        ) % SCALAR_MODULUS

    return tuple(
        row["index"]
        for row in reference["constraints"]
        if evaluate(row["a"]) * evaluate(row["b"]) % SCALAR_MODULUS
        != evaluate(row["c"])
    )


def _local_failed_rows(
    system: R1CS, variable_index: int, replacement: int
) -> tuple[int, ...]:
    return _local_failed_rows_with_assignments(
        system, {variable_index: replacement}
    )


def _local_failed_rows_with_assignments(
    system: R1CS, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = list(system._values)
    for variable_index, replacement in replacements.items():
        assignments[variable_index] = replacement % SCALAR_MODULUS
    return tuple(
        index
        for index, row in enumerate(system.constraints)
        if system._evaluate(row.left, assignments)
        * system._evaluate(row.right, assignments)
        % SCALAR_MODULUS
        != system._evaluate(row.output, assignments)
    )


def _conditional_anchor_reference_index(identity: str, input_count: int) -> int:
    if identity.startswith("Input(") and identity.endswith(")"):
        return int(identity[6:-1])
    if identity.startswith("Aux(") and identity.endswith(")"):
        return input_count + int(identity[4:-1])
    raise AssertionError(f"unexpected anchor reference variable {identity!r}")


def _conditional_anchor_terms(
    terms: list[dict], input_count: int
) -> tuple[tuple[int, int], ...]:
    combined: dict[int, int] = {}
    for term in terms:
        index = _conditional_anchor_reference_index(
            term["identity"], input_count
        )
        coefficient = int.from_bytes(
            bytes.fromhex(term["coefficient_hex"]), "little"
        )
        combined[index] = (combined.get(index, 0) + coefficient) % SCALAR_MODULUS
    return tuple(
        (index, coefficient)
        for index, coefficient in sorted(combined.items())
        if coefficient
    )


def _conditional_anchor_failed_rows(
    reference: dict, replacements: dict[int, int]
) -> tuple[int, ...]:
    assignments = [1] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["inputs"]
    ] + [
        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
        for record in reference["variables"]
    ]
    for variable_index, replacement in replacements.items():
        assignments[variable_index] = replacement % SCALAR_MODULUS

    def evaluate(terms: list[dict]) -> int:
        return sum(
            int.from_bytes(bytes.fromhex(term["coefficient_hex"]), "little")
            * assignments[
                _conditional_anchor_reference_index(
                    term["identity"], len(reference["inputs"]) + 1
                )
            ]
            for term in terms
        ) % SCALAR_MODULUS

    return tuple(
        row["index"]
        for row in reference["constraints"]
        if evaluate(row["a"]) * evaluate(row["b"]) % SCALAR_MODULUS
        != evaluate(row["c"])
    )


def _ivk_digest_bit_record(system: R1CS, bit) -> dict:
    if isinstance(bit, Variable):
        return {
            "identity": f"Aux({bit.index - 1})",
            "value": bool(_read_bit(system, bit)),
            "negated": False,
        }
    if isinstance(bit, _NegatedBit):
        return {
            "identity": f"Aux({bit.variable.index - 1})",
            "value": bool(_read_bit(system, bit)),
            "negated": True,
        }
    if isinstance(bit, _BellmanNegated):
        return {
            "identity": f"Aux({bit.variable.index - 1})",
            "value": bool(1 - system.witness_value(bit.variable)),
            "negated": True,
        }
    return {
        "identity": f"Constant({int(bit)})",
        "value": bool(bit),
        "negated": False,
    }


def _spend_digest_bit_record(system: SpendReferenceR1CS, bit) -> dict:
    if isinstance(bit, Variable):
        return {
            "identity": f"Aux({system.auxiliary_index(bit)})",
            "value": bool(system.witness_value(bit)),
            "negated": False,
        }
    if isinstance(bit, _NegatedBit):
        return {
            "identity": f"Aux({system.auxiliary_index(bit.variable)})",
            "value": bool(_read_bit(system, bit)),
            "negated": True,
        }
    if isinstance(bit, _BellmanNegated):
        return {
            "identity": f"Aux({system.auxiliary_index(bit.variable)})",
            "value": bool(1 - system.witness_value(bit.variable)),
            "negated": True,
        }
    return {
        "identity": f"Constant({int(bit)})",
        "value": bool(bit),
        "negated": False,
    }


def _ivk_bit_value(system: R1CS, bit) -> int:
    if isinstance(bit, _BellmanNegated):
        return 1 - int(system.witness_value(bit.variable))
    return _read_bit(system, bit)


def _sapling_representation_bits(point: Point) -> tuple[int, ...]:
    return tuple((point.v >> index) & 1 for index in range(255)) + (
        point.u & 1,
    )


def _allocate_boolean_bits(
    system: R1CS, values: list[bool], label: str = "scalar bits"
) -> tuple:
    bits = []
    for index, value in enumerate(values):
        bit = system.alloc_private(f"{label}/bit {index}/boolean", int(value))
        system.enforce(
            1 - bit.lc(),
            bit,
            0,
            f"{label}/bit {index}/boolean constraint",
        )
        bits.append(bit)
    return tuple(bits)


class SpendEdwardsPointReferencePortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SAPLING_NULLIFIER_MULTIPACK_REFERENCE_ONLY") == "1":
            cls.reference = _reference_nullifier_multipacking_cases()
            if cls.reference["format"] != (
                "bellman-sapling-nullifier-multipacking-reference-v1"
            ):
                raise AssertionError(
                    "unexpected Bellman nullifier-multipacking export format"
                )
            if cls.reference["sapling_crypto_revision"] != (
                "88a7946b4a3066787776e11f0a502654167e022d"
            ):
                raise AssertionError("unexpected pinned Sapling source revision")
            if cls.reference["bellman_revision"] != (
                "b726862a4ece8a627e7fea486d77b502a6edbb0b"
            ):
                raise AssertionError("unexpected Bellman source revision")
            if cls.reference["bellman_crate_version"] != "0.15.0":
                raise AssertionError("unexpected Bellman crate version")
            if (
                cls.reference["full_synthesis_count"] != 1
                or len(cls.reference["cases"]) != 1
            ):
                raise AssertionError(
                    "multipacking exporter must synthesize exactly one trace"
                )
            cls.nullifier_multipacking_cases = {
                case["name"]: case for case in cls.reference["cases"]
            }
            cls.nullifier_multipacking_vectors = {
                vector["name"]: vector for vector in cls.reference["vectors"]
            }
            return

        if os.environ.get("SAPLING_VALUE_COMMITMENT_REFERENCE_ONLY") == "1":
            cls.reference = _reference_value_commitment_cases()
            if cls.reference["format"] != (
                "bellman-sapling-value-commitment-reference-v1"
            ):
                raise AssertionError(
                    "unexpected Bellman value-commitment export format"
                )
            if cls.reference["sapling_crypto_revision"] != (
                "88a7946b4a3066787776e11f0a502654167e022d"
            ):
                raise AssertionError("unexpected pinned Sapling source revision")
            if cls.reference["bellman_revision"] != (
                "b726862a4ece8a627e7fea486d77b502a6edbb0b"
            ):
                raise AssertionError("unexpected Bellman source revision")
            if cls.reference["bellman_crate_version"] != "0.15.0":
                raise AssertionError("unexpected Bellman crate version")
            if (
                cls.reference["full_synthesis_count"] != 1
                or len(cls.reference["cases"]) != 1
            ):
                raise AssertionError(
                    "value-commitment exporter must synthesize exactly one trace"
                )
            cls.value_commitment_cases = {
                case["name"]: case for case in cls.reference["cases"]
            }
            cls.value_commitment_vectors = {
                vector["name"]: vector for vector in cls.reference["vectors"]
            }
            return

        if os.environ.get("SAPLING_NULLIFIER_REFERENCE_ONLY") == "1":
            cls.reference = _reference_nullifier_cases()
            if cls.reference["format"] != (
                "bellman-sapling-nullifier-blake2s-reference-v1"
            ):
                raise AssertionError("unexpected Bellman nullifier export format")
            if cls.reference["sapling_crypto_revision"] != (
                "88a7946b4a3066787776e11f0a502654167e022d"
            ):
                raise AssertionError("unexpected pinned Sapling source revision")
            if cls.reference["bellman_revision"] != (
                "b726862a4ece8a627e7fea486d77b502a6edbb0b"
            ):
                raise AssertionError("unexpected Bellman source revision")
            if cls.reference["bellman_crate_version"] != "0.15.0":
                raise AssertionError("unexpected Bellman crate version")
            if (
                cls.reference["full_synthesis_count"] != 1
                or len(cls.reference["cases"]) != 1
            ):
                raise AssertionError(
                    "nullifier exporter must synthesize exactly one trace"
                )
            cls.nullifier_blake2s_cases = {
                case["name"]: case for case in cls.reference["cases"]
            }
            cls.nullifier_blake2s_vectors = {
                vector["name"]: vector for vector in cls.reference["vectors"]
            }
            return

        if os.environ.get("SAPLING_IVK_REFERENCE_ONLY") == "1":
            cls.reference = _reference_ivk_cases()
            if cls.reference["format"] != (
                "bellman-sapling-ivk-blake2s-reference-v1"
            ):
                raise AssertionError("unexpected Bellman IVK export format")
            if cls.reference["sapling_crypto_revision"] != (
                "88a7946b4a3066787776e11f0a502654167e022d"
            ):
                raise AssertionError("unexpected pinned Sapling source revision")
            if cls.reference["bellman_revision"] != (
                "b726862a4ece8a627e7fea486d77b502a6edbb0b"
            ):
                raise AssertionError("unexpected Bellman source revision")
            if cls.reference["bellman_crate_version"] != "0.15.0":
                raise AssertionError("unexpected Bellman crate version")
            if (
                cls.reference["full_synthesis_count"] != 1
                or len(cls.reference["cases"]) != 1
            ):
                raise AssertionError("IVK exporter must synthesize exactly one trace")
            cls.ivk_blake2s_cases = {
                case["name"]: case for case in cls.reference["cases"]
            }
            cls.ivk_blake2s_vectors = {
                vector["name"]: vector for vector in cls.reference["vectors"]
            }
            return

        cls.reference = _reference_cases()
        if cls.reference["format"] != "bellman-sapling-edwards-point-reference-v12":
            raise AssertionError("unexpected Bellman Edwards point export format")
        if cls.reference["sapling_crypto_revision"] != (
            "88a7946b4a3066787776e11f0a502654167e022d"
        ):
            raise AssertionError("unexpected pinned Sapling source revision")
        if cls.reference["bellman_revision"] != (
            "b726862a4ece8a627e7fea486d77b502a6edbb0b"
        ):
            raise AssertionError("unexpected Bellman source revision")
        if cls.reference["bellman_crate_version"] != "0.15.0":
            raise AssertionError("unexpected Bellman crate version")
        cls.cases = {case["name"]: case for case in cls.reference["cases"]}
        cls.non_small_order_cases = {
            case["name"]: case
            for case in cls.reference["non_small_order_cases"]
        }
        cls.representation_cases = {
            case["name"]: case for case in cls.reference["representations"]
        }
        cls.fixed_base = cls.reference["fixed_base"]
        cls.fixed_base_cases = {
            case["name"]: case for case in cls.fixed_base["cases"]
        }
        cls.variable_base_cases = {
            case["name"]: case
            for case in cls.reference["variable_base"]["cases"]
        }
        cls.montgomery_cases = {
            case["name"]: case for case in cls.reference["montgomery_cases"]
        }
        cls.signed_lookup = cls.reference["signed_lookup"]
        cls.signed_lookup_cases = {
            case["name"]: case for case in cls.signed_lookup["cases"]
        }
        cls.pedersen = cls.reference["pedersen"]
        cls.pedersen_cases = {case["name"]: case for case in cls.pedersen["cases"]}
        cls.note_commitment = cls.reference["note_commitment"]
        cls.note_commitment_cases = {
            case["name"]: case for case in cls.note_commitment["cases"]
        }
        cls.merkle_authentication = cls.reference["merkle_authentication"]
        cls.merkle_authentication_cases = {
            case["name"]: case
            for case in cls.merkle_authentication["cases"]
        }
        cls.conditional_anchor_cases = {
            case["name"]: case
            for case in cls.reference["conditional_anchor"]["cases"]
        }
        cls.ivk_blake2s_cases = {
            case["name"]: case for case in cls.reference["ivk_blake2s"]["cases"]
        }

    def assert_case_matches(
        self, name: str, point: Point, *, expected_satisfied: bool = True
    ) -> None:
        reference = self.cases[name]
        self.assertEqual(int(reference["u"]), point.u)
        self.assertEqual(int(reference["v"]), point.v)
        self.assertEqual(
            int.from_bytes(
                bytes.fromhex(self.reference["curve_d"]), "little"
            ),
            CURVE_D,
        )

        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, point)
        self.assert_system_matches_reference(
            name, system, reference, expected_satisfied
        )
        self.assertEqual((variables.u.index, variables.v.index), (1, 2))

    def assert_system_matches_reference(
        self,
        name: str,
        system: R1CS,
        reference: dict,
        expected_satisfied: bool = True,
    ) -> None:
        self.assertEqual(system.public_input_count, 0)
        self.assertEqual(
            [(variable.name, variable.index) for variable in system.variables[1:]],
            [
                (record["annotation"], _reference_index(record["identity"]))
                for record in reference["variables"]
            ],
        )
        self.assertEqual(
            [system._witness_value(variable) for variable in system.variables[1:]],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["variables"]
            ],
        )
        self.assertEqual(system.constraint_count, len(reference["constraints"]))

        for local_row, reference_row in zip(
            system.constraints, reference["constraints"], strict=True
        ):
            with self.subTest(case=name, row=reference_row["index"]):
                self.assertEqual(local_row.label, reference_row["annotation"])
                self.assertEqual(local_row.left.terms, _canonical_terms(reference_row["a"]))
                self.assertEqual(local_row.right.terms, _canonical_terms(reference_row["b"]))
                self.assertEqual(local_row.output.terms, _canonical_terms(reference_row["c"]))

        self.assertEqual(system.is_satisfied(), expected_satisfied)
        self.assertEqual(reference["satisfied"], expected_satisfied)

    def assert_ivk_system_matches_reference(
        self,
        name: str,
        system: R1CS,
        reference: dict,
        *,
        baseline_reference: dict | None = None,
        baseline_fingerprint: str | None = None,
    ) -> None:
        self.assertEqual(system.public_input_count, 0)
        self.assertEqual(
            [(variable.name, variable.index) for variable in system.variables[1:]],
            [
                (record["annotation"], _reference_index(record["identity"]))
                for record in reference["variables"]
            ],
        )
        self.assertEqual(
            [system._witness_value(variable) for variable in system.variables[1:]],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["variables"]
            ],
        )
        self.assertEqual(system.constraint_count, len(reference["constraints"]))

        if baseline_reference is not None:
            self.assertEqual(
                reference["constraints"], baseline_reference["constraints"]
            )
            self.assertEqual(system.matrix_fingerprint(), baseline_fingerprint)
        else:
            for row_index, (local_row, reference_row) in enumerate(
                zip(system.constraints, reference["constraints"], strict=True)
            ):
                actual = (
                    local_row.label,
                    local_row.left.terms,
                    local_row.right.terms,
                    local_row.output.terms,
                )
                expected = (
                    reference_row["annotation"],
                    _canonical_terms(reference_row["a"]),
                    _canonical_terms(reference_row["b"]),
                    _canonical_terms(reference_row["c"]),
                )
                if actual != expected:
                    differences = []
                    for side, actual_terms, expected_terms in zip(
                        ("A", "B", "C"),
                        actual[1:],
                        expected[1:],
                        strict=True,
                    ):
                        if actual_terms == expected_terms:
                            continue
                        term_index = next(
                            (
                                index
                                for index, (actual_term, expected_term) in enumerate(
                                    zip(actual_terms, expected_terms)
                                )
                                if actual_term != expected_term
                            ),
                            min(len(actual_terms), len(expected_terms)),
                        )
                        differences.append(
                            f"{side}[{term_index}] local="
                            f"{actual_terms[term_index:term_index + 1]!r} "
                            f"Bellman={expected_terms[term_index:term_index + 1]!r} "
                            f"lengths={len(actual_terms)}/{len(expected_terms)}"
                        )
                    self.fail(
                        f"{name}: ordered A/B/C mismatch at row {row_index}; "
                        f"labels local={actual[0]!r}, Bellman={expected[0]!r}; "
                        + "; ".join(differences)
                    )

        self.assertTrue(system.is_satisfied())
        self.assertTrue(reference["satisfied"])

    def test_exact_addition_and_doubling_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        negative = Point(*self._negative_generator_coordinates())
        identity = IDENTITY
        twice_generator = generator + generator
        cases = (
            (
                "identity_add_generator",
                "add",
                identity,
                generator,
            ),
            (
                "generator_add_identity",
                "add",
                generator,
                identity,
            ),
            (
                "negative_generator_add_generator",
                "add",
                negative,
                generator,
            ),
            (
                "generator_add_negative_generator",
                "add",
                generator,
                negative,
            ),
            (
                "equal_point_addition",
                "add",
                generator,
                generator,
            ),
            (
                "nontrivial_point_addition",
                "add",
                generator,
                twice_generator,
            ),
            ("identity_double", "double", identity, None),
            ("generator_double", "double", generator, None),
            ("negative_generator_double", "double", negative, None),
        )
        for name, operation, left, right in cases:
            with self.subTest(case=name):
                system = R1CS()
                left_variables = constrain_spend_edwards_point_witness(
                    system, left, "left" if right is not None else "point"
                )
                if operation == "add":
                    assert right is not None
                    right_variables = constrain_spend_edwards_point_witness(
                        system, right, "right"
                    )
                    result_variables = constrain_spend_edwards_point_add(
                        system,
                        left_variables,
                        left,
                        right_variables,
                        right,
                    )
                    expected = left + right
                else:
                    result_variables = constrain_spend_edwards_point_double(
                        system, left_variables, left
                    )
                    expected = left + left
                reference = self.cases[name]
                self.assertEqual(int(reference["u"]), expected.u)
                self.assertEqual(int(reference["v"]), expected.v)
                self.assertEqual(
                    len(system.variables) - 1,
                    16 if operation == "add" else 10,
                )
                self.assertEqual(
                    system.constraint_count,
                    14 if operation == "add" else 9,
                )
                self.assertEqual(
                    system.witness_value(result_variables.u), expected.u
                )
                self.assertEqual(
                    system.witness_value(result_variables.v), expected.v
                )
                self.assert_system_matches_reference(name, system, reference)

    def test_invalid_operation_input_and_inconsistent_intermediate(self) -> None:
        generator = Point(*self._generator_coordinates())
        invalid = Point(1, 1)
        system = R1CS()
        invalid_variables = constrain_spend_edwards_point_witness(
            system, invalid, "left"
        )
        generator_variables = constrain_spend_edwards_point_witness(
            system, generator, "right"
        )
        constrain_spend_edwards_point_add(
            system,
            invalid_variables,
            invalid,
            generator_variables,
            generator,
        )
        self.assert_system_matches_reference(
            "off_curve_addition", system, self.cases["off_curve_addition"], False
        )

        valid_system = R1CS()
        point_variables = constrain_spend_edwards_point_witness(
            valid_system, generator
        )
        result = constrain_spend_edwards_point_double(
            valid_system, point_variables, generator
        )
        self.assertTrue(valid_system.is_satisfied())
        reference = self.cases["generator_double"]
        self.assert_system_matches_reference(
            "generator_double", valid_system, reference
        )
        changed_variable = next(
            variable for variable in valid_system.variables
            if variable.name == "doubling/C/num"
        )
        changed_assignment = (
            valid_system.witness_value(changed_variable) + 1
        ) % SCALAR_MODULUS
        self.assertFalse(
            valid_system.is_satisfied(
                {changed_variable.index: changed_assignment}
            )
        )
        self.assertEqual(
            _local_failed_rows(
                valid_system, changed_variable.index, changed_assignment
            ),
            _reference_failed_rows(
                reference, changed_variable.index, changed_assignment
            ),
        )
        self.assertEqual(
            (result.u.index, result.v.index),
            (changed_variable.index + 1, changed_variable.index + 2),
        )

    def test_exact_non_small_order_check_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        cases = (
            ("generator", generator),
            (
                "negative_generator",
                Point(*self._negative_generator_coordinates()),
            ),
            ("twice_generator", generator + generator),
            ("identity", IDENTITY),
            ("order_two", Point(0, SCALAR_MODULUS - 1)),
            ("off_curve", Point(1, 1)),
        )
        for name, point in cases:
            with self.subTest(case=name):
                reference = self.non_small_order_cases[name]
                system = R1CS()
                point_variables = constrain_spend_edwards_point_witness(
                    system, point
                )
                if reference["synthesis_succeeded"]:
                    result_variables = constrain_spend_edwards_point_not_small_order(
                        system, point_variables, point
                    )
                    expected = point
                    for _ in range(3):
                        expected = expected + expected
                    self.assertEqual(
                        system.witness_value(result_variables.u), expected.u
                    )
                    self.assertEqual(
                        system.witness_value(result_variables.v), expected.v
                    )
                    self.assertEqual(len(system.variables) - 1, 21)
                    self.assertEqual(system.constraint_count, 20)
                else:
                    with self.assertRaises(R1CSError):
                        constrain_spend_edwards_point_not_small_order(
                            system, point_variables, point
                        )
                    self.assertEqual(len(system.variables) - 1, 20)
                    self.assertEqual(system.constraint_count, 19)
                    self.assertEqual(
                        reference["synthesis_error"], "DivisionByZero"
                    )
                self.assertEqual(
                    reference["synthesis_succeeded"],
                    any(
                        variable.name
                        == "non-small-order/check u != 0/ephemeral inverse"
                        for variable in system.variables
                    ),
                )
                self.assert_system_matches_reference(
                    name, system, reference, reference["satisfied"]
                )

    def test_non_small_order_input_validation_and_intermediate_failures(self) -> None:
        generator = Point(*self._generator_coordinates())
        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, generator)
        foreign = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            foreign, generator
        )
        for point_variables, point_witness in (
            (foreign_variables, generator),
            (variables, Point(generator.u + 1, generator.v)),
            (variables, None),
            (variables, object()),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                constrain_spend_edwards_point_not_small_order(
                    system, point_variables, point_witness  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        reference = self.non_small_order_cases["generator"]
        result = constrain_spend_edwards_point_not_small_order(
            system, variables, generator
        )
        changed = next(
            variable for variable in system.variables
            if variable.name == "non-small-order/second doubling/C/num"
        )
        replacement = (
            system.witness_value(changed) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, changed.index, replacement),
            _reference_failed_rows(reference, changed.index, replacement),
        )

        inverse = next(
            variable for variable in system.variables
            if variable.name
            == "non-small-order/check u != 0/ephemeral inverse"
        )
        inverse_replacement = (
            system.witness_value(inverse) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, inverse.index, inverse_replacement),
            _reference_failed_rows(reference, inverse.index, inverse_replacement),
        )
        self.assertEqual(result.v.index + 1, inverse.index)

    def test_exact_strict_point_representation_parity(self) -> None:
        generator = Point(*self._generator_coordinates())
        cases = (
            ("generator", generator),
            (
                "negative_generator",
                Point(*self._negative_generator_coordinates()),
            ),
            ("identity", IDENTITY),
            ("order_two", Point(0, SCALAR_MODULUS - 1)),
            ("twice_generator", generator + generator),
            ("off_curve", Point(1, 1)),
        )
        for name, point in cases:
            with self.subTest(case=name):
                reference = self.representation_cases[name]
                system = R1CS()
                point_variables = constrain_spend_edwards_point_witness(
                    system, point
                )
                bits = constrain_spend_edwards_point_repr(
                    system, point_variables, point
                )
                expected_bits = tuple(
                    (point.v >> index) & 1
                    for index in range(SCALAR_MODULUS.bit_length())
                ) + (point.u & 1,)
                self.assertEqual(len(bits), 256)
                self.assertEqual(
                    tuple(system.witness_value(bit) for bit in bits),
                    expected_bits,
                )
                self.assertTrue(all(value < 2 for value in expected_bits))
                self.assertEqual(
                    len(system.variables) - 1,
                    len(reference["variables"]),
                )
                self.assert_system_matches_reference(
                    name, system, reference, reference["satisfied"]
                )
                self.assertEqual(
                    [bit.index for bit in bits],
                    [
                        _reference_index(bit["identity"])
                        for bit in reference["bits"]
                    ],
                )
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["bits"]],
                )
                self.assertEqual(len(reference["bits"]), 256)

    def test_strict_representation_rejects_bad_inputs_and_detects_bit_changes(
        self,
    ) -> None:
        generator = Point(*self._generator_coordinates())
        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, generator)
        foreign = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            foreign, generator
        )
        for point_variables, point_witness in (
            (foreign_variables, generator),
            (variables, Point(generator.u + 1, generator.v)),
            (variables, None),
            (variables, object()),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                constrain_spend_edwards_point_repr(
                    system,
                    point_variables,
                    point_witness,  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        reference = self.representation_cases["generator"]
        bits = constrain_spend_edwards_point_repr(system, variables, generator)
        changed_bit = bits[0]
        changed_value = 1 - system.witness_value(changed_bit)
        self.assertEqual(
            _local_failed_rows(system, changed_bit.index, changed_value),
            _reference_failed_rows(reference, changed_bit.index, changed_value),
        )
        field_coordinate = variables.u
        replacement = (system.witness_value(field_coordinate) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, field_coordinate.index, replacement),
            _reference_failed_rows(reference, field_coordinate.index, replacement),
        )
        noncanonical_alias = Point(
            generator.u + SCALAR_MODULUS, generator.v
        )
        self.assertEqual(noncanonical_alias, generator)
        alias_system = R1CS()
        alias_variables = constrain_spend_edwards_point_witness(
            alias_system, noncanonical_alias
        )
        alias_bits = constrain_spend_edwards_point_repr(
            alias_system, alias_variables, noncanonical_alias
        )
        self.assertEqual(
            [alias_system.witness_value(bit) for bit in alias_bits],
            [int(bit["value"]) for bit in reference["bits"]],
        )
        self.assert_system_matches_reference(
            "generator",
            alias_system,
            reference,
        )

        noncanonical_field_bits = {
            bit.index: (SCALAR_MODULUS >> index) & 1
            for index, bit in enumerate(bits[: SCALAR_MODULUS.bit_length()])
        }
        self.assertFalse(system.is_satisfied(noncanonical_field_bits))
        self.assertEqual(
            _local_failed_rows_with_assignments(system, noncanonical_field_bits),
            _reference_failed_rows_with_assignments(
                reference, noncanonical_field_bits
            ),
        )
        self.assertEqual(len(bits), 256)

    def test_fixed_base_tables_and_all_lookup_selectors_match_bellman(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        tables = spend_fixed_base_tables(base)
        reference_tables = self.fixed_base["windows"]
        self.assertEqual(len(tables), 84)
        self.assertEqual(len(reference_tables), 84)
        for window_index, (table, reference_table) in enumerate(
            zip(tables, reference_tables, strict=True)
        ):
            with self.subTest(window=window_index):
                self.assertEqual(len(table), 8)
                self.assertEqual(len(reference_table), 8)
                self.assertEqual(
                    [(point.u, point.v) for point in table],
                    [
                        (int(point["u"]), int(point["v"]))
                        for point in reference_table
                    ],
                )

        for selector in range(8):
            name = f"selector_{selector}"
            reference = self.fixed_base_cases[name]
            system = R1CS()
            bits = allocate_spend_fixed_base_scalar_bits(
                system, selector, 3
            )
            point = constrain_spend_fixed_base_mul(
                system, bits, base
            )
            self.assertEqual(
                (system.witness_value(point.u), system.witness_value(point.v)),
                (int(reference["output_u"]), int(reference["output_v"])),
            )
            self.assert_system_matches_reference(name, system, reference)
            self.assertEqual(
                [system.witness_value(bit) for bit in bits],
                [int(bit["value"]) for bit in reference["selectors"]],
            )

    def test_fixed_base_scalar_boundaries_and_full_window_parity(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        case_scalars = {
            "scalar_0": 0,
            "scalar_1": 1,
            "scalar_7": 7,
            "scalar_8": 8,
            "scalar_9": 9,
            "scalar_63": 63,
            "scalar_64": 64,
            "scalar_65": 65,
            "scalar_511": 511,
            "scalar_512": 512,
            "scalar_513": 513,
            "u64_max": (1 << 64) - 1,
            "maximum_scalar": JUBJUB_SCALAR_MODULUS - 1,
            "all_windows_all_selectors": sum(
                ((window % 8) << (3 * window))
                for window in range(84)
            ),
        }
        for name, scalar in case_scalars.items():
            with self.subTest(case=name):
                reference = self.fixed_base_cases[name]
                bit_length = (
                    64 if name == "u64_max"
                    else 3 if name.startswith("selector_")
                    else 252
                )
                system = R1CS()
                bits = allocate_spend_fixed_base_scalar_bits(
                    system, scalar, bit_length
                )
                point = constrain_spend_fixed_base_mul(system, bits, base)
                expected = base.multiply(scalar)
                self.assertEqual(
                    (system.witness_value(point.u), system.witness_value(point.v)),
                    (expected.u, expected.v),
                )
                self.assertEqual(
                    (expected.u, expected.v),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(len(bits), len(reference["selectors"]))
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["selectors"]],
                )

    def test_fixed_base_invalid_selector_lookup_witness_and_rejection(self) -> None:
        base = Point(int(self.fixed_base["base_u"]), int(self.fixed_base["base_v"]))
        reference = self.fixed_base_cases["selector_5"]
        system = R1CS()
        bits = allocate_spend_fixed_base_scalar_bits(system, 5, 3)
        point = constrain_spend_fixed_base_mul(system, bits, base)
        self.assertEqual(
            _local_failed_rows(system, bits[0].index, 2),
            _reference_failed_rows(
                reference, bits[0].index, 2
            ),
        )
        lookup_x = next(
            variable for variable in system.variables
            if variable.name
            == "fixed base multiplication/window table lookup 0/x/num"
        )
        altered_x = (system.witness_value(lookup_x) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, lookup_x.index, altered_x),
            _reference_failed_rows(reference, lookup_x.index, altered_x),
        )
        self.assertEqual(point.u.index, lookup_x.index)

        foreign = R1CS()
        foreign_bit = allocate_spend_fixed_base_scalar_bits(foreign, 1, 1)[0]
        for bad_bits, bad_base in (
            ([foreign_bit], base),
            ([None], base),
            ([object()], base),
            ([True], object()),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                constrain_spend_fixed_base_mul(
                    system,
                    bad_bits,  # type: ignore[arg-type]
                    bad_base,  # type: ignore[arg-type]
                )
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

        unassigned_system = R1CS()
        unassigned = unassigned_system.alloc_private("unassigned bit", None)
        with self.assertRaises(R1CSError):
            constrain_spend_fixed_base_mul(
                unassigned_system, [unassigned], base
            )
        self.assertEqual(len(unassigned_system.variables), 2)
        self.assertEqual(unassigned_system.constraint_count, 0)

        for scalar, bit_length in (
            (None, 252),
            (-1, 252),
            (JUBJUB_SCALAR_MODULUS, 252),
            (1, 0),
        ):
            target = R1CS()
            with self.subTest(scalar=scalar, bit_length=bit_length):
                with self.assertRaises(R1CSError):
                    allocate_spend_fixed_base_scalar_bits(
                        target, scalar, bit_length  # type: ignore[arg-type]
                    )
                self.assertEqual(len(target.variables), 1)
                self.assertEqual(target.constraint_count, 0)

    def test_variable_base_multiplication_matches_bellman_ordered_traces(self) -> None:
        expected_scalars = {
            "generator_zero": 0,
            "generator_one": 1,
            "generator_small": 13,
            "generator_boundary_31": 31,
            "generator_boundary_32": 32,
            "generator_boundary_63": 63,
            "generator_boundary_64": 64,
            "generator_maximum_scalar": JUBJUB_SCALAR_MODULUS - 1,
            "identity_mixed": 13,
            "negative_generator_mixed": 11,
            "generator_all_zero_252": 0,
            "generator_all_one_252": (1 << 252) - 1,
        }
        for name, scalar in expected_scalars.items():
            with self.subTest(case=name):
                reference = self.variable_base_cases[name]
                base = Point(int(reference["base_u"]), int(reference["base_v"]))
                bits_values = [bool(bit["value"]) for bit in reference["scalar_bits"]]
                system = R1CS()
                base_variables = constrain_spend_edwards_point_witness(
                    system, base, "base"
                )
                bits = _allocate_boolean_bits(system, bits_values)
                result = constrain_spend_edwards_point_mul(
                    system, base_variables, base, bits
                )
                expected = base.multiply(scalar)
                self.assertEqual(
                    (system.witness_value(result.u), system.witness_value(result.v)),
                    (expected.u, expected.v),
                )
                self.assertEqual(
                    (expected.u, expected.v),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(
                    [system.witness_value(bit) for bit in bits],
                    [int(bit["value"]) for bit in reference["scalar_bits"]],
                )

    def test_variable_base_invalid_bits_and_altered_witnesses_match_bellman(self) -> None:
        name = "generator_small"
        reference = self.variable_base_cases[name]
        base = Point(int(reference["base_u"]), int(reference["base_v"]))
        system = R1CS()
        base_variables = constrain_spend_edwards_point_witness(
            system, base, "base"
        )
        bits = _allocate_boolean_bits(
            system, [bool(bit["value"]) for bit in reference["scalar_bits"]]
        )
        constrain_spend_edwards_point_mul(system, base_variables, base, bits)
        self.assertEqual(
            _local_failed_rows(system, bits[0].index, 2),
            _reference_failed_rows(reference, bits[0].index, 2),
        )
        altered_selection = next(
            variable for variable in system.variables
            if variable.name
            == "variable base multiplication/selection 1/u'/num"
        )
        changed_value = (
            system.witness_value(altered_selection) + 1
        ) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered_selection.index, changed_value),
            _reference_failed_rows(
                reference, altered_selection.index, changed_value
            ),
        )

    def test_variable_base_rejects_bad_inputs_before_mutation(self) -> None:
        base = Point(*self._generator_coordinates())
        system = R1CS()
        base_variables = constrain_spend_edwards_point_witness(system, base, "base")
        foreign = R1CS()
        foreign_bit = _allocate_boolean_bits(foreign, [True])[0]
        unassigned = system.alloc_private("unassigned bit", None)
        out_of_range = system.alloc_private("out of range bit", 2)

        invalid_inputs = (
            ([], base_variables, base),
            ([foreign_bit], base_variables, base),
            ([None], base_variables, base),
            ([object()], base_variables, base),
            ([unassigned], base_variables, base),
            ([out_of_range], base_variables, base),
            ([True], object(), base),
            ([True], base_variables, IDENTITY),
        )
        for bad_bits, bad_point, witness in invalid_inputs:
            with self.subTest(bad_bits=bad_bits, bad_point=bad_point):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_mul(
                        system,
                        bad_point,  # type: ignore[arg-type]
                        witness,
                        bad_bits,  # type: ignore[arg-type]
                    )
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    def test_signed_lookup_matches_bellman_for_all_digits_and_signs(self) -> None:
        table = tuple(
            (int(point["u"]), int(point["v"]))
            for point in self.signed_lookup["table"]
        )
        self.assertEqual(len(table), 4)
        self.assertEqual(table, _pedersen_montgomery_tables()[0][0][:4])
        for selector in range(8):
            name = f"selector_{selector}"
            reference = self.signed_lookup_cases[name]
            with self.subTest(selector=selector):
                system = R1CS()
                bits = _allocate_boolean_bits(
                    system,
                    [
                        bool(selector & 1),
                        bool(selector & 2),
                        bool(selector & 4),
                    ],
                    "selector bits",
                )
                result = constrain_spend_signed_montgomery_lookup(
                    system, bits, table, "signed lookup"
                )
                self.assertEqual(result.selected_index, selector & 3)
                self.assertEqual(result.negative, bool(selector & 4))
                self.assertEqual(
                    result.x.value, table[selector & 3][0]
                )
                expected_y = table[selector & 3][1]
                if selector & 4:
                    expected_y = -expected_y % SCALAR_MODULUS
                self.assertEqual(result.y.value, expected_y)
                self.assertEqual(
                    (
                        system._evaluate(result.x.expression, system._values),
                        system.witness_value(result.y.expression),
                    ),
                    (int(reference["output_x"]), int(reference["output_y"])),
                )
                self.assert_system_matches_reference(name, system, reference)

    def test_signed_lookup_invalid_selectors_witnesses_and_mutations(self) -> None:
        table = tuple(
            (int(point["u"]), int(point["v"]))
            for point in self.signed_lookup["table"]
        )
        reference = self.signed_lookup_cases["selector_7"]
        system = R1CS()
        bits = _allocate_boolean_bits(
            system, [True, True, True], "selector bits"
        )
        result = constrain_spend_signed_montgomery_lookup(
            system, bits, table, "signed lookup"
        )
        self.assert_system_matches_reference("selector_7", system, reference)

        self.assertEqual(
            _local_failed_rows(system, bits[2].index, 2),
            _reference_failed_rows(reference, bits[2].index, 2),
        )
        y_variable = result.y.expression
        assert isinstance(y_variable, Variable)
        replacement = (system.witness_value(y_variable) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, y_variable.index, replacement),
            _reference_failed_rows(reference, y_variable.index, replacement),
        )
        precomp = next(
            variable for variable in system.variables
            if variable.name == "signed lookup/precomp/and result"
        )
        replacement_precomp = 1 - int(system.witness_value(precomp))
        self.assertEqual(
            _local_failed_rows(system, precomp.index, replacement_precomp),
            _reference_failed_rows(reference, precomp.index, replacement_precomp),
        )

        foreign = R1CS()
        foreign_bit = _allocate_boolean_bits(foreign, [True], "foreign")[0]
        unassigned = system.alloc_private("unassigned selector", None)
        out_of_range = system.alloc_private("non-boolean selector", 2)
        invalid_calls = (
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, True], table[:3]
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, foreign_bit], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, unassigned], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, out_of_range], table
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, None], table  # type: ignore[list-item]
            ),
            lambda: constrain_spend_signed_montgomery_lookup(
                system, [True, True, True], [(SCALAR_MODULUS, 0), *table[1:]]
            ),
        )
        for call in invalid_calls:
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                call()
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

    def test_edwards_to_montgomery_coordinate_mapping(self) -> None:
        mappings = {
            case["name"]: case
            for case in self.reference["montgomery_mappings"]
        }
        for name, expected in mappings.items():
            point = Point(int(expected["edwards_u"]), int(expected["edwards_v"]))
            with self.subTest(point=name):
                mapped = spend_edwards_to_montgomery_coordinates(point)
                if expected["x"] is None:
                    self.assertIsNone(mapped)
                else:
                    self.assertEqual(
                        mapped, (int(expected["x"]), int(expected["y"]))
                    )
        with self.assertRaises(R1CSError):
            spend_edwards_to_montgomery_coordinates(Point(1, 1))

    def test_montgomery_operations_match_bellman_ordered_traces(self) -> None:
        for name, reference in self.montgomery_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                synthesis_succeeded = True
                synthesis_error = None
                converted = None
                try:
                    point = allocate_spend_montgomery_point(
                        system,
                        int(reference["input_x"]),
                        int(reference["input_y"]),
                        "montgomery point",
                    )
                    if reference["other_x"] is not None:
                        other = allocate_spend_montgomery_point(
                            system,
                            int(reference["other_x"]),
                            int(reference["other_y"]),
                            "other point",
                        )
                        point = constrain_spend_montgomery_add(
                            system, point, other, "montgomery addition"
                        )
                    if name != "add_boundary_coordinates":
                        converted = constrain_spend_montgomery_into_edwards(
                            system, point, "conversion"
                        )
                except R1CSError as error:
                    synthesis_succeeded = False
                    synthesis_error = str(error)
                self.assertEqual(
                    synthesis_succeeded, reference["synthesis_succeeded"]
                )
                expected_errors = {
                    "convert_zero_y": "u conversion",
                    "convert_x_minus_one": "v conversion",
                    "add_equal_x_opposites": "equal x coordinates",
                }
                if name in expected_errors:
                    self.assertEqual(reference["synthesis_error"], "DivisionByZero")
                    self.assertIn(expected_errors[name], synthesis_error)
                else:
                    self.assertIsNone(synthesis_error)
                self.assert_system_matches_reference(
                    name,
                    system,
                    reference,
                    expected_satisfied=reference["satisfied"],
                )
                if reference["synthesis_succeeded"]:
                    if reference["montgomery_x"] is not None:
                        self.assertEqual(
                            system.witness_value(point.x.expression)
                            if isinstance(point.x.expression, Variable)
                            else system._evaluate(point.x.expression, system._values),
                            int(reference["montgomery_x"]),
                        )
                        self.assertEqual(
                            system.witness_value(point.y.expression)
                            if isinstance(point.y.expression, Variable)
                            else system._evaluate(point.y.expression, system._values),
                            int(reference["montgomery_y"]),
                        )
                    if converted is not None:
                        self.assertEqual(
                            (system.witness_value(converted.u), system.witness_value(converted.v)),
                            (int(reference["edwards_u"]), int(reference["edwards_v"])),
                        )

    def test_montgomery_altered_witnesses_and_invalid_inputs(self) -> None:
        reference = self.montgomery_cases["add_generator_twice_generator"]
        system = R1CS()
        left = allocate_spend_montgomery_point(
            system,
            int(reference["input_x"]),
            int(reference["input_y"]),
            "montgomery point",
        )
        right = allocate_spend_montgomery_point(
            system,
            int(reference["other_x"]),
            int(reference["other_y"]),
            "other point",
        )
        result = constrain_spend_montgomery_add(
            system, left, right, "montgomery addition"
        )
        converted = constrain_spend_montgomery_into_edwards(
            system, result, "conversion"
        )
        self.assert_system_matches_reference(
            "add_generator_twice_generator", system, reference
        )
        altered = result.x.expression
        assert isinstance(altered, Variable)
        replacement = (system.witness_value(altered) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered.index, replacement),
            _reference_failed_rows(reference, altered.index, replacement),
        )
        altered_u = converted.u
        replacement_u = (system.witness_value(altered_u) + 1) % SCALAR_MODULUS
        self.assertEqual(
            _local_failed_rows(system, altered_u.index, replacement_u),
            _reference_failed_rows(reference, altered_u.index, replacement_u),
        )

        foreign = R1CS()
        foreign_point = allocate_spend_montgomery_point(foreign, 1, 2)
        unassigned = system.alloc_private("unassigned Montgomery x", None)
        unassigned_point = type(left)(
            type(left.x)(unassigned, 1), left.y
        )
        mismatched_point = type(left)(
            type(left.x)(left.x.expression, (left.x.value + 1) % SCALAR_MODULUS),
            left.y,
        )
        invalid_calls = (
            lambda: constrain_spend_montgomery_add(
                system, left, foreign_point
            ),
            lambda: constrain_spend_montgomery_into_edwards(
                system, unassigned_point
            ),
            lambda: constrain_spend_montgomery_add(
                system, mismatched_point, left
            ),
            lambda: allocate_spend_montgomery_point(
                system, SCALAR_MODULUS, 1
            ),
            lambda: allocate_spend_montgomery_point(system, None, 1),
            lambda: constrain_spend_montgomery_add(
                system, object(), left  # type: ignore[arg-type]
            ),
        )
        for call in invalid_calls:
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.assertRaises((R1CSError, TypeError)):
                call()
            self.assertEqual(len(system.variables), before_variables)
            self.assertEqual(system.constraint_count, before_rows)

    def test_pedersen_generator_windows_match_pinned_bellman_tables(self) -> None:
        local_tables = spend_pedersen_montgomery_tables()
        self.assertEqual(len(local_tables), len(self.pedersen["tables"]))
        for segment_index, (local_segment, reference_segment) in enumerate(
            zip(local_tables, self.pedersen["tables"], strict=True)
        ):
            self.assertEqual(len(local_segment), 63)
            self.assertEqual(len(reference_segment), 63)
            for window_index, (local_window, reference_window) in enumerate(
                zip(local_segment, reference_segment, strict=True)
            ):
                with self.subTest(segment=segment_index, window=window_index):
                    self.assertEqual(len(local_window), 4)
                    self.assertEqual(
                        local_window,
                        tuple(
                            (int(point["u"]), int(point["v"]))
                            for point in reference_window
                        ),
                    )

    def test_pedersen_hash_matches_complete_bellman_traces(self) -> None:
        for name, reference in self.pedersen_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                message_bits = _allocate_boolean_bits(
                    system, reference["message_bits"], "input bits"
                )
                result = constrain_spend_pedersen_hash(system, message_bits)
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(
                    (
                        system.witness_value(result.variables.u),
                        system.witness_value(result.variables.v),
                    ),
                    (int(reference["output_u"]), int(reference["output_v"])),
                )
                self.assertEqual(
                    result.witness,
                    Point(int(reference["output_u"]), int(reference["output_v"])),
                )

    def test_pedersen_altered_witnesses_fail_on_identical_rows(self) -> None:
        reference = self.pedersen_cases["alternating_multi_segment"]
        system = R1CS()
        message_bits = _allocate_boolean_bits(
            system, reference["message_bits"], "input bits"
        )
        result = constrain_spend_pedersen_hash(system, message_bits)
        self.assert_system_matches_reference(
            "alternating_multi_segment", system, reference
        )

        message_bit_index = message_bits[0].index
        invalid_boolean_value = 2
        self.assertEqual(
            _local_failed_rows(system, message_bit_index, invalid_boolean_value),
            _reference_failed_rows(reference, message_bit_index, invalid_boolean_value),
        )

        sign_bit = message_bits[2]
        sign_value = system.witness_value(sign_bit)
        self.assertIn(sign_value, (0, 1))
        self.assertEqual(
            _local_failed_rows(system, sign_bit.index, 1 - sign_value),
            _reference_failed_rows(reference, sign_bit.index, 1 - sign_value),
        )

        y_record = next(
            record
            for record in reference["variables"]
            if record["annotation"] == "pedersen hash/segment 0, window 0/y/num"
        )
        y_index = _reference_index(y_record["identity"])
        y_value = int.from_bytes(bytes.fromhex(y_record["assignment"]), "little")
        self.assertEqual(
            _local_failed_rows(system, y_index, y_value + 1),
            _reference_failed_rows(reference, y_index, y_value + 1),
        )

        lambda_record = next(
            record
            for record in reference["variables"]
            if record["annotation"]
            == "pedersen hash/addition of segment 0, window 1/lambda/num"
        )
        lambda_index = _reference_index(lambda_record["identity"])
        lambda_value = int.from_bytes(
            bytes.fromhex(lambda_record["assignment"]), "little"
        )
        self.assertEqual(
            _local_failed_rows(system, lambda_index, lambda_value + 1),
            _reference_failed_rows(reference, lambda_index, lambda_value + 1),
        )

        output_u = result.variables.u
        output_u_value = system.witness_value(output_u)
        self.assertIsNotNone(output_u_value)
        self.assertEqual(
            _local_failed_rows(system, output_u.index, output_u_value + 1),
            _reference_failed_rows(reference, output_u.index, output_u_value + 1),
        )

    def test_pedersen_invalid_bits_reject_before_mutation(self) -> None:
        system = R1CS()
        valid = system.alloc_private("valid bit", 1)
        unassigned = system.alloc_private("unassigned bit", None)
        out_of_range = system.alloc_private("out of range bit", 2)
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign bit", 0)
        invalid_arguments = (
            lambda: constrain_spend_pedersen_hash(system, (unassigned,)),
            lambda: constrain_spend_pedersen_hash(system, (out_of_range,)),
            lambda: constrain_spend_pedersen_hash(system, (foreign,)),
            lambda: constrain_spend_pedersen_hash(
                system, (valid,), personalization_bits=(True,)
            ),
            lambda: constrain_spend_pedersen_hash(system, (valid, False, 1)),  # type: ignore[arg-type]
            lambda: constrain_spend_pedersen_hash(system, (valid,) * (1128 + 1)),
        )
        for call in invalid_arguments:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    @unittest.skipUnless(
        os.environ.get("SAPLING_VALUE_COMMITMENT_REFERENCE_ONLY") == "1",
        "requires the isolated Bellman value-commitment fixture",
    )
    def test_spend_value_commitment_matches_bellman_ordered_trace(self) -> None:
        reference = self.value_commitment_cases["middle_value_high_randomness"]
        system = SpendReferenceR1CS()
        value = reference["value"]
        randomness = int(reference["randomness"])
        with patch(
            __name__ + ".constrain_spend_value_commitment",
            wraps=constrain_spend_value_commitment,
        ) as python_syntheses:
            result = constrain_spend_value_commitment(
                system, value, randomness
            )
            python_syntheses.assert_called_once()

        private_variables = [
            variable for variable in system.variables[1:]
            if variable.kind == "private"
        ]
        public_variables = [
            variable for variable in system.variables[1:]
            if variable.kind == "public"
        ]
        self.assertEqual(len(public_variables), 2)
        self.assertEqual(system.public_input_count, len(reference["inputs"]))
        self.assertEqual(
            [variable.name for variable in private_variables],
            [record["annotation"] for record in reference["variables"]],
        )
        self.assertEqual(
            [system.witness_value(variable) for variable in private_variables],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["variables"]
            ],
        )
        self.assertEqual(
            [variable.name for variable in public_variables],
            [record["annotation"] for record in reference["inputs"]],
        )
        self.assertEqual(
            [system.witness_value(variable) for variable in public_variables],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["inputs"]
            ],
        )
        self.assertEqual(
            [system.public_input_position(variable) for variable in public_variables],
            [1, 2],
        )
        self.assertEqual(
            [
                variable.name
                for variable in system.variables[1:]
            ],
            [record["annotation"] for record in reference["variables"]]
            + [record["annotation"] for record in reference["inputs"]],
        )

        self.assertEqual(system.constraint_count, len(reference["constraints"]))
        for local_row, reference_row in zip(
            system.constraints, reference["constraints"], strict=True
        ):
            with self.subTest(row=reference_row["index"]):
                self.assertEqual(local_row.label, reference_row["annotation"])
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.left.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["a"], len(reference["inputs"])
                        )
                    ),
                )
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.right.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["b"], len(reference["inputs"])
                        )
                    ),
                )
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.output.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["c"], len(reference["inputs"])
                        )
                    ),
                )

        self.assertTrue(system.is_satisfied())
        self.assertTrue(reference["satisfied"])
        self.assertEqual(
            system.public_inputs(),
            tuple(
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["inputs"]
            ),
        )
        self.assertEqual(
            (
                system.witness_value(result.commitment_variables.u),
                system.witness_value(result.commitment_variables.v),
            ),
            (int(reference["commitment_u"]), int(reference["commitment_v"])),
        )
        self.assertEqual(
            [
                system.witness_value(bit)
                for bit in result.value_bits
            ],
            [(value >> index) & 1 for index in range(64)],
        )
        self.assertEqual(
            [
                system.witness_value(bit)
                for bit in result.randomness_bits
            ],
            [(randomness >> index) & 1 for index in range(252)],
        )
        self.assertEqual(
            [
                {
                    "identity": f"Aux({bit.index - 1})",
                    "value": bool(system.witness_value(bit)),
                }
                for bit in result.value_bits
            ],
            reference["value_bits"],
        )
        self.assertEqual(
            [
                {
                    "identity": f"Aux({bit.index - 1})",
                    "value": bool(system.witness_value(bit)),
                }
                for bit in result.randomness_bits
            ],
            reference["randomness_bits"],
        )

        self.value_commitment_matrix_rows = system.constraint_count
        self.value_commitment_matrix_columns = (
            1 + system.public_input_count + len(private_variables)
        )
        self.value_commitment_matrix_fingerprint = system.matrix_fingerprint()
        self.assertEqual(self.value_commitment_matrix_rows, 1265)
        self.assertEqual(self.value_commitment_matrix_columns, 1266)
        self.assertEqual(
            self.value_commitment_matrix_fingerprint,
            "6b3c7e369962530b0bb495a07876b5745a5f233539557f6d8307bf17d9ebfda7",
        )
        self.assertEqual(
            self.value_commitment_matrix_fingerprint,
            _reference_matrix_fingerprint_with_inputs(reference),
        )
        print(
            "Spend value-commitment matrix",
            self.value_commitment_matrix_rows,
            self.value_commitment_matrix_columns,
            self.value_commitment_matrix_fingerprint,
        )

    @unittest.skipUnless(
        os.environ.get("SAPLING_VALUE_COMMITMENT_REFERENCE_ONLY") == "1",
        "requires isolated Bellman value-commitment vectors",
    )
    def test_spend_value_commitment_vectors_without_synthesis(self) -> None:
        expected_names = {
            "zero_value_zero_randomness",
            "maximum_value_zero_randomness",
            "zero_value_maximum_randomness",
        }
        self.assertEqual(set(self.value_commitment_vectors), expected_names)
        value_generator = sapling_fixed_base_generator(
            "value_commitment_value"
        )
        randomness_generator = sapling_fixed_base_generator(
            "value_commitment_randomness"
        )
        with patch(
            __name__ + ".constrain_spend_value_commitment",
            side_effect=AssertionError("vector checks must not synthesize"),
        ):
            for name, reference in self.value_commitment_vectors.items():
                with self.subTest(case=name):
                    value = reference["value"]
                    randomness = int(reference["randomness"])
                    commitment = value_generator.multiply(value) + (
                        randomness_generator.multiply(randomness)
                    )
                    self.assertEqual(
                        (commitment.u, commitment.v),
                        (
                            int(reference["commitment_u"]),
                            int(reference["commitment_v"]),
                        ),
                    )
        trace_case = self.value_commitment_cases[
            "middle_value_high_randomness"
        ]
        commitment = value_generator.multiply(trace_case["value"]) + (
            randomness_generator.multiply(int(trace_case["randomness"]))
        )
        self.assertEqual(
            (commitment.u, commitment.v),
            (int(trace_case["commitment_u"]), int(trace_case["commitment_v"])),
        )

    @unittest.skipUnless(
        os.environ.get("SAPLING_VALUE_COMMITMENT_REFERENCE_ONLY") == "1",
        "requires the isolated value-commitment input",
    )
    def test_spend_value_commitment_rejects_invalid_inputs_before_mutation(
        self,
    ) -> None:
        invalid_values = (
            (-1, 0),
            (1 << 64, 0),
            (True, 0),
            (None, 0),
            (0, -1),
            (0, JUBJUB_SCALAR_MODULUS),
            (0, True),
            (0, None),
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_spend_fixed_base_mul",
            side_effect=AssertionError("invalid input reached synthesis"),
        ) as fixed_base_syntheses:
            for value, randomness in invalid_values:
                system = SpendReferenceR1CS()
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.subTest(value=value, randomness=randomness):
                    with self.assertRaises((R1CSError, TypeError)):
                        constrain_spend_value_commitment(
                            system, value, randomness
                        )
                    self.assertEqual(len(system.variables), before_variables)
                    self.assertEqual(system.constraint_count, before_rows)
            fixed_base_syntheses.assert_not_called()

        system = R1CS()
        with self.assertRaises(R1CSError):
            constrain_spend_value_commitment(system, 1, 1)
        self.assertEqual(len(system.variables), 1)
        self.assertEqual(system.constraint_count, 0)

        nonfresh_system = SpendReferenceR1CS()
        nonfresh_system.alloc_private("prior allocation", 0)
        before_variables = len(nonfresh_system.variables)
        with self.assertRaises(R1CSError):
            constrain_spend_value_commitment(nonfresh_system, 1, 1)
        self.assertEqual(len(nonfresh_system.variables), before_variables)
        self.assertEqual(nonfresh_system.constraint_count, 0)

    def test_note_commitment_matches_complete_bellman_traces(self) -> None:
        diversifiers = [
            tuple(case["diversifier"])
            for case in self.note_commitment_cases.values()
        ]
        self.assertTrue(all(len(diversifier) == 11 for diversifier in diversifiers))
        self.assertEqual(len(set(diversifiers)), len(diversifiers))
        randomness_base = sapling_fixed_base_generator(
            "note_commitment_randomness"
        )
        self.assertEqual(
            (randomness_base.u, randomness_base.v),
            (
                int(self.note_commitment["randomness_base"]["u"]),
                int(self.note_commitment["randomness_base"]["v"]),
            ),
        )
        for name, reference in self.note_commitment_cases.items():
            with self.subTest(case=name):
                system = R1CS()
                g_d_witness = Point(int(reference["g_d_u"]), int(reference["g_d_v"]))
                pk_d_witness = Point(
                    int(reference["pk_d_u"]), int(reference["pk_d_v"])
                )
                g_d_variables = constrain_spend_edwards_point_witness(
                    system, g_d_witness, "input g_d"
                )
                pk_d_variables = constrain_spend_edwards_point_witness(
                    system, pk_d_witness, "input pk_d"
                )
                rcm = sum(
                    int(bit) << index
                    for index, bit in enumerate(reference["rcm_bits"])
                )
                result = constrain_spend_note_commitment(
                    system,
                    reference["value"],
                    g_d_variables,
                    g_d_witness,
                    pk_d_variables,
                    pk_d_witness,
                    rcm,
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(reference["note_bit_count"], 576)
                self.assertEqual(len(result.note_contents), 576)
                self.assertEqual(
                    (
                        system.witness_value(result.note_hash.variables.u),
                        system.witness_value(result.note_hash.variables.v),
                    ),
                    (int(reference["hash_u"]), int(reference["hash_v"])),
                )
                self.assertEqual(
                    (
                        system.witness_value(result.commitment_variables.u),
                        system.witness_value(result.commitment_variables.v),
                    ),
                    (
                        int(reference["commitment_u"]),
                        int(reference["commitment_v"]),
                    ),
                )
                self.assertEqual(
                    result.commitment_witness,
                    Point(
                        int(reference["commitment_u"]),
                        int(reference["commitment_v"]),
                    ),
                )
                self.assertEqual(
                    [system.witness_value(bit) for bit in result.value_bits],
                    [(reference["value"] >> index) & 1 for index in range(64)],
                )

    def test_note_commitment_altered_inputs_and_witnesses_match_bellman_rows(
        self,
    ) -> None:
        reference = self.note_commitment_cases["maximum_value_maximum_rcm"]
        system = R1CS()
        g_d_witness = Point(int(reference["g_d_u"]), int(reference["g_d_v"]))
        pk_d_witness = Point(int(reference["pk_d_u"]), int(reference["pk_d_v"]))
        g_d_variables = constrain_spend_edwards_point_witness(
            system, g_d_witness, "input g_d"
        )
        pk_d_variables = constrain_spend_edwards_point_witness(
            system, pk_d_witness, "input pk_d"
        )
        rcm = sum(
            int(bit) << index for index, bit in enumerate(reference["rcm_bits"])
        )
        result = constrain_spend_note_commitment(
            system,
            reference["value"],
            g_d_variables,
            g_d_witness,
            pk_d_variables,
            pk_d_witness,
            rcm,
        )
        self.assert_system_matches_reference(
            "maximum_value_maximum_rcm", system, reference
        )

        mutation_annotations = (
            "value commitment/value/bit 63/boolean",
            "representation of g_d/unpack u/bit 0/boolean",
            "note content hash/segment 0, window 0/y/num",
            "rcm/bit 0/boolean",
            "computation of commitment randomness/window table lookup 0/x/num",
            "randomization of note commitment/u3/num",
        )
        for annotation in mutation_annotations:
            variable = next(
                item for item in system.variables if item.name == annotation
            )
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (
                1 - assigned
                if assigned in (0, 1)
                else (assigned + 1) % SCALAR_MODULUS
            )
            with self.subTest(variable=annotation):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _reference_failed_rows(
                        reference, variable.index, replacement
                    ),
                )

        commitment_v = result.commitment_variables.v
        commitment_v_value = system.witness_value(commitment_v)
        self.assertIsNotNone(commitment_v_value)
        self.assertEqual(
            _local_failed_rows(
                system, commitment_v.index, commitment_v_value + 1
            ),
            _reference_failed_rows(
                reference, commitment_v.index, commitment_v_value + 1
            ),
        )

    def test_note_commitment_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        point = Point(
            int(self.cases["generator"]["u"]),
            int(self.cases["generator"]["v"]),
        )
        variables = constrain_spend_edwards_point_witness(
            system, point, "valid point"
        )
        foreign_system = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            foreign_system, point, "foreign point"
        )
        unassigned_u = system.alloc_private("unassigned u", None)
        unassigned_v = system.alloc_private("unassigned v", None)
        unassigned_variables = EdwardsPointWitnessVariables(
            unassigned_u, unassigned_v
        )
        invalid_calls = (
            lambda: constrain_spend_note_commitment(
                system, -1, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1 << 64, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, True, variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point, None
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, None, variables, point, 0  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point, -1
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, variables, point,
                JUBJUB_SCALAR_MODULUS,
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, foreign_variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, point, foreign_variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, unassigned_variables, point, variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, variables, Point(point.u + 1, point.v), variables, point, 0
            ),
            lambda: constrain_spend_note_commitment(
                system, 1, object(), point, variables, point, 0  # type: ignore[arg-type]
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

    def test_merkle_authentication_matches_bellman_ordered_traces(self) -> None:
        for name, reference in self.merkle_authentication_cases.items():
            path = list(
                zip(reference["siblings"], reference["directions"], strict=True)
            )
            path = [(int(sibling), direction) for sibling, direction in path]
            with self.subTest(case=name, depth=len(path)):
                system = R1CS()
                leaf_value = int(reference["leaf"])
                leaf_variable = system.alloc_private("leaf/num", leaf_value)
                result = constrain_spend_merkle_authentication_path(
                    system, leaf_variable, leaf_value, path
                )
                self.assert_system_matches_reference(name, system, reference)
                self.assertEqual(len(result.position_bits), len(path))
                self.assertEqual(len(result.path_nodes), len(path))
                self.assertEqual(
                    [system.witness_value(bit) for bit in result.position_bits],
                    [int(direction) for direction in reference["directions"]],
                )
                self.assertEqual(
                    [system.witness_value(node) for node in result.path_nodes],
                    [int(sibling) for sibling in reference["siblings"]],
                )
                self.assertEqual(result.root_value, int(reference["root"]))
                self.assertEqual(
                    system.witness_value(result.root_variable),
                    int(reference["root"]),
                )

    def test_merkle_direction_sibling_intermediate_and_root_mutations_match(
        self,
    ) -> None:
        reference = self.merkle_authentication_cases["mixed_directions"]
        path = [
            (int(sibling), direction)
            for sibling, direction in zip(
                reference["siblings"], reference["directions"], strict=True
            )
        ]
        system = R1CS()
        leaf_value = int(reference["leaf"])
        leaf_variable = system.alloc_private("leaf/num", leaf_value)
        result = constrain_spend_merkle_authentication_path(
            system, leaf_variable, leaf_value, path
        )
        self.assert_system_matches_reference("mixed_directions", system, reference)

        mutation_annotations = (
            "merkle tree hash 0/position bit/boolean",
            "merkle tree hash 0/path element/num",
            (
                "merkle tree hash 0/conditional reversal of preimage/"
                "conditional reversal result 1/num"
            ),
            (
                "merkle tree hash 0/computation of pedersen hash/"
                "segment 0, window 0/y/num"
            ),
        )
        for annotation in mutation_annotations:
            variable = next(
                item for item in system.variables if item.name == annotation
            )
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (
                1 - assigned
                if assigned in (0, 1)
                else (assigned + 1) % SCALAR_MODULUS
            )
            with self.subTest(variable=annotation):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _reference_failed_rows(
                        reference, variable.index, replacement
                    ),
                )

        root_value = system.witness_value(result.root_variable)
        self.assertIsNotNone(root_value)
        self.assertEqual(
            _local_failed_rows(
                system, result.root_variable.index, root_value + 1
            ),
            _reference_failed_rows(
                reference, result.root_variable.index, root_value + 1
            ),
        )

    def test_merkle_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        system.alloc_private("existing", 0)
        leaf_variable = system.alloc_private("leaf/num", 1)
        unassigned_leaf = system.alloc_private("unassigned leaf", None)
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign sibling", 1)
        invalid_calls = (
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, -1, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, SCALAR_MODULUS, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, True, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, None  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, None, 1, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, foreign, 1, []  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, unassigned_leaf, 1, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 2, []
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(None, False)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(SCALAR_MODULUS, False)]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(foreign, False)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, 0)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, None)]  # type: ignore[list-item]
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, False)] * 33
            ),
            lambda: constrain_spend_merkle_authentication_path(
                system, leaf_variable, 1, [(1, False, 2)]  # type: ignore[list-item]
            ),
        )
        for call in invalid_calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

        empty_leaf = system.alloc_private("empty leaf/num", 5)
        empty_path = constrain_spend_merkle_authentication_path(
            system, empty_leaf, 5, []
        )
        self.assertEqual(empty_path.root_value, 5)
        self.assertEqual(system.witness_value(empty_path.root_variable), 5)

    def _anchor_fixture(self, reference: dict) -> tuple[R1CS, Variable, Variable, Variable]:
        system = R1CS()
        for name in ("rk.u", "rk.v", "cv.u", "cv.v"):
            system.alloc_public(name, 1)
        anchor = system.alloc_public("anchor/input variable", int(reference["anchor"]))
        value = system.alloc_private("note value/num", int(reference["value"]))
        root = system.alloc_private("merkle root/num", int(reference["root"]))
        return system, root, value, anchor

    def test_conditional_anchor_matches_bellman_ordered_traces(self) -> None:
        for name, reference in self.conditional_anchor_cases.items():
            with self.subTest(case=name):
                system, root, value, anchor = self._anchor_fixture(reference)
                result = constrain_spend_conditional_anchor(
                    system,
                    root,
                    int(reference["root"]),
                    value,
                    int(reference["value"]),
                    anchor,
                    int(reference["anchor"]),
                )
                input_count = len(reference["inputs"]) + 1
                expected_variables = reference["inputs"] + reference["variables"]
                self.assertEqual(
                    [
                        (variable.name, variable.index)
                        for variable in system.variables[1:]
                    ],
                    [
                        (
                            record["annotation"],
                            _conditional_anchor_reference_index(
                                record["identity"], input_count
                            ),
                        )
                        for record in expected_variables
                    ],
                )
                self.assertEqual(
                    [
                        system.witness_value(variable)
                        for variable in system.variables[1:]
                    ],
                    [
                        int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                        for record in expected_variables
                    ],
                )
                self.assertEqual(
                    system.public_input_position(anchor),
                    reference["anchor_position"],
                )
                self.assertEqual(
                    system.public_inputs(),
                    tuple(
                        int.from_bytes(
                            bytes.fromhex(record["assignment"]), "little"
                        )
                        for record in reference["inputs"]
                    ),
                )
                self.assertEqual(system.constraint_count, len(reference["constraints"]))
                for local_row, reference_row in zip(
                    system.constraints, reference["constraints"], strict=True
                ):
                    with self.subTest(case=name, row=reference_row["index"]):
                        self.assertEqual(
                            local_row.label, reference_row["annotation"]
                        )
                        self.assertEqual(
                            local_row.left.terms,
                            _conditional_anchor_terms(
                                reference_row["a"], input_count
                            ),
                        )
                        self.assertEqual(
                            local_row.right.terms,
                            _conditional_anchor_terms(
                                reference_row["b"], input_count
                            ),
                        )
                        self.assertEqual(
                            local_row.output.terms,
                            _conditional_anchor_terms(
                                reference_row["c"], input_count
                            ),
                        )
                self.assertEqual(system.is_satisfied(), reference["satisfied"])
                self.assertEqual(result.conditional_anchor_variable.name, "conditional anchor/num")
                self.assertEqual(
                    system.witness_value(result.conditional_anchor_variable),
                    int(reference["anchor"]),
                )

    def test_conditional_anchor_witness_mutations_match_bellman(self) -> None:
        reference = self.conditional_anchor_cases["nonzero_mismatching_anchor"]
        system, root, value, anchor = self._anchor_fixture(reference)
        result = constrain_spend_conditional_anchor(
            system,
            root,
            int(reference["root"]),
            value,
            int(reference["value"]),
            anchor,
            int(reference["anchor"]),
        )
        for variable in (
            root,
            value,
            anchor,
            result.conditional_anchor_variable,
        ):
            assigned = system.witness_value(variable)
            self.assertIsNotNone(assigned)
            replacement = (assigned + 1) % SCALAR_MODULUS
            with self.subTest(variable=variable.name):
                self.assertEqual(
                    _local_failed_rows(system, variable.index, replacement),
                    _conditional_anchor_failed_rows(
                        reference, {variable.index: replacement}
                    ),
                )

    def test_conditional_anchor_invalid_inputs_reject_before_mutation(self) -> None:
        system = R1CS()
        prior_inputs = [
            system.alloc_public(f"prior/{index}", 1) for index in range(4)
        ]
        anchor = system.alloc_public("anchor", 7)
        value = system.alloc_private("value", 3)
        root = system.alloc_private("root", 5)
        unassigned_root = system.alloc_private("unassigned root", None)
        unassigned_value = system.alloc_private("unassigned value", None)
        unassigned_anchor_system = R1CS()
        for index in range(4):
            unassigned_anchor_system.alloc_public(f"prior/{index}", 1)
        unassigned_anchor = unassigned_anchor_system.alloc_public("anchor", None)
        unassigned_anchor_value = unassigned_anchor_system.alloc_private("value", 3)
        unassigned_anchor_root = unassigned_anchor_system.alloc_private("root", 5)
        foreign_system = R1CS()
        for index in range(6):
            foreign_system.alloc_public(f"foreign prior/{index}", 1)
        foreign_anchor = foreign_system.variables[-1]
        foreign_root = foreign_system.alloc_private("foreign root", 5)
        foreign_value = foreign_system.alloc_private("foreign value", 3)
        calls = (
            lambda: constrain_spend_conditional_anchor(
                system, None, 5, value, 3, anchor, 7  # type: ignore[arg-type]
            ),
            lambda: constrain_spend_conditional_anchor(
                system, foreign_root, 5, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, foreign_value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, foreign_anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, unassigned_root, 5, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, unassigned_value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, SCALAR_MODULUS, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, -1, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, anchor, SCALAR_MODULUS
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 6, value, 3, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 4, anchor, 7
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, anchor, 8
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, 5, value, 3, root, 5
            ),
            lambda: constrain_spend_conditional_anchor(
                system, root, True, value, 3, anchor, 7  # type: ignore[arg-type]
            ),
        )
        for call in calls:
            with self.subTest(call=call):
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                with self.assertRaises((R1CSError, TypeError)):
                    call()
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)
        before_variables = len(unassigned_anchor_system.variables)
        before_rows = unassigned_anchor_system.constraint_count
        with self.assertRaises(R1CSError):
            constrain_spend_conditional_anchor(
                unassigned_anchor_system,
                unassigned_anchor_root,
                5,
                unassigned_anchor_value,
                3,
                unassigned_anchor,
                7,
            )
        self.assertEqual(len(unassigned_anchor_system.variables), before_variables)
        self.assertEqual(
            unassigned_anchor_system.constraint_count, before_rows
        )
        self.assertEqual(prior_inputs[-1].kind, "public")

    def test_ivk_blake2s_matches_bellman_ordered_traces(self) -> None:
        name = "generator_pair"
        reference = self.ivk_blake2s_cases[name]
        system = R1CS()
        ak = Point(int(reference["ak_u"]), int(reference["ak_v"]))
        nk = Point(int(reference["nk_u"]), int(reference["nk_v"]))
        ak_variables = constrain_spend_edwards_point_witness(system, ak, "ak")
        nk_variables = constrain_spend_edwards_point_witness(system, nk, "nk")
        ak_repr_bits = constrain_spend_edwards_point_repr(
            system, ak_variables, ak, "representation of ak"
        )
        nk_repr_bits = constrain_spend_edwards_point_repr(
            system, nk_variables, nk, "representation of nk"
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            wraps=constrain_bellman_blake2s_reference,
        ) as python_syntheses:
            result = constrain_spend_ivk_blake2s(
                system, ak_repr_bits, nk_repr_bits
            )
            python_syntheses.assert_called_once()
        self.assert_ivk_system_matches_reference(name, system, reference)
        self.assertEqual(
            [
                _ivk_digest_bit_record(system, bit)
                for bit in result.digest_bits
            ],
            reference["digest_bits"],
        )
        self.assertEqual(
            [_ivk_digest_bit_record(system, bit) for bit in result.ivk_bits],
            reference["ivk_bits"],
        )
        self.assertEqual(len(result.digest_bits), 256)
        self.assertEqual(len(result.ivk_bits), 251)
        message = bytes(
            sum(
                system.witness_value(result.preimage_bits[start + offset])
                << offset
                for offset in range(8)
            )
            for start in range(0, 512, 8)
        )
        expected_digest = blake2s(
            message, digest_size=32, person=b"Zcashivk"
        ).digest()
        actual_digest = bytes(
            sum(
                _ivk_bit_value(system, result.digest_bits[start + offset]) << offset
                for offset in range(8)
            )
            for start in range(0, 256, 8)
        )
        self.assertEqual(actual_digest, expected_digest)
        expected_ivk = int.from_bytes(expected_digest, "little") & (
            (1 << 251) - 1
        )
        actual_ivk = sum(
            _ivk_bit_value(system, bit) << index
            for index, bit in enumerate(result.ivk_bits)
        )
        self.assertEqual(actual_ivk, expected_ivk)

        mutation_variables = [ak_repr_bits[0], nk_repr_bits[255]]
        digest_zero = result.digest_bits[0]
        if isinstance(digest_zero, Variable):
            mutation_variables.append(digest_zero)
        elif isinstance(digest_zero, (_NegatedBit, _BellmanNegated)):
            mutation_variables.append(digest_zero.variable)
        for variable in mutation_variables:
            with self.subTest(variable=variable.name):
                replacement = 1 - int(system.witness_value(variable))
                local_failures = _local_failed_rows_with_assignments(
                    system, {variable.index: replacement}
                )
                reference_failures = _reference_failed_rows_with_assignments(
                    reference, {variable.index: replacement}
                )
                self.assertTrue(local_failures)
                self.assertEqual(local_failures, reference_failures)

        self.ivk_matrix_fingerprint = system.matrix_fingerprint()
        self.ivk_matrix_rows = system.constraint_count
        self.ivk_matrix_columns = len(system.variables)
        print(
            "IVK matrix",
            self.ivk_matrix_rows,
            self.ivk_matrix_columns,
            self.ivk_matrix_fingerprint,
        )

    def test_ivk_first_mixing_result_annotation_matches_bellman_source(self) -> None:
        system = R1CS()
        input_word = tuple(
            system.alloc_private(f"test input bit[{index}]", index & 1)
            for index in range(32)
        )
        multieq = _BellmanMultiEq(system, "computation of ivk/final block")
        result_word = _bellman_add(
            system,
            (_constant_word(0), _constant_word(0), input_word),
            multieq,
            (
                "computation of ivk/final block/round 0/"
                "mixing invocation 1/mixing step 1"
            ),
        )
        multieq.flush()
        self.assertEqual(
            system.variables[33].name,
            (
                "computation of ivk/final block/round 0/mixing invocation 1/"
                "mixing step 1/result bit 0/boolean"
            ),
        )
        self.assertEqual(
            system.constraints[0].label,
            (
                "computation of ivk/final block/round 0/mixing invocation 1/"
                "mixing step 1/result bit 0/boolean constraint"
            ),
        )
        self.assertEqual(
            [
                variable.name
                for variable in system.variables[33:67]
            ],
            [
                (
                    "computation of ivk/final block/round 0/"
                    f"mixing invocation 1/mixing step 1/result bit {index}/boolean"
                )
                for index in range(34)
            ],
        )
        self.assertEqual(
            [
                system.witness_value(variable)
                for variable in system.variables[33:67]
            ],
            [index & 1 for index in range(32)] + [0, 0],
        )
        self.assertEqual(
            [system.witness_value(bit) for bit in result_word],
            [index & 1 for index in range(32)],
        )

    def test_ivk_xor_swaps_negated_left_operand_like_bellman(self) -> None:
        system = R1CS()
        left = system.alloc_private("negated left", 1)
        right = system.alloc_private("right", 0)
        result = _bellman_xor_bit(
            _BellmanNegated(left),
            right,
            system,
            (
                "computation of ivk/final block/round 0/"
                "mixing invocation 1/mixing step 6/xor of bit 1"
            ),
        )
        self.assertIsInstance(result, _BellmanNegated)
        row = system.constraints[-1]
        self.assertEqual(
            row.label,
            (
                "computation of ivk/final block/round 0/mixing invocation 1/"
                "mixing step 6/xor of bit 1/xor constraint"
            ),
        )
        self.assertEqual(row.left, right.lc() * 2)
        self.assertEqual(row.right, left.lc())
        self.assertEqual(
            row.output,
            left.lc() + right.lc() - result.variable.lc(),
        )

    def test_ivk_digest_vectors_match_independent_blake2s(self) -> None:
        expected_names = {
            "identity_points",
            "generator_pair",
            "negative_generator_pair",
            "raw_half_boundary",
        }
        self.assertEqual(set(self.ivk_blake2s_vectors), expected_names)
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            side_effect=AssertionError("output-vector checks must not synthesize"),
        ):
            for name, reference in self.ivk_blake2s_vectors.items():
                with self.subTest(case=name):
                    if reference["raw_half_boundary"]:
                        self.assertEqual(name, "raw_half_boundary")
                        bits = (0,) * 256 + (1,) * 256
                    else:
                        ak = Point(int(reference["ak_u"]), int(reference["ak_v"]))
                        nk = Point(int(reference["nk_u"]), int(reference["nk_v"]))
                        bits = _sapling_representation_bits(ak) + _sapling_representation_bits(nk)
                    self.assertEqual(len(bits), 512)
                    message = bytes(
                        sum(bits[start + offset] << offset for offset in range(8))
                        for start in range(0, 512, 8)
                    )
                    expected_digest = blake2s(
                        message, digest_size=32, person=b"Zcashivk"
                    ).digest()
                    self.assertEqual(
                        reference["digest_bits"],
                        [
                            bool((byte >> bit) & 1)
                            for byte in expected_digest
                            for bit in range(8)
                        ],
                    )
                    self.assertEqual(
                        reference["ivk_bits"],
                        [
                            bool(
                                (int.from_bytes(expected_digest, "little") >> index)
                                & 1
                            )
                            for index in range(251)
                        ],
                    )

    def test_ivk_blake2s_rejects_invalid_inputs_before_mutation(self) -> None:
        system = R1CS()
        valid = tuple(
            system.alloc_private(f"valid IVK input[{index}]", index & 1)
            for index in range(512)
        )
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign IVK input", 0)
        unassigned = system.alloc_private("unassigned IVK input", None)
        non_boolean = system.alloc_private("non-Boolean IVK input", 2)
        invalid_calls = (
            lambda: constrain_spend_ivk_blake2s(system, valid[:255], valid[256:]),
            lambda: constrain_spend_ivk_blake2s(system, valid[:256], valid[256:511]),
            lambda: constrain_spend_ivk_blake2s(
                system, cast(tuple[Variable, ...], None), valid[256:]
            ),
            lambda: constrain_spend_ivk_blake2s(
                system,
                valid[:256],
                cast(tuple[Variable, ...], tuple(True for _ in range(256))),
            ),
            lambda: constrain_spend_ivk_blake2s(
                system, (foreign,) + valid[1:256], valid[256:]
            ),
            lambda: constrain_spend_ivk_blake2s(
                system, (unassigned,) + valid[1:256], valid[256:]
            ),
            lambda: constrain_spend_ivk_blake2s(
                system, (non_boolean,) + valid[1:256], valid[256:]
            ),
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            side_effect=AssertionError("invalid input reached synthesis"),
        ) as python_syntheses:
            for call in invalid_calls:
                with self.subTest(call=call):
                    before_variables = len(system.variables)
                    before_rows = system.constraint_count
                    with self.assertRaises((R1CSError, TypeError)):
                        call()
                    self.assertEqual(len(system.variables), before_variables)
                    self.assertEqual(system.constraint_count, before_rows)
            python_syntheses.assert_not_called()

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_REFERENCE_ONLY") == "1",
        "requires the isolated Bellman nullifier fixture",
    )
    def test_nullifier_blake2s_matches_bellman_ordered_traces(self) -> None:
        reference = self.nullifier_blake2s_cases["generator_pair"]
        system = R1CS()
        nk = Point(int(reference["nk_u"]), int(reference["nk_v"]))
        rho = Point(int(reference["rho_u"]), int(reference["rho_v"]))
        nk_variables = constrain_spend_edwards_point_witness(system, nk, "nk")
        nk_repr_bits = constrain_spend_edwards_point_repr(
            system, nk_variables, nk, "representation of nk"
        )
        rho_variables = constrain_spend_edwards_point_witness(system, rho, "rho")
        rho_repr_bits = constrain_spend_edwards_point_repr(
            system, rho_variables, rho, "representation of rho"
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            wraps=constrain_bellman_blake2s_reference,
        ) as python_syntheses:
            result = constrain_spend_nullifier_blake2s(
                system, nk_repr_bits, rho_repr_bits
            )
            python_syntheses.assert_called_once()

        self.assertEqual(reference["inputs"], [])
        self.assertEqual(system.public_input_count, 0)
        self.assert_ivk_system_matches_reference(
            "nullifier generator_pair", system, reference
        )
        self.assertEqual(
            result.preimage_bits,
            tuple(nk_repr_bits) + tuple(rho_repr_bits),
        )
        self.assertEqual(len(result.digest_bits), 256)
        self.assertEqual(
            [_ivk_digest_bit_record(system, bit) for bit in result.digest_bits],
            reference["digest_bits"],
        )

        message = bytes(
            sum(
                system.witness_value(result.preimage_bits[start + offset])
                << offset
                for offset in range(8)
            )
            for start in range(0, 512, 8)
        )
        expected_digest = blake2s(
            message, digest_size=32, person=b"Zcash_nf"
        ).digest()
        actual_digest = bytes(
            sum(
                _ivk_bit_value(system, result.digest_bits[start + offset])
                << offset
                for offset in range(8)
            )
            for start in range(0, 256, 8)
        )
        self.assertEqual(actual_digest, expected_digest)
        self.nullifier_matrix_fingerprint = system.matrix_fingerprint()
        self.nullifier_matrix_rows = system.constraint_count
        self.nullifier_matrix_columns = len(system.variables)
        print(
            "Nullifier matrix",
            self.nullifier_matrix_rows,
            self.nullifier_matrix_columns,
            self.nullifier_matrix_fingerprint,
        )

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_MULTIPACK_REFERENCE_ONLY") == "1",
        "requires the isolated Bellman nullifier-multipacking fixture",
    )
    def test_spend_nullifier_multipacking_matches_bellman_ordered_trace(
        self,
    ) -> None:
        reference = self.nullifier_multipacking_cases["generator_pair"]
        system = SpendReferenceR1CS()
        prior_input_names = (
            "rk/u/input variable",
            "rk/v/input variable",
            "value commitment/commitment point/u/input variable",
            "value commitment/commitment point/v/input variable",
            "anchor/input variable",
        )
        for name in prior_input_names:
            system.alloc_public(name, 0)

        nk = Point(int(reference["nk_u"]), int(reference["nk_v"]))
        rho = Point(int(reference["rho_u"]), int(reference["rho_v"]))
        nk_variables = constrain_spend_edwards_point_witness(system, nk, "nk")
        nk_repr_bits = constrain_spend_edwards_point_repr(
            system, nk_variables, nk, "representation of nk"
        )
        rho_variables = constrain_spend_edwards_point_witness(system, rho, "rho")
        rho_repr_bits = constrain_spend_edwards_point_repr(
            system, rho_variables, rho, "representation of rho"
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            wraps=constrain_bellman_blake2s_reference,
        ) as python_hash_syntheses, patch(
            __name__ + ".constrain_spend_nullifier_multipacking",
            wraps=constrain_spend_nullifier_multipacking,
        ) as python_packing_syntheses:
            hash_result = constrain_spend_nullifier_blake2s(
                system, nk_repr_bits, rho_repr_bits
            )
            result = constrain_spend_nullifier_multipacking(
                system, hash_result.digest_bits
            )
            python_hash_syntheses.assert_called_once()
            python_packing_syntheses.assert_called_once()

        private_variables = [
            variable for variable in system.variables[1:]
            if variable.kind == "private"
        ]
        public_variables = [
            variable for variable in system.variables[1:]
            if variable.kind == "public"
        ]
        self.assertEqual(len(public_variables), 7)
        self.assertEqual(
            [variable.name for variable in public_variables],
            [record["annotation"] for record in reference["inputs"]],
        )
        self.assertEqual(
            [system.public_input_position(variable) for variable in public_variables],
            list(range(1, 8)),
        )
        self.assertEqual(
            [variable.name for variable in private_variables],
            [record["annotation"] for record in reference["variables"]],
        )
        self.assertEqual(
            [system.witness_value(variable) for variable in private_variables],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["variables"]
            ],
        )
        self.assertEqual(
            [
                system.witness_value(variable)
                for variable in public_variables
            ],
            [
                int.from_bytes(bytes.fromhex(record["assignment"]), "little")
                for record in reference["inputs"]
            ],
        )
        self.assertEqual(system.public_inputs(), tuple(
            int.from_bytes(bytes.fromhex(record["assignment"]), "little")
            for record in reference["inputs"]
        ))

        self.assertEqual(len(hash_result.digest_bits), 256)
        self.assertEqual(result.digest_bits, hash_result.digest_bits)
        self.assertEqual(result.chunk_sizes, (254, 2))
        self.assertEqual(result.chunk_sizes, tuple(reference["chunk_sizes"]))
        self.assertEqual(sum(result.chunk_sizes), 256)
        self.assertEqual(
            [system.public_input_position(variable) for variable in result.input_variables],
            [6, 7],
        )
        self.assertEqual(
            [system.witness_value(variable) for variable in result.input_variables],
            [int(value) for value in reference["packed_values"]],
        )
        self.assertEqual(
            [_spend_digest_bit_record(system, bit) for bit in result.digest_bits],
            reference["digest_bits"],
        )
        self.assertTrue(system.is_satisfied())
        self.assertTrue(reference["satisfied"])

        input_count = len(reference["inputs"])
        self.assertEqual(system.constraint_count, len(reference["constraints"]))
        for local_row, reference_row in zip(
            system.constraints, reference["constraints"], strict=True
        ):
            with self.subTest(row=reference_row["index"]):
                self.assertEqual(local_row.label, reference_row["annotation"])
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.left.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["a"], input_count
                        )
                    ),
                )
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.right.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["b"], input_count
                        )
                    ),
                )
                self.assertEqual(
                    _canonical_local_terms_with_inputs(system, local_row.output.terms),
                    tuple(
                        (column, int(coefficient))
                        for column, coefficient in _canonical_reference_terms_with_inputs(
                            reference_row["c"], input_count
                        )
                    ),
                )

        self.assertEqual(
            system.matrix_fingerprint(),
            _reference_matrix_fingerprint_with_inputs(reference),
        )
        self.nullifier_multipacking_matrix_rows = system.constraint_count
        self.nullifier_multipacking_matrix_columns = len(system.variables)
        self.nullifier_multipacking_matrix_fingerprint = system.matrix_fingerprint()
        print(
            "Nullifier multipacking matrix",
            self.nullifier_multipacking_matrix_rows,
            self.nullifier_multipacking_matrix_columns,
            self.nullifier_multipacking_matrix_fingerprint,
        )

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_MULTIPACK_REFERENCE_ONLY") == "1",
        "requires isolated Bellman nullifier-multipacking vectors",
    )
    def test_spend_nullifier_multipacking_vectors_without_synthesis(self) -> None:
        expected_names = {
            "all_zero",
            "all_one",
            "alternating_lsb_first",
            "capacity_boundary_bits",
        }
        self.assertEqual(set(self.nullifier_multipacking_vectors), expected_names)
        capacity = SCALAR_MODULUS.bit_length() - 1
        self.assertEqual(capacity, 254)
        with patch(
            __name__ + ".constrain_spend_nullifier_multipacking",
            side_effect=AssertionError("packing vectors must not synthesize"),
        ):
            for name, reference in self.nullifier_multipacking_vectors.items():
                with self.subTest(case=name):
                    digest_bits = reference["digest_bits"]
                    self.assertEqual(len(digest_bits), 256)
                    sizes = tuple(
                        min(capacity, len(digest_bits) - offset)
                        for offset in range(0, len(digest_bits), capacity)
                    )
                    self.assertEqual(tuple(reference["chunk_sizes"]), sizes)
                    self.assertEqual(sizes, (254, 2))
                    packed_values = [
                        sum(
                            int(bit) << bit_index
                            for bit_index, bit in enumerate(
                                digest_bits[offset : offset + chunk_size]
                            )
                        )
                        for offset, chunk_size in zip(
                            (0, capacity), sizes, strict=True
                        )
                    ]
                    self.assertEqual(
                        [int(value) for value in reference["packed_values"]],
                        packed_values,
                    )
                    self.assertTrue(
                        all(0 <= value < SCALAR_MODULUS for value in packed_values)
                    )
        boundary = self.nullifier_multipacking_vectors["capacity_boundary_bits"]
        self.assertEqual(
            [index for index, bit in enumerate(boundary["digest_bits"]) if bit],
            [253, 254, 255],
        )
        self.assertEqual(
            [int(value) for value in boundary["packed_values"]],
            [1 << 253, 3],
        )

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_MULTIPACK_REFERENCE_ONLY") == "1",
        "requires the isolated nullifier-multipacking input",
    )
    def test_spend_nullifier_multipacking_rejects_invalid_bits_before_mutation(
        self,
    ) -> None:
        system = SpendReferenceR1CS()
        for name in (
            "rk/u/input variable",
            "rk/v/input variable",
            "value commitment/commitment point/u/input variable",
            "value commitment/commitment point/v/input variable",
            "anchor/input variable",
        ):
            system.alloc_public(name, 0)
        valid = tuple(
            system.alloc_private(f"nullifier bit[{index}]", index & 1)
            for index in range(256)
        )
        foreign_system = SpendReferenceR1CS()
        foreign = foreign_system.alloc_private("foreign nullifier bit", 1)
        unassigned = system.alloc_private("unassigned nullifier bit", None)
        non_boolean = system.alloc_private("non-Boolean nullifier bit", 2)
        invalid_calls = (
            lambda: constrain_spend_nullifier_multipacking(system, valid[:255]),
            lambda: constrain_spend_nullifier_multipacking(
                system, valid + (valid[0],)
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, cast(tuple, None)
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, (foreign,) + valid[1:]
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, (unassigned,) + valid[1:]
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, (non_boolean,) + valid[1:]
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, (2,) + valid[1:]
            ),
            lambda: constrain_spend_nullifier_multipacking(
                system, (None,) + valid[1:]
            ),
        )
        with patch.object(
            system,
            "alloc_public",
            wraps=system.alloc_public,
        ) as input_allocations:
            for call in invalid_calls:
                before_variables = len(system.variables)
                before_rows = system.constraint_count
                before_public_inputs = system.public_input_count
                with self.subTest(call=call):
                    with self.assertRaises((R1CSError, TypeError)):
                        call()
                    self.assertEqual(len(system.variables), before_variables)
                    self.assertEqual(system.constraint_count, before_rows)
                    self.assertEqual(system.public_input_count, before_public_inputs)
            input_allocations.assert_not_called()

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_REFERENCE_ONLY") == "1",
        "requires the isolated Bellman nullifier vectors",
    )
    def test_nullifier_digest_vectors_match_independent_blake2s(self) -> None:
        expected_names = {
            "identity_points",
            "generator_pair",
            "negative_generator_pair",
            "raw_half_boundary",
        }
        self.assertEqual(set(self.nullifier_blake2s_vectors), expected_names)
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            side_effect=AssertionError("output-vector checks must not synthesize"),
        ):
            for name, reference in self.nullifier_blake2s_vectors.items():
                with self.subTest(case=name):
                    if reference["raw_half_boundary"]:
                        self.assertEqual(name, "raw_half_boundary")
                        bits = (0,) * 256 + (1,) * 256
                    else:
                        nk = Point(int(reference["nk_u"]), int(reference["nk_v"]))
                        rho = Point(int(reference["rho_u"]), int(reference["rho_v"]))
                        bits = (
                            _sapling_representation_bits(nk)
                            + _sapling_representation_bits(rho)
                        )
                    self.assertEqual(len(bits), 512)
                    message = bytes(
                        sum(bits[start + offset] << offset for offset in range(8))
                        for start in range(0, 512, 8)
                    )
                    expected_digest = blake2s(
                        message, digest_size=32, person=b"Zcash_nf"
                    ).digest()
                    self.assertEqual(
                        reference["digest_bits"],
                        [
                            bool((byte >> bit) & 1)
                            for byte in expected_digest
                            for bit in range(8)
                        ],
                    )

    @unittest.skipUnless(
        os.environ.get("SAPLING_NULLIFIER_REFERENCE_ONLY") == "1",
        "requires the isolated Bellman nullifier fixture",
    )
    def test_nullifier_blake2s_rejects_invalid_inputs_before_mutation(self) -> None:
        system = R1CS()
        valid = tuple(
            system.alloc_private(f"valid nullifier input[{index}]", index & 1)
            for index in range(512)
        )
        foreign_system = R1CS()
        foreign = foreign_system.alloc_private("foreign nullifier input", 0)
        unassigned = system.alloc_private("unassigned nullifier input", None)
        non_boolean = system.alloc_private("non-Boolean nullifier input", 2)
        invalid_calls = (
            lambda: constrain_spend_nullifier_blake2s(
                system, valid[:255], valid[256:]
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system, valid[:256], valid[256:511]
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system, cast(tuple[Variable, ...], None), valid[256:]
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system,
                valid[:256],
                cast(tuple[Variable, ...], tuple(True for _ in range(256))),
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system, (foreign,) + valid[1:256], valid[256:]
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system, (unassigned,) + valid[1:256], valid[256:]
            ),
            lambda: constrain_spend_nullifier_blake2s(
                system, (non_boolean,) + valid[1:256], valid[256:]
            ),
        )
        with patch.object(
            sapling_spend_reference_port,
            "constrain_bellman_blake2s_reference",
            side_effect=AssertionError("invalid input reached synthesis"),
        ) as python_syntheses:
            for call in invalid_calls:
                with self.subTest(call=call):
                    before_variables = len(system.variables)
                    before_rows = system.constraint_count
                    with self.assertRaises((R1CSError, TypeError)):
                        call()
                    self.assertEqual(len(system.variables), before_variables)
                    self.assertEqual(system.constraint_count, before_rows)
            python_syntheses.assert_not_called()

    def test_missing_foreign_and_inconsistent_point_witnesses_reject_before_mutation(
        self,
    ) -> None:
        generator = Point(*self._generator_coordinates())
        system = R1CS()
        point_variables = constrain_spend_edwards_point_witness(system, generator)
        other_system = R1CS()
        foreign_variables = constrain_spend_edwards_point_witness(
            other_system, generator
        )
        for witness, variables, target in (
            (None, point_variables, system),
            (object(), point_variables, system),
            (generator, foreign_variables, system),
            (Point(generator.u + 1, generator.v), point_variables, system),
        ):
            before_variables = len(system.variables)
            before_rows = system.constraint_count
            with self.subTest(witness=type(witness).__name__):
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_double(
                        target, variables, witness  # type: ignore[arg-type]
                    )
                self.assertEqual(len(system.variables), before_variables)
                self.assertEqual(system.constraint_count, before_rows)

        valid_variables = constrain_spend_edwards_point_witness(
            system, generator, "valid"
        )
        before_variables = len(system.variables)
        before_rows = system.constraint_count
        with self.assertRaises(R1CSError):
            constrain_spend_edwards_point_add(
                system,
                valid_variables,
                Point(generator.u + 1, generator.v),
                valid_variables,
                generator,
            )
        self.assertEqual(len(system.variables), before_variables)
        self.assertEqual(system.constraint_count, before_rows)

    def test_exact_parity_for_identity_and_generator_points(self) -> None:
        self.assert_case_matches("identity", IDENTITY)
        self.assert_case_matches("generator", Point(*self._generator_coordinates()))
        self.assert_case_matches(
            "negative_generator",
            Point(*self._negative_generator_coordinates()),
        )

    def test_invalid_assignment_is_unsatisfied_like_bellman(self) -> None:
        point = IDENTITY
        system = R1CS()
        variables = constrain_spend_edwards_point_witness(system, point)
        self.assertTrue(system.is_satisfied())
        self.assertFalse(system.is_satisfied({variables.u.index: 1}))
        off_curve_system = R1CS()
        off_curve_point = Point(1, 1)
        constrain_spend_edwards_point_witness(off_curve_system, off_curve_point)
        self.assertFalse(off_curve_system.is_satisfied())
        self.assert_case_matches(
            "off_curve", off_curve_point, expected_satisfied=False
        )

    def test_unassigned_or_malformed_witness_is_rejected_before_mutation(self) -> None:
        for invalid in (None, object()):
            system = R1CS()
            with self.subTest(witness=type(invalid).__name__):
                with self.assertRaises((R1CSError, TypeError)):
                    constrain_spend_edwards_point_witness(system, invalid)  # type: ignore[arg-type]
                self.assertEqual(len(system.variables), 1)
                self.assertEqual(system.constraint_count, 0)

    def _generator_coordinates(self) -> tuple[int, int]:
        case = self.cases["generator"]
        return int(case["u"]), int(case["v"])

    def _negative_generator_coordinates(self) -> tuple[int, int]:
        case = self.cases["negative_generator"]
        return int(case["u"]), int(case["v"])


if __name__ == "__main__":
    unittest.main()
