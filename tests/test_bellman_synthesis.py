import hashlib
import unittest
from typing import cast

from src.bellman_synthesis import (
    BellmanRecorderError,
    BellmanSynthesisRecorder,
    R1CSReferenceAdapter,
    RecorderIndex,
    RecorderLinearCombination,
    RecorderSynthesisBackend,
    RecorderVariable,
)
from src.bls12_381 import SCALAR_MODULUS
from src.jubjub import (
    FIELD_MODULUS,
    Point,
    find_group_hash,
    spending_key_base,
)
from src.jubjub import (
    SCALAR_MODULUS as JUBJUB_SCALAR_MODULUS,
)
from src.r1cs import R1CS, R1CSError
from src.sapling_gadgets import (
    SaplingOutputWitness,
    _allocate_jubjub_scalar_bits,
    _constrain_jubjub_scalar_bit,
    _constrain_jubjub_scalar_mul_accumulation,
    allocate_jubjub_point,
    allocate_unchecked_jubjub_repr,
    constrain_jubjub_add,
    constrain_jubjub_double,
    constrain_jubjub_point,
    constrain_jubjub_repr,
    constrain_jubjub_scalar_mul,
    constrain_jubjub_select,
    constrain_sapling_output,
    jubjub_add_witness,
    jubjub_double_witness,
    make_jubjub_scalar_mul_witness,
)
from src.synthesis import VariableLike
from tests.bellman_blake2s_reference import (
    bellman_bits_to_bytes,
    constrain_bellman_blake2s_reference,
)
from tests.bellman_pedersen_reference import synthesize_pedersen_hash


class BellmanSynthesisRecorderTests(unittest.TestCase):
    def test_unchecked_jubjub_repr_allocation_matches_backends(self):
        generator = spending_key_base()
        fixtures = (
            ("identity", Point(0, 1)),
            ("generator", generator),
            ("negative generator", generator.multiply(JUBJUB_SCALAR_MODULUS - 1)),
            ("zero coordinates unchecked", Point(0, 0)),
            ("field boundary unchecked", Point(FIELD_MODULUS - 1, FIELD_MODULUS - 1)),
        )
        for name, point in fixtures:
            with self.subTest(fixture=name):
                expected_bits = tuple(
                    (point.v >> index) & 1 for index in range(255)
                ) + (point.u & 1,)

                production = R1CS()
                production_start = len(production.variables)
                production_rows = production.constraint_count
                production_bits = allocate_unchecked_jubjub_repr(
                    production, "pk_d representation", point
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorder_start = len(recorder.auxiliary_variables)
                recorder_rows = recorder.constraint_count
                recorder_bits = allocate_unchecked_jubjub_repr(
                    backend, "pk_d representation", point
                )

                self.assertEqual(len(production_bits), 256)
                self.assertEqual(len(recorder_bits), 256)
                self.assertEqual(
                    len(production.variables) - production_start, 256
                )
                self.assertEqual(
                    len(recorder.auxiliary_variables) - recorder_start, 256
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production_bits),
                    tuple(variable.index.index for variable in recorder_bits),
                )
                self.assertEqual(
                    tuple(variable.name for variable in production_bits),
                    tuple(variable.name for variable in recorder_bits),
                )
                self.assertEqual(
                    tuple(
                        production.witness_value(variable)
                        for variable in production_bits
                    ),
                    expected_bits,
                )
                self.assertEqual(
                    tuple(variable.value for variable in recorder_bits),
                    expected_bits,
                )
                self.assertEqual(
                    tuple(variable.name for variable in production_bits),
                    tuple(
                        f"pk_d representation.v bit[{index}]"
                        for index in range(256)
                    ),
                )
                self.assertEqual(production.constraint_count, production_rows)
                self.assertEqual(recorder.constraint_count, recorder_rows)
                self.assertEqual(production.constraint_count, 0)
                self.assertEqual(recorder.constraint_count, 0)

    def test_unchecked_jubjub_repr_rejects_invalid_inputs_before_mutation(self):
        production = R1CS()
        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        foreign_production_variable = R1CS().alloc_private("foreign", 1)
        foreign_recorder_variable = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)

        production_before = production.serialize()
        recorder_before = recorder.serialize()
        invalid_points = (
            None,
            object(),
            foreign_production_variable,
            foreign_recorder_variable,
        )
        for point in invalid_points:
            with self.subTest(point_type=type(point).__name__):
                with self.assertRaisesRegex(TypeError, "Jubjub Point"):
                    allocate_unchecked_jubjub_repr(
                        production, "invalid", cast(Point, point)
                    )
                with self.assertRaisesRegex(TypeError, "Jubjub Point"):
                    allocate_unchecked_jubjub_repr(
                        backend, "invalid", cast(Point, point)
                    )
                self.assertEqual(production.serialize(), production_before)
                self.assertEqual(recorder.serialize(), recorder_before)

    def test_unchecked_jubjub_repr_preserves_backend_namespaces(self):
        point = spending_key_base()
        production = R1CS()
        production_bits = allocate_unchecked_jubjub_repr(
            production.namespace("outer").namespace("nested"),
            "pk_d representation",
            point,
        )

        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorder_bits = allocate_unchecked_jubjub_repr(
            recorder_backend.namespace("outer").namespace("nested"),
            "pk_d representation",
            point,
        )

        self.assertEqual(production.constraint_count, 0)
        self.assertEqual(recorder.constraint_count, 0)
        self.assertEqual(len(production_bits), 256)
        self.assertEqual(len(recorder_bits), 256)
        self.assertEqual(
            tuple(variable.index - 1 for variable in production_bits),
            tuple(variable.index.index for variable in recorder_bits),
        )
        self.assertEqual(
            tuple(variable.name for variable in production_bits),
            tuple(
                variable.name.replace("/", " ") for variable in recorder_bits
            ),
        )
        self.assertEqual(
            tuple(production.witness_value(variable) for variable in production_bits),
            tuple(variable.value for variable in recorder_bits),
        )

    def test_jubjub_membership_gadget_matches_production_matrix(self):
        point_value = spending_key_base()
        production = R1CS()
        production_point = allocate_jubjub_point(
            production, "compat point", point_value
        )
        constrain_jubjub_point(production, production_point, "compat curve")

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_point = allocate_jubjub_point(
            backend, "compat point", point_value
        )
        constrain_jubjub_point(backend, recorder_point, "compat curve")

        self.assertEqual(recorder.constraint_count, 4)
        self.assertEqual(len(recorder.auxiliary_variables), 5)
        self.assertEqual(
            tuple((variable.index.kind, variable.index.index)
                  for variable in recorder.auxiliary_variables[:2]),
            (("aux", 0), ("aux", 1)),
        )
        self.assertEqual(
            tuple(variable.index for variable in production_point),
            (1, 2),
        )
        self.assertEqual(
            tuple(variable.index.index + 1 for variable in recorder_point),
            tuple(variable.index for variable in production_point),
        )
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertEqual(
            production.matrix_fingerprint(),
            "2285a26c3911777b051fc133f62d8b2778a01fbe758c4d7bb63d0e5f153869a8",
        )
        self.assertEqual(
            tuple(variable.name for variable in production.variables),
            (
                "ONE",
                "compat point.u",
                "compat point.v",
                "compat curve u squared",
                "compat curve v squared",
                "compat curve coordinate product",
            ),
        )
        self.assertEqual(
            tuple(constraint.label for constraint in production.constraints),
            (
                "compat curve u squared multiplication",
                "compat curve v squared multiplication",
                "compat curve coordinate product multiplication",
                "compat curve twisted Edwards equation",
            ),
        )
        self.assertTrue(production.is_satisfied())
        self.assertEqual(
            tuple(variable.value for variable in recorder_point),
            (point_value.u, point_value.v),
        )
        with self.assertRaisesRegex(TypeError, "Jubjub Point or None"):
            before_invalid_recorder_allocation = recorder.serialize()
            allocate_jubjub_point(backend, "invalid", cast(Point, (1, 2)))
        self.assertEqual(
            recorder.serialize(),
            before_invalid_recorder_allocation,
        )
        self.assertEqual(
            tuple(constraint.name for constraint in recorder.constraints),
            (
                "compat curve/u squared multiplication",
                "compat curve/v squared multiplication",
                "compat curve/coordinate product multiplication",
                "compat curve/twisted Edwards equation",
            ),
        )

    def test_backend_neutral_gadget_rejects_foreign_variables_before_mutation(self):
        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        point = (
            backend.alloc_private("owned.u", 0),
            backend.alloc_private("owned.v", 1),
        )
        foreign = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 0)
        before = recorder.serialize()

        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_point(backend, (point[0], foreign))

        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            backend.multiply(foreign.lc(), 1, "foreign LC")

        self.assertEqual(recorder.serialize(), before)
        self.assertEqual(recorder.constraint_count, 0)

        production = R1CS()
        production_point = (
            production.alloc_private("owned.u", 0),
            production.alloc_private("owned.v", 1),
        )
        other_system = R1CS()
        foreign_production_variable = other_system.alloc_private("foreign", 0)
        production_before = production.serialize()

        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_point(
                production,
                (production_point[0], foreign_production_variable),
            )

        with self.assertRaisesRegex(R1CSError, "different systems"):
            production.multiply(foreign_production_variable.lc(), 1, "foreign LC")

        self.assertEqual(production.serialize(), production_before)

    def test_recorder_backend_preserves_input_one_and_namespace_order(self):
        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        public = backend.alloc_public("public", 3)
        auxiliary = backend.namespace("slice").alloc_private("auxiliary", 4)
        expression = backend.linear_combination(
            ((public, 2), (auxiliary, 1)),
            constant=5,
        )
        backend.namespace("slice").enforce_equal(
            expression,
            12,
            "linear combination",
        )

        self.assertIs(backend.one, recorder.one())
        self.assertEqual(
            tuple((item.index.kind, item.index.index, item.name)
                  for item in recorder.inputs),
            (("input", 0, "ONE"), ("input", 1, "public")),
        )
        self.assertEqual(
            tuple((item.index.kind, item.index.index, item.name)
                  for item in recorder.auxiliary_variables),
            (("aux", 0, "slice/auxiliary"),),
        )
        self.assertEqual(
            recorder.constraints[0].name,
            "slice/linear combination",
        )

    def test_jubjub_point_allocation_matches_across_backends(self):
        point_value = spending_key_base()
        production = R1CS()
        production_backend = production.namespace("outer").namespace("inner")
        production_point = allocate_jubjub_point(
            production_backend, "point", point_value
        )

        recorder = BellmanSynthesisRecorder()
        recorder_backend = RecorderSynthesisBackend(recorder)
        recorder_point = allocate_jubjub_point(
            recorder_backend.namespace("outer").namespace("inner"),
            "point",
            point_value,
        )

        self.assertEqual(
            tuple((variable.index, variable.kind, variable.name)
                  for variable in production.variables),
            (
                (0, "one", "ONE"),
                (1, "private", "outer inner point.u"),
                (2, "private", "outer inner point.v"),
            ),
        )
        self.assertEqual(
            tuple((variable.index.kind, variable.index.index, variable.name)
                  for variable in recorder.auxiliary_variables),
            (
                ("aux", 0, "outer/inner/point.u"),
                ("aux", 1, "outer/inner/point.v"),
            ),
        )
        self.assertEqual(
            tuple(variable.index.index + 1 for variable in recorder_point),
            tuple(variable.index for variable in production_point),
        )
        self.assertEqual(production.constraint_count, 0)
        self.assertEqual(recorder.constraint_count, 0)
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertEqual(
            production.matrix_fingerprint(),
            "880efe8a2dffdedc69b198304e12aa7b2519c661cd0d6541be92ce50cee4d124",
        )
        self.assertEqual(
            tuple(production._witness_value(variable)
                  for variable in production_point),
            tuple(variable.value for variable in recorder_point),
        )

        unassigned_production = R1CS()
        unassigned_local_point = allocate_jubjub_point(
            unassigned_production, "unassigned", None
        )
        unassigned_recorder = BellmanSynthesisRecorder()
        unassigned_recorded_point = allocate_jubjub_point(
            RecorderSynthesisBackend(unassigned_recorder),
            "unassigned",
            None,
        )
        self.assertEqual(
            tuple(
                unassigned_production._witness_value(variable)
                for variable in unassigned_local_point
            ),
            (None, None),
        )
        self.assertEqual(
            tuple(variable.value for variable in unassigned_recorded_point),
            (None, None),
        )
        self.assertEqual(
            unassigned_recorder.serialize_local_matrix(),
            unassigned_production.serialize_matrix(),
        )

        invalid_production = R1CS()
        invalid_recorder = BellmanSynthesisRecorder()
        invalid_backends = (
            invalid_production,
            RecorderSynthesisBackend(invalid_recorder),
        )
        before_invalid_allocations = (
            invalid_production.serialize(),
            invalid_recorder.serialize(),
        )
        for backend in invalid_backends:
            with self.assertRaisesRegex(TypeError, "Jubjub Point or None"):
                allocate_jubjub_point(backend, "invalid", cast(Point, (1, 2)))
        self.assertEqual(
            invalid_production.serialize(),
            before_invalid_allocations[0],
        )
        self.assertEqual(
            invalid_recorder.serialize(),
            before_invalid_allocations[1],
        )

    def test_jubjub_representation_matches_production_matrix(self):
        production = R1CS()
        production_point = (
            production.alloc_private("u", 1),
            production.alloc_private("v", SCALAR_MODULUS - 1),
        )
        production_bits = constrain_jubjub_repr(production, production_point)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_point = (
            backend.alloc_private("u", 1),
            backend.alloc_private("v", SCALAR_MODULUS - 1),
        )
        recorder_bits = constrain_jubjub_repr(backend, recorder_point)

        self.assertEqual(len(production_bits), 256)
        self.assertEqual(len(recorder_bits), 256)
        self.assertEqual(production.constraint_count, 776)
        self.assertEqual(recorder.constraint_count, 776)
        self.assertEqual(
            production.matrix_fingerprint(),
            "32695731f48144ff08bc2b0cce8394f7fe0f160e3cd22d71b84dbe1fdf28dda0",
        )
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertEqual(
            tuple(
                production._witness_value(variable)
                for variable in production.variables[1:]
            ),
            tuple(variable.value for variable in recorder.auxiliary_variables),
        )
        self.assertEqual(
            tuple(
                production._witness_value(variable)
                for variable in production_bits
            ),
            tuple(variable.value for variable in recorder_bits),
        )
        self.assertTrue(production.is_satisfied())

        tampered_coordinate = production_point[0]
        self.assertFalse(
            production.is_satisfied(
                {tampered_coordinate.index: 2}
            )
        )
        representation_bit = production.variables[
            next(
                variable.index
                for variable in production.variables
                if variable.name == "Jubjub representation v bit[0]"
            )
        ]
        self.assertFalse(
            production.is_satisfied(
                {representation_bit.index: 1 - int(
                    production._witness_value(representation_bit)
                )}
            )
        )

        alias_assignments = {
            variable.index: (SCALAR_MODULUS >> bit_index) & 1
            for variable in production.variables
            if variable.name.startswith("Jubjub representation v bit[")
            for bit_index in (int(variable.name.split("[")[-1][:-1]),)
        }
        self.assertFalse(production.is_satisfied(alias_assignments))

    def test_jubjub_representation_preserves_unassigned_values_and_rejects_foreign(self):
        production = R1CS()
        production_point = (
            production.alloc_private("u", None),
            production.alloc_private("v", None),
        )
        constrain_jubjub_repr(production, production_point)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_point = (
            backend.alloc_private("u", None),
            backend.alloc_private("v", None),
        )
        constrain_jubjub_repr(backend, recorder_point)

        self.assertEqual(production.constraint_count, 776)
        self.assertEqual(recorder.constraint_count, 776)
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertTrue(
            all(
                production._witness_value(variable) is None
                for variable in production.variables[1:]
            )
        )
        self.assertTrue(
            all(variable.value is None for variable in recorder.auxiliary_variables)
        )

        foreign = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)
        before = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_repr(backend, (recorder_point[0], foreign))
        self.assertEqual(recorder.serialize(), before)

    def test_jubjub_point_selection_matches_across_backends(self):
        when_true_value = spending_key_base()
        when_false_value = Point(0, 1)

        for selector_value in (0, 1):
            with self.subTest(selector=selector_value):
                selected_value = (
                    when_true_value if selector_value else when_false_value
                )
                production = R1CS()
                selector = production.alloc_private("selector", selector_value)
                true_point = allocate_jubjub_point(
                    production, "true point", when_true_value
                )
                false_point = allocate_jubjub_point(
                    production, "false point", when_false_value
                )
                selected = allocate_jubjub_point(
                    production, "selected point", selected_value
                )
                production.enforce(
                    selector,
                    selector.lc() - 1,
                    0,
                    "selector boolean",
                )
                constrain_jubjub_select(
                    production,
                    selector,
                    true_point,
                    false_point,
                    selected,
                    "select u",
                    "select v",
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_selector = backend.alloc_private(
                    "selector", selector_value
                )
                recorded_true = allocate_jubjub_point(
                    backend, "true point", when_true_value
                )
                recorded_false = allocate_jubjub_point(
                    backend, "false point", when_false_value
                )
                recorded_selected = allocate_jubjub_point(
                    backend, "selected point", selected_value
                )
                backend.enforce(
                    recorded_selector,
                    recorded_selector.lc() - 1,
                    0,
                    "selector boolean",
                )
                constrain_jubjub_select(
                    backend,
                    recorded_selector,
                    recorded_true,
                    recorded_false,
                    recorded_selected,
                    "select u",
                    "select v",
                )

                self.assertEqual(production.constraint_count, 3)
                self.assertEqual(recorder.constraint_count, 3)
                self.assertEqual(
                    production.matrix_fingerprint(),
                    "ffc4829f0e72c68da37758b7c077b8793a155658b36406ab577e61fd44b9d920",
                )
                self.assertEqual(
                    recorder.serialize_local_matrix(),
                    production.serialize_matrix(),
                )
                self.assertEqual(
                    tuple(
                        production._witness_value(variable)
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.value for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertTrue(production.is_satisfied())
                self.assertFalse(production.is_satisfied({selector.index: 2}))

                for coordinate in selected:
                    selected_coordinate = production._witness_value(coordinate)
                    if selected_coordinate is None:
                        self.fail("selected coordinate must be assigned")
                    self.assertFalse(
                        production.is_satisfied(
                            {
                                coordinate.index:
                                    (selected_coordinate + 1) % SCALAR_MODULUS
                            }
                        )
                    )

                unselected = (
                    false_point if selector_value else true_point
                )
                for coordinate in unselected:
                    unselected_coordinate = production._witness_value(coordinate)
                    if unselected_coordinate is None:
                        self.fail("unselected coordinate must be assigned")
                    self.assertTrue(
                        production.is_satisfied(
                            {
                                coordinate.index:
                                    (unselected_coordinate + 1) % SCALAR_MODULUS
                            }
                        )
                    )

    def test_jubjub_point_selection_rejects_foreign_variables_before_mutation(self):
        production = R1CS()
        selector = production.alloc_private("selector", 1)
        true_point = allocate_jubjub_point(
            production, "true", spending_key_base()
        )
        false_point = allocate_jubjub_point(production, "false", Point(0, 1))
        selected = allocate_jubjub_point(
            production, "selected", spending_key_base()
        )
        foreign = R1CS().alloc_private("foreign", 1)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_select(
                production,
                selector,
                (foreign, true_point[1]),
                false_point,
                selected,
                "select u",
                "select v",
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_selector = backend.alloc_private("selector", 1)
        recorded_true = allocate_jubjub_point(
            backend, "true", spending_key_base()
        )
        recorded_false = allocate_jubjub_point(backend, "false", Point(0, 1))
        recorded_selected = allocate_jubjub_point(
            backend, "selected", spending_key_base()
        )
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_select(
                backend,
                recorded_selector,
                (foreign_recorder, recorded_true[1]),
                recorded_false,
                recorded_selected,
                "select u",
                "select v",
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_doubling_matches_across_backends(self):
        for point_value in (spending_key_base(), Point(0, 1)):
            with self.subTest(point=point_value):
                result_value = jubjub_double_witness(point_value)
                production = R1CS()
                point = allocate_jubjub_point(
                    production, "double point", point_value
                )
                result = allocate_jubjub_point(
                    production, "double result", result_value
                )
                constrain_jubjub_double(
                    production, point, result, "double fixture"
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_point = allocate_jubjub_point(
                    backend, "double point", point_value
                )
                recorded_result = allocate_jubjub_point(
                    backend, "double result", result_value
                )
                constrain_jubjub_double(
                    backend, recorded_point, recorded_result, "double fixture"
                )

                self.assertEqual(production.constraint_count, 5)
                self.assertEqual(recorder.constraint_count, 5)
                self.assertEqual(len(production.variables), 8)
                if point_value == spending_key_base():
                    self.assertEqual(
                        production.matrix_fingerprint(),
                        "12ba0c9c8b468d3aab43719068b117d58ebc06777ee7647ae0724378e586c8d6",
                    )
                self.assertEqual(
                    recorder.serialize_local_matrix(),
                    production.serialize_matrix(),
                )
                self.assertEqual(
                    tuple(
                        production._witness_value(variable)
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.value for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertTrue(production.is_satisfied())
                self.assertEqual(
                    tuple(
                        production._witness_value(coordinate)
                        for coordinate in result
                    ),
                    (result_value.u, result_value.v),
                )
                tamper_targets = [
                    variable
                    for variable in production.variables
                    if variable.index not in (0, point[0].index, point[1].index)
                ]
                self.assertEqual(len(tamper_targets), 5)
                for coordinate in tamper_targets:
                    value = production._witness_value(coordinate)
                    if value is None:
                        self.fail("doubling witness coordinate must be assigned")
                    self.assertFalse(
                        production.is_satisfied(
                            {
                                coordinate.index:
                                    (value + 1) % SCALAR_MODULUS
                            }
                        )
                    )

    def test_jubjub_doubling_rejects_foreign_linear_combinations_before_mutation(self):
        production = R1CS()
        point = allocate_jubjub_point(
            production, "point", spending_key_base()
        )
        result = allocate_jubjub_point(
            production, "result", jubjub_double_witness(spending_key_base())
        )
        foreign_lc = R1CS().alloc_private("foreign", 1).lc()
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_double(
                production,
                (cast(VariableLike, foreign_lc), point[1]),
                result,
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_point = allocate_jubjub_point(
            backend, "point", spending_key_base()
        )
        recorded_result = allocate_jubjub_point(
            backend, "result", jubjub_double_witness(spending_key_base())
        )
        foreign_recorder_lc = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1).lc()
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_double(
                backend,
                (cast(VariableLike, foreign_recorder_lc), recorded_point[1]),
                recorded_result,
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_doubling_rejects_foreign_variables_before_mutation(self):
        production = R1CS()
        point = allocate_jubjub_point(
            production, "point", spending_key_base()
        )
        result = allocate_jubjub_point(
            production, "result", jubjub_double_witness(spending_key_base())
        )
        foreign = R1CS().alloc_private("foreign", 1)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_double(
                production, (point[0], foreign), result
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_point = allocate_jubjub_point(
            backend, "point", spending_key_base()
        )
        recorded_result = allocate_jubjub_point(
            backend, "result", jubjub_double_witness(spending_key_base())
        )
        foreign_recorded = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_double(
                backend, (recorded_point[0], foreign_recorded), recorded_result
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_addition_matches_across_backends_and_edge_cases(self):
        base = spending_key_base()
        other = find_group_hash(b"Zcash_G_", b"gadgets")
        cases = (
            ("representative", base, other),
            ("identity left", Point(0, 1), base),
            ("identity right", base, Point(0, 1)),
            ("equal", base, base),
            ("inverse", base, Point(-base.u, base.v)),
        )
        for case_name, left_value, right_value in cases:
            with self.subTest(case=case_name):
                result_value = jubjub_add_witness(left_value, right_value)
                self.assertTrue(left_value.is_in_subgroup())
                self.assertTrue(right_value.is_in_subgroup())
                self.assertTrue(result_value.is_in_subgroup())
                production = R1CS()
                left = allocate_jubjub_point(production, "left", left_value)
                right = allocate_jubjub_point(production, "right", right_value)
                result = allocate_jubjub_point(
                    production, "result", result_value
                )
                constrain_jubjub_add(
                    production, left, right, result, "addition fixture"
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_left = allocate_jubjub_point(
                    backend, "left", left_value
                )
                recorded_right = allocate_jubjub_point(
                    backend, "right", right_value
                )
                recorded_result = allocate_jubjub_point(
                    backend, "result", result_value
                )
                constrain_jubjub_add(
                    backend,
                    recorded_left,
                    recorded_right,
                    recorded_result,
                    "addition fixture",
                )

                self.assertEqual(production.constraint_count, 6)
                self.assertEqual(recorder.constraint_count, 6)
                self.assertEqual(len(production.variables), 11)
                self.assertEqual(
                    recorder.serialize_local_matrix(),
                    production.serialize_matrix(),
                )
                for production_point, recorded_point in zip(
                    (left, right, result),
                    (recorded_left, recorded_right, recorded_result),
                ):
                    self.assertEqual(
                        tuple(variable.index - 1 for variable in production_point),
                        tuple(
                            variable.index.index
                            for variable in recorded_point
                        ),
                    )
                self.assertEqual(
                    tuple(
                        production._witness_value(variable)
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.value for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertEqual(
                    tuple(
                        production._witness_value(variable)
                        for variable in result
                    ),
                    (result_value.u, result_value.v),
                )

                self.assertTrue(production.is_satisfied())

                tamper_targets = [
                    variable
                    for variable in production.variables
                    if variable.index not in (
                        0,
                        *(coordinate.index for point in (left, right) for coordinate in point),
                    )
                ]
                self.assertEqual(len(tamper_targets), 6)
                for variable in tamper_targets:
                    value = production._witness_value(variable)
                    if value is None:
                        self.fail("addition witness value must be assigned")
                    self.assertFalse(
                        production.is_satisfied(
                            {
                                variable.index:
                                    (value + 1) % SCALAR_MODULUS
                            }
                        ),
                        variable.name,
                    )
                for point in (left, right, result):
                    constrain_jubjub_point(
                        production, point, f"{case_name} curve"
                    )
                self.assertTrue(production.is_satisfied())
                self.assertEqual(
                    result_value,
                    left_value + right_value,
                )

    def test_jubjub_addition_matrix_fingerprint_is_stable(self):
        left_value = spending_key_base()
        right_value = find_group_hash(b"Zcash_G_", b"gadgets")
        result_value = jubjub_add_witness(left_value, right_value)
        production = R1CS()
        left = allocate_jubjub_point(production, "left", left_value)
        right = allocate_jubjub_point(production, "right", right_value)
        result = allocate_jubjub_point(production, "result", result_value)
        constrain_jubjub_add(
            production, left, right, result, "addition fixture"
        )
        self.assertEqual(
            production.matrix_fingerprint(),
            "b9c3cfc17d0b5201e6f4c69a10138911190b747f9c09ffcc6ee56a0fbadce39c",
        )

    def test_jubjub_addition_preserves_unassigned_witnesses_and_rejects_foreign_inputs(self):
        production = R1CS()
        production_points = tuple(
            (
                production.alloc_private(f"point[{point_index}].u", None),
                production.alloc_private(f"point[{point_index}].v", None),
            )
            for point_index in range(3)
        )
        constrain_jubjub_add(
            production,
            production_points[0],
            production_points[1],
            production_points[2],
        )
        self.assertEqual(production.constraint_count, 6)
        self.assertTrue(
            all(
                production._witness_value(variable) is None
                for variable in production.variables[1:]
            )
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_points = tuple(
            (
                backend.alloc_private(f"point[{point_index}].u", None),
                backend.alloc_private(f"point[{point_index}].v", None),
            )
            for point_index in range(3)
        )
        constrain_jubjub_add(
            backend,
            recorder_points[0],
            recorder_points[1],
            recorder_points[2],
        )
        self.assertEqual(recorder.constraint_count, 6)
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertTrue(
            all(variable.value is None for variable in recorder.auxiliary_variables)
        )

        foreign_production = R1CS().alloc_private("foreign", 1)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_add(
                production,
                (foreign_production, production_points[0][1]),
                production_points[1],
                production_points[2],
            )
        self.assertEqual(production.serialize(), before_production)

        foreign_production_lc = R1CS().alloc_private("foreign", 1).lc()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_add(
                production,
                (cast(VariableLike, foreign_production_lc), production_points[0][1]),
                production_points[1],
                production_points[2],
            )
        self.assertEqual(production.serialize(), before_production)

        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_add(
                backend,
                (foreign_recorder, recorder_points[0][1]),
                recorder_points[1],
                recorder_points[2],
            )
        self.assertEqual(recorder.serialize(), before_recorder)

        foreign_recorder_lc = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1).lc()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_add(
                backend,
                (cast(VariableLike, foreign_recorder_lc), recorder_points[0][1]),
                recorder_points[1],
                recorder_points[2],
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_scalar_bit_decomposition_matches_across_backends(self):
        width = JUBJUB_SCALAR_MODULUS.bit_length()
        cases = (
            ("zero", 0),
            ("one", 1),
            ("intermediate", 0x123456789ABCDEF),
            ("largest scalar", JUBJUB_SCALAR_MODULUS - 1),
        )
        fingerprint = None
        for case_name, scalar in cases:
            with self.subTest(case=case_name):
                expected_bits = tuple(
                    (scalar >> index) & 1 for index in range(width)
                )
                production = R1CS()
                production_bits = _allocate_jubjub_scalar_bits(
                    production, expected_bits, "scalar bit"
                )
                for index, bit in enumerate(production_bits):
                    _constrain_jubjub_scalar_bit(
                        production, bit, f"scalar bit[{index}] boolean"
                    )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_bits = _allocate_jubjub_scalar_bits(
                    backend, expected_bits, "scalar bit"
                )
                for index, bit in enumerate(recorded_bits):
                    _constrain_jubjub_scalar_bit(
                        backend, bit, f"scalar bit[{index}] boolean"
                    )

                self.assertEqual(len(production_bits), width)
                self.assertEqual(len(recorded_bits), width)
                self.assertEqual(production.constraint_count, width)
                self.assertEqual(recorder.constraint_count, width)
                self.assertEqual(len(production.variables), width + 1)
                self.assertEqual(
                    tuple(
                        production._witness_value(bit)
                        for bit in production_bits
                    ),
                    expected_bits,
                )
                self.assertEqual(
                    tuple(bit.value for bit in recorded_bits),
                    expected_bits,
                )
                self.assertEqual(
                    sum(
                        production._witness_value(bit) << index
                        for index, bit in enumerate(production_bits)
                    ),
                    scalar,
                )
                self.assertEqual(
                    recorder.serialize_local_matrix(),
                    production.serialize_matrix(),
                )
                self.assertEqual(
                    tuple(bit.index - 1 for bit in production_bits),
                    tuple(bit.index.index for bit in recorded_bits),
                )
                self.assertTrue(production.is_satisfied())
                current_fingerprint = production.matrix_fingerprint()
                if fingerprint is None:
                    fingerprint = current_fingerprint
                self.assertEqual(current_fingerprint, fingerprint)
                self.assertEqual(
                    current_fingerprint,
                    "2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467",
                )

                for bit in production_bits:
                    self.assertFalse(
                        production.is_satisfied({bit.index: 2})
                    )
                if expected_bits[0] == 0:
                    changed_bit = 1
                else:
                    changed_bit = 0
                self.assertTrue(
                    production.is_satisfied(
                        {production_bits[0].index: changed_bit}
                    )
                )

    def test_output_pk_d_boolean_checks_match_across_backends(self):
        point = spending_key_base()
        production = R1CS()
        production_scope = production.namespace("outer").namespace("nested")
        production_bits = allocate_unchecked_jubjub_repr(
            production_scope, "pk_d representation", point
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_scope = backend.namespace("outer").namespace("nested")
        recorded_bits = allocate_unchecked_jubjub_repr(
            recorder_scope, "pk_d representation", point
        )

        constraint_labels = tuple(
            f"Sapling Output note commitment pk_d representation[{index}]"
            for index in range(256)
        )
        for index, (production_bit, recorded_bit) in enumerate(
            zip(production_bits, recorded_bits)
        ):
            label = constraint_labels[index]
            _constrain_jubjub_scalar_bit(production_scope, production_bit, label)
            _constrain_jubjub_scalar_bit(recorder_scope, recorded_bit, label)

        self.assertEqual(len(production_bits), 256)
        self.assertEqual(len(recorded_bits), 256)
        self.assertEqual(production.constraint_count, 256)
        self.assertEqual(recorder.constraint_count, 256)
        self.assertEqual(
            tuple(constraint.label for constraint in production.constraints),
            tuple(f"outer nested {label}" for label in constraint_labels),
        )
        self.assertEqual(
            tuple(bit.name for bit in production_bits),
            tuple(bit.name.replace("/", " ") for bit in recorded_bits),
        )
        self.assertEqual(
            tuple(bit.index - 1 for bit in production_bits),
            tuple(bit.index.index for bit in recorded_bits),
        )
        self.assertEqual(
            tuple(production._witness_value(bit) for bit in production_bits),
            tuple(bit.value for bit in recorded_bits),
        )
        self.assertEqual(
            production.serialize_matrix(), recorder.serialize_local_matrix()
        )
        self.assertEqual(
            production.matrix_fingerprint(),
            "d7ea7fec9edd70b8333431e6cc81379702bc6b7ce37676eac784893493608168",
        )
        self.assertTrue(production.is_satisfied())
        self.assertEqual(
            sum(
                constraint.label.startswith(
                    "outer nested Sapling Output note commitment "
                    "pk_d representation["
                )
                for constraint in production.constraints
            ),
            256,
        )

        non_boolean_production = R1CS()
        invalid_production_bit = non_boolean_production.alloc_private(
            "pk_d representation.v bit[0]", 2
        )
        _constrain_jubjub_scalar_bit(
            non_boolean_production, invalid_production_bit, constraint_labels[0]
        )
        self.assertFalse(non_boolean_production.is_satisfied())

        non_boolean_recorder = BellmanSynthesisRecorder()
        non_boolean_backend = RecorderSynthesisBackend(non_boolean_recorder)
        invalid_recorded_bit = non_boolean_backend.alloc_private(
            "pk_d representation.v bit[0]", 2
        )
        _constrain_jubjub_scalar_bit(
            non_boolean_backend, invalid_recorded_bit, constraint_labels[0]
        )
        self.assertEqual(
            non_boolean_production.serialize_matrix(),
            non_boolean_recorder.serialize_local_matrix(),
        )

        foreign_production = R1CS().alloc_private("foreign pk_d bit", 0)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                production, foreign_production, "foreign pk_d bit"
            )
        self.assertEqual(production.serialize(), before_production)

        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign pk_d bit", 0)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                backend, foreign_recorder, "foreign pk_d bit"
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_output_rcm_boolean_checks_match_across_backends(self):
        bits_le = tuple((0x123456789ABCDEF >> index) & 1 for index in range(252))
        production = R1CS()
        production_scope = production.namespace("outer").namespace("nested")
        production_bits = tuple(
            production_scope.alloc_private(f"Sapling Output rcm bit[{i}]", bit)
            for i, bit in enumerate(bits_le)
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_scope = backend.namespace("outer").namespace("nested")
        recorded_bits = tuple(
            recorder_scope.alloc_private(f"Sapling Output rcm bit[{i}]", bit)
            for i, bit in enumerate(bits_le)
        )

        constraint_labels = tuple(
            f"Sapling Output note commitment rcm bit[{index}]"
            for index in range(252)
        )
        for index, (production_bit, recorded_bit) in enumerate(
            zip(production_bits, recorded_bits)
        ):
            label = constraint_labels[index]
            _constrain_jubjub_scalar_bit(production_scope, production_bit, label)
            _constrain_jubjub_scalar_bit(recorder_scope, recorded_bit, label)

        self.assertEqual(production.constraint_count, 252)
        self.assertEqual(recorder.constraint_count, 252)
        self.assertEqual(
            tuple(constraint.label for constraint in production.constraints),
            tuple(f"outer nested {label}" for label in constraint_labels),
        )
        self.assertEqual(
            tuple(bit.name for bit in production_bits),
            tuple(bit.name.replace("/", " ") for bit in recorded_bits),
        )
        self.assertEqual(
            tuple(bit.index - 1 for bit in production_bits),
            tuple(bit.index.index for bit in recorded_bits),
        )
        self.assertEqual(
            tuple(production.witness_value(bit) for bit in production_bits),
            tuple(bit.value for bit in recorded_bits),
        )
        self.assertEqual(
            production.serialize_matrix(), recorder.serialize_local_matrix()
        )
        self.assertEqual(
            production.matrix_fingerprint(),
            "2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467",
        )
        self.assertTrue(production.is_satisfied())

        invalid_production = R1CS()
        invalid_production_bit = invalid_production.alloc_private(
            "Sapling Output rcm bit[0]", 2
        )
        _constrain_jubjub_scalar_bit(
            invalid_production,
            invalid_production_bit,
            constraint_labels[0],
        )
        self.assertFalse(invalid_production.is_satisfied())

        invalid_recorder = BellmanSynthesisRecorder()
        invalid_backend = RecorderSynthesisBackend(invalid_recorder)
        invalid_recorded_bit = invalid_backend.alloc_private(
            "Sapling Output rcm bit[0]", 2
        )
        _constrain_jubjub_scalar_bit(
            invalid_backend, invalid_recorded_bit, constraint_labels[0]
        )
        self.assertEqual(
            invalid_production.serialize_matrix(),
            invalid_recorder.serialize_local_matrix(),
        )

        foreign_production = R1CS().alloc_private("foreign rcm bit", 0)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                production_scope, foreign_production, "foreign rcm bit"
            )
        self.assertEqual(production.serialize(), before_production)

        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign rcm bit", 0)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                recorder_scope, foreign_recorder, "foreign rcm bit"
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_fixed_base_scalar_boolean_checks_match_across_backends(self):
        cases = (
            (
                "value",
                64,
                "Sapling Output value commitment value multiplication",
                "0647ab54621fcd156c698b16eac2aef84b1529bd5230926f6cf570ff820d7abc",
            ),
            (
                "rcv",
                252,
                "Sapling Output value commitment randomness multiplication",
                "2f8c306e76c185c5f6d4ab2516ccf048facd32d0d2b1b5a587c202b148d77467",
            ),
        )
        for case_name, width, label, expected_fingerprint in cases:
            with self.subTest(case=case_name):
                bits_le = tuple((0x123456789ABCDEF >> i) & 1 for i in range(width))
                production = R1CS()
                production_scope = production.namespace("outer").namespace("nested")
                production_bits = tuple(
                    production_scope.alloc_private(f"{case_name} bit[{i}]", bit)
                    for i, bit in enumerate(bits_le)
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorder_scope = backend.namespace("outer").namespace("nested")
                recorded_bits = tuple(
                    recorder_scope.alloc_private(f"{case_name} bit[{i}]", bit)
                    for i, bit in enumerate(bits_le)
                )
                expected_labels = tuple(
                    f"{label} scalar bit[{index}]" for index in range(width)
                )
                for index, (production_bit, recorded_bit) in enumerate(
                    zip(production_bits, recorded_bits)
                ):
                    _constrain_jubjub_scalar_bit(
                        production_scope, production_bit, expected_labels[index]
                    )
                    _constrain_jubjub_scalar_bit(
                        recorder_scope, recorded_bit, expected_labels[index]
                    )

                self.assertEqual(production.constraint_count, width)
                self.assertEqual(recorder.constraint_count, width)
                self.assertEqual(
                    tuple(c.label for c in production.constraints),
                    tuple(f"outer nested {label}" for label in expected_labels),
                )
                self.assertEqual(
                    tuple(bit.name for bit in production_bits),
                    tuple(bit.name.replace("/", " ") for bit in recorded_bits),
                )
                self.assertEqual(
                    tuple(bit.index - 1 for bit in production_bits),
                    tuple(bit.index.index for bit in recorded_bits),
                )
                self.assertEqual(
                    tuple(production.witness_value(bit) for bit in production_bits),
                    tuple(bit.value for bit in recorded_bits),
                )
                self.assertEqual(
                    production.serialize_matrix(), recorder.serialize_local_matrix()
                )
                self.assertEqual(
                    production.matrix_fingerprint(), expected_fingerprint
                )
                self.assertTrue(production.is_satisfied())

                invalid_production = R1CS()
                invalid_bit = invalid_production.alloc_private(
                    f"{case_name} bit[0]", 2
                )
                _constrain_jubjub_scalar_bit(
                    invalid_production, invalid_bit, expected_labels[0]
                )
                self.assertFalse(invalid_production.is_satisfied())

                foreign_production = R1CS().alloc_private("foreign fixed-base bit", 0)
                before_production = production.serialize()
                with self.assertRaisesRegex(R1CSError, "does not belong"):
                    _constrain_jubjub_scalar_bit(
                        production, foreign_production, "foreign fixed-base bit"
                    )
                self.assertEqual(production.serialize(), before_production)

                foreign_recorder = RecorderSynthesisBackend(
                    BellmanSynthesisRecorder()
                ).alloc_private("foreign fixed-base bit", 0)
                before_recorder = recorder.serialize()
                with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
                    _constrain_jubjub_scalar_bit(
                        backend, foreign_recorder, "foreign fixed-base bit"
                    )
                self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_scalar_bit_slice_has_no_reconstruction_or_canonical_range_row(self):
        width = JUBJUB_SCALAR_MODULUS.bit_length()
        largest_width_value = (1 << width) - 1
        bits_le = tuple(
            (largest_width_value >> index) & 1 for index in range(width)
        )
        system = R1CS()
        bits = _allocate_jubjub_scalar_bits(system, bits_le, "width bit")
        for index, bit in enumerate(bits):
            _constrain_jubjub_scalar_bit(
                system, bit, f"width bit[{index}] boolean"
            )
        self.assertEqual(system.constraint_count, width)
        self.assertEqual(len(system.variables), width + 1)
        self.assertTrue(system.is_satisfied())
        self.assertEqual(
            sum(system._witness_value(bit) << index for index, bit in enumerate(bits)),
            largest_width_value,
        )

    def test_jubjub_scalar_bit_decomposition_preserves_unassigned_values(self):
        width = JUBJUB_SCALAR_MODULUS.bit_length()
        production = R1CS()
        production_bits = _allocate_jubjub_scalar_bits(
            production, (None,) * width, "unassigned scalar bit"
        )
        for index, bit in enumerate(production_bits):
            _constrain_jubjub_scalar_bit(
                production, bit, f"unassigned scalar bit[{index}] boolean"
            )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_bits = _allocate_jubjub_scalar_bits(
            backend, (None,) * width, "unassigned scalar bit"
        )
        for index, bit in enumerate(recorded_bits):
            _constrain_jubjub_scalar_bit(
                backend, bit, f"unassigned scalar bit[{index}] boolean"
            )

        self.assertEqual(production.constraint_count, width)
        self.assertEqual(recorder.constraint_count, width)
        self.assertTrue(
            all(production._witness_value(bit) is None for bit in production_bits)
        )
        self.assertTrue(all(bit.value is None for bit in recorded_bits))
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )

    def test_jubjub_scalar_bit_decomposition_rejects_foreign_variables_before_mutation(self):
        production = R1CS()
        production_bit = _allocate_jubjub_scalar_bits(
            production, (0,) * JUBJUB_SCALAR_MODULUS.bit_length(), "scalar bit"
        )[0]
        foreign_production = R1CS().alloc_private("foreign", 0)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                production, foreign_production, "foreign bit"
            )
        self.assertEqual(production.serialize(), before_production)
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                production, cast(VariableLike, foreign_production.lc()), "foreign LC"
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_bit = _allocate_jubjub_scalar_bits(
            backend, (0,) * JUBJUB_SCALAR_MODULUS.bit_length(), "scalar bit"
        )[0]
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 0)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                backend, foreign_recorder, "foreign bit"
            )
        self.assertEqual(recorder.serialize(), before_recorder)
        foreign_recorder_lc = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 0).lc()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_bit(
                backend,
                cast(VariableLike, foreign_recorder_lc),
                "foreign LC",
            )
        self.assertEqual(recorder.serialize(), before_recorder)
        self.assertIsNotNone(production_bit)
        self.assertIsNotNone(recorder_bit)

    def test_jubjub_scalar_accumulation_matches_backends_and_host_progression(self):
        bases = (spending_key_base(), Point(0, 1))
        scalars = (0, 1, 0xB)
        width = 4
        for base_index, base in enumerate(bases):
            for scalar in scalars:
                with self.subTest(base=base_index, scalar=scalar):
                    bits_le = tuple((scalar >> i) & 1 for i in range(width))
                    witness = make_jubjub_scalar_mul_witness(base, bits_le)
                    self.assertEqual(witness.result, base.multiply(scalar))
                    self.assertEqual(witness.selected_points[0], witness.accumulators[0])

                    expected_accumulator = Point(0, 1)
                    for index, bit in enumerate(bits_le):
                        selected = (
                            base.multiply(1 << index)
                            if bit
                            else Point(0, 1)
                        )
                        expected_accumulator = expected_accumulator + selected
                        self.assertEqual(
                            witness.accumulators[index],
                            expected_accumulator,
                        )
                    self.assertEqual(expected_accumulator, base.multiply(scalar))

                    production = R1CS()
                    production_accumulator = None
                    production_selected = []
                    for index, selected_value in enumerate(witness.selected_points):
                        selected = allocate_jubjub_point(
                            production,
                            f"scalar selected[{index}]",
                            selected_value,
                        )
                        production_selected.append(selected)
                        production_accumulator = (
                            _constrain_jubjub_scalar_mul_accumulation(
                                production,
                                production_accumulator,
                                selected,
                                witness.accumulators[index],
                                f"scalar accumulator[{index}]",
                                f"scalar accumulation[{index}]",
                            )
                        )

                    recorder = BellmanSynthesisRecorder()
                    backend = RecorderSynthesisBackend(recorder)
                    recorder_accumulator = None
                    recorder_selected = []
                    for index, selected_value in enumerate(witness.selected_points):
                        selected = allocate_jubjub_point(
                            backend,
                            f"scalar selected[{index}]",
                            selected_value,
                        )
                        recorder_selected.append(selected)
                        recorder_accumulator = (
                            _constrain_jubjub_scalar_mul_accumulation(
                                backend,
                                recorder_accumulator,
                                selected,
                                witness.accumulators[index],
                                f"scalar accumulator[{index}]",
                                f"scalar accumulation[{index}]",
                            )
                        )

                    self.assertIsNotNone(production_accumulator)
                    self.assertIsNotNone(recorder_accumulator)
                    self.assertEqual(production.constraint_count, 6 * (width - 1))
                    self.assertEqual(recorder.constraint_count, 6 * (width - 1))
                    self.assertEqual(
                        production.matrix_fingerprint(),
                        "2a095999443d2a45416b2e06c6003fcb83f736d1401f38e3dd1334867cda33a0",
                    )
                    self.assertEqual(
                        recorder.serialize_local_matrix(),
                        production.serialize_matrix(),
                    )
                    for local_point, recorded_point in zip(
                        production_selected + [production_accumulator],
                        recorder_selected + [recorder_accumulator],
                    ):
                        self.assertEqual(
                            tuple(variable.index - 1 for variable in local_point),
                            tuple(variable.index.index for variable in recorded_point),
                        )
                    self.assertEqual(
                        tuple(
                            production._witness_value(variable)
                            for variable in production.variables[1:]
                        ),
                        tuple(
                            variable.value
                            for variable in recorder.auxiliary_variables
                        ),
                    )
                    self.assertEqual(
                        tuple(
                            production._witness_value(variable)
                            for variable in production_accumulator
                        ),
                        (witness.result.u, witness.result.v),
                    )
                    self.assertTrue(production.is_satisfied())

                    intermediate_and_accumulator_coordinates = (
                        production.variables[1 + 2 * width :]
                    )
                    self.assertEqual(
                        len(intermediate_and_accumulator_coordinates),
                        6 * (width - 1),
                    )
                    for variable in intermediate_and_accumulator_coordinates:
                        assigned = production._witness_value(variable)
                        self.assertIsNotNone(assigned)
                        self.assertFalse(
                            production.is_satisfied(
                                {
                                    variable.index:
                                        (assigned + 1) % SCALAR_MODULUS
                                }
                            ),
                            variable.name,
                        )

    def test_jubjub_scalar_accumulation_preserves_unassigned_and_rejects_foreign_inputs(self):
        production = R1CS()
        production_selected = tuple(
            allocate_jubjub_point(production, f"selected[{i}]", None)
            for i in range(2)
        )
        first = _constrain_jubjub_scalar_mul_accumulation(
            production,
            None,
            production_selected[0],
            None,
            "accumulator[0]",
            "accumulation[0]",
        )
        final = _constrain_jubjub_scalar_mul_accumulation(
            production,
            first,
            production_selected[1],
            None,
            "accumulator[1]",
            "accumulation[1]",
        )
        self.assertTrue(
            all(
                production._witness_value(variable) is None
                for variable in production.variables[1:]
            )
        )

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorder_selected = tuple(
            allocate_jubjub_point(backend, f"selected[{i}]", None)
            for i in range(2)
        )
        recorder_first = _constrain_jubjub_scalar_mul_accumulation(
            backend,
            None,
            recorder_selected[0],
            None,
            "accumulator[0]",
            "accumulation[0]",
        )
        recorder_final = _constrain_jubjub_scalar_mul_accumulation(
            backend,
            recorder_first,
            recorder_selected[1],
            None,
            "accumulator[1]",
            "accumulation[1]",
        )
        self.assertTrue(
            all(variable.value is None for variable in recorder.auxiliary_variables)
        )
        self.assertEqual(
            recorder.serialize_local_matrix(),
            production.serialize_matrix(),
        )
        self.assertEqual(
            tuple(variable.name for variable in production.variables[1:]),
            tuple(variable.name for variable in recorder.auxiliary_variables),
        )
        self.assertEqual(len(final), 2)
        self.assertEqual(len(recorder_final), 2)

        before_production = production.serialize()
        with self.assertRaises(TypeError):
            _constrain_jubjub_scalar_mul_accumulation(
                production,
                first,
                production_selected[1],
                cast(Point, object()),
                "accumulator[invalid]",
                "accumulation[invalid]",
            )
        self.assertEqual(production.serialize(), before_production)
        foreign_variable = R1CS().alloc_private("foreign", 1)
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            _constrain_jubjub_scalar_mul_accumulation(
                production,
                (foreign_variable, production_selected[0][1]),
                production_selected[1],
                None,
                "accumulator[foreign]",
                "accumulation[foreign]",
            )
        self.assertEqual(production.serialize(), before_production)
        with self.assertRaises(R1CSError):
            _constrain_jubjub_scalar_mul_accumulation(
                production,
                None,
                (cast(VariableLike, foreign_variable.lc()), production_selected[0][1]),
                None,
                "accumulator[foreign]",
                "accumulation[foreign]",
            )
        self.assertEqual(production.serialize(), before_production)

        before_recorder = recorder.serialize()
        with self.assertRaises(TypeError):
            _constrain_jubjub_scalar_mul_accumulation(
                backend,
                recorder_first,
                recorder_selected[1],
                cast(Point, object()),
                "accumulator[invalid]",
                "accumulation[invalid]",
            )
        self.assertEqual(recorder.serialize(), before_recorder)
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1)
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_mul_accumulation(
                backend,
                (foreign_recorder, recorder_selected[0][1]),
                recorder_selected[1],
                None,
                "accumulator[foreign]",
                "accumulation[foreign]",
            )
        self.assertEqual(recorder.serialize(), before_recorder)
        foreign_recorder_lc = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign", 1).lc()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _constrain_jubjub_scalar_mul_accumulation(
                backend,
                None,
                (cast(VariableLike, foreign_recorder_lc), recorder_selected[0][1]),
                None,
                "accumulator[foreign]",
                "accumulation[foreign]",
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_jubjub_scalar_multiplication_matches_full_backends(self):
        width = JUBJUB_SCALAR_MODULUS.bit_length()
        generator = spending_key_base()
        identity = Point(0, 1)
        fixtures = (
            ("zero", generator, 0),
            ("one", generator, 1),
            ("representative", generator, 0x1234),
            ("maximum scalar", generator, JUBJUB_SCALAR_MODULUS - 1),
            ("identity zero", identity, 0),
            ("identity one", identity, 1),
        )
        expected_fingerprint = None
        for name, base_value, scalar in fixtures:
            with self.subTest(fixture=name):
                bits_le = tuple((scalar >> index) & 1 for index in range(width))
                witness = make_jubjub_scalar_mul_witness(base_value, bits_le)
                self.assertEqual(witness.result, base_value.multiply(scalar))
                self.assertEqual(len(witness.bases), width)
                self.assertEqual(len(witness.selected_points), width)
                self.assertEqual(len(witness.accumulators), width)
                self.assertEqual(witness.bit_values, bits_le)
                expected_bases = tuple(
                    base_value.multiply(1 << index) for index in range(width)
                )
                expected_selected = tuple(
                    expected_bases[index] if bit else identity
                    for index, bit in enumerate(bits_le)
                )
                expected_accumulators = []
                expected_accumulator = identity
                for selected_point in expected_selected:
                    expected_accumulator = expected_accumulator + selected_point
                    expected_accumulators.append(expected_accumulator)
                self.assertEqual(witness.bases, expected_bases)
                self.assertEqual(witness.selected_points, expected_selected)
                self.assertEqual(
                    witness.accumulators, tuple(expected_accumulators)
                )

                production = R1CS()
                base = allocate_jubjub_point(production, "base", base_value)
                constrain_jubjub_point(production, base, "base curve")
                production_bits = _allocate_jubjub_scalar_bits(
                    production, bits_le, "scalar bit"
                )
                production_result = constrain_jubjub_scalar_mul(
                    production, base, production_bits, witness
                )

                recorder = BellmanSynthesisRecorder()
                backend = RecorderSynthesisBackend(recorder)
                recorded_base = allocate_jubjub_point(
                    backend, "base", base_value
                )
                constrain_jubjub_point(backend, recorded_base, "base curve")
                recorder_bits = _allocate_jubjub_scalar_bits(
                    backend, bits_le, "scalar bit"
                )
                recorder_result = constrain_jubjub_scalar_mul(
                    backend, recorded_base, recorder_bits, witness
                )

                self.assertEqual(len(production_bits), 252)
                self.assertEqual(len(recorder_bits), 252)
                self.assertEqual(
                    tuple(
                        production._witness_value(bit)
                        for bit in production_bits
                    ),
                    bits_le,
                )
                self.assertEqual(
                    tuple(bit.value for bit in recorder_bits),
                    bits_le,
                )
                self.assertEqual(
                    tuple(
                        production._witness_value(point)
                        for point in production_result
                    ),
                    (witness.result.u, witness.result.v),
                )
                self.assertEqual(
                    tuple(point.value for point in recorder_result),
                    (witness.result.u, witness.result.v),
                )
                self.assertEqual(
                    recorder.serialize_local_matrix(),
                    production.serialize_matrix(),
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production_bits),
                    tuple(variable.index.index for variable in recorder_bits),
                )
                self.assertEqual(
                    tuple(variable.index - 1 for variable in production.variables[1:]),
                    tuple(
                        variable.index.index
                        for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertEqual(
                    tuple(
                        variable.name.replace("/", " ")
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.name.replace("/", " ")
                        for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertEqual(
                    tuple(
                        production._witness_value(variable)
                        for variable in production.variables[1:]
                    ),
                    tuple(
                        variable.value for variable in recorder.auxiliary_variables
                    ),
                )
                self.assertTrue(production.is_satisfied())
                self.assertEqual(
                    production.constraint_count,
                    252 + 4 + 251 * (5 + 6) + 252 * 2,
                )
                fingerprint = production.matrix_fingerprint()
                if expected_fingerprint is None:
                    expected_fingerprint = fingerprint
                self.assertEqual(fingerprint, expected_fingerprint)
                self.assertEqual(
                    fingerprint,
                    "1e53bdeacde8d6565d678691dc5a47723f9bcdf781aced9a50cf8dee94c8216f",
                )
                self.assertEqual(
                    tuple(variable.name for variable in production_bits),
                    tuple(f"scalar bit[{index}]" for index in range(width)),
                )

                if base_value != identity:
                    for bit in (
                        production_bits[0],
                        production_bits[127],
                        production_bits[-1],
                    ):
                        bit_value = production._witness_value(bit)
                        self.assertIsNotNone(bit_value)
                        self.assertFalse(
                            production.is_satisfied(
                                {bit.index: 1 - bit_value}
                            ),
                            bit.name,
                        )
                for coordinate in production_result:
                    coordinate_value = production._witness_value(coordinate)
                    self.assertIsNotNone(coordinate_value)
                    self.assertFalse(
                        production.is_satisfied(
                            {
                                coordinate.index:
                                    (coordinate_value + 1) % SCALAR_MODULUS
                            }
                        ),
                        coordinate.name,
                    )

                accumulator_variables = [
                    variable
                    for variable in production.variables
                    if "accumulator[" in variable.name
                ]
                self.assertEqual(len(accumulator_variables), 2 * (width - 1))
                for tampered_accumulator in accumulator_variables:
                    tampered_value = production._witness_value(
                        tampered_accumulator
                    )
                    self.assertIsNotNone(tampered_value)
                    self.assertFalse(
                        production.is_satisfied(
                            {
                                tampered_accumulator.index:
                                    (tampered_value + 1) % SCALAR_MODULUS
                            }
                        ),
                        tampered_accumulator.name,
                    )

    def test_jubjub_scalar_multiplication_rejects_unassigned_and_foreign_bits_before_mutation(self):
        base_value = spending_key_base()
        bits_le = (0,) * JUBJUB_SCALAR_MODULUS.bit_length()
        witness = make_jubjub_scalar_mul_witness(base_value, bits_le)

        production = R1CS()
        base = allocate_jubjub_point(production, "base", base_value)
        constrain_jubjub_point(production, base)
        unassigned_bits = _allocate_jubjub_scalar_bits(
            production, (None,) * len(bits_le), "unassigned bit"
        )
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "unassigned or invalid"):
            constrain_jubjub_scalar_mul(
                production, base, unassigned_bits, witness
            )
        self.assertEqual(production.serialize(), before_production)

        production_bits = _allocate_jubjub_scalar_bits(
            production, bits_le, "scalar bit"
        )
        foreign_production = R1CS().alloc_private("foreign bit", 0)
        before_production = production.serialize()
        with self.assertRaisesRegex(R1CSError, "does not belong"):
            constrain_jubjub_scalar_mul(
                production,
                base,
                (foreign_production,) + production_bits[1:],
                witness,
            )
        self.assertEqual(production.serialize(), before_production)
        with self.assertRaises(TypeError):
            constrain_jubjub_scalar_mul(
                production,
                base,
                (cast(VariableLike, foreign_production.lc()),)
                + production_bits[1:],
                witness,
            )
        self.assertEqual(production.serialize(), before_production)

        recorder = BellmanSynthesisRecorder()
        backend = RecorderSynthesisBackend(recorder)
        recorded_base = allocate_jubjub_point(backend, "base", base_value)
        constrain_jubjub_point(backend, recorded_base)
        unassigned_recorder_bits = _allocate_jubjub_scalar_bits(
            backend, (None,) * len(bits_le), "unassigned bit"
        )
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(R1CSError, "unassigned or invalid"):
            constrain_jubjub_scalar_mul(
                backend, recorded_base, unassigned_recorder_bits, witness
            )
        self.assertEqual(recorder.serialize(), before_recorder)

        recorder_bits = _allocate_jubjub_scalar_bits(
            backend, bits_le, "scalar bit"
        )
        foreign_recorder = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign bit", 0)
        before_recorder = recorder.serialize()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            constrain_jubjub_scalar_mul(
                backend,
                recorded_base,
                (foreign_recorder,) + recorder_bits[1:],
                witness,
            )
        self.assertEqual(recorder.serialize(), before_recorder)
        foreign_recorder_lc = RecorderSynthesisBackend(
            BellmanSynthesisRecorder()
        ).alloc_private("foreign bit", 0).lc()
        with self.assertRaises(TypeError):
            constrain_jubjub_scalar_mul(
                backend,
                recorded_base,
                (cast(VariableLike, foreign_recorder_lc),)
                + recorder_bits[1:],
                witness,
            )
        self.assertEqual(recorder.serialize(), before_recorder)

    def test_output_composition_stops_at_r1cs_type_boundary_without_mutation(self):
        recorder = BellmanSynthesisRecorder()
        adapter = R1CSReferenceAdapter(recorder)

        with self.assertRaisesRegex(TypeError, "system must be a fresh SynthesisBackend"):
            constrain_sapling_output(
                cast(R1CS, adapter), cast(SaplingOutputWitness, None)
            )

        self.assertEqual(len(recorder.inputs), 1)
        self.assertEqual(recorder.inputs[0].index, RecorderIndex("input", 0))
        self.assertEqual(recorder.auxiliary_variables, ())
        self.assertEqual(recorder.constraints, ())

    def _small_fixture(self):
        recorder = BellmanSynthesisRecorder()
        root = recorder.namespace("root")
        x = root.alloc_input("x", 7)
        y = root.namespace("nested").alloc("y", 3)
        root.enforce(
            "multiply",
            lambda lc: lc + x,
            lambda lc: lc + (2, y) - x,
            lambda lc: lc + 1,
        )
        return recorder, x, y

    def test_records_implicit_one_typed_indices_and_ordered_abc_rows(self):
        recorder, x, y = self._small_fixture()
        self.assertEqual(
            tuple((item.index, item.name) for item in recorder.inputs),
            ((recorder.one().index, "ONE"), (x.index, "root/x")),
        )
        self.assertEqual(
            (x.index.kind, x.index.index),
            ("input", 1),
        )
        self.assertEqual(
            (y.index.kind, y.index.index),
            ("aux", 0),
        )
        self.assertEqual(
            tuple((item.index.kind, item.index.index, item.name)
                  for item in recorder.auxiliary_variables),
            (("aux", 0, "root/nested/y"),),
        )
        row = recorder.constraints[0]
        self.assertEqual(row.name, "root/multiply")
        self.assertEqual(
            tuple((variable.index.kind, variable.index.index, coefficient)
                  for variable, coefficient in row.a.terms),
            (("input", 1, 1),),
        )
        self.assertEqual(
            tuple((variable.index.kind, variable.index.index, coefficient)
                  for variable, coefficient in row.b.terms),
            (
                ("aux", 0, 2),
                (
                    "input",
                    1,
                    52435875175126190479447740508185965837690552500527637822603658699938581184512,
                ),
            ),
        )
        self.assertEqual(
            tuple((variable.index.kind, variable.index.index, coefficient)
                  for variable, coefficient in row.c.terms),
            (("input", 0, 1),),
        )

    def test_canonical_serialization_and_recorder_fingerprint_are_pinned(self):
        recorder, _, _ = self._small_fixture()
        expected = (
            b'{"auxiliary_variable_count":1,"constraint_count":1,"constraints":'
            b'[{"a":[[["input",1],"1"]],"b":[[["input",1],'
            b'"52435875175126190479447740508185965837690552500527637822603658699938581184512"],'
            b'[["aux",0],"2"]],'
            b'"c":[[["input",0],"1"]]}],"field_modulus":'
            b'"52435875175126190479447740508185965837690552500527637822603658699938581184513",'
            b'"format":"zycoin-bellman-recorder-matrix-v1","input_count_including_one":2}'
        )
        self.assertEqual(recorder.serialize_matrix(), expected)
        self.assertEqual(
            recorder.matrix_fingerprint(),
            "e2df365901ff36ef01ffc1b30d84951e3428887c82c328af37c7e17a5d477e07",
        )
        self.assertEqual(
            recorder.serialize_local_matrix(),
            b'{"auxiliary_variable_count":1,"column_count":3,"constraints":'
            b'[[[[1,"1"]],[[1,"52435875175126190479447740508185965837690552500527637822603658699938581184512"],'
            b'[2,"2"]],[[0,"1"]]]],"field_modulus":'
            b'"52435875175126190479447740508185965837690552500527637822603658699938581184513",'
            b'"format":"zycoin-r1cs-matrix-v1","one_column":0,"public_input_count":1,'
            b'"variable_kinds":["one","public","private"]}',
        )
        repeated, _, _ = self._small_fixture()
        self.assertEqual(recorder.serialize(), repeated.serialize())
        self.assertEqual(recorder.serialize_matrix(), repeated.serialize_matrix())
        self.assertNotEqual(
            recorder.matrix_fingerprint(),
            hashlib.sha256(recorder.serialize_matrix()).hexdigest(),
        )
        self.assertIn(b"zycoin-bellman-recorder-matrix-v1", expected)

        renamed = BellmanSynthesisRecorder()
        renamed_root = renamed.namespace("other namespace")
        renamed_x = renamed_root.alloc_input("renamed input", 7)
        renamed_y = renamed_root.alloc("renamed auxiliary", 3)
        renamed_root.enforce(
            "renamed row",
            lambda lc: lc + renamed_x,
            lambda lc: lc + (2, renamed_y) - renamed_x,
            lambda lc: lc + 1,
        )
        self.assertNotEqual(recorder.serialize(), renamed.serialize())
        self.assertEqual(
            recorder.matrix_fingerprint(), renamed.matrix_fingerprint()
        )

    def test_interleaved_allocations_keep_independent_input_and_aux_indices(self):
        recorder = BellmanSynthesisRecorder()
        root = recorder.namespace("allocations")
        input_one = root.alloc_input("first input", 4)
        aux_zero = root.alloc("first auxiliary", 5)
        input_two = root.alloc_input("second input", 6)
        aux_one = root.alloc("second auxiliary", 7)

        self.assertEqual(
            tuple((variable.index.kind, variable.index.index) for variable in recorder.inputs),
            (("input", 0), ("input", 1), ("input", 2)),
        )
        self.assertEqual(
            tuple(
                (variable.index.kind, variable.index.index)
                for variable in recorder.auxiliary_variables
            ),
            (("aux", 0), ("aux", 1)),
        )
        self.assertEqual(recorder.one().index, RecorderIndex("input", 0))
        self.assertEqual(
            (input_one.index, aux_zero.index, input_two.index, aux_one.index),
            (
                RecorderIndex("input", 1),
                RecorderIndex("aux", 0),
                RecorderIndex("input", 2),
                RecorderIndex("aux", 1),
            ),
        )

    def test_namespace_scope_reuse_and_annotation_names_do_not_change_matrix(self):
        recorder = BellmanSynthesisRecorder()
        root = recorder.namespace("root")
        first_scope = root.namespace("shared")
        second_scope = root.namespace("shared")
        x = first_scope.alloc_input("x", 9)
        y = second_scope.alloc("y", 8)
        first_scope.enforce(
            "row",
            lambda lc: lc + x + (2, y) - y,
            lambda lc: lc + 1,
            lambda lc: lc + x,
        )

        renamed = BellmanSynthesisRecorder()
        other = renamed.namespace("different root").namespace("different scope")
        other_x = other.alloc_input("different x", 9)
        other_y = other.alloc("different y", 8)
        other.enforce(
            "different row",
            lambda lc: lc + (1, other_x) + other_y,
            lambda lc: lc + 1,
            lambda lc: lc + other_x,
        )
        self.assertEqual(recorder.matrix_fingerprint(), renamed.matrix_fingerprint())
        self.assertNotEqual(recorder.serialize(), renamed.serialize())

    def test_equivalent_linear_combinations_have_canonical_matrix_fingerprint(self):
        first = BellmanSynthesisRecorder()
        first_x = first.alloc_input("x", 0)
        first_y = first.alloc("y", 0)
        first.enforce(
            "first row",
            lambda lc: lc + first_x + (2, first_x) - first_x + (0, first_y),
            lambda lc: lc + (SCALAR_MODULUS, first_y) + 2 - 2,
            lambda lc: lc + (1, first_y) - first_y + first_x,
        )

        second = BellmanSynthesisRecorder()
        second_x = second.alloc_input("renamed x", 0)
        second.alloc("renamed y", 0)
        second.enforce(
            "second row",
            lambda lc: lc + (2, second_x),
            lambda lc: lc,
            lambda lc: lc + second_x,
        )
        self.assertEqual(first.serialize_matrix(), second.serialize_matrix())
        self.assertEqual(first.matrix_fingerprint(), second.matrix_fingerprint())
        self.assertEqual(len(first.constraints[0].a.terms), 4)
        self.assertEqual(first.constraints[0].a.terms[-1], (first_y, 0))

    def test_invalid_foreign_forged_and_noncanonical_references_fail_explicitly(self):
        recorder = BellmanSynthesisRecorder()
        variable = recorder.alloc_input("input", 1)
        foreign = BellmanSynthesisRecorder().alloc_private("foreign", 1)

        with self.assertRaisesRegex(BellmanRecorderError, "different recorders"):
            _ = variable.lc() + foreign.lc()
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            recorder.add_constraint(foreign, 1, 0, "foreign variable")
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _ = variable.lc() + (1, foreign)
        with self.assertRaisesRegex(TypeError, "expected integer"):
            recorder.add_constraint(1.0, 1, 0, "malformed expression")
        with self.assertRaisesRegex(TypeError, "coefficient must be an integer"):
            _ = variable.lc() + (True, variable)
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            recorder.linear_combination(((foreign, 1),))

        malformed = RecorderLinearCombination(
            ((variable, SCALAR_MODULUS),),
            variable._owner,
        )
        with self.assertRaisesRegex(BellmanRecorderError, "not canonical"):
            recorder.add_constraint(malformed, 1, 0, "noncanonical coefficient")

        forged = RecorderVariable(
            RecorderIndex("input", 4),
            "forged",
            1,
            variable._owner,
        )
        with self.assertRaisesRegex(BellmanRecorderError, "does not belong"):
            _ = variable.lc() + forged
        with self.assertRaisesRegex(BellmanRecorderError, "not allocated"):
            recorder.add_constraint(forged, 1, 0, "unallocated variable")

    def test_independent_multi_constraint_fixture_and_setup_query_layout(self):
        recorder = BellmanSynthesisRecorder()
        root = recorder.namespace("fixture")
        x = recorder.alloc_input("x", 5)
        a = root.alloc("a", 2)
        y = recorder.alloc_input("y", 10)
        b = root.namespace("inner").alloc("b", 3)

        root.enforce(
            "row one",
            lambda lc: lc + x + (2, a) - a + (0, b) + 3,
            lambda lc: lc + y - y + b,
            lambda lc: lc + x + b - b,
        )
        recorder.enforce(
            "row two",
            lambda lc: lc + b + y + (SCALAR_MODULUS, x),
            lambda lc: lc + 2 + 4 - 6,
            lambda lc: lc + (2, x) - x + y - y,
        )

        self.assertEqual(
            tuple((item.index.kind, item.index.index, item.name) for item in recorder.inputs),
            (
                ("input", 0, "ONE"),
                ("input", 1, "x"),
                ("input", 2, "y"),
            ),
        )
        self.assertEqual(
            tuple(
                (item.index.kind, item.index.index, item.name)
                for item in recorder.auxiliary_variables
            ),
            (("aux", 0, "fixture/a"), ("aux", 1, "fixture/inner/b")),
        )
        self.assertEqual(
            tuple(
                tuple(
                    tuple((variable.index.kind, variable.index.index, coefficient)
                          for variable, coefficient in expression.terms)
                    for expression in (row.a, row.b, row.c)
                )
                for row in recorder.constraints
            ),
            (
                (
                    (
                        ("input", 1, 1),
                        ("aux", 0, 2),
                        ("aux", 0, SCALAR_MODULUS - 1),
                        ("aux", 1, 0),
                        ("input", 0, 3),
                    ),
                    (
                        ("input", 2, 1),
                        ("input", 2, SCALAR_MODULUS - 1),
                        ("aux", 1, 1),
                    ),
                    (
                        ("input", 1, 1),
                        ("aux", 1, 1),
                        ("aux", 1, SCALAR_MODULUS - 1),
                    ),
                ),
                (
                    (
                        ("aux", 1, 1),
                        ("input", 2, 1),
                        ("input", 1, 0),
                    ),
                    (("input", 0, 2), ("input", 0, 4), ("input", 0, SCALAR_MODULUS - 6)),
                    (
                        ("input", 1, 2),
                        ("input", 1, SCALAR_MODULUS - 1),
                        ("input", 2, 1),
                        ("input", 2, SCALAR_MODULUS - 1),
                    ),
                ),
            ),
        )
        self.assertEqual(recorder.query_variable_order, (recorder.one(), x, y, a, b))
        self.assertEqual(
            tuple(recorder.query_index(variable) for variable in recorder.query_variable_order),
            (0, 1, 2, 3, 4),
        )
        self.assertEqual(recorder.ic_query_variables, (recorder.one(), x, y))
        self.assertEqual(recorder.l_query_variables, (a, b))

        recorder.append_dummy_input_constraints()
        self.assertEqual(recorder.constraint_count, 5)
        self.assertEqual(recorder.domain_size, 8)
        self.assertEqual(recorder.h_query_count, 7)
        self.assertEqual(
            tuple(row.name for row in recorder.constraints[-3:]),
            (
                "__setup_dummy_input_0",
                "__setup_dummy_input_1",
                "__setup_dummy_input_2",
            ),
        )
        for row, variable in zip(recorder.constraints[-3:], recorder.inputs):
            self.assertEqual(row.a.terms, ((variable, 1),))
            self.assertEqual(row.b.terms, ())
            self.assertEqual(row.c.terms, ())
            self.assertTrue(row.is_dummy_input_constraint)
        self.assertEqual(
            recorder.matrix_fingerprint(),
            "5b3c17e947d75d1686b43c6fe0b399a6cb1e2e1698e259c143989739f0035c04",
        )

    def test_query_layout_dummy_rows_and_domain_padding_follow_setup_order(self):
        recorder, x, y = self._small_fixture()
        self.assertEqual(recorder.query_variable_order, (recorder.one(), x, y))
        self.assertEqual(recorder.query_index(recorder.one()), 0)
        self.assertEqual(recorder.query_index(x), 1)
        self.assertEqual(recorder.query_index(y), 2)
        self.assertEqual(recorder.ic_query_variables, (recorder.one(), x))
        self.assertEqual(recorder.l_query_variables, (y,))
        self.assertEqual(recorder.domain_size, 1)

        recorder.append_dummy_input_constraints()
        self.assertEqual(recorder.constraint_count, 3)
        self.assertEqual(recorder.domain_size, 4)
        self.assertEqual(recorder.h_query_count, 3)
        self.assertEqual(
            tuple(row.is_dummy_input_constraint for row in recorder.constraints),
            (False, True, True),
        )
        self.assertEqual(
            tuple(row.name for row in recorder.constraints[-2:]),
            ("__setup_dummy_input_0", "__setup_dummy_input_1"),
        )
        for row, variable in zip(recorder.constraints[-2:], recorder.inputs):
            self.assertEqual(row.a.terms, ((variable, 1),))
            self.assertEqual(row.b.terms, ())
            self.assertEqual(row.c.terms, ())
        with self.assertRaisesRegex(BellmanRecorderError, "already added"):
            recorder.append_dummy_input_constraints()
        with self.assertRaisesRegex(BellmanRecorderError, "after setup dummy"):
            recorder.alloc_private("late", 0)

    def test_source_pedersen_transcription_agrees_across_recorders(self):
        local = R1CS()
        local_bits = tuple(
            local.alloc_private(f"message bit[{index}]", index & 1)
            for index in range(9)
        )
        for index, bit in enumerate(local_bits):
            local.boolean(bit, f"message bit[{index}] Boolean")
        local_result = synthesize_pedersen_hash(
            local, (1,) * 6, local_bits, "Pedersen recorder fixture"
        )

        recorder = BellmanSynthesisRecorder()
        recorder_bits = tuple(
            recorder.alloc_private(f"message bit[{index}]", index & 1)
            for index in range(9)
        )
        for index, bit in enumerate(recorder_bits):
            recorder.add_constraint(
                bit,
                bit.lc() - 1,
                0,
                f"message bit[{index}] Boolean",
            )
        recorder_result = synthesize_pedersen_hash(
            R1CSReferenceAdapter(recorder),
            (1,) * 6,
            recorder_bits,
            "Pedersen recorder fixture",
        )

        self.assertEqual(local.constraint_count, 31)
        self.assertEqual(recorder.constraint_count, local.constraint_count)
        self.assertEqual(
            recorder.serialize_local_matrix(),
            local.serialize_matrix(),
        )
        self.assertEqual(
            tuple(
                local._witness_value(variable)
                for variable in local_result
            ),
            tuple(variable.value for variable in recorder_result),
        )
        self.assertTrue(local.is_satisfied())
        self.assertNotEqual(
            recorder.matrix_fingerprint(),
            local.matrix_fingerprint(),
        )
        self.assertEqual(
            recorder.matrix_fingerprint(),
            "aa02682a888b8e6c6beba4bdce946ca4e1cbf56cca2d146430819065cb7132e7",
        )

    def test_source_blake2s_transcription_agrees_across_recorders(self):
        message = b"\x5a"
        message_values = tuple(
            (message[0] >> bit_index) & 1 for bit_index in range(8)
        )
        local = R1CS()
        local_bits = tuple(
            local.alloc_private(f"input bit[{index}]", value)
            for index, value in enumerate(message_values)
        )
        for bit in local_bits:
            local.enforce(1 - bit.lc(), bit, 0, "input Boolean")
        local_digest = constrain_bellman_blake2s_reference(
            local,
            local_bits,
            b"Zcash_nf",
        )

        recorder = BellmanSynthesisRecorder()
        recorder_bits = tuple(
            recorder.alloc_private(f"input bit[{index}]", value)
            for index, value in enumerate(message_values)
        )
        reference_adapter = R1CSReferenceAdapter(recorder)
        for bit in recorder_bits:
            reference_adapter.enforce(
                1 - bit.lc(),
                bit,
                0,
                "input Boolean",
            )
        recorder_digest = constrain_bellman_blake2s_reference(
            reference_adapter,
            recorder_bits,
            b"Zcash_nf",
        )

        self.assertEqual(
            recorder.serialize_local_matrix(),
            local.serialize_matrix(),
        )
        recorder_digest_bytes = bellman_bits_to_bytes(
            reference_adapter,
            recorder_digest,
        )
        self.assertEqual(
            recorder_digest_bytes,
            bellman_bits_to_bytes(local, local_digest),
        )
        self.assertEqual(
            recorder_digest_bytes,
            hashlib.blake2s(
                message,
                digest_size=32,
                person=b"Zcash_nf",
            ).digest(),
        )
        self.assertTrue(local.is_satisfied())
        self.assertEqual(recorder.constraint_count, local.constraint_count)
        self.assertEqual(recorder.constraint_count, 20094)
        self.assertEqual(len(recorder.auxiliary_variables), 20050)
        self.assertEqual(
            recorder.matrix_fingerprint(),
            "6d6fcc239e15b88dad899f9f69a7d40e828cb4a7e152a466cf415c584c41c5b7",
        )


if __name__ == "__main__":
    unittest.main()
