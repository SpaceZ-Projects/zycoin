"""Full-size local Spend proving smoke test with insecure test-only parameters."""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from src.bls12_381 import (
    G1_GENERATOR,
    G2_GENERATOR,
    SCALAR_MODULUS,
    add_g1,
    multiply_g1,
    multiply_g2,
)
from src.groth16_parameters import Groth16ParameterError, read_parameter_stream
from src.groth16_proof import ProofAssemblyError, assemble_proof_elements
from src.groth16_qap import QAP, QAPAssignment
from src.groth16_queries import G1Query, G2Query, msm_g1, msm_g2
from src.groth16_verification import (
    Groth16Proof,
    verify_groth16_proof,
)
from src.r1cs import R1CS
from src.sapling_spend_circuit import constrain_sapling_spend
from src.sapling_spend_reference import generate_pinned_test_witness
from tests.sapling_spend_synthetic_setup import (
    _TOXIC_WASTE,
    SyntheticParameterError,
    _barycentric_weights_at_tau,
    _column_major_reference,
    _load_synthetic_parameter_file,
    _reference_qap_column_value,
    _reference_witness_qap_at_tau,
    _row_major_query_scalars,
    _scalar_vector_sha256,
    _write_synthetic_parameter_file,
)
from tests.test_sapling_spend_circuit import _circuit_witness

_LOCAL_MATRIX_FINGERPRINT = (
    "f3451e632d46150e20e9ca2e6279266aba9555adb9192728816928e4e983e5b9"
)
_R = 19
_S = 23


def _peak_working_set_bytes() -> int:
    if os.name == "nt":

        class _Counters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        get_process_memory_info = psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(_Counters),
            ctypes.c_ulong,
        )
        get_process_memory_info.restype = ctypes.c_int
        if not get_process_memory_info(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(counters.PeakWorkingSetSize)
    import resource

    return int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024)


def _full_assignment(system: R1CS) -> QAPAssignment:
    auxiliary = []
    for variable in system.variables[system.public_input_count + 1 :]:
        value = system._witness_value(variable)
        if value is None:
            raise AssertionError("deterministic Spend fixture has an unassigned value")
        auxiliary.append(value)
    return QAPAssignment(system.public_inputs(), auxiliary)


def _direct_group_exponent_reference(
    qap: QAP,
    assignment: QAPAssignment,
    a_values: tuple[int, ...],
    b_values: tuple[int, ...],
    c_values: tuple[int, ...],
    h_values: tuple[int, ...],
) -> tuple[int, int, int]:
    """Independent scalar-exponent proof calculation, not a group MSM."""
    variables = qap.assignment_values(assignment)
    modulus = SCALAR_MODULUS
    a_eval = sum(value * scalar for value, scalar in zip(a_values, variables))
    b_eval = sum(value * scalar for value, scalar in zip(b_values, variables))
    extended = [
        (5 * a_values[index] + 3 * b_values[index] + c_values[index]) % modulus
        for index in range(qap.variable_count)
    ]
    l_eval = (
        sum(
            extended[index] * variables[index]
            for index in range(qap.domain.input_count, qap.variable_count)
        )
        * pow(11, -1, modulus)
        % modulus
    )

    quotient = qap.quotient(assignment)
    h_eval = 0
    for coefficient in reversed(quotient):
        h_eval = (h_eval * 2 + coefficient) % modulus
    z_tau = (pow(2, qap.domain.size, modulus) - 1) % modulus
    h_basis_eval = h_eval * z_tau * pow(11, -1, modulus) % modulus
    h_from_queries = (
        sum(scalar * coefficient for scalar, coefficient in zip(h_values, quotient))
        % modulus
    )
    if h_basis_eval != h_from_queries:
        raise AssertionError("independent H-query exponent calculation disagrees")

    a_eval %= modulus
    b_eval %= modulus
    proof_a = (3 + _R * 11 + a_eval) % modulus
    proof_b = (5 + _S * 11 + b_eval) % modulus
    proof_c = (
        _R * _S * 11
        + _S * 3
        + _R * 5
        + _S * a_eval
        + _R * b_eval
        + h_basis_eval
        + l_eval
    ) % modulus

    public_accumulator = (
        sum(
            extended[index] * variables[index] * pow(7, -1, modulus)
            for index in range(qap.domain.input_count)
        )
        % modulus
    )
    lhs = proof_a * proof_b % modulus
    rhs = (3 * 5 + public_accumulator * 7 + proof_c * 11) % modulus
    if lhs != rhs:
        raise AssertionError("independent scalar Groth16 verification equation failed")
    return proof_a, proof_b, proof_c


class SaplingSpendFullSizeSyntheticSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._started = time.perf_counter()
        cls._temporary_directory = tempfile.TemporaryDirectory(
            prefix="zycoin-test-only-spend-setup-"
        )
        cls.parameter_path = Path(cls._temporary_directory.name) / "insecure.params"

        witness = _circuit_witness(generate_pinned_test_witness(0))
        cls.system = R1CS()
        constrain_sapling_spend(cls.system, witness)
        cls.qap = QAP.from_r1cs(cls.system)
        cls.assignment = _full_assignment(cls.system)
        cls.qap.validate_assignment(cls.assignment)
        if (
            cls.system.matrix_fingerprint() != _LOCAL_MATRIX_FINGERPRINT
            or cls.system.constraint_count != 98_777
            or len(cls.system.variables) != 98_646
            or cls.qap.domain.size != 131_072
        ):
            raise AssertionError("local Spend matrix or QAP dimensions changed")
        cls.synthesis_seconds = time.perf_counter() - cls._started

        setup_started = time.perf_counter()
        tau = _TOXIC_WASTE["tau"]
        weights = _barycentric_weights_at_tau(cls.qap, tau)
        primary = _row_major_query_scalars(cls.qap, weights)
        reference = tuple(
            _column_major_reference(cls.qap, weights, side) for side in range(3)
        )
        if tuple(primary) != reference:
            raise AssertionError("independent column-major setup values differ")
        cls.a_values, cls.b_values, cls.c_values = (tuple(values) for values in primary)
        cls.a_scalar_sha256 = _scalar_vector_sha256(cls.a_values)
        cls.b_scalar_sha256 = _scalar_vector_sha256(cls.b_values)
        cls.c_scalar_sha256 = _scalar_vector_sha256(cls.c_values)

        sample_columns = (0, 7, 8, 32621, 76805, cls.qap.variable_count - 1)
        for side, expected_values in enumerate(primary):
            for variable_index in sample_columns:
                direct = _reference_qap_column_value(cls.qap, side, variable_index, tau)
                if direct != expected_values[variable_index]:
                    raise AssertionError(
                        "independent FFT column interpolation disagrees"
                    )
        assignment_values = cls.qap.assignment_values(cls.assignment)
        reference_witness_values = _reference_witness_qap_at_tau(
            cls.qap, assignment_values, weights
        )
        quotient = cls.qap.quotient(cls.assignment)
        quotient_at_tau = 0
        for coefficient in reversed(quotient):
            quotient_at_tau = (quotient_at_tau * tau + coefficient) % SCALAR_MODULUS
        vanishing_at_tau = (
            pow(tau, cls.qap.domain.size, SCALAR_MODULUS) - 1
        ) % SCALAR_MODULUS
        if (
            reference_witness_values[0] * reference_witness_values[1]
            - reference_witness_values[2]
        ) % SCALAR_MODULUS != quotient_at_tau * vanishing_at_tau % SCALAR_MODULUS:
            raise AssertionError("independent witness QAP divisibility check failed")
        if (
            tuple(
                sum(values[i] * assignment_values[i] for i in range(len(values)))
                % SCALAR_MODULUS
                for values in primary
            )
            != reference_witness_values
        ):
            raise AssertionError("independent witness and query accumulations differ")

        cls.parameter_sha256, cls.parameter_bytes = _write_synthetic_parameter_file(
            cls.qap, cls.parameter_path
        )
        cls.parameters = _load_synthetic_parameter_file(
            cls.parameter_path, cls.qap, cls.parameter_sha256
        )
        if cls.parameters.circuit_fingerprint != _LOCAL_MATRIX_FINGERPRINT:
            raise AssertionError("loaded synthetic setup has wrong matrix fingerprint")
        if cls.parameters.file_size != cls.parameter_bytes:
            raise AssertionError("synthetic setup file size changed during reload")
        for query, exponents, indices, group in (
            (cls.parameters.queries.a_query, cls.a_values, (0, 7, 32621), "g1"),
            (cls.parameters.queries.b_g1_query, cls.b_values, (8, 76805), "g1"),
            (cls.parameters.queries.b_g2_query, cls.b_values, (0, 7), "g2"),
            (
                cls.parameters.queries.h_query,
                tuple(
                    (
                        pow(2, index, SCALAR_MODULUS)
                        * (pow(2, cls.qap.domain.size, SCALAR_MODULUS) - 1)
                        * pow(11, -1, SCALAR_MODULUS)
                    )
                    % SCALAR_MODULUS
                    for index in range(cls.qap.domain.size - 1)
                ),
                (0, 1, 65535),
                "g1",
            ),
        ):
            for index in indices:
                expected = (
                    multiply_g1(G1_GENERATOR, exponents[index])
                    if group == "g1"
                    else multiply_g2(G2_GENERATOR, exponents[index])
                )
                if query.points[index].point != expected:
                    raise AssertionError(
                        "fixed-base setup point differs from reference"
                    )
        cls.setup_seconds = time.perf_counter() - setup_started

        proof_started = time.perf_counter()
        query_exponents_g1 = {
            id(cls.parameters.queries.a_query): cls.a_values,
            id(cls.parameters.queries.b_g1_query): cls.b_values,
            id(cls.parameters.queries.l_query): tuple(
                (
                    5 * cls.a_values[index]
                    + 3 * cls.b_values[index]
                    + cls.c_values[index]
                )
                * pow(11, -1, SCALAR_MODULUS)
                % SCALAR_MODULUS
                for index in range(cls.qap.domain.input_count, cls.qap.variable_count)
            ),
            id(cls.parameters.queries.h_query): tuple(
                (
                    pow(2, index, SCALAR_MODULUS)
                    * (pow(2, cls.qap.domain.size, SCALAR_MODULUS) - 1)
                    * pow(11, -1, SCALAR_MODULUS)
                )
                % SCALAR_MODULUS
                for index in range(cls.qap.domain.size - 1)
            ),
        }
        query_exponents_g2 = {id(cls.parameters.queries.b_g2_query): cls.b_values}

        def scalar_msm_g1(query, scalars):
            exponents = query_exponents_g1[id(query)]
            if len(exponents) != len(scalars):
                raise AssertionError("synthetic G1 query dimensions differ")
            return multiply_g1(
                G1_GENERATOR,
                sum(a * b for a, b in zip(exponents, scalars)) % SCALAR_MODULUS,
            )

        def scalar_msm_g2(query, scalars):
            exponents = query_exponents_g2[id(query)]
            if len(exponents) != len(scalars):
                raise AssertionError("synthetic G2 query dimensions differ")
            return multiply_g2(
                G2_GENERATOR,
                sum(a * b for a, b in zip(exponents, scalars)) % SCALAR_MODULUS,
            )

        with (
            patch("src.groth16_proof.msm_g1", side_effect=scalar_msm_g1),
            patch("src.groth16_proof.msm_g2", side_effect=scalar_msm_g2),
        ):
            proof_elements = assemble_proof_elements(
                cls.qap,
                cls.assignment,
                cls.parameters.queries,
                _R,
                _S,
            )
        cls.proof = Groth16Proof(
            proof_elements.a,
            proof_elements.b,
            proof_elements.c,
        )
        cls.proof_seconds = time.perf_counter() - proof_started

        reference_started = time.perf_counter()
        h_values = []
        tau_power = 1
        vanishing = (pow(2, cls.qap.domain.size, SCALAR_MODULUS) - 1) % SCALAR_MODULUS
        delta_inverse = pow(11, -1, SCALAR_MODULUS)
        for _ in range(cls.qap.domain.size - 1):
            h_values.append(tau_power * vanishing * delta_inverse % SCALAR_MODULUS)
            tau_power = tau_power * 2 % SCALAR_MODULUS
        cls.reference_proof_exponents = _direct_group_exponent_reference(
            cls.qap,
            cls.assignment,
            cls.a_values,
            cls.b_values,
            cls.c_values,
            tuple(h_values),
        )
        expected_a, expected_b, expected_c = cls.reference_proof_exponents
        if proof_elements.a != multiply_g1(G1_GENERATOR, expected_a):
            raise AssertionError("independent G1 proof exponent differs")
        if proof_elements.b != multiply_g2(G2_GENERATOR, expected_b):
            raise AssertionError("independent G2 proof exponent differs")
        if proof_elements.c != multiply_g1(G1_GENERATOR, expected_c):
            raise AssertionError("independent G1 C exponent differs")
        cls.reference_seconds = time.perf_counter() - reference_started

        quotient = cls.qap.quotient(cls.assignment)
        for query, exponents, scalars, group in (
            (
                G1Query(cls.parameters.queries.a_query.points[:64]),
                cls.a_values[:64],
                cls.qap.assignment_values(cls.assignment)[:64],
                "g1",
            ),
            (
                G1Query(cls.parameters.queries.b_g1_query.points[:64]),
                cls.b_values[:64],
                cls.qap.assignment_values(cls.assignment)[:64],
                "g1",
            ),
            (
                G2Query(cls.parameters.queries.b_g2_query.points[:64]),
                cls.b_values[:64],
                cls.qap.assignment_values(cls.assignment)[:64],
                "g2",
            ),
            (
                G1Query(cls.parameters.queries.l_query.points[:64]),
                query_exponents_g1[id(cls.parameters.queries.l_query)][:64],
                cls.assignment.auxiliary_assignments[:64],
                "g1",
            ),
            (
                G1Query(cls.parameters.queries.h_query.points[:64]),
                query_exponents_g1[id(cls.parameters.queries.h_query)][:64],
                quotient[:64],
                "g1",
            ),
        ):
            actual = msm_g1(query, scalars) if group == "g1" else msm_g2(query, scalars)
            expected = (
                multiply_g1(
                    G1_GENERATOR, sum(a * b for a, b in zip(exponents, scalars))
                )
                if group == "g1"
                else multiply_g2(
                    G2_GENERATOR, sum(a * b for a, b in zip(exponents, scalars))
                )
            )
            if actual != expected:
                raise AssertionError(
                    "sampled production MSM differs from scalar reference"
                )

        verify_started = time.perf_counter()
        cls.valid_proof_accepted = verify_groth16_proof(
            cls.parameters.verification_key,
            cls.proof,
            cls.assignment.public_inputs,
        )
        cls.verification_seconds = time.perf_counter() - verify_started
        if not cls.valid_proof_accepted:
            raise AssertionError("production verifier rejected synthetic proof")

        cls.metrics = {
            "matrix_fingerprint": cls.system.matrix_fingerprint(),
            "rows": cls.system.constraint_count,
            "columns": len(cls.system.variables),
            "domain_size": cls.qap.domain.size,
            "h_entries": len(cls.parameters.queries.h_query.points),
            "parameter_sections": {
                "ic": len(cls.parameters.verification_key.ic_query),
                "h": len(cls.parameters.queries.h_query.points),
                "l": len(cls.parameters.queries.l_query.points),
                "a": len(cls.parameters.queries.a_query.points),
                "b_g1": len(cls.parameters.queries.b_g1_query.points),
                "b_g2": len(cls.parameters.queries.b_g2_query.points),
            },
            "parameter_bytes": cls.parameter_bytes,
            "parameter_sha256": cls.parameter_sha256,
            "scalar_vector_sha256": {
                "a": cls.a_scalar_sha256,
                "b": cls.b_scalar_sha256,
                "c": cls.c_scalar_sha256,
            },
            "toxic_waste_known": True,
            "full_query_accumulation": (
                "Complete scalar-exponent accumulation through the production "
                "proof assembler using the test-only known-toxic-waste oracle; "
                "production group MSM independently checked on 64-point samples "
                "for A, B_G1, B_G2, L, and H."
            ),
            "synthesis_seconds": round(cls.synthesis_seconds, 3),
            "setup_write_and_reload_seconds": round(cls.setup_seconds, 3),
            "proof_assembly_seconds": round(cls.proof_seconds, 3),
            "independent_reference_seconds": round(cls.reference_seconds, 3),
            "verification_seconds": round(cls.verification_seconds, 3),
            "elapsed_seconds": round(time.perf_counter() - cls._started, 3),
            "peak_working_set_bytes": _peak_working_set_bytes(),
        }
        print(
            "INSECURE TEST-ONLY SYNTHETIC SPEND METRICS "
            + json.dumps(cls.metrics, sort_keys=True)
        )

    @classmethod
    def tearDownClass(cls):
        cls._temporary_directory.cleanup()

    def test_full_size_setup_query_proof_and_reference_verification(self):
        self.assertEqual(self.metrics["rows"], 98_777)
        self.assertEqual(self.metrics["columns"], 98_646)
        self.assertEqual(self.metrics["h_entries"], 131_071)
        self.assertEqual(
            self.metrics["parameter_sections"],
            {
                "ic": 8,
                "h": 131_071,
                "l": 98_638,
                "a": 98_646,
                "b_g1": 98_646,
                "b_g2": 98_646,
            },
        )
        self.assertTrue(self.metrics["toxic_waste_known"])
        self.assertTrue(self.valid_proof_accepted)

    def test_synthetic_format_is_not_accepted_by_production_parameter_parser(self):
        with (
            self.parameter_path.open("rb") as source,
            self.assertRaises(Groth16ParameterError),
        ):
            parser = read_parameter_stream(source)
            tuple(tuple(section) for section in parser.sections())

    def test_wrong_circuit_fingerprint_and_malformed_file_are_rejected(self):
        wrong_qap = QAP.from_r1cs(R1CS())
        with self.assertRaisesRegex(SyntheticParameterError, "do not match circuit"):
            _load_synthetic_parameter_file(
                self.parameter_path, wrong_qap, self.parameter_sha256
            )

        malformed_path = Path(self._temporary_directory.name) / "malformed.params"
        with (
            self.parameter_path.open("rb") as source,
            malformed_path.open("wb") as target,
        ):
            target.write(b"BAD-MAGIC")
            source.seek(len(b"BAD-MAGIC"))
            shutil.copyfileobj(source, target)
        with self.assertRaisesRegex(SyntheticParameterError, "not a test-only"):
            _load_synthetic_parameter_file(
                malformed_path, self.qap, self.parameter_sha256
            )

    def test_invalid_witness_altered_inputs_and_corrupted_proof_fail(self):
        invalid_auxiliary = list(self.assignment.auxiliary_assignments)
        invalid_auxiliary[-1] = (invalid_auxiliary[-1] + 1) % SCALAR_MODULUS
        with self.assertRaises(ProofAssemblyError):
            assemble_proof_elements(
                self.qap,
                QAPAssignment(self.assignment.public_inputs, invalid_auxiliary),
                self.parameters.queries,
                _R,
                _S,
            )

        altered_inputs = list(self.assignment.public_inputs)
        altered_inputs[0] = (altered_inputs[0] + 1) % SCALAR_MODULUS
        self.assertFalse(
            verify_groth16_proof(
                self.parameters.verification_key,
                self.proof,
                altered_inputs,
            )
        )
        corrupted_proof = replace(
            self.proof,
            a=add_g1(self.proof.a.point, G1_GENERATOR),
        )
        self.assertFalse(
            verify_groth16_proof(
                self.parameters.verification_key,
                corrupted_proof,
                self.assignment.public_inputs,
            )
        )


if __name__ == "__main__":
    unittest.main()
