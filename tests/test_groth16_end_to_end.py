import hashlib
import json
import unittest
from dataclasses import replace

from src.bls12_381 import (
    G1_GENERATOR,
    G2_GENERATOR,
    SCALAR_MODULUS,
    Fp12,
    multiply_g1,
    multiply_g2,
    pairing,
)
from src.groth16_fft import FFTDomain
from src.groth16_proof import (
    Groth16ProvingQueries,
    ProofAssemblyError,
    assemble_proof_elements,
)
from src.groth16_qap import QAP, QAPAssignment, UnsatisfiedAssignmentError
from src.groth16_queries import (
    G1Query,
    G2Query,
    ValidatedG1Point,
    ValidatedG2Point,
)
from src.groth16_verification import (
    Groth16Proof,
    Groth16VerificationError,
    Groth16VerificationKey,
    public_input_accumulator,
    verify_groth16_proof,
)
from src.r1cs import R1CS

_X = 3
_Y = 4
_Z = 12
_TAU = 11
_ALPHA = 5
_BETA = 7
_GAMMA = 13
_DELTA = 17
_R = 19
_S = 23


def _fixture():
    system = R1CS()
    x = system.alloc_public("x", _X)
    y = system.alloc_private("y", _Y)
    z = system.alloc_private("z", _Z)
    system.enforce(x, y, z, "x times y equals z")
    return system, QAP.from_r1cs(system), QAPAssignment((_X,), (_Y, _Z))


def _poly_evaluate(coefficients, point):
    result = 0
    for coefficient in reversed(coefficients):
        result = (result * point + coefficient) % SCALAR_MODULUS
    return result


def _poly_multiply(left, right):
    result = [0] * (len(left) + len(right) - 1)
    for left_degree, left_coefficient in enumerate(left):
        for right_degree, right_coefficient in enumerate(right):
            result[left_degree + right_degree] = (
                result[left_degree + right_degree]
                + left_coefficient * right_coefficient
            ) % SCALAR_MODULUS
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result


def _poly_subtract(left, right):
    result = [
        (
            (left[index] if index < len(left) else 0)
            - (right[index] if index < len(right) else 0)
        )
        % SCALAR_MODULUS
        for index in range(max(len(left), len(right)))
    ]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result


def _poly_divide_by_vanishing(numerator, domain_size):
    """Independent long division by X**domain_size - 1."""
    remainder = list(numerator)
    quotient = [0] * max(1, len(remainder) - domain_size)
    while len(remainder) > domain_size:
        degree = len(remainder) - 1
        factor = remainder[degree]
        quotient_degree = degree - domain_size
        quotient[quotient_degree] = factor
        remainder[degree] = 0
        remainder[quotient_degree] = (
            remainder[quotient_degree] + factor
        ) % SCALAR_MODULUS
        while len(remainder) > 1 and remainder[-1] == 0:
            remainder.pop()
    return quotient, remainder


def _lagrange_evaluate(domain_points, evaluations, point):
    """Evaluate an interpolant using the explicit Lagrange formula."""
    value = 0
    for index, y_value in enumerate(evaluations):
        basis = 1
        for other_index, x_value in enumerate(domain_points):
            if other_index == index:
                continue
            basis = (
                basis
                * (point - x_value)
                * pow(domain_points[index] - x_value, -1, SCALAR_MODULUS)
            ) % SCALAR_MODULUS
        value = (value + y_value * basis) % SCALAR_MODULUS
    return value


def _synthetic_setup(qap):
    """Build test-only Groth16 queries from an explicitly insecure scalar setup.

    The fixture has columns ONE, x, y, z and QAP row evaluations derived
    directly from the single relation and the two Bellman dummy-input rows.
    """
    omega = FFTDomain.create(qap.domain.size).omega
    domain_points = tuple(
        pow(omega, index, SCALAR_MODULUS) for index in range(qap.domain.size)
    )
    # Constraint row x*y=z; dummy rows for ONE and public x; final zero pad.
    a_rows = (
        (0, 1, 0, 0),  # x * y = z
        (1, 0, 0, 0),  # dummy ONE input
        (0, 1, 0, 0),  # dummy x input
        (0, 0, 0, 0),  # padding
    )
    b_rows = (
        (0, 0, 1, 0),
        (0, 0, 0, 0),
        (0, 0, 0, 0),
        (0, 0, 0, 0),
    )
    c_rows = (
        (0, 0, 0, 1),
        (0, 0, 0, 0),
        (0, 0, 0, 0),
        (0, 0, 0, 0),
    )
    a_at_tau = tuple(
        _lagrange_evaluate(domain_points, tuple(row[i] for row in a_rows), _TAU)
        for i in range(4)
    )
    b_at_tau = tuple(
        _lagrange_evaluate(domain_points, tuple(row[i] for row in b_rows), _TAU)
        for i in range(4)
    )
    c_at_tau = tuple(
        _lagrange_evaluate(domain_points, tuple(row[i] for row in c_rows), _TAU)
        for i in range(4)
    )
    vanishing_at_tau = (pow(_TAU, qap.domain.size, SCALAR_MODULUS) - 1) % (
        SCALAR_MODULUS
    )
    assert vanishing_at_tau != 0
    delta_inverse = pow(_DELTA, -1, SCALAR_MODULUS)
    gamma_inverse = pow(_GAMMA, -1, SCALAR_MODULUS)

    a_query = G1Query(
        tuple(multiply_g1(G1_GENERATOR, value) for value in a_at_tau)
    )
    b_g1_query = G1Query(
        tuple(multiply_g1(G1_GENERATOR, value) for value in b_at_tau)
    )
    b_g2_query = G2Query(
        tuple(multiply_g2(G2_GENERATOR, value) for value in b_at_tau)
    )
    l_query = G1Query(
        tuple(
            multiply_g1(
                G1_GENERATOR,
                (
                    _BETA * a_at_tau[index]
                    + _ALPHA * b_at_tau[index]
                    + c_at_tau[index]
                )
                * delta_inverse
                % SCALAR_MODULUS,
            )
            for index in (2, 3)
        )
    )
    h_query = G1Query(
        tuple(
            multiply_g1(
                G1_GENERATOR,
                pow(_TAU, degree, SCALAR_MODULUS)
                * vanishing_at_tau
                * delta_inverse
                % SCALAR_MODULUS,
            )
            for degree in range(qap.domain.size - 1)
        )
    )
    queries = Groth16ProvingQueries(
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _ALPHA)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _BETA)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, _BETA)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _DELTA)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, _DELTA)),
        a_query,
        b_g1_query,
        b_g2_query,
        l_query,
        h_query,
    )

    ic_query = tuple(
        multiply_g1(
            G1_GENERATOR,
            (
                _BETA * a_at_tau[index]
                + _ALPHA * b_at_tau[index]
                + c_at_tau[index]
            )
            * gamma_inverse
            % SCALAR_MODULUS,
        )
        for index in (0, 1)
    )
    verification_key = Groth16VerificationKey(
        multiply_g1(G1_GENERATOR, _ALPHA),
        multiply_g2(G2_GENERATOR, _BETA),
        multiply_g2(G2_GENERATOR, _GAMMA),
        multiply_g2(G2_GENERATOR, _DELTA),
        ic_query,
    )
    return queries, verification_key, (a_at_tau, b_at_tau, c_at_tau)


def _synthetic_setup_for_qap(qap):
    """Derive test-only Groth16 queries from this fixture's ordered QAP."""
    variable_count = qap.variable_count
    domain_size = qap.domain.size
    input_count = qap.domain.input_count
    sides = [
        [[0] * domain_size for _ in range(variable_count)]
        for _ in range(3)
    ]
    for row, constraint in enumerate(qap.system.iter_constraints()):
        for side, expression in enumerate(
            (constraint.left, constraint.right, constraint.output)
        ):
            for variable_index, coefficient in expression.terms:
                sides[side][variable_index][row] = coefficient
    for input_index in range(input_count):
        sides[0][input_index][qap.domain.constraint_count + input_index] = 1

    domain = qap.domain.fft_domain
    evaluations = tuple(
        tuple(
            _poly_evaluate(domain.ifft(column), _TAU)
            for column in side
        )
        for side in sides
    )
    a_at_tau, b_at_tau, c_at_tau = evaluations
    vanishing_at_tau = (
        pow(_TAU, domain_size, SCALAR_MODULUS) - 1
    ) % SCALAR_MODULUS
    delta_inverse = pow(_DELTA, -1, SCALAR_MODULUS)
    gamma_inverse = pow(_GAMMA, -1, SCALAR_MODULUS)
    extended = tuple(
        (
            _BETA * a_at_tau[index]
            + _ALPHA * b_at_tau[index]
            + c_at_tau[index]
        )
        % SCALAR_MODULUS
        for index in range(variable_count)
    )
    queries = Groth16ProvingQueries(
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _ALPHA)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _BETA)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, _BETA)),
        ValidatedG1Point(multiply_g1(G1_GENERATOR, _DELTA)),
        ValidatedG2Point(multiply_g2(G2_GENERATOR, _DELTA)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, value) for value in a_at_tau)),
        G1Query(tuple(multiply_g1(G1_GENERATOR, value) for value in b_at_tau)),
        G2Query(tuple(multiply_g2(G2_GENERATOR, value) for value in b_at_tau)),
        G1Query(
            tuple(
                multiply_g1(
                    G1_GENERATOR,
                    extended[index] * delta_inverse % SCALAR_MODULUS,
                )
                for index in range(input_count, variable_count)
            )
        ),
        G1Query(
            tuple(
                multiply_g1(
                    G1_GENERATOR,
                    pow(_TAU, degree, SCALAR_MODULUS)
                    * vanishing_at_tau
                    * delta_inverse
                    % SCALAR_MODULUS,
                )
                for degree in range(domain_size - 1)
            )
        ),
    )
    verification_key = Groth16VerificationKey(
        multiply_g1(G1_GENERATOR, _ALPHA),
        multiply_g2(G2_GENERATOR, _BETA),
        multiply_g2(G2_GENERATOR, _GAMMA),
        multiply_g2(G2_GENERATOR, _DELTA),
        tuple(
            multiply_g1(
                G1_GENERATOR,
                extended[index] * gamma_inverse % SCALAR_MODULUS,
            )
            for index in range(input_count)
        ),
    )
    return queries, verification_key, evaluations


def _synthetic_coefficients_sha256(coefficients):
    encoded = json.dumps(coefficients, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


class Groth16EndToEndSyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.system, cls.qap, cls.assignment = _fixture()
        cls.queries, cls.verification_key, cls.variable_evaluations = (
            _synthetic_setup(cls.qap)
        )
        cls.proof_elements = assemble_proof_elements(
            cls.qap, cls.assignment, cls.queries, _R, _S
        )
        cls.proof = Groth16Proof(
            cls.proof_elements.a,
            cls.proof_elements.b,
            cls.proof_elements.c,
        )
        cls.public_inputs = tuple(cls.assignment.public_inputs)

    def test_complete_witness_qap_query_assembly_and_verification(self):
        self.assertEqual(self.system.public_inputs(), (_X,))
        self.assertEqual(self.qap.assignment_values(self.assignment), (1, _X, _Y, _Z))
        self.assertEqual(self.qap.validate_assignment(self.assignment), (1, _X, _Y, _Z))

        quotient = self.qap.quotient(self.assignment)
        domain_points = tuple(
            pow(
                self.qap.domain.fft_domain.omega,
                index,
                SCALAR_MODULUS,
            )
            for index in range(self.qap.domain.size)
        )
        a_values = (_X, 1, _X, 0)
        b_values = (_Y, 0, 0, 0)
        c_values = (_Z, 0, 0, 0)
        a_tau = _lagrange_evaluate(domain_points, a_values, _TAU)
        b_tau = _lagrange_evaluate(domain_points, b_values, _TAU)
        c_tau = _lagrange_evaluate(domain_points, c_values, _TAU)
        h_tau = _poly_evaluate(quotient, _TAU)
        z_tau = (pow(_TAU, self.qap.domain.size, SCALAR_MODULUS) - 1) % (
            SCALAR_MODULUS
        )
        self.assertEqual((a_tau * b_tau - c_tau) % SCALAR_MODULUS, h_tau * z_tau % SCALAR_MODULUS)

        # Independently interpolate, multiply, and divide the three degree-<4
        # fixture polynomials; this does not use QAP.quotient or the FFT API.
        # Values at this small domain are powers-of-omega ordered. Convert to
        # coefficients by explicitly solving the four-point DFT equations.
        inverse_size = pow(self.qap.domain.size, -1, SCALAR_MODULUS)

        def direct_coefficients(values):
            return tuple(
                sum(
                    values[row]
                    * pow(domain_points[row], -degree, SCALAR_MODULUS)
                    for row in range(self.qap.domain.size)
                )
                * inverse_size
                % SCALAR_MODULUS
                for degree in range(self.qap.domain.size)
            )

        a_poly = direct_coefficients(a_values)
        b_poly = direct_coefficients(b_values)
        c_poly = direct_coefficients(c_values)
        numerator = _poly_subtract(_poly_multiply(a_poly, b_poly), c_poly)
        direct_quotient, direct_remainder = _poly_divide_by_vanishing(
            numerator, self.qap.domain.size
        )
        self.assertEqual(tuple(direct_remainder), (0,))
        direct_quotient.extend([0] * (len(quotient) - len(direct_quotient)))
        self.assertEqual(tuple(direct_quotient), quotient)
        self.assertEqual(_poly_evaluate(direct_quotient, _TAU), h_tau)

        self.assertEqual(len(self.queries.a_query.points), 4)
        self.assertEqual(len(self.queries.b_g1_query.points), 4)
        self.assertEqual(len(self.queries.b_g2_query.points), 4)
        self.assertEqual(len(self.queries.l_query.points), 2)
        self.assertEqual(len(self.queries.h_query.points), 3)
        self.assertTrue(verify_groth16_proof(
            self.verification_key, self.proof, self.public_inputs
        ))

    def test_query_and_proof_exponents_satisfy_independent_group_equations(self):
        a_at_tau, b_at_tau, c_at_tau = self.variable_evaluations
        witness = (1, _X, _Y, _Z)
        quotient = self.qap.quotient(self.assignment)
        h_at_tau = _poly_evaluate(quotient, _TAU)
        z_at_tau = (pow(_TAU, self.qap.domain.size, SCALAR_MODULUS) - 1) % (
            SCALAR_MODULUS
        )
        delta_inverse = pow(_DELTA, -1, SCALAR_MODULUS)
        a_eval = sum(a * w for a, w in zip(a_at_tau, witness)) % SCALAR_MODULUS
        b_eval = sum(b * w for b, w in zip(b_at_tau, witness)) % SCALAR_MODULUS
        l_eval = sum(
            (
                _BETA * a_at_tau[index]
                + _ALPHA * b_at_tau[index]
                + c_at_tau[index]
            )
            * delta_inverse
            * witness[index]
            for index in (2, 3)
        ) % SCALAR_MODULUS
        h_eval = h_at_tau * z_at_tau * delta_inverse % SCALAR_MODULUS
        c_eval = (
            _R * _S * _DELTA
            + _S * _ALPHA
            + _R * _BETA
            + _S * a_eval
            + _R * b_eval
            + h_eval
            + l_eval
        ) % SCALAR_MODULUS
        self.assertEqual(
            self.proof_elements.a,
            multiply_g1(G1_GENERATOR, _ALPHA + _R * _DELTA + a_eval),
        )
        self.assertEqual(
            self.proof_elements.b,
            multiply_g2(G2_GENERATOR, _BETA + _S * _DELTA + b_eval),
        )
        self.assertEqual(self.proof_elements.c, multiply_g1(G1_GENERATOR, c_eval))

        # Independent scalar-exponent equation for the complete synthetic key.
        ic_scalars = tuple(
            (
                _BETA * a_at_tau[index]
                + _ALPHA * b_at_tau[index]
                + c_at_tau[index]
            )
            * pow(_GAMMA, -1, SCALAR_MODULUS)
            % SCALAR_MODULUS
            for index in (0, 1)
        )
        public_accumulator_scalar = (
            ic_scalars[0] + _X * ic_scalars[1]
        ) % SCALAR_MODULUS
        lhs_exponent = (
            (_ALPHA + _R * _DELTA + a_eval)
            * (_BETA + _S * _DELTA + b_eval)
        ) % SCALAR_MODULUS
        rhs_exponent = (
            _ALPHA * _BETA
            + public_accumulator_scalar * _GAMMA
            + c_eval * _DELTA
        ) % SCALAR_MODULUS
        self.assertEqual(lhs_exponent, rhs_exponent)

        # Check the pairing equation directly, independently of the verifier's
        # four-Miller-loop product-to-one implementation.
        accumulator = public_input_accumulator(
            self.verification_key, self.public_inputs
        )
        self.assertEqual(
            pairing(self.proof.b.point, self.proof.a.point),
            pairing(self.verification_key.beta_g2.point, self.verification_key.alpha_g1.point)
            * pairing(self.verification_key.gamma_g2.point, accumulator)
            * pairing(self.verification_key.delta_g2.point, self.proof.c.point),
        )
        self.assertEqual(
            pairing(self.proof.b.point, self.proof.a.point)
            * pairing(
                multiply_g2(self.verification_key.gamma_g2.point, -1),
                accumulator,
            )
            * pairing(
                multiply_g2(self.verification_key.delta_g2.point, -1),
                self.proof.c.point,
            )
            * pairing(
                self.verification_key.beta_g2.point,
                multiply_g1(self.verification_key.alpha_g1.point, -1),
            ),
            Fp12.one(),
        )

    def test_row_permutation_and_factor_swap_require_qap_specific_queries(self):
        systems = []
        for reverse_rows in (False, True):
            system = R1CS()
            x = system.alloc_public("x", _X)
            y = system.alloc_private("y", _Y)
            z = system.alloc_private("z", _Z)
            if reverse_rows:
                inverse_two = pow(2, -1, SCALAR_MODULUS)
                scaled_x = system.linear_combination(((x, inverse_two),))
                scaled_y = system.linear_combination(((y, 2),))
                product = (scaled_y, scaled_x, z)
                trivial = (2, scaled_x, x)
            else:
                product = (x, y, z)
                trivial = (x, 1, x)
            constraints = (product, trivial) if not reverse_rows else (trivial, product)
            for index, (left, right, output) in enumerate(constraints):
                system.enforce(left, right, output, f"relation {index}")
            qap = QAP.from_r1cs(system)
            assignment = QAPAssignment((_X,), (_Y, _Z))
            self.assertEqual(
                qap.validate_assignment(assignment),
                (1, _X, _Y, _Z),
            )
            systems.append((system, qap, assignment))

        reference_qap = systems[0][1]
        reordered_qap = systems[1][1]
        self.assertEqual(reference_qap.variable_count, reordered_qap.variable_count)
        self.assertEqual(reference_qap.domain.size, reordered_qap.domain.size)
        reference_assignment = systems[0][2]
        reordered_assignment = systems[1][2]
        self.assertEqual(
            reference_qap.assignment_values(reference_assignment),
            reordered_qap.assignment_values(reordered_assignment),
        )
        self.assertNotEqual(
            reference_qap.polynomials(reference_assignment),
            reordered_qap.polynomials(reordered_assignment),
        )
        self.assertEqual(
            _synthetic_coefficients_sha256(
                tuple(
                    getattr(reference_qap.polynomials(reference_assignment), name)
                    for name in ("a", "b", "c")
                )
            ),
            "4ac16be4127e30ea9f809af1e2ec1a0721a4d19817f6d5f9187de3f5a20f160c",
        )
        self.assertEqual(
            _synthetic_coefficients_sha256(
                tuple(
                    getattr(reordered_qap.polynomials(reordered_assignment), name)
                    for name in ("a", "b", "c")
                )
            ),
            "fe6cc0832cada50c17ff87071cd04a102c9835fe7880d8fd4f6c224043f5a1fa",
        )
        self.assertNotEqual(
            reference_qap.quotient(reference_assignment),
            reordered_qap.quotient(reordered_assignment),
        )
        self.assertEqual(
            _synthetic_coefficients_sha256(
                reference_qap.quotient(reference_assignment)
            ),
            "33e4df9d5b1a8070e4d813a65534d4b3cad05f47db35e6e45353a24c941f89a5",
        )
        self.assertEqual(
            _synthetic_coefficients_sha256(
                reordered_qap.quotient(reordered_assignment)
            ),
            "4bb457f9a9b998bcd62c861e968d34d1bd1c9c85a2ba8ba90866f6393cb29dc3",
        )

        setups = tuple(_synthetic_setup_for_qap(qap) for _, qap, _ in systems)
        reference_queries, reference_vk, reference_evaluations = setups[0]
        reordered_queries, reordered_vk, reordered_evaluations = setups[1]
        self.assertEqual(
            reference_evaluations,
            (
                (
                    52435875175126190479447740508185965837690552500527637822603658699938581184208,
                    306,
                    0,
                    0,
                ),
                (
                    1143497792604305265196168945126955116829183314692569447792610,
                    0,
                    366,
                    0,
                ),
                (
                    0,
                    1143497792604305265196168945126955116829183314692569447792610,
                    0,
                    366,
                ),
            ),
        )
        self.assertEqual(
            reordered_evaluations,
            (
                (
                    427,
                    52435875175126189335949947903880700641521607373572520993420344007369133391843,
                    2286995585208610530392337890253910233658366629385138895585220,
                    0,
                ),
                (
                    0,
                    571748896302152632598084472563477558414591657346284723896488,
                    0,
                    0,
                ),
                (
                    0,
                    366,
                    0,
                    1143497792604305265196168945126955116829183314692569447792610,
                ),
            ),
        )
        self.assertNotEqual(reference_evaluations, reordered_evaluations)
        self.assertEqual(len(reference_queries.a_query.points), 4)
        self.assertEqual(len(reference_queries.b_g1_query.points), 4)
        self.assertEqual(len(reference_queries.b_g2_query.points), 4)
        self.assertEqual(len(reference_vk.ic_query), 2)
        self.assertEqual(len(reference_queries.l_query.points), 2)
        self.assertEqual(len(reference_queries.h_query.points), 3)
        self.assertNotEqual(
            reference_queries.a_query.points,
            reordered_queries.a_query.points,
        )
        self.assertNotEqual(
            reference_queries.b_g1_query.points,
            reordered_queries.b_g1_query.points,
        )
        self.assertNotEqual(
            reference_queries.b_g2_query.points,
            reordered_queries.b_g2_query.points,
        )
        self.assertNotEqual(reference_vk.ic_query, reordered_vk.ic_query)
        self.assertEqual(
            reference_queries.h_query.points,
            reordered_queries.h_query.points,
        )

        proofs = []
        for (_, qap, assignment), (queries, _, _) in zip(systems, setups):
            proof = assemble_proof_elements(qap, assignment, queries, _R, _S)
            proofs.append(Groth16Proof(proof.a, proof.b, proof.c))
        self.assertTrue(
            verify_groth16_proof(reference_vk, proofs[0], systems[0][2].public_inputs)
        )
        self.assertTrue(
            verify_groth16_proof(reordered_vk, proofs[1], systems[1][2].public_inputs)
        )
        self.assertFalse(
            verify_groth16_proof(reordered_vk, proofs[0], systems[0][2].public_inputs)
        )

    def test_invalid_assignments_dimensions_randomizers_and_keys_are_rejected(self):
        with self.assertRaises(UnsatisfiedAssignmentError):
            self.qap.validate_assignment(QAPAssignment((_X,), (_Y + 1, _Z)))
        with self.assertRaises(ProofAssemblyError):
            assemble_proof_elements(
                self.qap,
                QAPAssignment((_X,), (_Y + 1, _Z)),
                self.queries,
                _R,
                _S,
            )

        malformed_queries = replace(
            self.queries,
            a_query=G1Query(self.queries.a_query.points[:-1]),
        )
        with self.assertRaisesRegex(ProofAssemblyError, "A-query length"):
            assemble_proof_elements(
                self.qap, self.assignment, malformed_queries, _R, _S
            )
        for invalid_r, invalid_s in ((SCALAR_MODULUS, _S), (_R, -1), (True, _S)):
                with self.subTest(randomizers=(invalid_r, invalid_s)), self.assertRaises(
                    ProofAssemblyError
                ):
                    assemble_proof_elements(
                        self.qap, self.assignment, self.queries, invalid_r, invalid_s
                    )

        wrong_key = replace(
            self.verification_key,
            gamma_g2=multiply_g2(G2_GENERATOR, _GAMMA + 1),
        )
        self.assertFalse(verify_groth16_proof(wrong_key, self.proof, self.public_inputs))
        self.assertFalse(
            verify_groth16_proof(
                self.verification_key,
                self.proof,
                (self.public_inputs[0] + 1,),
            )
        )
        self.assertFalse(
            verify_groth16_proof(
                self.verification_key,
                Groth16Proof(
                    multiply_g1(G1_GENERATOR, 2),
                    self.proof.b,
                    self.proof.c,
                ),
                self.public_inputs,
            )
        )
        with self.assertRaises(Groth16VerificationError):
            verify_groth16_proof(
                self.verification_key, self.proof, (SCALAR_MODULUS,)
            )


if __name__ == "__main__":
    unittest.main()
