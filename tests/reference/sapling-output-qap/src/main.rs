use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use bellman::domain::{EvaluationDomain, Scalar as BellmanScalar};
use bellman::multicore::Worker;
use bls12_381::Scalar;
use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};

const SAPLING_REVISION: &str = "88a7946b4a3066787776e11f0a502654167e022d";
const BELLMAN_REVISION: &str = "b726862a4ece8a627e7fea486d77b502a6edbb0b";
const BELLMAN_CRATE_VERSION: &str = "0.15.0";

#[derive(Deserialize)]
struct AssignmentInput {
    format: String,
    row_artifact_sha256: String,
    variable_mapping_fingerprint_sha256: String,
    matrix_fingerprint: String,
    cases: Vec<AssignmentCase>,
}

#[derive(Deserialize)]
struct AssignmentCase {
    name: String,
    assignment_sha256: String,
    assignment_hex: Vec<String>,
}

#[derive(Deserialize)]
struct RowArtifact {
    format: String,
    rows: Vec<ArtifactRow>,
}

#[derive(Deserialize)]
struct ArtifactRow {
    upstream_abc: Abc,
}

#[derive(Deserialize)]
struct Abc {
    a: Factor,
    b: Factor,
    c: Factor,
}

#[derive(Deserialize)]
struct Factor {
    canonical_terms: Vec<Term>,
}

#[derive(Deserialize)]
struct Term {
    identity: String,
    coefficient_hex: String,
}

#[derive(Serialize)]
struct ReferenceOutput {
    format: &'static str,
    bellman_crate_version: &'static str,
    bellman_revision: &'static str,
    sapling_revision: &'static str,
    reference_algorithm: &'static str,
    row_artifact_sha256: String,
    variable_mapping_fingerprint_sha256: String,
    matrix_fingerprint: String,
    constraint_count: usize,
    input_count_including_one: usize,
    auxiliary_variable_count: usize,
    row_count_with_dummy_inputs: usize,
    padding_count: usize,
    domain_size: usize,
    omega_hex: String,
    coset_generator_hex: String,
    cases: Vec<CaseOutput>,
}

#[derive(Serialize)]
struct CaseOutput {
    name: String,
    assignment_sha256: String,
    satisfied: bool,
    failed_constraints: Vec<usize>,
    a_evaluations_hex: Vec<String>,
    b_evaluations_hex: Vec<String>,
    c_evaluations_hex: Vec<String>,
    a_polynomial_coefficients_hex: Vec<String>,
    b_polynomial_coefficients_hex: Vec<String>,
    c_polynomial_coefficients_hex: Vec<String>,
    quotient_coefficients_hex: Option<Vec<String>>,
    quotient_divisibility_verified: bool,
    highest_nonzero_degree: [Option<usize>; 4],
}

type Domain = EvaluationDomain<Scalar, BellmanScalar<Scalar>>;

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn decode_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() != expected_bytes * 2 {
        return Err(format!(
            "expected {} hexadecimal characters",
            expected_bytes * 2
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(expected_bytes);
    for pair in bytes.chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hexadecimal digit".to_owned())?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hexadecimal digit".to_owned())?;
        decoded.push(((high << 4) | low) as u8);
    }
    Ok(decoded)
}

fn decode_scalar(value: &str) -> Result<Scalar, String> {
    let bytes = decode_hex(value, 32)?;
    let repr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "invalid scalar width".to_owned())?;
    Option::from(Scalar::from_repr(repr))
        .ok_or_else(|| "noncanonical scalar-field value".to_owned())
}

fn scalar_hex(value: Scalar) -> String {
    value
        .to_repr()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn variable_index(identity: &str, input_count: usize) -> Result<usize, String> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let index = index
            .parse::<usize>()
            .map_err(|_| "invalid input variable identity".to_owned())?;
        if index >= input_count {
            return Err("input variable identity is out of range".to_owned());
        }
        return Ok(index);
    }
    if let Some(index) = identity
        .strip_prefix("Aux(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let index = index
            .parse::<usize>()
            .map_err(|_| "invalid auxiliary variable identity".to_owned())?;
        return input_count
            .checked_add(index)
            .ok_or_else(|| "auxiliary variable index overflow".to_owned());
    }
    Err("unknown variable identity".to_owned())
}

fn factor_value(
    factor: &Factor,
    assignments: &[Scalar],
    input_count: usize,
) -> Result<Scalar, String> {
    let mut result = Scalar::ZERO;
    for term in &factor.canonical_terms {
        let index = variable_index(&term.identity, input_count)?;
        let assignment = assignments
            .get(index)
            .ok_or_else(|| "variable identity exceeds assignment length".to_owned())?;
        result += decode_scalar(&term.coefficient_hex)? * assignment;
    }
    Ok(result)
}

fn padded_domain(values: &[Scalar]) -> Result<Domain, String> {
    let wrapped = values.iter().copied().map(BellmanScalar).collect();
    Domain::from_coeffs(wrapped).map_err(|_| "Bellman rejected QAP domain size".to_owned())
}

fn unwrap_domain(domain: Domain) -> Vec<Scalar> {
    domain
        .into_coeffs()
        .into_iter()
        .map(|value| value.0)
        .collect()
}

fn interpolate(values: &[Scalar], worker: &Worker) -> Result<Vec<Scalar>, String> {
    let mut domain = padded_domain(values)?;
    domain.ifft(worker);
    Ok(unwrap_domain(domain))
}

fn highest_nonzero_degree(coefficients: &[Scalar]) -> Option<usize> {
    coefficients
        .iter()
        .rposition(|coefficient| !bool::from(coefficient.is_zero()))
}

fn quotient(
    a_coefficients: &[Scalar],
    b_coefficients: &[Scalar],
    c_coefficients: &[Scalar],
    worker: &Worker,
) -> Result<(Vec<Scalar>, bool), String> {
    let mut a = padded_domain(a_coefficients)?;
    let mut b = padded_domain(b_coefficients)?;
    let mut c = padded_domain(c_coefficients)?;
    a.ifft(worker);
    a.coset_fft(worker);
    b.ifft(worker);
    b.coset_fft(worker);
    c.ifft(worker);
    c.coset_fft(worker);

    a.mul_assign(worker, &b);
    a.sub_assign(worker, &c);
    a.divide_by_z_on_coset(worker);
    a.icoset_fft(worker);
    let mut coefficients = unwrap_domain(a);
    if coefficients.is_empty() {
        return Err("Bellman produced an empty quotient vector".to_owned());
    }
    let final_coefficient = coefficients.pop().unwrap();
    Ok((coefficients, bool::from(final_coefficient.is_zero())))
}

fn verify_quotient_identity(
    a: &[Scalar],
    b: &[Scalar],
    c: &[Scalar],
    h: &[Scalar],
    worker: &Worker,
) -> Result<bool, String> {
    let size = a.len();
    if b.len() != size || c.len() != size || h.len() + 1 != size {
        return Err("polynomial lengths do not match Bellman quotient bounds".to_owned());
    }

    let mut a_padded = a.to_vec();
    a_padded.resize(size * 2, Scalar::ZERO);
    let mut b_padded = b.to_vec();
    b_padded.resize(size * 2, Scalar::ZERO);
    let mut a_domain = padded_domain(&a_padded)?;
    let mut b_domain = padded_domain(&b_padded)?;
    a_domain.fft(worker);
    b_domain.fft(worker);
    a_domain.mul_assign(worker, &b_domain);
    a_domain.ifft(worker);
    let mut product = unwrap_domain(a_domain);
    product.resize(size * 2, Scalar::ZERO);

    for (index, coefficient) in c.iter().enumerate() {
        product[index] -= coefficient;
    }

    let mut quotient_product = vec![Scalar::ZERO; size * 2];
    for (index, coefficient) in h.iter().enumerate() {
        quotient_product[index] -= coefficient;
        quotient_product[index + size] += coefficient;
    }
    Ok(product == quotient_product)
}

fn build_case(
    case: &AssignmentCase,
    rows: &[ArtifactRow],
    input_count: usize,
    auxiliary_variable_count: usize,
    worker: &Worker,
) -> Result<CaseOutput, String> {
    let assignments = case
        .assignment_hex
        .iter()
        .map(|value| decode_scalar(value))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_variable_count = input_count + auxiliary_variable_count;
    if assignments.len() != expected_variable_count {
        return Err(format!(
            "{}: expected {expected_variable_count} assignment values, got {}",
            case.name,
            assignments.len()
        ));
    }

    let mut a_values = Vec::with_capacity(rows.len() + input_count);
    let mut b_values = Vec::with_capacity(rows.len() + input_count);
    let mut c_values = Vec::with_capacity(rows.len() + input_count);
    let mut failed_constraints = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let a = factor_value(&row.upstream_abc.a, &assignments, input_count)?;
        let b = factor_value(&row.upstream_abc.b, &assignments, input_count)?;
        let c = factor_value(&row.upstream_abc.c, &assignments, input_count)?;
        if a * b != c {
            failed_constraints.push(index);
        }
        a_values.push(a);
        b_values.push(b);
        c_values.push(c);
    }
    for value in assignments.iter().take(input_count) {
        a_values.push(*value);
        b_values.push(Scalar::ZERO);
        c_values.push(Scalar::ZERO);
    }

    let a_domain = padded_domain(&a_values)?;
    let b_domain = padded_domain(&b_values)?;
    let c_domain = padded_domain(&c_values)?;
    let domain_size = a_domain.as_ref().len();
    if b_domain.as_ref().len() != domain_size || c_domain.as_ref().len() != domain_size {
        return Err("A/B/C domain sizes differ".to_owned());
    }
    let a_evaluations = unwrap_domain(a_domain);
    let b_evaluations = unwrap_domain(b_domain);
    let c_evaluations = unwrap_domain(c_domain);
    let a_coefficients = interpolate(&a_evaluations, worker)?;
    let b_coefficients = interpolate(&b_evaluations, worker)?;
    let c_coefficients = interpolate(&c_evaluations, worker)?;

    let satisfied = failed_constraints.is_empty();
    let (quotient_coefficients, quotient_divisibility_verified) = if satisfied {
        let (h, zero_final_coefficient) =
            quotient(&a_evaluations, &b_evaluations, &c_evaluations, worker)?;
        let divisible = zero_final_coefficient
            && verify_quotient_identity(
                &a_coefficients,
                &b_coefficients,
                &c_coefficients,
                &h,
                worker,
            )?;
        (Some(h), divisible)
    } else {
        (None, false)
    };

    let highest_nonzero_degree = [
        highest_nonzero_degree(&a_coefficients),
        highest_nonzero_degree(&b_coefficients),
        highest_nonzero_degree(&c_coefficients),
        quotient_coefficients
            .as_ref()
            .and_then(|coefficients| highest_nonzero_degree(coefficients)),
    ];

    Ok(CaseOutput {
        name: case.name.clone(),
        satisfied,
        failed_constraints,
        a_evaluations_hex: a_evaluations.into_iter().map(scalar_hex).collect(),
        b_evaluations_hex: b_evaluations.into_iter().map(scalar_hex).collect(),
        c_evaluations_hex: c_evaluations.into_iter().map(scalar_hex).collect(),
        a_polynomial_coefficients_hex: a_coefficients.into_iter().map(scalar_hex).collect(),
        b_polynomial_coefficients_hex: b_coefficients.into_iter().map(scalar_hex).collect(),
        c_polynomial_coefficients_hex: c_coefficients.into_iter().map(scalar_hex).collect(),
        quotient_coefficients_hex: quotient_coefficients
            .map(|coefficients| coefficients.into_iter().map(scalar_hex).collect()),
        quotient_divisibility_verified,
        highest_nonzero_degree,
        assignment_sha256: case.assignment_sha256.clone(),
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err(fail(
            "usage: sapling-output-qap-reference <row-artifact.json> <assignments.json> <output.json>",
        ));
    }
    let row_artifact: RowArtifact = serde_json::from_reader(BufReader::new(File::open(&args[0])?))?;
    let input: AssignmentInput = serde_json::from_reader(BufReader::new(File::open(&args[1])?))?;
    if row_artifact.format != "zycoin-bellman-sapling-output-row-correspondence-v1" {
        return Err(fail("unexpected Output row-artifact format"));
    }
    if row_artifact.rows.len() != 7_827 {
        return Err(fail("pinned Output row count must be 7,827"));
    }
    if input.format != "zycoin-sapling-output-qap-assignment-input-v1" {
        return Err(fail("unexpected QAP assignment-input format"));
    }
    let input_count = 6;
    let auxiliary_variable_count = 7_821;
    let row_count = row_artifact.rows.len() + input_count;
    let domain_size = row_count.next_power_of_two();
    let worker = Worker::new();
    let cases = input
        .cases
        .iter()
        .map(|case| {
            build_case(
                case,
                &row_artifact.rows,
                input_count,
                auxiliary_variable_count,
                &worker,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(fail)?;
    let omega = {
        let mut root = Scalar::ROOT_OF_UNITY;
        for _ in domain_size.trailing_zeros()..Scalar::S {
            root = root.square();
        }
        root
    };

    let output = ReferenceOutput {
        format: "bellman-sapling-output-qap-reference-v1",
        bellman_crate_version: BELLMAN_CRATE_VERSION,
        bellman_revision: BELLMAN_REVISION,
        sapling_revision: SAPLING_REVISION,
        reference_algorithm: "Bellman 0.15 EvaluationDomain::ifft; prover-order ifft/coset_fft, pointwise A*B-C, divide_by_z_on_coset, icoset_fft, and H truncation; polynomial identity independently checked by Bellman FFT convolution",
        row_artifact_sha256: input.row_artifact_sha256,
        variable_mapping_fingerprint_sha256: input.variable_mapping_fingerprint_sha256,
        matrix_fingerprint: input.matrix_fingerprint,
        constraint_count: row_artifact.rows.len(),
        input_count_including_one: input_count,
        auxiliary_variable_count,
        row_count_with_dummy_inputs: row_count,
        padding_count: domain_size - row_count,
        domain_size,
        omega_hex: scalar_hex(omega),
        coset_generator_hex: scalar_hex(Scalar::MULTIPLICATIVE_GENERATOR),
        cases,
    };
    let mut output_file = BufWriter::new(File::create(&args[2])?);
    serde_json::to_writer(&mut output_file, &output)?;
    output_file.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factor(terms: Vec<Term>) -> Factor {
        Factor {
            canonical_terms: terms,
        }
    }

    fn term(identity: &str, value: Scalar) -> Term {
        Term {
            identity: identity.to_owned(),
            coefficient_hex: scalar_hex(value),
        }
    }

    #[test]
    fn rejects_noncanonical_scalars() {
        assert!(decode_scalar(&"ff".repeat(32)).is_err());
        assert!(decode_scalar("00").is_err());
    }

    #[test]
    fn rejects_unsatisfied_assignments_before_quotient() {
        let row = ArtifactRow {
            upstream_abc: Abc {
                a: factor(vec![term("Aux(0)", Scalar::ONE)]),
                b: factor(vec![term("Input(0)", Scalar::ONE)]),
                c: factor(vec![]),
            },
        };
        let assignments = AssignmentCase {
            name: "unsatisfied".to_owned(),
            assignment_sha256: "test".to_owned(),
            assignment_hex: vec![scalar_hex(Scalar::ONE), scalar_hex(Scalar::ONE)],
        };
        let result = build_case(&assignments, &[row], 1, 1, &Worker::new()).unwrap();
        assert!(!result.satisfied);
        assert_eq!(result.failed_constraints, vec![0]);
        assert!(result.quotient_coefficients_hex.is_none());
        assert!(!result.quotient_divisibility_verified);
    }
}
