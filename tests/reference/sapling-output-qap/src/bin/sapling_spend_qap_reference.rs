use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use bellman::domain::{EvaluationDomain, Scalar as BellmanScalar};
use bellman::multicore::Worker;
use bls12_381::Scalar;
use ff::{Field, PrimeField};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BELLMAN_REVISION: &str = "b726862a4ece8a627e7fea486d77b502a6edbb0b";
const SAPLING_REVISION: &str = "88a7946b4a3066787776e11f0a502654167e022d";
const EXPECTED_UPSTREAM_TEST_HASH: &str =
    "d37c738e83df5d9b0bb6495ac96abf21bcb2697477e2c15c2c7916ff7a3b6a89";
const INPUT_COUNT: usize = 8;
const AUXILIARY_COUNT: usize = 98_638;
const CONSTRAINT_COUNT: usize = 98_777;

type Domain = EvaluationDomain<Scalar, BellmanScalar<Scalar>>;

#[derive(Deserialize)]
struct SpendExport {
    format: String,
    sapling_crypto_revision: String,
    bellman_revision: String,
    satisfied: bool,
    num_inputs_including_one: usize,
    num_auxiliary_variables: usize,
    num_constraints: usize,
    observed_test_constraint_system_hash: String,
    inputs: Vec<VariableRecord>,
    auxiliary_variables: Vec<VariableRecord>,
    constraints: Vec<Row>,
}

#[derive(Deserialize)]
struct VariableRecord {
    identity: String,
    assignment_hex: Option<String>,
}

#[derive(Deserialize)]
struct Row {
    a: Vec<Term>,
    b: Vec<Term>,
    c: Vec<Term>,
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
    assignment_sha256: String,
    assignment_hex: Vec<String>,
    quotient_coefficients_h_hex: Vec<String>,
    upstream_test_constraint_system_hash: String,
    constraint_count: usize,
    input_count_including_one: usize,
    auxiliary_variable_count: usize,
    row_count_with_dummy_inputs: usize,
    padding_count: usize,
    domain_size: usize,
    satisfied: bool,
    failed_rows: Vec<usize>,
    vectors: Vec<VectorDigest>,
    quotient_divisibility_verified: bool,
}

#[derive(Serialize)]
struct VectorDigest {
    name: &'static str,
    count: usize,
    sha256_little_endian_scalars: String,
}

fn fail(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hexadecimal string has odd length".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid hexadecimal digit".to_owned())?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| "invalid hexadecimal digit".to_owned())?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn decode_scalar(value: &str) -> Result<Scalar, String> {
    let bytes = decode_hex(value)?;
    let repr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "scalar must be exactly 32 bytes".to_owned())?;
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

fn variable_index(identity: &str) -> Result<usize, String> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let index = index
            .parse::<usize>()
            .map_err(|_| "invalid input variable identity".to_owned())?;
        if index >= INPUT_COUNT {
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
        if index >= AUXILIARY_COUNT {
            return Err("auxiliary variable identity is out of range".to_owned());
        }
        return Ok(INPUT_COUNT + index);
    }
    Err("unknown variable identity".to_owned())
}

fn evaluate(terms: &[Term], assignments: &[Scalar]) -> Result<Scalar, String> {
    let mut result = Scalar::ZERO;
    for term in terms {
        let index = variable_index(&term.identity)?;
        let assignment = assignments
            .get(index)
            .ok_or_else(|| "variable identity exceeds assignment length".to_owned())?;
        result += decode_scalar(&term.coefficient_hex)? * assignment;
    }
    Ok(result)
}

fn padded_domain(values: &[Scalar]) -> Result<Domain, String> {
    Domain::from_coeffs(values.iter().copied().map(BellmanScalar).collect())
        .map_err(|_| "Bellman rejected QAP domain size".to_owned())
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

fn quotient(
    a_evaluations: &[Scalar],
    b_evaluations: &[Scalar],
    c_evaluations: &[Scalar],
    worker: &Worker,
) -> Result<(Vec<Scalar>, bool), String> {
    let mut a = padded_domain(a_evaluations)?;
    let mut b = padded_domain(b_evaluations)?;
    let mut c = padded_domain(c_evaluations)?;
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
    let final_coefficient = coefficients
        .pop()
        .ok_or_else(|| "Bellman produced an empty quotient vector".to_owned())?;
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

fn digest(values: &[Scalar]) -> VectorDigest {
    let mut hasher = Sha256::new();
    for value in values {
        hasher.update(value.to_repr().as_ref());
    }
    VectorDigest {
        name: "",
        count: values.len(),
        sha256_little_endian_scalars: format!("{:x}", hasher.finalize()),
    }
}

fn named_digest(name: &'static str, values: &[Scalar]) -> VectorDigest {
    let mut result = digest(values);
    result.name = name;
    result
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err(fail(
            "usage: sapling_spend_qap_reference <bellman-spend-trace.json> <output.json>",
        ));
    }
    let export: SpendExport = serde_json::from_reader(BufReader::new(File::open(&args[0])?))?;
    if export.format != "bellman-sapling-spend-reference-v1"
        || export.sapling_crypto_revision != SAPLING_REVISION
        || export.bellman_revision != BELLMAN_REVISION
        || export.observed_test_constraint_system_hash != EXPECTED_UPSTREAM_TEST_HASH
        || export.num_inputs_including_one != INPUT_COUNT
        || export.num_auxiliary_variables != AUXILIARY_COUNT
        || export.num_constraints != CONSTRAINT_COUNT
        || export.inputs.len() != INPUT_COUNT
        || export.auxiliary_variables.len() != AUXILIARY_COUNT
        || export.constraints.len() != CONSTRAINT_COUNT
    {
        return Err(fail(
            "Bellman Spend trace metadata does not match pinned dimensions",
        ));
    }

    let mut assignments = Vec::with_capacity(INPUT_COUNT + AUXILIARY_COUNT);
    for (index, variable) in export.inputs.iter().enumerate() {
        if variable.identity != format!("Input({index})") {
            return Err(fail("Bellman input assignment order is invalid"));
        }
        assignments.push(
            decode_scalar(
                variable
                    .assignment_hex
                    .as_deref()
                    .ok_or("Bellman input assignment is missing")?,
            )
            .map_err(fail)?,
        );
    }
    for (index, variable) in export.auxiliary_variables.iter().enumerate() {
        if variable.identity != format!("Aux({index})") {
            return Err(fail("Bellman auxiliary assignment order is invalid"));
        }
        assignments.push(
            decode_scalar(
                variable
                    .assignment_hex
                    .as_deref()
                    .ok_or("Bellman auxiliary assignment is missing")?,
            )
            .map_err(fail)?,
        );
    }
    if assignments[0] != Scalar::ONE {
        return Err(fail("Bellman implicit ONE assignment is not one"));
    }

    let mut a_evaluations = vec![Scalar::ZERO; CONSTRAINT_COUNT + INPUT_COUNT];
    let mut b_evaluations = vec![Scalar::ZERO; CONSTRAINT_COUNT + INPUT_COUNT];
    let mut c_evaluations = vec![Scalar::ZERO; CONSTRAINT_COUNT + INPUT_COUNT];
    let mut failed_rows = Vec::new();
    for (index, row) in export.constraints.iter().enumerate() {
        let a = evaluate(&row.a, &assignments).map_err(fail)?;
        let b = evaluate(&row.b, &assignments).map_err(fail)?;
        let c = evaluate(&row.c, &assignments).map_err(fail)?;
        if a * b != c {
            failed_rows.push(index);
        }
        a_evaluations[index] = a;
        b_evaluations[index] = b;
        c_evaluations[index] = c;
    }
    for (index, value) in assignments.iter().take(INPUT_COUNT).enumerate() {
        a_evaluations[CONSTRAINT_COUNT + index] = *value;
    }
    let domain_size = (CONSTRAINT_COUNT + INPUT_COUNT).next_power_of_two();
    a_evaluations.resize(domain_size, Scalar::ZERO);
    b_evaluations.resize(domain_size, Scalar::ZERO);
    c_evaluations.resize(domain_size, Scalar::ZERO);
    let satisfied = failed_rows.is_empty();
    if !satisfied || !export.satisfied {
        return Err(fail("Bellman Spend assignment is not fully satisfied"));
    }

    let worker = Worker::new();
    let a_coefficients = interpolate(&a_evaluations, &worker).map_err(fail)?;
    let b_coefficients = interpolate(&b_evaluations, &worker).map_err(fail)?;
    let c_coefficients = interpolate(&c_evaluations, &worker).map_err(fail)?;
    let (h_coefficients, zero_final_coefficient) =
        quotient(&a_evaluations, &b_evaluations, &c_evaluations, &worker).map_err(fail)?;
    let quotient_divisibility_verified = zero_final_coefficient
        && verify_quotient_identity(
            &a_coefficients,
            &b_coefficients,
            &c_coefficients,
            &h_coefficients,
            &worker,
        )
        .map_err(fail)?;
    if !quotient_divisibility_verified {
        return Err(fail("Bellman quotient polynomial identity did not verify"));
    }
    let mut h_padded = h_coefficients.clone();
    h_padded.resize(domain_size, Scalar::ZERO);
    let mut h_domain = padded_domain(&h_padded).map_err(fail)?;
    h_domain.fft(&worker);
    let h_evaluations = unwrap_domain(h_domain);

    let mut assignment_hasher = Sha256::new();
    for value in &assignments {
        assignment_hasher.update(value.to_repr().as_ref());
    }
    let assignment_sha256 = format!("{:x}", assignment_hasher.finalize());
    let vectors = vec![
        named_digest("a_evaluations", &a_evaluations),
        named_digest("b_evaluations", &b_evaluations),
        named_digest("c_evaluations", &c_evaluations),
        named_digest("a_polynomial_coefficients", &a_coefficients),
        named_digest("b_polynomial_coefficients", &b_coefficients),
        named_digest("c_polynomial_coefficients", &c_coefficients),
        named_digest("quotient_coefficients_h", &h_coefficients),
        named_digest("quotient_evaluations_h", &h_evaluations),
    ];
    let output = ReferenceOutput {
        format: "bellman-sapling-spend-qap-reference-v1",
        bellman_crate_version: "0.15.0",
        bellman_revision: BELLMAN_REVISION,
        sapling_revision: SAPLING_REVISION,
        assignment_sha256,
        assignment_hex: assignments.iter().copied().map(scalar_hex).collect(),
        quotient_coefficients_h_hex: h_coefficients
            .iter()
            .copied()
            .map(scalar_hex)
            .collect(),
        upstream_test_constraint_system_hash: export.observed_test_constraint_system_hash,
        constraint_count: CONSTRAINT_COUNT,
        input_count_including_one: INPUT_COUNT,
        auxiliary_variable_count: AUXILIARY_COUNT,
        row_count_with_dummy_inputs: CONSTRAINT_COUNT + INPUT_COUNT,
        padding_count: domain_size - CONSTRAINT_COUNT - INPUT_COUNT,
        domain_size,
        satisfied,
        failed_rows,
        vectors,
        quotient_divisibility_verified,
    };
    let mut output_file = BufWriter::new(File::create(&args[1])?);
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
