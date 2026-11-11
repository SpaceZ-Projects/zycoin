use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Write};

use bls12_381::{Bls12, Scalar};
use ff::{Field, PrimeField};
use groth16::{Parameters, Proof, prepare_verifying_key, verify_proof};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct VerificationInput {
    format: String,
    public_input_order: Vec<String>,
    cases: Vec<ProofCase>,
}

#[derive(Deserialize)]
struct ProofCase {
    name: String,
    proof_hex: String,
    public_inputs_hex: Vec<String>,
}

#[derive(Serialize)]
struct VerificationOutput {
    format: &'static str,
    bellman_crate_version: &'static str,
    witness_validation: WitnessValidation,
    results: Vec<CaseResult>,
}

#[derive(Serialize)]
struct CaseResult {
    name: String,
    accepted: bool,
    canonical_proof_encoding: bool,
    public_inputs_canonical: bool,
}

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
struct WitnessValidation {
    assignment_sha256: String,
    constraints_checked: usize,
    satisfied: bool,
    public_inputs_match_assignment: bool,
    public_input_order: Vec<String>,
}

const EXPECTED_ASSIGNMENT_SHA256: &str =
    "b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea";
const EXPECTED_ROWS_SHA256: &str =
    "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761";
const EXPECTED_VARIABLE_MAPPING_FINGERPRINT: &str =
    "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc";
const EXPECTED_MATRIX_FINGERPRINT: &str =
    "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368";
const OUTPUT_PUBLIC_INPUT_ORDER: [&str; 5] = ["cv.u", "cv.v", "epk.u", "epk.v", "cmu.u"];

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex input has odd length".to_owned());
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

fn variable_index(identity: &str) -> Result<usize, String> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let index = index
            .parse::<usize>()
            .map_err(|_| "invalid input variable identity".to_owned())?;
        if index >= 6 {
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
        return 6usize
            .checked_add(index)
            .ok_or_else(|| "auxiliary variable index overflow".to_owned());
    }
    Err("unknown variable identity".to_owned())
}

fn factor_value(factor: &Factor, assignments: &[Scalar]) -> Result<Scalar, String> {
    let mut result = Scalar::ZERO;
    for term in &factor.canonical_terms {
        let index = variable_index(&term.identity)?;
        let assignment = assignments
            .get(index)
            .ok_or_else(|| "matrix identity exceeds assignment length".to_owned())?;
        let coefficient = decode_hex(&term.coefficient_hex)?;
        let repr: [u8; 32] = coefficient
            .try_into()
            .map_err(|_| "matrix coefficient has invalid width".to_owned())?;
        let coefficient: Scalar = Option::<Scalar>::from(Scalar::from_repr(repr))
            .ok_or_else(|| "matrix coefficient is noncanonical".to_owned())?;
        result += coefficient * assignment;
    }
    Ok(result)
}

fn validate_witness(
    rows_path: &str,
    assignment_path: &str,
) -> Result<(WitnessValidation, Vec<Scalar>), Box<dyn std::error::Error>> {
    let rows: RowArtifact = serde_json::from_reader(BufReader::new(File::open(rows_path)?))?;
    let input: AssignmentInput =
        serde_json::from_reader(BufReader::new(File::open(assignment_path)?))?;
    if rows.format != "zycoin-bellman-sapling-output-row-correspondence-v1"
        || rows.rows.len() != 7_827
        || input.format != "zycoin-sapling-output-qap-assignment-input-v1"
        || input.row_artifact_sha256 != EXPECTED_ROWS_SHA256
        || input.variable_mapping_fingerprint_sha256 != EXPECTED_VARIABLE_MAPPING_FINGERPRINT
        || input.matrix_fingerprint != EXPECTED_MATRIX_FINGERPRINT
    {
        return Err("pinned Output witness/matrix provenance mismatch".into());
    }
    let case = input
        .cases
        .iter()
        .find(|case| case.name == "zcash-note-encryption-vector-0")
        .ok_or("pinned Output witness is absent")?;
    if case.assignment_sha256 != EXPECTED_ASSIGNMENT_SHA256 || case.assignment_hex.len() != 7_827 {
        return Err("pinned Output assignment hash/shape mismatch".into());
    }
    let assignments = case
        .assignment_hex
        .iter()
        .map(|value| {
            let bytes = decode_hex(value)?;
            let repr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "assignment scalar has invalid width".to_owned())?;
            Option::from(Scalar::from_repr(repr))
                .ok_or_else(|| "assignment scalar is noncanonical".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if assignments[0] != Scalar::ONE {
        return Err("pinned Output assignment does not begin with ONE".into());
    }
    for row in &rows.rows {
        let a = factor_value(&row.upstream_abc.a, &assignments)?;
        let b = factor_value(&row.upstream_abc.b, &assignments)?;
        let c = factor_value(&row.upstream_abc.c, &assignments)?;
        if a * b != c {
            return Err("pinned Output assignment does not satisfy every row".into());
        }
    }
    Ok((
        WitnessValidation {
            assignment_sha256: case.assignment_sha256.clone(),
            constraints_checked: rows.rows.len(),
            satisfied: true,
            public_inputs_match_assignment: false,
            public_input_order: OUTPUT_PUBLIC_INPUT_ORDER
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        },
        assignments,
    ))
}

fn verify_case(
    case: &ProofCase,
    parameters: &Parameters<Bls12>,
) -> Result<CaseResult, Box<dyn std::error::Error>> {
    let proof_bytes = match decode_hex(&case.proof_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(CaseResult {
                name: case.name.clone(),
                accepted: false,
                canonical_proof_encoding: false,
                public_inputs_canonical: false,
            });
        }
    };
    let mut cursor = Cursor::new(proof_bytes.as_slice());
    let proof = match Proof::<Bls12>::read(&mut cursor) {
        Ok(proof) => proof,
        Err(_) => {
            return Ok(CaseResult {
                name: case.name.clone(),
                accepted: false,
                canonical_proof_encoding: false,
                public_inputs_canonical: false,
            });
        }
    };
    if cursor.position() != proof_bytes.len() as u64 {
        return Ok(CaseResult {
            name: case.name.clone(),
            accepted: false,
            canonical_proof_encoding: false,
            public_inputs_canonical: false,
        });
    }
    let mut reencoded = Vec::new();
    proof.write(&mut reencoded)?;
    let canonical_proof_encoding = reencoded == proof_bytes;

    let public_inputs = case
        .public_inputs_hex
        .iter()
        .map(|value| {
            let bytes = decode_hex(value)?;
            let repr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "public scalar has invalid width".to_owned())?;
            Option::from(Scalar::from_repr(repr))
                .ok_or_else(|| "public scalar is noncanonical".to_owned())
        })
        .collect::<Result<Vec<_>, _>>();
    let public_inputs = match public_inputs {
        Ok(values) if values.len() == parameters.vk.ic.len() - 1 => values,
        _ => {
            return Ok(CaseResult {
                name: case.name.clone(),
                accepted: false,
                canonical_proof_encoding,
                public_inputs_canonical: false,
            });
        }
    };

    let prepared_vk = prepare_verifying_key(&parameters.vk);
    let accepted =
        canonical_proof_encoding && verify_proof(&prepared_vk, &proof, &public_inputs).is_ok();
    Ok(CaseResult {
        name: case.name.clone(),
        accepted,
        canonical_proof_encoding,
        public_inputs_canonical: true,
    })
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: verify_python_output_proof <params> <rows.json> <assignment.json> <cases.json> <results.json>".into());
    }
    let parameters = Parameters::<Bls12>::read(BufReader::new(File::open(&args[0])?), true)?;
    if parameters.vk.ic.len() != 6 {
        return Err("official Output verification key must have six IC points".into());
    }
    let (mut witness_validation, assignments) = validate_witness(&args[1], &args[2])?;
    let input: VerificationInput = serde_json::from_reader(BufReader::new(File::open(&args[3])?))?;
    if input.format != "zycoin-python-output-proof-cases-v1" || input.cases.len() < 5 {
        return Err("unexpected Output proof verification case input".into());
    }
    if input.public_input_order != OUTPUT_PUBLIC_INPUT_ORDER {
        return Err("Output public-input order differs from the pinned Bellman circuit".into());
    }
    let expected_public_inputs = assignments[1..6]
        .iter()
        .map(|value| {
            value
                .to_repr()
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    if input.cases[0].name != "valid" || input.cases[0].public_inputs_hex != expected_public_inputs
    {
        return Err(
            "proof public inputs do not match Bellman's independently checked witness".into(),
        );
    }
    witness_validation.public_inputs_match_assignment = true;
    let results = input
        .cases
        .iter()
        .map(|case| verify_case(case, &parameters))
        .collect::<Result<Vec<_>, _>>()?;
    let mut output = BufWriter::new(File::create(&args[4])?);
    serde_json::to_writer(
        &mut output,
        &VerificationOutput {
            format: "bellman-0.15-python-output-proof-verification-v1",
            bellman_crate_version: "0.15.0",
            witness_validation,
            results,
        },
    )?;
    output.flush()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
