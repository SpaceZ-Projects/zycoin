use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use bellman::{Circuit, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use bls12_381::{Bls12, G1Affine, G2Affine, Scalar};
use ff::{Field, PrimeField};
use groth16::{Parameters, create_random_proof, prepare_verifying_key, verify_proof};
use rand_core::SeedableRng;
use rand_xorshift::XorShiftRng;
use serde::Deserialize;

const EXPECTED_ROWS_SHA256: &str =
    "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761";
const EXPECTED_ASSIGNMENT_SHA256: &str =
    "b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea";
const QUERY_EXPORT_MAGIC: &[u8; 8] = b"ZYQEXP01";

fn write_section_header(
    writer: &mut BufWriter<File>,
    name: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize || count > u32::MAX as usize {
        return Err("query export section metadata is out of range".into());
    }
    writer.write_all(&[name_bytes.len() as u8])?;
    writer.write_all(name_bytes)?;
    writer.write_all(&(count as u32).to_be_bytes())?;
    Ok(())
}

fn write_g1_section(
    writer: &mut BufWriter<File>,
    name: &str,
    points: &[G1Affine],
) -> Result<(), Box<dyn std::error::Error>> {
    write_section_header(writer, name, points.len())?;
    for point in points {
        writer.write_all(&point.to_uncompressed())?;
    }
    Ok(())
}

fn write_g2_section(
    writer: &mut BufWriter<File>,
    name: &str,
    points: &[G2Affine],
) -> Result<(), Box<dyn std::error::Error>> {
    write_section_header(writer, name, points.len())?;
    for point in points {
        writer.write_all(&point.to_uncompressed())?;
    }
    Ok(())
}

fn write_query_export(
    path: &str,
    parameters: &Parameters<Bls12>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = BufWriter::new(File::create(path)?);
    writer.write_all(QUERY_EXPORT_MAGIC)?;
    write_g1_section(&mut writer, "ic", &parameters.vk.ic)?;
    write_g1_section(&mut writer, "h", &parameters.h)?;
    write_g1_section(&mut writer, "l", &parameters.l)?;
    write_g1_section(&mut writer, "a", &parameters.a)?;
    write_g1_section(&mut writer, "b_g1", &parameters.b_g1)?;
    write_g2_section(&mut writer, "b_g2", &parameters.b_g2)?;
    writer.flush()?;
    Ok(())
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
    upstream_label: String,
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

struct OutputMatrixCircuit {
    input_assignments: Vec<Scalar>,
    auxiliary_assignments: Vec<Scalar>,
    rows: Vec<ArtifactRow>,
}

fn decode_hex(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() != expected_bytes * 2 {
        return Err(format!(
            "expected {} hexadecimal characters",
            expected_bytes * 2
        ));
    }
    let mut decoded = Vec::with_capacity(expected_bytes);
    for pair in value.as_bytes().chunks_exact(2) {
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
        .ok_or_else(|| "noncanonical scalar-field assignment".to_owned())
}

fn variable_index(identity: &str) -> Result<(bool, usize), String> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Ok((
            true,
            index
                .parse::<usize>()
                .map_err(|_| "invalid input identity".to_owned())?,
        ));
    }
    if let Some(index) = identity
        .strip_prefix("Aux(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Ok((
            false,
            index
                .parse::<usize>()
                .map_err(|_| "invalid auxiliary identity".to_owned())?,
        ));
    }
    Err("unknown typed variable identity".to_owned())
}

fn build_linear_combination(
    factor: &Factor,
    inputs: &[Variable],
    auxiliaries: &[Variable],
) -> Result<LinearCombination<Scalar>, String> {
    let mut result = LinearCombination::zero();
    for term in &factor.canonical_terms {
        let (is_input, index) = variable_index(&term.identity)?;
        let variable = if is_input {
            inputs.get(index)
        } else {
            auxiliaries.get(index)
        }
        .ok_or_else(|| format!("matrix variable {} is out of range", term.identity))?;
        let coefficient = decode_scalar(&term.coefficient_hex)?;
        result = result + (coefficient, *variable);
    }
    Ok(result)
}

impl Circuit<Scalar> for OutputMatrixCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        if self.input_assignments.len() != 6
            || self.input_assignments[0] != Scalar::ONE
            || self.auxiliary_assignments.len() != 7_821
            || self.rows.len() != 7_827
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        let mut inputs = vec![Variable::new_unchecked(Index::Input(0))];
        for (index, value) in self.input_assignments.iter().enumerate().skip(1) {
            inputs.push(cs.alloc_input(|| format!("Output public input {index}"), || Ok(*value))?);
        }
        let mut auxiliaries = Vec::with_capacity(self.auxiliary_assignments.len());
        for (index, value) in self.auxiliary_assignments.iter().enumerate() {
            auxiliaries.push(cs.alloc(|| format!("Output auxiliary {index}"), || Ok(*value))?);
        }

        for row in &self.rows {
            let a = build_linear_combination(&row.upstream_abc.a, &inputs, &auxiliaries)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            let b = build_linear_combination(&row.upstream_abc.b, &inputs, &auxiliaries)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            let c = build_linear_combination(&row.upstream_abc.c, &inputs, &auxiliaries)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            cs.enforce(
                || row.upstream_label.clone(),
                |lc| lc + &a,
                |lc| lc + &b,
                |lc| lc + &c,
            );
        }
        Ok(())
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err(
            "usage: authentic_output_prover <params> <rows.json> <assignment.json> <proof.bin> <query-export.bin>"
                .into(),
        );
    }
    let row_artifact: RowArtifact = serde_json::from_reader(BufReader::new(File::open(&args[1])?))?;
    let input: AssignmentInput = serde_json::from_reader(BufReader::new(File::open(&args[2])?))?;
    if row_artifact.format != "zycoin-bellman-sapling-output-row-correspondence-v1"
        || row_artifact.rows.len() != 7_827
    {
        return Err("pinned Output row artifact format/count mismatch".into());
    }
    if input.format != "zycoin-sapling-output-qap-assignment-input-v1"
        || input.row_artifact_sha256 != EXPECTED_ROWS_SHA256
        || input.variable_mapping_fingerprint_sha256
            != "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
        || input.matrix_fingerprint
            != "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368"
    {
        return Err("pinned Output assignment/matrix provenance mismatch".into());
    }
    let case = input
        .cases
        .iter()
        .find(|case| case.name == "zcash-note-encryption-vector-0")
        .ok_or("pinned Output witness is absent")?;
    if case.assignment_sha256 != EXPECTED_ASSIGNMENT_SHA256 || case.assignment_hex.len() != 7_827 {
        return Err("pinned Output witness fingerprint/shape mismatch".into());
    }
    let assignments = case
        .assignment_hex
        .iter()
        .map(|value| decode_scalar(value))
        .collect::<Result<Vec<_>, _>>()?;
    let circuit = OutputMatrixCircuit {
        input_assignments: assignments[..6].to_vec(),
        auxiliary_assignments: assignments[6..].to_vec(),
        rows: row_artifact.rows,
    };
    let public_inputs = assignments[1..6].to_vec();

    let parameters = Parameters::<Bls12>::read(BufReader::new(File::open(&args[0])?), true)?;
    let vk = &parameters.vk;
    if vk.ic.len() != 6
        || parameters.h.len() != 8_191
        || parameters.l.len() != 7_821
        || parameters.a.len() != 6_298
        || parameters.b_g1.len() != 4_850
        || parameters.b_g2.len() != 4_850
    {
        return Err("authentic parameter query counts do not match pinned Output map".into());
    }
    write_query_export(&args[4], &parameters)?;
    let mut rng = XorShiftRng::from_seed([
        0x5a, 0x59, 0x43, 0x4f, 0x49, 0x4e, 0x2d, 0x4f, 0x55, 0x54, 0x50, 0x55, 0x54, 0x2d, 0x30,
        0x31,
    ]);
    let proof = create_random_proof(circuit, &parameters, &mut rng)?;
    let prepared_vk = prepare_verifying_key(vk);
    verify_proof(&prepared_vk, &proof, &public_inputs)?;
    let mut writer = BufWriter::new(File::create(&args[3])?);
    proof.write(&mut writer)?;
    writer.flush()?;
    eprintln!(
        "bellman proof created and verified with IC={} H={} L={} A={} B_G1={} B_G2={}",
        vk.ic.len(),
        parameters.h.len(),
        parameters.l.len(),
        parameters.a.len(),
        parameters.b_g1.len(),
        parameters.b_g2.len()
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
