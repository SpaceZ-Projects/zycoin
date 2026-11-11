use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::ops::{AddAssign, Mul};
use std::time::Instant;

use bellman::domain::{EvaluationDomain, Scalar as BellmanScalar};
use bellman::multicore::Worker;
use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use groth16::Parameters;
use serde::{Deserialize, Serialize};

const EXPECTED_ROWS_SHA256: &str =
    "c17e909415811ce581349b54d1d2021cf77835ad126c54cbdb509a628890c761";
const EXPECTED_ASSIGNMENT_SHA256: &str =
    "b2e6789b3350848cbc2d96e3b9aef6fc74208b15effc08c3c53b936b245a71ea";
const EXPECTED_MAPPING_FINGERPRINT: &str =
    "b22fe72c3137ecc158b4b3a8cd7ce9aa2f08c86062424bb4fd4ecad5c3d306d2";
const EXPECTED_MATRIX_FINGERPRINT: &str =
    "cc1d052df9ea55d6d4aac21cae55615e84b1d5de54bc367894688ade9ab74368";
const EXPORT_MAGIC: &[u8; 8] = b"ZYMSM001";

type Domain = EvaluationDomain<Scalar, BellmanScalar<Scalar>>;

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

#[derive(Deserialize)]
struct QueryMapping {
    a_query: Vec<MappingEntry>,
    b_g1_query: Vec<MappingEntry>,
    b_g2_query: Vec<MappingEntry>,
    ic_query: Vec<MappingEntry>,
    mapping_fingerprint_sha256: String,
}

#[derive(Deserialize)]
struct MappingEntry {
    local_column: usize,
    query_index: usize,
}

#[derive(Serialize)]
struct Metrics {
    format: &'static str,
    bellman_crate_version: &'static str,
    parameter_sha256: &'static str,
    assignment_sha256: String,
    mapping_fingerprint_sha256: String,
    matrix_fingerprint: String,
    domain_size: usize,
    section_counts: SectionCounts,
    qap_quotient_seconds: f64,
    ic_accumulation_seconds: f64,
    h_accumulation_seconds: f64,
    l_accumulation_seconds: f64,
    a_accumulation_seconds: f64,
    b_g1_accumulation_seconds: f64,
    b_g2_accumulation_seconds: f64,
    identity_results: Vec<IdentityResult>,
}

#[derive(Serialize)]
struct SectionCounts {
    ic: usize,
    h: usize,
    l: usize,
    a: usize,
    b_g1: usize,
    b_g2: usize,
}

#[derive(Serialize)]
struct IdentityResult {
    name: &'static str,
    identity: bool,
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
        .ok_or_else(|| "noncanonical scalar-field value".to_owned())
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

fn quotient(
    rows: &[ArtifactRow],
    assignments: &[Scalar],
    input_count: usize,
    worker: &Worker,
) -> Result<(Vec<Scalar>, usize), String> {
    let mut a_values = Vec::with_capacity(rows.len() + input_count);
    let mut b_values = Vec::with_capacity(rows.len() + input_count);
    let mut c_values = Vec::with_capacity(rows.len() + input_count);
    for row in rows {
        let a = factor_value(&row.upstream_abc.a, assignments, input_count)?;
        let b = factor_value(&row.upstream_abc.b, assignments, input_count)?;
        let c = factor_value(&row.upstream_abc.c, assignments, input_count)?;
        if a * b != c {
            return Err("pinned Output witness does not satisfy the reference matrix".into());
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
    let domain_size = padded_domain(&a_values)?.as_ref().len();
    let mut a = padded_domain(&a_values)?;
    let mut b = padded_domain(&b_values)?;
    let mut c = padded_domain(&c_values)?;
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
    let mut h = unwrap_domain(a);
    if h.pop().is_none_or(|last| !bool::from(last.is_zero())) {
        return Err("Bellman QAP quotient is not divisible by the vanishing polynomial".into());
    }
    if h.len() != 8_191 {
        return Err("Bellman quotient coefficient count does not match Output H".into());
    }
    Ok((h, domain_size))
}

fn validate_mapping(
    entries: &[MappingEntry],
    point_count: usize,
    variable_count: usize,
) -> Result<(), String> {
    if entries.len() != point_count {
        return Err("sparse mapping count does not match parameter query section".into());
    }
    let mut query_seen = vec![false; point_count];
    let mut column_seen = vec![false; variable_count];
    for entry in entries {
        if entry.query_index >= point_count || entry.local_column >= variable_count {
            return Err("sparse mapping index is out of range".into());
        }
        if query_seen[entry.query_index] || column_seen[entry.local_column] {
            return Err("sparse mapping contains a duplicate index".into());
        }
        query_seen[entry.query_index] = true;
        column_seen[entry.local_column] = true;
    }
    if query_seen.iter().any(|seen| !seen) {
        return Err("sparse mapping omits a query index".into());
    }
    Ok(())
}

fn msm_g1(points: &[G1Affine], scalars: &[Scalar]) -> Result<G1Affine, String> {
    if points.len() != scalars.len() {
        return Err("G1 query/scalar length mismatch".into());
    }
    let mut result = G1Projective::identity();
    for (point, scalar) in points.iter().zip(scalars) {
        if !bool::from(scalar.is_zero()) {
            result.add_assign(point.mul(scalar));
        }
    }
    Ok(result.into())
}

fn msm_sparse_g1(
    points: &[G1Affine],
    mapping: &[MappingEntry],
    assignments: &[Scalar],
) -> Result<G1Affine, String> {
    validate_mapping(mapping, points.len(), assignments.len())?;
    let mut result = G1Projective::identity();
    for entry in mapping {
        let scalar = assignments
            .get(entry.local_column)
            .ok_or("mapped G1 scalar index is out of range")?;
        if !bool::from(scalar.is_zero()) {
            result.add_assign(points[entry.query_index].mul(scalar));
        }
    }
    Ok(result.into())
}

fn msm_sparse_g2(
    points: &[G2Affine],
    mapping: &[MappingEntry],
    assignments: &[Scalar],
) -> Result<G2Affine, String> {
    validate_mapping(mapping, points.len(), assignments.len())?;
    let mut result = G2Projective::identity();
    for entry in mapping {
        let scalar = assignments
            .get(entry.local_column)
            .ok_or("mapped G2 scalar index is out of range")?;
        if !bool::from(scalar.is_zero()) {
            result.add_assign(points[entry.query_index].mul(scalar));
        }
    }
    Ok(result.into())
}

fn write_section_header(
    writer: &mut BufWriter<File>,
    name: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    writer.write_all(&[name.len() as u8])?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(&(count as u32).to_be_bytes())?;
    Ok(())
}

fn write_g1(
    writer: &mut BufWriter<File>,
    name: &str,
    point: &G1Affine,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    write_section_header(writer, name, 1)?;
    let encoded = point.to_uncompressed();
    writer.write_all(&encoded)?;
    Ok(encoded.to_vec())
}

fn write_g2(
    writer: &mut BufWriter<File>,
    name: &str,
    point: &G2Affine,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    write_section_header(writer, name, 1)?;
    let encoded = point.to_uncompressed();
    writer.write_all(&encoded)?;
    Ok(encoded.to_vec())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("usage: authentic_output_msm_reference <params> <rows.json> <assignment.json> <mapping.json> <export.bin> <metrics.json>".into());
    }
    let rows: RowArtifact = serde_json::from_reader(BufReader::new(File::open(&args[1])?))?;
    let input: AssignmentInput = serde_json::from_reader(BufReader::new(File::open(&args[2])?))?;
    let mapping: QueryMapping = serde_json::from_reader(BufReader::new(File::open(&args[3])?))?;
    if rows.format != "zycoin-bellman-sapling-output-row-correspondence-v1"
        || rows.rows.len() != 7_827
    {
        return Err("pinned Output row artifact format/count mismatch".into());
    }
    if input.format != "zycoin-sapling-output-qap-assignment-input-v1"
        || input.row_artifact_sha256 != EXPECTED_ROWS_SHA256
        || input.variable_mapping_fingerprint_sha256
            != "c063108e9a779ca271407b207609c8daf1a05c99dc1eb4104d37cb76347155dc"
        || input.matrix_fingerprint != EXPECTED_MATRIX_FINGERPRINT
        || mapping.mapping_fingerprint_sha256 != EXPECTED_MAPPING_FINGERPRINT
    {
        return Err("pinned Output matrix/witness/query mapping provenance mismatch".into());
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
    if assignments[0] != Scalar::ONE {
        return Err("Output assignment does not start with the constant ONE".into());
    }

    let parameters = Parameters::<Bls12>::read(BufReader::new(File::open(&args[0])?), true)?;
    if parameters.vk.ic.len() != 6
        || parameters.h.len() != 8_191
        || parameters.l.len() != 7_821
        || parameters.a.len() != 6_298
        || parameters.b_g1.len() != 4_850
        || parameters.b_g2.len() != 4_850
    {
        return Err("official Output parameter query counts do not match".into());
    }
    if mapping.ic_query.len() != 6
        || mapping
            .ic_query
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.query_index != index || entry.local_column != index)
    {
        return Err("IC mapping is not ONE followed by five public inputs".into());
    }
    let public_values = &assignments[..6];

    let qap_started = Instant::now();
    let worker = Worker::new();
    let (h_scalars, domain_size) = quotient(&rows.rows, &assignments, 6, &worker)?;
    let qap_seconds = qap_started.elapsed().as_secs_f64();
    if domain_size != 8_192 {
        return Err("unexpected Bellman Output QAP domain size".into());
    }

    let ic_started = Instant::now();
    let ic = msm_g1(&parameters.vk.ic, public_values)?;
    let ic_seconds = ic_started.elapsed().as_secs_f64();

    let h_started = Instant::now();
    let h = msm_g1(&parameters.h, &h_scalars)?;
    let h_seconds = h_started.elapsed().as_secs_f64();

    let l_started = Instant::now();
    let l = msm_g1(&parameters.l, &assignments[6..])?;
    let l_seconds = l_started.elapsed().as_secs_f64();

    let a_started = Instant::now();
    let a = msm_sparse_g1(&parameters.a, &mapping.a_query, &assignments)?;
    let a_seconds = a_started.elapsed().as_secs_f64();

    if mapping.b_g1_query.len() != mapping.b_g2_query.len()
        || mapping
            .b_g1_query
            .iter()
            .zip(&mapping.b_g2_query)
            .any(|(g1, g2)| g1.query_index != g2.query_index || g1.local_column != g2.local_column)
    {
        return Err("B_G1 and B_G2 mappings differ".into());
    }
    let b_g1_started = Instant::now();
    let b_g1 = msm_sparse_g1(&parameters.b_g1, &mapping.b_g1_query, &assignments)?;
    let b_g1_seconds = b_g1_started.elapsed().as_secs_f64();

    let b_g2_started = Instant::now();
    let b_g2 = msm_sparse_g2(&parameters.b_g2, &mapping.b_g2_query, &assignments)?;
    let b_g2_seconds = b_g2_started.elapsed().as_secs_f64();

    let mut export = BufWriter::new(File::create(&args[4])?);
    export.write_all(EXPORT_MAGIC)?;
    write_g1(&mut export, "ic", &ic)?;
    write_g1(&mut export, "h", &h)?;
    write_g1(&mut export, "l", &l)?;
    write_g1(&mut export, "a", &a)?;
    write_g1(&mut export, "b_g1", &b_g1)?;
    write_g2(&mut export, "b_g2", &b_g2)?;
    export.flush()?;

    let metrics = Metrics {
        format: "bellman-0.15-authentic-output-msm-reference-v1",
        bellman_crate_version: "0.15.0",
        parameter_sha256: "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4",
        assignment_sha256: case.assignment_sha256.clone(),
        mapping_fingerprint_sha256: mapping.mapping_fingerprint_sha256,
        matrix_fingerprint: input.matrix_fingerprint,
        domain_size,
        section_counts: SectionCounts {
            ic: parameters.vk.ic.len(),
            h: parameters.h.len(),
            l: parameters.l.len(),
            a: parameters.a.len(),
            b_g1: parameters.b_g1.len(),
            b_g2: parameters.b_g2.len(),
        },
        qap_quotient_seconds: qap_seconds,
        ic_accumulation_seconds: ic_seconds,
        h_accumulation_seconds: h_seconds,
        l_accumulation_seconds: l_seconds,
        a_accumulation_seconds: a_seconds,
        b_g1_accumulation_seconds: b_g1_seconds,
        b_g2_accumulation_seconds: b_g2_seconds,
        identity_results: vec![
            IdentityResult {
                name: "ic",
                identity: bool::from(ic.is_identity()),
            },
            IdentityResult {
                name: "h",
                identity: bool::from(h.is_identity()),
            },
            IdentityResult {
                name: "l",
                identity: bool::from(l.is_identity()),
            },
            IdentityResult {
                name: "a",
                identity: bool::from(a.is_identity()),
            },
            IdentityResult {
                name: "b_g1",
                identity: bool::from(b_g1.is_identity()),
            },
            IdentityResult {
                name: "b_g2",
                identity: bool::from(b_g2.is_identity()),
            },
        ],
    };
    serde_json::to_writer(BufWriter::new(File::create(&args[5])?), &metrics)?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
