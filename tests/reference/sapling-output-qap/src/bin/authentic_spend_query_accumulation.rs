use std::env;
use std::fs::{File, read};
use std::io::{BufReader, BufWriter, Write};
use std::ops::{AddAssign, Mul};
use std::time::Instant;

use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use groth16::Parameters;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const PARAMETER_SHA256: &str =
    "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13";
const MAPPING_FINGERPRINT: &str =
    "183a399a8c7e749e011d690ffa216541ce1268e869723b4a0d4cb54d0cc54a08";
const MAGIC: &[u8; 8] = b"ZYSPMS01";

#[derive(Deserialize)]
struct QapSummary {
    format: String,
    assignment_sha256: String,
    assignment_hex: Vec<String>,
    quotient_coefficients_h_hex: Vec<String>,
    quotient_divisibility_verified: bool,
}

#[derive(Deserialize)]
struct Mapping {
    mapping_fingerprint_sha256: String,
    query_sections: QuerySections,
}

#[derive(Deserialize)]
struct QuerySections {
    a: QuerySection,
    b_g1: QuerySection,
    b_g2: QuerySection,
    l: QuerySection,
}

#[derive(Deserialize)]
struct QuerySection {
    upstream_variable_identities: Vec<String>,
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

fn identity_index(identity: &str) -> Result<usize, String> {
    if let Some(index) = identity
        .strip_prefix("Input(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return index
            .parse::<usize>()
            .map_err(|_| "invalid input identity".to_owned());
    }
    if let Some(index) = identity
        .strip_prefix("Aux(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return index
            .parse::<usize>()
            .map_err(|_| "invalid auxiliary identity".to_owned())
            .and_then(|value| {
                value
                    .checked_add(8)
                    .ok_or_else(|| "auxiliary identity overflow".to_owned())
            });
    }
    Err("unknown variable identity".to_owned())
}

fn mapped_scalars(
    identities: &[String],
    assignments: &[Scalar],
    expected_count: usize,
) -> Result<Vec<Scalar>, String> {
    if identities.len() != expected_count {
        return Err("query mapping count differs from Bellman section".to_owned());
    }
    identities
        .iter()
        .map(|identity| {
            let index = identity_index(identity)?;
            assignments
                .get(index)
                .copied()
                .ok_or_else(|| "query mapping exceeds witness assignment".to_owned())
        })
        .collect()
}

fn msm_g1(points: &[G1Affine], scalars: &[Scalar]) -> Result<G1Affine, String> {
    if points.len() != scalars.len() {
        return Err("G1 query/scalar length mismatch".to_owned());
    }
    let mut result = G1Projective::identity();
    for (point, scalar) in points.iter().zip(scalars) {
        if !bool::from(scalar.is_zero()) {
            result.add_assign(point.mul(scalar));
        }
    }
    Ok(result.into())
}

fn msm_g2(points: &[G2Affine], scalars: &[Scalar]) -> Result<G2Affine, String> {
    if points.len() != scalars.len() {
        return Err("G2 query/scalar length mismatch".to_owned());
    }
    let mut result = G2Projective::identity();
    for (point, scalar) in points.iter().zip(scalars) {
        if !bool::from(scalar.is_zero()) {
            result.add_assign(point.mul(scalar));
        }
    }
    Ok(result.into())
}

fn write_section(
    writer: &mut BufWriter<File>,
    name: &str,
    encoded: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    writer.write_all(&[name.len() as u8])?;
    writer.write_all(name.as_bytes())?;
    writer.write_all(&1u32.to_be_bytes())?;
    writer.write_all(encoded)?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: authentic_spend_query_accumulation <params> <bellman-qap.json> <mapping.json> <accumulations.bin>".into());
    }
    let file_bytes = read(&args[0])?;
    let digest = format!("{:x}", Sha256::digest(&file_bytes));
    if digest != PARAMETER_SHA256 {
        return Err("official Spend parameter SHA-256 mismatch".into());
    }

    let summary: QapSummary =
        serde_json::from_reader(BufReader::new(File::open(&args[1])?))?;
    if summary.format != "bellman-sapling-spend-qap-reference-v1"
        || !summary.quotient_divisibility_verified
        || summary.assignment_hex.len() != 98_646
        || summary.quotient_coefficients_h_hex.len() != 131_071
    {
        return Err("Bellman Spend QAP summary shape or validation mismatch".into());
    }
    let mapping: Mapping =
        serde_json::from_reader(BufReader::new(File::open(&args[2])?))?;
    if mapping.mapping_fingerprint_sha256 != MAPPING_FINGERPRINT {
        return Err("Spend query mapping fingerprint mismatch".into());
    }

    let assignments = summary
        .assignment_hex
        .iter()
        .map(|value| decode_scalar(value))
        .collect::<Result<Vec<_>, _>>()?;
    let h_scalars = summary
        .quotient_coefficients_h_hex
        .iter()
        .map(|value| decode_scalar(value))
        .collect::<Result<Vec<_>, _>>()?;
    if assignments[0] != Scalar::ONE {
        return Err("Bellman assignment does not start with ONE".into());
    }

    let parameters =
        Parameters::<Bls12>::read(BufReader::new(File::open(&args[0])?), true)?;
    if parameters.vk.ic.len() != 8
        || parameters.h.len() != 131_071
        || parameters.l.len() != 98_638
        || parameters.a.len() != 85_390
        || parameters.b_g1.len() != 61_300
        || parameters.b_g2.len() != 61_300
    {
        return Err("official Spend parameter query dimensions changed".into());
    }

    let a_scalars = mapped_scalars(
        &mapping.query_sections.a.upstream_variable_identities,
        &assignments,
        parameters.a.len(),
    )
    .map_err(|error| error.to_owned())?;
    let b_g1_scalars = mapped_scalars(
        &mapping.query_sections.b_g1.upstream_variable_identities,
        &assignments,
        parameters.b_g1.len(),
    )
    .map_err(|error| error.to_owned())?;
    let b_g2_scalars = mapped_scalars(
        &mapping.query_sections.b_g2.upstream_variable_identities,
        &assignments,
        parameters.b_g2.len(),
    )
    .map_err(|error| error.to_owned())?;
    let l_scalars = mapped_scalars(
        &mapping.query_sections.l.upstream_variable_identities,
        &assignments,
        parameters.l.len(),
    )
    .map_err(|error| error.to_owned())?;

    let started = Instant::now();
    let ic = msm_g1(&parameters.vk.ic, &assignments[..8]).map_err(|e| e.to_owned())?;
    let h = msm_g1(&parameters.h, &h_scalars).map_err(|e| e.to_owned())?;
    let l = msm_g1(&parameters.l, &l_scalars).map_err(|e| e.to_owned())?;
    let a = msm_g1(&parameters.a, &a_scalars).map_err(|e| e.to_owned())?;
    let b_g1 =
        msm_g1(&parameters.b_g1, &b_g1_scalars).map_err(|e| e.to_owned())?;
    let b_g2 =
        msm_g2(&parameters.b_g2, &b_g2_scalars).map_err(|e| e.to_owned())?;
    let elapsed = started.elapsed().as_secs_f64();

    let mut writer = BufWriter::new(File::create(&args[3])?);
    writer.write_all(MAGIC)?;
    write_section(&mut writer, "ic", &ic.to_uncompressed())?;
    write_section(&mut writer, "h", &h.to_uncompressed())?;
    write_section(&mut writer, "l", &l.to_uncompressed())?;
    write_section(&mut writer, "a", &a.to_uncompressed())?;
    write_section(&mut writer, "b_g1", &b_g1.to_uncompressed())?;
    write_section(&mut writer, "b_g2", &b_g2.to_uncompressed())?;
    writer.flush()?;
    eprintln!(
        "Bellman 0.15 accumulated all six Spend query sections in {elapsed:.3}s; witness {}",
        summary.assignment_sha256
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
