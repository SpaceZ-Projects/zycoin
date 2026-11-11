use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

use bls12_381::{Bls12, G1Affine, G2Affine};
use groth16::Parameters;

const MAGIC: &[u8; 8] = b"ZYQEXP01";

fn write_header(
    writer: &mut BufWriter<File>,
    name: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let name = name.as_bytes();
    if name.len() > u8::MAX as usize || count > u32::MAX as usize {
        return Err("query export section metadata is out of range".into());
    }
    writer.write_all(&[name.len() as u8])?;
    writer.write_all(name)?;
    writer.write_all(&(count as u32).to_be_bytes())?;
    Ok(())
}

fn write_g1(
    writer: &mut BufWriter<File>,
    name: &str,
    points: &[G1Affine],
) -> Result<(), Box<dyn std::error::Error>> {
    write_header(writer, name, points.len())?;
    for point in points {
        writer.write_all(&point.to_uncompressed())?;
    }
    Ok(())
}

fn write_g2(
    writer: &mut BufWriter<File>,
    name: &str,
    points: &[G2Affine],
) -> Result<(), Box<dyn std::error::Error>> {
    write_header(writer, name, points.len())?;
    for point in points {
        writer.write_all(&point.to_uncompressed())?;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: export_parameter_queries <params> <query-export>".into());
    }
    let parameters = Parameters::<Bls12>::read(BufReader::new(File::open(&args[1])?), true)?;
    let mut writer = BufWriter::new(File::create(&args[2])?);
    writer.write_all(MAGIC)?;
    write_g1(&mut writer, "ic", &parameters.vk.ic)?;
    write_g1(&mut writer, "h", &parameters.h)?;
    write_g1(&mut writer, "l", &parameters.l)?;
    write_g1(&mut writer, "a", &parameters.a)?;
    write_g1(&mut writer, "b_g1", &parameters.b_g1)?;
    write_g2(&mut writer, "b_g2", &parameters.b_g2)?;
    writer.flush()?;
    eprintln!(
        "Bellman 0.15 exported IC={} H={} L={} A={} B_G1={} B_G2={}",
        parameters.vk.ic.len(),
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
