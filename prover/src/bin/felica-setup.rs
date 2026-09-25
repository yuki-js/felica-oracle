//! Thin frontend over [`felica_prover::setup`]: parse args, write files.
//! All crypto lives in the library.

use std::path::{Path, PathBuf};

use ark_serialize::CanonicalSerialize;
use rand::rngs::OsRng;

use felica_prover::blank_constraint_counts;
use felica_prover::setup::{generate_keys, load_proving_key, load_verifying_key};

const PK_FILE: &str = "proving_key.bin";
const VK_FILE: &str = "verifying_key.bin";

fn fail(msg: String) -> ! {
    eprintln!("felica-setup: {msg}");
    eprintln!("usage: felica-setup <OUT_DIR> [--force]");
    std::process::exit(1);
}

fn write_key(path: &Path, bytes: &[u8], force: bool) -> Result<(), String> {
    if path.exists() && !force {
        return Err(format!(
            "{} exists (pass --force to overwrite)",
            path.display()
        ));
    }
    std::fs::write(path, bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out_dir = match args.next() {
        Some(d) => PathBuf::from(d),
        None => fail("missing OUT_DIR".to_string()),
    };
    let mut force = false;
    for arg in args {
        if arg == "--force" {
            force = true;
        } else {
            fail(format!("unknown argument: {arg}"));
        }
    }

    if let Err(e) = run(&out_dir, force) {
        fail(e);
    }
}

fn run(out_dir: &Path, force: bool) -> Result<(), String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("create dir {}: {e}", out_dir.display()))?;

    report_circuit();
    let (pk_bytes, vk_bytes) = generate_and_encode()?;
    verify_roundtrip(&pk_bytes, &vk_bytes)?;
    write_outputs(out_dir, &pk_bytes, &vk_bytes, force)
}

fn report_circuit() {
    let (n_constraints, n_instance, n_witness) = blank_constraint_counts();
    println!("circuit: {n_constraints} constraints, {n_instance} instance, {n_witness} witness");
}

fn encode(label: &str, key: &impl CanonicalSerialize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    key.serialize_compressed(&mut bytes)
        .map_err(|e| format!("serialize {label}: {e}"))?;
    Ok(bytes)
}

fn generate_and_encode() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut rng = OsRng;
    let (pk, vk) = generate_keys(&mut rng).map_err(|e| e.to_string())?;
    Ok((encode("proving key", &pk)?, encode("verifying key", &vk)?))
}

/// Byte-level roundtrip: the files must load through the exact functions
/// the oracle and tests use, and re-encode identically. Catches format
/// skew and truncation at ceremony time, not at first attest.
fn verify_roundtrip(pk_bytes: &[u8], vk_bytes: &[u8]) -> Result<(), String> {
    let pk_rt = load_proving_key(pk_bytes).map_err(|e| format!("roundtrip pk: {e}"))?;
    let vk_rt = load_verifying_key(vk_bytes).map_err(|e| format!("roundtrip vk: {e}"))?;
    if encode("proving key", &pk_rt)? != pk_bytes {
        return Err("proving key roundtrip mismatch".to_string());
    }
    if encode("verifying key", &vk_rt)? != vk_bytes {
        return Err("verifying key roundtrip mismatch".to_string());
    }
    Ok(())
}

fn write_outputs(
    out_dir: &Path,
    pk_bytes: &[u8],
    vk_bytes: &[u8],
    force: bool,
) -> Result<(), String> {
    let pk_path = out_dir.join(PK_FILE);
    let vk_path = out_dir.join(VK_FILE);
    write_key(&pk_path, pk_bytes, force)?;
    write_key(&vk_path, vk_bytes, force)?;

    println!("wrote {} ({} bytes)", pk_path.display(), pk_bytes.len());
    println!("wrote {} ({} bytes)", vk_path.display(), vk_bytes.len());
    println!("next: mount {PK_FILE} at the oracle, embed {VK_FILE} into verifiers");
    Ok(())
}
