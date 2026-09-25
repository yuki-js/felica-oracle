//! Key-provisioning wizard: ingest `keys.jsonl` records, emit `keys.json`.
//!
//! Run: `cargo run -p felica-prover --bin felica-keys -- [OUT] [--force]`
//!
//! Flow: system-key record (1 line, node `FFFF`) → area records (lines
//! until `{}`) → service records (lines until `{}`). Each line is a full
//! JSONL record, e.g.:
//! `{"system_code":"0003","node":"FFFF","algo":"DES","version":"0000","idm":null,"key":"00112233445566FF"}`
//! Only `DES` with `idm: null` is supported (single-card oracle).
//! Writes `keys.json` (derived GSK/USK + node path, for the Secret) next
//! to a normalized `keys.jsonl`. Prompts go to stderr; terminal echoes
//! input — prefer stdin redirect for real keys.

use std::io::Write;
use std::path::{Path, PathBuf};

use felica::felica_standard::generate_service_keys_des;
use serde::Deserialize;

/// One `keys.jsonl` line (felica-rs `JsonlKeyRecord` shape, minimally).
#[derive(Debug, Clone, Deserialize)]
struct JsonlRecord {
    system_code: String,
    node: String,
    algo: String,
    version: String,
    #[serde(default)]
    idm: Option<String>,
    key: String,
}

fn fail(msg: String) -> ! {
    eprintln!("felica-keys: {msg}");
    eprintln!("usage: felica-keys [OUT] [--force]");
    std::process::exit(1);
}

fn ask(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    std::io::stderr()
        .flush()
        .map_err(|e| format!("prompt output: {e}"))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read stdin: {e}"))?;
    Ok(line.trim().to_string())
}

fn parse_hex_u16(label: &str, s: &str) -> Result<u16, String> {
    let s = s.trim();
    let digits = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u16::from_str_radix(digits, 16).map_err(|_| format!("{label}: not hex u16: {s:?}"))
}

fn parse_key(label: &str, rec: &JsonlRecord) -> Result<[u8; 8], String> {
    if !rec.algo.eq_ignore_ascii_case("DES") {
        return Err(format!("{label}: algo {:?} unsupported (DES only)", rec.algo));
    }
    // `version` is required by the format but unused; `idm` must be null
    // (None after deserialization) — this oracle serves a single card chain.
    if rec.idm.is_some() {
        return Err(format!("{label}: card-specific idm unsupported (use null)"));
    }
    let v = hex::decode(rec.key.trim())
        .map_err(|_| format!("{label}: not hex key: {:?}", rec.key))?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("{label}: expected 8 bytes, got {}", v.len()))
}

/// Read record lines until a literal `{}` line. Empty sections rejected.
fn read_records(label: &str) -> Result<Vec<JsonlRecord>, String> {
    let mut recs = Vec::new();
    loop {
        let line = ask(&format!("{label} record (JSONL, `{}` to end): ", "{}"))?;
        if line == "{}" {
            break;
        }
        let rec: JsonlRecord =
            serde_json::from_str(&line).map_err(|e| format!("{label}: bad record: {e}"))?;
        recs.push(rec);
    }
    if recs.is_empty() {
        return Err(format!("{label}: at least one record required"));
    }
    Ok(recs)
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut out = PathBuf::from("keys.json");
    let mut force = false;
    for arg in args.by_ref() {
        if arg == "--force" {
            force = true;
        } else if arg.starts_with('-') {
            fail(format!("unknown argument: {arg}"));
        } else {
            out = PathBuf::from(arg);
        }
    }

    if let Err(e) = run(&out, force) {
        fail(e);
    }
}

fn run(out: &Path, force: bool) -> Result<(), String> {
    eprintln!("FeliCa key-provisioning wizard (input echoes; prefer stdin redirect).");

    let sys_line = ask("system-key record (JSONL, node FFFF): ")?;
    if sys_line == "{}" {
        return Err("system-key: record required".to_string());
    }
    let sys: JsonlRecord =
        serde_json::from_str(&sys_line).map_err(|e| format!("system-key: bad record: {e}"))?;
    let system_code = parse_hex_u16("system_code", &sys.system_code)?;
    let system_node = parse_hex_u16("node", &sys.node)?;
    if system_node != 0xFFFF {
        return Err(format!("system-key: node must be FFFF, got {:04X}", system_node));
    }
    let system_key = parse_key("system-key", &sys)?;

    let area_recs = read_records("area")?;
    let svc_recs = read_records("service")?;

    let mut area_keys = Vec::with_capacity(area_recs.len());
    let mut areas = Vec::with_capacity(area_recs.len());
    for rec in &area_recs {
        if parse_hex_u16("system_code", &rec.system_code)? != system_code {
            return Err("area: system_code mismatch".to_string());
        }
        areas.push(parse_hex_u16("node", &rec.node)?);
        area_keys.push(parse_key("area", rec)?);
    }
    let mut svc_keys = Vec::with_capacity(svc_recs.len());
    let mut services = Vec::with_capacity(svc_recs.len());
    for rec in &svc_recs {
        if parse_hex_u16("system_code", &rec.system_code)? != system_code {
            return Err("service: system_code mismatch".to_string());
        }
        services.push(parse_hex_u16("node", &rec.node)?);
        svc_keys.push(parse_key("service", rec)?);
    }

    let (gsk, usk) = generate_service_keys_des(&system_key, &area_keys, &svc_keys);
    eprintln!("derived k_group (GSK): {}", hex::encode(gsk));
    eprintln!("derived k_user  (USK): {}", hex::encode(usk));

    let sc = format!("{system_code:04X}");
    let mut jsonl = format!(
        "{{\"system_code\":\"{sc}\",\"node\":\"FFFF\",\"algo\":\"DES\",\"version\":\"0000\",\"idm\":null,\"key\":\"{}\"}}\n",
        hex::encode_upper(system_key),
    );
    for (code, key) in areas.iter().zip(area_keys.iter()) {
        jsonl.push_str(&format!(
            "{{\"system_code\":\"{sc}\",\"node\":\"{code:04X}\",\"algo\":\"DES\",\"version\":\"0000\",\"idm\":null,\"key\":\"{}\"}}\n",
            hex::encode_upper(key),
        ));
    }
    for (code, key) in services.iter().zip(svc_keys.iter()) {
        jsonl.push_str(&format!(
            "{{\"system_code\":\"{sc}\",\"node\":\"{code:04X}\",\"algo\":\"DES\",\"version\":\"0000\",\"idm\":null,\"key\":\"{}\"}}\n",
            hex::encode_upper(key),
        ));
    }
    let json = format!(
        "{{\"k_group\":\"{}\",\"k_user\":\"{}\",\"system_code\":{},\"areas\":{:?},\"services\":{:?}}}\n",
        hex::encode(gsk),
        hex::encode(usk),
        system_code,
        areas,
        services,
    );

    let jsonl_path = out.with_extension("jsonl");
    for path in [out, &jsonl_path] {
        if path.exists() && !force {
            return Err(format!(
                "{} exists (pass --force to overwrite)",
                path.display()
            ));
        }
    }
    match ask(&format!(
        "write {} and {}? [y/N]: ",
        out.display(),
        jsonl_path.display()
    ))?
    .as_str()
    {
        "y" | "Y" | "yes" => {},
        _ => return Err("aborted".to_string()),
    }
    std::fs::write(out, &json).map_err(|e| format!("write {}: {e}", out.display()))?;
    std::fs::write(&jsonl_path, &jsonl)
        .map_err(|e| format!("write {}: {e}", jsonl_path.display()))?;
    eprintln!("wrote {} and {}", out.display(), jsonl_path.display());
    Ok(())
}
