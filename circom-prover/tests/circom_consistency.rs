//! circom ↔ Rust consistency: the `.circom` sources and the executable Rust
//! mirror must agree on tables, S-box polys, public inputs, and constants.
//!
//! - `circuits/des.circom` tables (`IP_TBL`, `E_TBL`, `P_TBL`, `PC1_TBL`,
//!   `PC2_TBL`, `SHIFT_TBL`, `S_TBL_*`) are byte-for-byte equal to
//!   `felica_circom_prover::des`.
//! - `S_POLY_*` equal an independent re-interpolation (own Gauss–Jordan over
//!   Fr, not the crate's) of the binary-indexed S-box mapping — so neither
//!   the committed constants nor the crate's polys can drift alone.
//! - `circuits/felica.circom` exposes exactly the 8 `PUBLIC_INPUT_ORDER`
//!   public inputs in order, includes `des.circom`, and hardcodes the spec
//!   M0 (`[34, 0x13, 0*6]`).
//!
//! These tests need no `circom` binary; `scripts/compile.sh` covers actual
//! compilation separately.

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use felica_circom_prover::circuit::PUBLIC_INPUT_ORDER;

fn circuits_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("circuits")
}

/// Parse every `var NAME[N] = [v, v, ...];` line into decimal-token vectors.
fn parse_var_arrays(src: &str) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for line in src.lines() {
        let t = line.trim();
        if !t.starts_with("var ") || !t.contains('=') || !t.contains('[') {
            continue;
        }
        // var NAME[N] = [body];
        let after_var = &t[4..];
        let name_end = after_var.find('[').expect("var array shape");
        let name = after_var[..name_end].to_string();
        // The shape prefix `NAME[N]` contains brackets too: find the `= [` body.
        let eq = t.find('=').unwrap();
        let body_open = t[eq..].find('[').unwrap() + eq;
        let body_close = t.rfind(']').unwrap();
        let body = &t[body_open + 1..body_close];
        let vals: Vec<String> = body.split(',').map(|s| s.trim().to_string()).collect();
        out.insert(name, vals);
    }
    out
}

fn expect_small(name: &str, vals: &[String], expected: &[usize]) {
    assert_eq!(vals.len(), expected.len(), "{name} length");
    for (i, (got, want)) in vals.iter().zip(expected.iter()).enumerate() {
        let g: usize = got.parse().unwrap_or_else(|_| panic!("{name}[{i}] not small: {got}"));
        assert_eq!(g, *want, "{name}[{i}]");
    }
}

/// Independent Gauss–Jordan interpolation of the binary-indexed S-box table.
fn interpolate(table: &[u8; 64]) -> Vec<Fr> {
    let n = 64usize;
    let mut mat: Vec<Vec<Fr>> = vec![vec![Fr::from(0u64); n + 1]; n];
    for i in 0..n {
        let x = Fr::from(i as u64);
        let mut pow = Fr::from(1u64);
        for j in 0..n {
            mat[i][j] = pow;
            pow *= x;
        }
        mat[i][n] = Fr::from(table[i] as u64);
    }
    for col in 0..n {
        let mut pivot = col;
        while pivot < n && mat[pivot][col].is_zero() {
            pivot += 1;
        }
        assert!(pivot < n, "vandermonde invertible");
        mat.swap(col, pivot);
        let inv = mat[col][col].inverse().expect("nonzero pivot");
        for j in col..=n {
            mat[col][j] *= inv;
        }
        for row in 0..n {
            if row != col {
                let factor = mat[row][col];
                if !factor.is_zero() {
                    for j in col..=n {
                        let sub = mat[col][j] * factor;
                        mat[row][j] -= sub;
                    }
                }
            }
        }
    }
    (0..n).map(|i| mat[i][n]).collect()
}

fn mapped_table(box_idx: usize) -> [u8; 64] {
    use felica_circom_prover::des::sbox_lookup;
    let mut out = [0u8; 64];
    for v in 0..64u8 {
        let bits = [
            (v >> 5) & 1 == 1,
            (v >> 4) & 1 == 1,
            (v >> 3) & 1 == 1,
            (v >> 2) & 1 == 1,
            (v >> 1) & 1 == 1,
            v & 1 == 1,
        ];
        out[v as usize] = sbox_lookup(box_idx, bits);
    }
    out
}

#[test]
fn circom_tables_match_rust() {
    use felica_circom_prover::des::{E, IP, P, PC1, PC2, SBOX, SHIFTS};
    let src = std::fs::read_to_string(circuits_dir().join("des.circom")).expect("des.circom");
    let vars = parse_var_arrays(&src);
    expect_small("IP_TBL", &vars["IP_TBL"], &IP);
    expect_small("E_TBL", &vars["E_TBL"], &E);
    expect_small("P_TBL", &vars["P_TBL"], &P);
    expect_small("PC1_TBL", &vars["PC1_TBL"], &PC1);
    expect_small("PC2_TBL", &vars["PC2_TBL"], &PC2);
    expect_small("SHIFT_TBL", &vars["SHIFT_TBL"], &SHIFTS);
    for b in 0..8 {
        let name = format!("S_TBL_{b}");
        let vals = &vars[&name];
        assert_eq!(vals.len(), 64, "{name} length");
        for (i, got) in vals.iter().enumerate() {
            let g: u8 = got.parse().unwrap_or_else(|_| panic!("{name}[{i}] not a byte"));
            assert_eq!(g, SBOX[b][i], "{name}[{i}]");
        }
    }
}

#[test]
fn circom_sbox_polys_match_interpolation() {
    let src = std::fs::read_to_string(circuits_dir().join("des.circom")).expect("des.circom");
    let vars = parse_var_arrays(&src);
    for b in 0..8 {
        let name = format!("S_POLY_{b}");
        let vals = &vars[&name];
        assert_eq!(vals.len(), 64, "{name} length");
        let expected = interpolate(&mapped_table(b));
        for (j, (got, want)) in vals.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, &want.into_bigint().to_string(), "{name}[{j}]");
        }
    }
}

#[test]
fn circom_main_public_inputs_match_packing() {
    let src =
        std::fs::read_to_string(circuits_dir().join("felica.circom")).expect("felica.circom");
    assert!(src.contains("include \"des.circom\""), "felica includes des");
    let start = src.find("component main").expect("main component");
    let head = &src[start..];
    let l = head.find('[').unwrap();
    let r = head.find(']').unwrap();
    let pubs: Vec<String> = head[l + 1..r].split(',').map(|s| s.trim().to_string()).collect();
    let want: Vec<String> = PUBLIC_INPUT_ORDER.iter().map(|s| s.to_string()).collect();
    assert_eq!(pubs, want, "main public inputs match PUBLIC_INPUT_ORDER");
}

#[test]
fn circom_m0_matches_spec() {
    // M0 = [34, 0x13, 0*6] as LE bits (length 34 = 2 + 24 payload + 8 MAC).
    let src = std::fs::read_to_string(circuits_dir().join("felica.circom")).expect("felica.circom");
    let vars = parse_var_arrays(&src);
    let m0 = &vars["M0LE"];
    assert_eq!(m0.len(), 64, "M0LE length");
    let bytes = [34u8, 0x13, 0, 0, 0, 0, 0, 0];
    for (i, byte) in bytes.iter().enumerate() {
        for j in 0..8 {
            let want = ((byte >> j) & 1).to_string();
            assert_eq!(m0[i * 8 + j], want, "M0LE bit {}", i * 8 + j);
        }
    }
}
