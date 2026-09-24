//! Regenerate the `S_POLY_*` blocks embedded in `circuits/des.circom`.
//!
//! Run from the crate root:
//! ```sh
//! cargo run --example gen_sbox_poly > /tmp/spoly.txt
//! # splice the `var S_POLY_*[64] = [...];` lines into circuits/des.circom
//! ```
//! The committed constants must match this output byte-for-byte; any drift
//! fails `tests/circom_consistency.rs`. Tables come from the crate's public
//! `des` module (single source of truth); interpolation here is deliberately
//! self-contained so the generator has no private imports.

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, Zero};
use felica_circom_prover::des::{SBOX, sbox_lookup};

fn mapped_table(box_idx: usize) -> [u8; 64] {
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

fn main() {
    // Sanity: generator tables are the crate tables (checked again by tests).
    let _ = SBOX;
    for b in 0..8 {
        let coeffs = interpolate(&mapped_table(b));
        print!("    var S_POLY_{b}[64] = [");
        for (i, c) in coeffs.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("{}", c.into_bigint());
        }
        println!("];");
    }
}
