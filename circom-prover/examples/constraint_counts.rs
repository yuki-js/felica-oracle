//! Print blank-circuit (constraints, instance vars, witness vars).
//! Used for the head-to-head comparison table (see `scripts/head_to_head.sh`).

fn main() {
    let (c, i, w) = felica_circom_prover::blank_constraint_counts();
    println!("constraints={c} instance={i} witness={w}");
}
