//! Backend-parity runner: the `felica-prover` suite, executed verbatim
//! against `felica-circom-prover`.
//!
//! The two crates expose identical APIs by design, so the suite is a single
//! source of truth (`prover/tests/attest_prove.rs`) included here with the
//! crate name aliased. Any vector/pin/budget change on the prover side is
//! picked up here with zero mirroring — drift is impossible by construction.
//! Backend-specific checks (circom↔Rust table/poly links) live separately in
//! `tests/circom_consistency.rs`.

extern crate felica_circom_prover as felica_prover;

#[path = "../../prover/tests/attest_prove.rs"]
mod suite;
