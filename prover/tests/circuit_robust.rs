//! Circuit robustness: every §7 constraint must actually constrain.
//!
//! `prove`-level tests cannot tell a circuit hole from a native rejection —
//! [`prove`](felica_prover::prove) runs native pre-checks first. These tests
//! bypass them via [`check_satisfiable`](felica_prover::check_satisfiable)
//! and feed adversarial witnesses straight into the constraint system:
//! each mutation below violates exactly one constraint's relation, so a
//! satisfiable outcome would mean that constraint is dead wiring.
//! The emulator is only a genuine-witness mint (`common`); nothing here
//! trusts card behavior.

mod common;

use common::*;
use felica_prover::{check_satisfiable, des::tdes_encrypt, verify_attestation};

/// Deterministic xorshift64* — no extra deps for fuzz randomness.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn blank_is_unsatisfiable() {
    // All-zero witnesses must not satisfy anything: 3DES(0,0,0) != 0.
    assert!(
        !check_satisfiable(felica_prover::circuit::FelicaCircuit::blank()),
        "blank circuit must be unsatisfiable"
    );
}

#[test]
fn genuine_is_satisfiable() {
    assert!(
        check_satisfiable(genuine_circuit(&R1)),
        "genuine witnesses must satisfy"
    );
}

/// Constraint 1 binds alone: flipped `c1b` breaks nothing else.
#[test]
fn constraint1_c1b_binds() {
    let mut c = genuine_circuit(&R1);
    c.c1b[0] ^= 0xFF;
    assert!(!check_satisfiable(c), "c1b mismatch must be unsatisfiable");
}

/// Constraint 2 binds alone: flipped `c2a` breaks nothing else
/// (`r2` witness and AUTH2 path are untouched).
#[test]
fn constraint2_c2a_binds() {
    let mut c = genuine_circuit(&R1);
    c.c2a[0] ^= 0xFF;
    assert!(!check_satisfiable(c), "c2a mismatch must be unsatisfiable");
}

/// Constraints 3+4 bind: flipped AUTH2 block diffuses through CBC+MAC.
#[test]
fn constraint34_auth2_binds() {
    for byte in [0, 8, 16, 24] {
        let mut c = genuine_circuit(&R1);
        c.auth2[byte] ^= 0xFF;
        assert!(
            !check_satisfiable(c),
            "auth2[{byte}] forgery must be unsatisfiable"
        );
    }
}

/// Constraint 5 binds in isolation: re-key `c1b` for a mutated `r1`, so
/// constraint 1 still holds and only the TID relation breaks.
#[test]
fn constraint5_tid_binds() {
    let mut c = genuine_circuit(&R1);
    c.r1[2] ^= 0xFF;
    // Recompute c1b for the mutated r1 (same card keys — the fixture card
    // is deterministic): constraint 1 holds by construction.
    let (_, gsk, usk) = setup_card();
    let (l, _, beta) = session_keys(&gsk, &usk);
    c.c1b = tdes_encrypt(&c.r1, &l, &beta);
    assert!(!check_satisfiable(c), "tid mismatch must be unsatisfiable");
}

/// Constraint 6 binds alone: flipped `idi` breaks nothing else
/// (`idi` feeds only the IDi equality and its own packing limb).
#[test]
fn constraint6_idi_binds() {
    let mut c = genuine_circuit(&R1);
    c.idi[0] ^= 0xFF;
    assert!(!check_satisfiable(c), "idi mismatch must be unsatisfiable");
}

/// Constraint 7 is a public-input alias by design: `cm` feeds no arithmetic,
/// so flipping it stays satisfiable — but the public inputs differ, which is
/// exactly what binds the proof to the commitment in the pairing equation.
/// Same for the oracle-certified `attested_at`.
#[test]
fn free_variables_bind_via_public_inputs() {
    use felica_prover::circuit::public_inputs_fr;
    let c = genuine_circuit(&R1);
    let pi_before = public_inputs_fr(&c.r1, &c.c1b, &c.c2a, &c.auth2, &c.cm, &c.idi, &c.r2, c.attested_at);
    let mut d = c.clone();
    d.cm[0] ^= 0xFF;
    d.attested_at ^= 0xFF;
    assert!(
        check_satisfiable(d.clone()),
        "free variables stay satisfiable by design"
    );
    let pi_after = public_inputs_fr(&d.r1, &d.c1b, &d.c2a, &d.auth2, &d.cm, &d.idi, &d.r2, d.attested_at);
    assert_ne!(pi_before, pi_after, "free variables move the public inputs");
}

/// DES parity bits are equivalent keys, not forgeries: flipping bit 0 of
/// any `l`/`beta` byte changes nothing natively (PC-1 drops it) and keeps
/// the circuit satisfiable. Pinned so the fuzz exclusion above stays honest.
#[test]
fn parity_flips_are_equivalent_keys() {
    let c = genuine_circuit(&R1);
    // Native: parity flips leave every 3DES output unchanged.
    for i in 0..8 {
        let mut l = c.l;
        l[i] ^= 0x01;
        assert_eq!(tdes_encrypt(&c.r1, &l, &c.beta), c.c1b);
        let mut beta = c.beta;
        beta[i] ^= 0x01;
        assert_eq!(tdes_encrypt(&c.r1, &c.l, &beta), c.c1b);
    }
    // Circuit: still satisfiable under parity flips.
    let mut d = c.clone();
    d.l[4] ^= 0x01;
    d.beta[2] ^= 0x01;
    assert!(check_satisfiable(d), "parity flips stay satisfiable");
}

/// Fuzz: every constrained witness byte-array is mutated dozens of times at
/// deterministic pseudorandom positions; all outcomes must be unsatisfiable.
/// `cm`/`attested_at` are excluded — free by design, covered above.
/// Key fields (`l`, `beta`) skip bit 0 of each byte: DES parity bits, which
/// are dropped by PC-1 both natively and in-circuit (pinned separately).
/// `r2` keeps full flips — it is also 3DES *data* in constraint 2, where
/// every bit binds.
#[test]
fn fuzz_mutations_never_satisfy() {
    let base = genuine_circuit(&R1);
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    // (name, length, setter): flipping any constrained byte must break it.
    let mut hit = [false; 8];
    for step in 0..96 {
        let mut c = base.clone();
        let region = rng.below(8);
        let (field, idx, bit) = match region {
            0 => { let i = rng.below(8); let b = rng.below(8); c.r1[i] ^= 1 << b; hit[0] = true; ("r1", i, b) }
            1 => { let i = rng.below(8); let b = rng.below(8); c.c1b[i] ^= 1 << b; hit[1] = true; ("c1b", i, b) }
            2 => { let i = rng.below(8); let b = rng.below(8); c.c2a[i] ^= 1 << b; hit[2] = true; ("c2a", i, b) }
            3 => { let i = rng.below(32); let b = rng.below(8); c.auth2[i] ^= 1 << b; hit[3] = true; ("auth2", i, b) }
            4 => { let i = rng.below(8); let b = rng.below(8); c.idi[i] ^= 1 << b; hit[4] = true; ("idi", i, b) }
            5 => { let i = rng.below(8); let b = rng.below(8); c.r2[i] ^= 1 << b; hit[5] = true; ("r2", i, b) }
            6 => { let i = rng.below(8); let b = 1 + rng.below(7); c.l[i] ^= 1 << b; hit[6] = true; ("l", i, b) }
            _ => { let i = rng.below(8); let b = 1 + rng.below(7); c.beta[i] ^= 1 << b; hit[7] = true; ("beta", i, b) }
        };
        assert!(
            !check_satisfiable(c),
            "fuzz step {step}: {field}[{idx}] bit {bit} must be unsatisfiable"
        );
    }
    assert!(hit.iter().all(|h| *h), "fuzz must cover all witness regions");
}

/// `verify_attestation` never panics and rejects garbage: empty strings,
/// non-hex, wrong lengths, and off-modulus field encodings (e.g. 32 bytes
/// of `0xff`, which exceeds `r`).
#[test]
fn verify_rejects_garbage() {
    let (c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    let base = felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk))
        .expect("genuine session proves");
    assert!(verify_attestation(&base));
    for tamper in ["zz", "", "00", &"ff".repeat(31), &"ff".repeat(33)] {
        let mut bad = base.clone();
        bad.proof.a.0 = tamper.to_string();
        assert!(!verify_attestation(&bad), "garbage a.x rejected");
        let mut bad = base.clone();
        bad.proof.public_inputs[5] = tamper.to_string();
        assert!(!verify_attestation(&bad), "garbage pi rejected");
    }
    let mut bad = base.clone();
    bad.proof.public_inputs.pop();
    assert!(!verify_attestation(&bad), "short pi rejected");
    let mut bad = base.clone();
    bad.proof.public_inputs.push("00".repeat(32));
    assert!(!verify_attestation(&bad), "long pi rejected");
}
