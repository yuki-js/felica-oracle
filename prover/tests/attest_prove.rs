//! Session vectors minted entirely through felica-rs public API.
//!
//! A logging test driver (`EmuDriver`, felica-rs's own `emulator/tests`
//! pattern) wires the `FelicaStandard` reader straight against the card
//! emulator: polling → mutual_authentication → secure read. The commitment
//! binds the exact logged wire frames. No DES/crypto mirror lives here —
//! oracle-side crypto is the prover's job (`src/`), card-side is the
//! emulator's.
//!
//! Property tests (roundtrip, packing pins, negatives, budget) use the same
//! fixture card with a fixed holder challenge (`R1`), so every public-input
//! limb can be pinned byte-for-byte. Fixture code lives in `common`.

mod common;

use common::*;
use felica_prover::{ProveRequest, ProverError, blank_constraint_counts, verify_attestation,
    circuit::PUBLIC_INPUT_ORDER};

#[test]
fn polling_finds_card() {
    let (mut emu, _, _) = setup_card();
    let mut drv = EmuDriver {
        emu: &mut emu,
        log: Vec::new(),
    };
    let (_, poll) =
        felica::felica_standard::FelicaStandard::polling(&mut drv, "212F", SYSTEM_CODE, 0x00, 0x00)
            .expect("polling");
    assert_eq!(poll.idm, IDM);
}

#[test]
fn mutual_authentication_returns_idi() {
    let (_, _, _, idi) = auth_log();
    assert_eq!(idi, IDI);
}

#[test]
fn secure_read_returns_block() {
    let (_, _, _, blocks) = read_log();
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], BLOCK);
}

#[test]
fn commit_binds_wire_frames() {
    let (log, _, _, _) = read_log();
    let (ecmd, resp) = read_frames(&log);
    assert_eq!(&ecmd[..2], &[ecmd.len() as u8, 0x14]);
    assert_eq!(&resp[..2], &[resp.len() as u8, 0x15]);
    let cm = felica_prover::commit(&ecmd, &resp, &RANDOMNESS);
    assert_eq!(cm, felica_prover::commit(&ecmd, &resp, &RANDOMNESS));
    let mut bad = resp.clone();
    bad[10] ^= 0xFF;
    assert_ne!(cm, felica_prover::commit(&ecmd, &bad, &RANDOMNESS));
}

#[test]
fn proves_genuine_session() {
    let (log, gsk, usk, _) = read_log();
    let (c1b, c2a, auth2) = auth_vectors(&log);
    let (ecmd, resp) = read_frames(&log);
    let cm = felica_prover::commit(&ecmd, &resp, &RANDOMNESS);

    let req = ProveRequest {
        idm: IDM,
        c1b,
        c2a,
        auth2,
        cm,
        k_group: gsk,
        k_user: usk,
        attested_at: ATTESTED_AT,
    };
    let att = felica_prover::prove(&req).expect("prove certifies genuine session");
    assert_eq!(att.idi, IDI, "circuit certifies IDi");
    assert_eq!(att.cm_out, cm, "cm_out == cm");
    assert_eq!(att.attested_at, ATTESTED_AT);
    assert!(!att.proof.public_inputs.is_empty(), "proof binds public inputs");
}

#[test]
fn prove_api_error_is_typed() {
    // Guarantees callers can match on the spec §8.4 mapping once green.
    let e = ProverError::NotImplemented;
    assert_eq!(e.to_string(), "circuit not yet implemented");
}

#[test]
fn roundtrip_and_packing_pins() {
    let (c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    let att = felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk))
        .expect("genuine session proves");
    assert_eq!(att.idi, IDI);
    assert_eq!(att.cm_out, cm);
    assert_eq!(att.attested_at, ATTESTED_AT);
    assert!(verify_attestation(&att), "fresh proof verifies");

    // 8-limb Sui packing, pinned byte-for-byte (all limbs < r, so LE
    // canonical round-trips exactly).
    assert_eq!(att.proof.public_inputs.len(), PUBLIC_INPUT_ORDER.len());
    assert_eq!(att.proof.public_inputs.len(), 8);
    let pi: Vec<Vec<u8>> = att.proof.public_inputs.iter().map(|s| hex::decode(s).unwrap()).collect();
    for (i, raw) in pi.iter().enumerate() {
        assert_eq!(raw.len(), 32, "limb {i}");
    }
    assert_eq!(&pi[0][..8], &R1, "pi0 = r1");
    assert_eq!(&pi[1][..8], &c1b, "pi1 = c1b");
    assert_eq!(&pi[2][..8], &c2a, "pi2 = c2a");
    assert_eq!(&pi[3][..16], &auth2[..16], "pi3 = auth2_lo");
    assert_eq!(&pi[4][..16], &auth2[16..], "pi4 = auth2_hi");
    assert_eq!(&pi[6][..8], &IDI, "pi6 low = idi");
    assert_eq!(&pi[6][8..16], &att.r2, "pi6 high = r2");
    assert_eq!(
        u64::from_le_bytes(pi[7][..8].try_into().unwrap()),
        ATTESTED_AT,
        "pi7 = attested_at"
    );
}

#[test]
fn tampered_public_input_fails_verify() {
    let (c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    let mut att = felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk))
        .expect("genuine session proves");
    // Flip the lowest nibble of pi0 (r1): stays valid hex/Fr, breaks pairing.
    let mut s = att.proof.public_inputs[0].clone();
    let last = s.pop().unwrap();
    s.push(if last == '0' { '1' } else { '0' });
    att.proof.public_inputs[0] = s;
    assert!(!verify_attestation(&att), "tampered pi must not verify");
}

#[test]
fn tampered_proof_bytes_fail_verify() {
    let (c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    let mut att = felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk))
        .expect("genuine session proves");
    let mut s = att.proof.a.0.clone();
    let last = s.pop().unwrap();
    s.push(if last == '0' { '1' } else { '0' });
    att.proof.a.0 = s;
    assert!(!verify_attestation(&att), "tampered proof must not verify");
}

#[test]
fn rejects_tampered_auth2() {
    let (c1b, c2a, mut auth2, gsk, usk, cm) = mint_fixed(&R1);
    auth2[0] ^= 0xFF;
    assert_eq!(
        felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk)),
        Err(ProverError::MacMismatch)
    );
}

#[test]
fn rejects_tid_mismatch() {
    let (_, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    let (c1b_b, _, _, _, _, _) = mint_fixed(&R1B);
    assert_eq!(
        felica_prover::prove(&prove_req(c1b_b, c2a, auth2, cm, gsk, usk)),
        Err(ProverError::TidMismatch)
    );
}

#[test]
fn rejects_tampered_c1b() {
    let (mut c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(&R1);
    c1b[0] ^= 0xFF;
    assert!(
        felica_prover::prove(&prove_req(c1b, c2a, auth2, cm, gsk, usk)).is_err(),
        "forged c1b must not prove"
    );
}

#[test]
fn constraint_budget_is_pinned() {
    let (n_constraints, n_instance, n_witness) = blank_constraint_counts();
    // 8 public inputs + ONE.
    assert_eq!(n_instance, PUBLIC_INPUT_ORDER.len() + 1, "instance pins packing");
    assert_eq!(PUBLIC_INPUT_ORDER.len(), 8);
    assert!(n_witness > 100_000, "witnesses: {n_witness}");
    assert!(
        n_constraints <= 150_000,
        "constraint budget blown: {n_constraints}"
    );
}
