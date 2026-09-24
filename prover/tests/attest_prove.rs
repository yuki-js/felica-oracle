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
//! limb can be pinned byte-for-byte.

use felica::RemoteTarget;
use felica::driver::errors::{DriverError, Result as DriverResult};
use felica::felica_standard::{
    BlockListElement, EmulatedArea as EmuArea, EmulatedService as EmuSvc,
    EmulatedSystem as EmuSys, FelicaDriver, FelicaStandard, FelicaStandardEmulator,
    FelicaStandardCommand, FelicaStandardResponse, ServiceCode, Type3TagPollingResult,
    generate_service_keys_des,
};
use felica_prover::{
    ProveRequest, ProverError, blank_constraint_counts, verify_attestation,
    circuit::PUBLIC_INPUT_ORDER,
    des::{des_encrypt, tdes_decrypt, tdes_encrypt},
};
use hex_literal::hex;

const IDM: [u8; 8] = hex!("0102030405060708");
const IDI: [u8; 8] = hex!("1020304050607080");
const PMI: [u8; 8] = hex!("a0a1a2a3a4a5a6a7");
const PMM: [u8; 8] = hex!("0100000000000000");
const SYSTEM_KEY: [u8; 8] = hex!("1122334455667788");
const AREA_KEY: [u8; 8] = hex!("21436587a9cbed0f");
const SERVICE_KEY: [u8; 8] = hex!("0102030405060708");
const SYSTEM_CODE: u16 = 0x0003;
const AREA: u16 = 0x0040;
const SERVICE: u16 = 0x0048;
const BLOCK: [u8; 16] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
/// Deterministic stand-in for the holder's 32B CSPRNG blinding randomness.
const RANDOMNESS: [u8; 32] =
    hex!("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
/// Fixed holder challenges for the pinning vectors (reader-driven flows use
/// fresh randomness instead).
const R1: [u8; 8] = hex!("0011223344556677");
const R1B: [u8; 8] = hex!("aabbccddeeff0011");
const ATTESTED_AT: u64 = 1_758_768_000;

type WireLog = Vec<(Vec<u8>, Vec<u8>)>;

/// Test driver: reader `transceive` straight into the emulator, logging every
/// wire frame. `detect_type_f` answers the fixed fixture card.
struct EmuDriver<'a> {
    emu: &'a mut FelicaStandardEmulator,
    log: WireLog,
}

impl FelicaDriver for EmuDriver<'_> {
    fn detect_type_f(
        &mut self,
        _target: &RemoteTarget,
        _system_code: u16,
        _request_code: u8,
        _time_slots: u8,
    ) -> DriverResult<Type3TagPollingResult> {
        Ok(Type3TagPollingResult {
            idm: IDM.to_vec(),
            pmm: PMM.to_vec(),
            optional: Vec::new(),
        })
    }

    fn transceive(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        _timeout_ms: Option<u16>,
    ) -> DriverResult<Vec<u8>> {
        let resp = self
            .emu
            .handle_frame(data)
            .ok_or_else(|| DriverError::other("card rejected frame"))?;
        self.log.push((data.to_vec(), resp.clone()));
        Ok(resp)
    }
}

fn setup_card() -> (FelicaStandardEmulator, [u8; 8], [u8; 8]) {
    let (gsk, usk) = generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[SERVICE_KEY]);
    let mut emusys = EmuSys::new(SYSTEM_CODE, IDM, PMM).expect("system");
    emusys.set_system_key(SYSTEM_KEY);
    emusys.set_idi_pmi(IDI, PMI);
    let mut emuarea = EmuArea::new(AREA, 0x00FF).expect("area");
    emuarea.set_key(AREA_KEY);
    let mut emusvc = EmuSvc::with_blocks(ServiceCode::new(SERVICE), 0x0000, vec![BLOCK]);
    emusvc.set_key(SERVICE_KEY);
    emuarea.add_service(emusvc).expect("service fits");
    emusys.add_area(emuarea).expect("area fits");
    let mut card = FelicaStandardEmulator::new();
    card.add_system(emusys);
    (card, gsk, usk)
}

/// Poll + DES mutual authentication. Returns the wire log, keys, and IDi.
fn auth_log() -> (WireLog, [u8; 8], [u8; 8], [u8; 8]) {
    let (mut emu, gsk, usk) = setup_card();
    let mut drv = EmuDriver {
        emu: &mut emu,
        log: Vec::new(),
    };
    let (mut reader, _) =
        FelicaStandard::polling(&mut drv, "212F", SYSTEM_CODE, 0x00, 0x00).expect("polling");
    let auth = reader
        .mutual_authentication(&[AREA], &[ServiceCode::new(SERVICE)], &gsk, &usk)
        .expect("mutual authentication");
    drop(reader);
    (drv.log, gsk, usk, auth.issue_id)
}

/// Poll + mutual authentication + one secure single-block read.
fn read_log() -> (WireLog, [u8; 8], [u8; 8], Vec<[u8; 16]>) {
    let (mut emu, gsk, usk) = setup_card();
    let mut drv = EmuDriver {
        emu: &mut emu,
        log: Vec::new(),
    };
    let (mut reader, _) =
        FelicaStandard::polling(&mut drv, "212F", SYSTEM_CODE, 0x00, 0x00).expect("polling");
    reader
        .mutual_authentication(&[AREA], &[ServiceCode::new(SERVICE)], &gsk, &usk)
        .expect("mutual authentication");
    let blocks = reader
        .read(&[BlockListElement::new(0, 0, 0)])
        .expect("secure read");
    drop(reader);
    (drv.log, gsk, usk, blocks)
}

/// `(c1b, c2a, auth2_ct)` from the logged Authentication exchange.
fn auth_vectors(log: &WireLog) -> ([u8; 8], [u8; 8], [u8; 32]) {
    let mut challenges = None;
    let mut auth2 = None;
    for (_, resp) in log {
        match FelicaStandardResponse::from_bytes(resp).expect("parse response") {
            FelicaStandardResponse::Authentication1 {
                challenge_1b,
                challenge_2a,
                ..
            } => challenges = Some((challenge_1b, challenge_2a)),
            FelicaStandardResponse::Authentication2(_) => {
                assert_eq!(resp.len(), 34, "AUTH2 frame");
                assert_eq!(resp[1], 0x13, "AUTH2 code");
                auth2 = Some(resp[2..34].try_into().expect("32B ciphertext"));
            }
            _ => {}
        }
    }
    let (c1b, c2a) = challenges.expect("Authentication1 logged");
    (c1b, c2a, auth2.expect("Authentication2 logged"))
}

/// `(ecmd, resp)` wire frames of the logged secure read: the `0x14` request
/// and its `0x15` response. (Secure inner responses stay `Unknown` to
/// `from_bytes` by felica-rs design — decryption belongs to the session, i.e.
/// to the future circuit — so the pair is identified by frame codes. `0x14` /
/// `0x15` are the DES secure-messaging codes, cf. server `schedule`.)
fn read_frames(log: &WireLog) -> (Vec<u8>, Vec<u8>) {
    for (req, resp) in log {
        if req.len() >= 2 && req[1] == 0x14 {
            assert_eq!(resp.len(), 42, "secure read response frame");
            assert_eq!(resp[1], 0x15, "secure read response code");
            return (req.clone(), resp.clone());
        }
    }
    panic!("secure read logged");
}

/// Full mutual authentication with an explicit holder challenge, returning
/// `(c1b, c2a, auth2_ct, gsk, usk, cm)`. `cm` binds fixed dummy wire frames
/// so the packing pin covers a canonical commitment.
fn mint_fixed(r1: &[u8; 8]) -> ([u8; 8], [u8; 8], [u8; 32], [u8; 8], [u8; 8], [u8; 32]) {
    let (mut card, gsk, usk) = setup_card();
    let mut l = [0u8; 8];
    for i in 0..8 {
        l[i] = gsk[i] ^ IDM[i];
    }
    let alpha = des_encrypt(&usk, &l);
    let beta = des_encrypt(&l, &alpha);
    let c1a = tdes_encrypt(r1, &alpha, &l);
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication1 {
            idm: IDM,
            areas: vec![AREA],
            services: vec![SERVICE],
            challenge_1a: c1a,
        })
        .expect("card answers authentication1");
    let (c1b, c2a) = match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication1 { challenge_1b, challenge_2a, .. } => {
            (challenge_1b, challenge_2a)
        }
        other => panic!("unexpected response: {other:?}"),
    };
    let r2 = tdes_decrypt(&c2a, &l, &beta);
    let c2b = tdes_encrypt(&r2, &alpha, &l);
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2");
    assert_eq!(&frame[..2], &[34, 0x13]);
    let auth2_ct: [u8; 32] = frame[2..34].try_into().expect("32B ciphertext");
    let cm = felica_prover::commit(&[0x1Au8; 26], &[0x2Au8; 42], &RANDOMNESS);
    (c1b, c2a, auth2_ct, gsk, usk, cm)
}

fn prove_req(
    c1b: [u8; 8], c2a: [u8; 8], auth2: [u8; 32],
    cm: [u8; 32], gsk: [u8; 8], usk: [u8; 8],
) -> ProveRequest {
    ProveRequest {
        idm: IDM, c1b, c2a, auth2, cm,
        k_group: gsk, k_user: usk, attested_at: ATTESTED_AT,
    }
}

#[test]
fn polling_finds_card() {
    let (mut emu, _, _) = setup_card();
    let mut drv = EmuDriver {
        emu: &mut emu,
        log: Vec::new(),
    };
    let (_, poll) =
        FelicaStandard::polling(&mut drv, "212F", SYSTEM_CODE, 0x00, 0x00).expect("polling");
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
