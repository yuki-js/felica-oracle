//! Session vectors minted entirely through felica-rs public API.
//!
//! A logging test driver (`EmuDriver`, felica-rs's own `emulator/tests`
//! pattern) wires the `FelicaStandard` reader straight against the card
//! emulator: polling → mutual_authentication → secure read. The commitment
//! binds the exact logged wire frames. No DES/crypto mirror lives here —
//! oracle-side crypto is the prover's job (`src/`), card-side is the
//! emulator's.

use felica::RemoteTarget;
use felica::driver::errors::{DriverError, Result as DriverResult};
use felica::felica_standard::{
    BlockListElement, EmulatedArea as EmuArea, EmulatedService as EmuSvc,
    EmulatedSystem as EmuSys, FelicaDriver, FelicaStandard, FelicaStandardEmulator,
    FelicaStandardResponse, ServiceCode, Type3TagPollingResult, generate_service_keys_des,
};
use felica_prover::{ProveRequest, ProverError};
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
        attested_at: 1_758_768_000,
    };
    let att = felica_prover::prove(&req).expect("prove certifies genuine session");
    assert_eq!(att.idi, IDI, "circuit certifies IDi");
    assert_eq!(att.cm_out, cm, "cm_out == cm");
    assert_eq!(att.attested_at, 1_758_768_000);
    assert!(!att.proof.public_inputs.is_empty(), "proof binds public inputs");
}

#[test]
fn prove_api_error_is_typed() {
    // Guarantees callers can match on the spec §8.4 mapping once green.
    let e = ProverError::NotImplemented;
    assert_eq!(e.to_string(), "circuit not yet implemented");
}
