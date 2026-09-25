//! Shared emulator fixture for prover integration tests.
//!
//! One fixed card (`setup_card`), two wiring styles against it — the
//! reader-driven log (`auth_log`/`read_log`) and direct commands with an
//! explicit holder challenge (`mint_fixed`) — plus full-circuit witnesses
//! (`genuine_circuit`). No crypto mirror lives here beyond key-schedule
//! derivation; oracle-side DES is the prover's job (`src/`).

use felica::RemoteTarget;
use felica::driver::errors::{DriverError, Result as DriverResult};
use felica::felica_standard::{
    BlockListElement, EmulatedArea as EmuArea, EmulatedService as EmuSvc,
    EmulatedSystem as EmuSys, FelicaDriver, FelicaStandard, FelicaStandardEmulator,
    FelicaStandardCommand, FelicaStandardResponse, ServiceCode, Type3TagPollingResult,
    generate_service_keys_des,
};
use felica_prover::{
    ProveRequest,
    circuit::FelicaCircuit,
    des::{cbc_decrypt, command_mac, des_encrypt, tdes_decrypt, tdes_encrypt},
};
use hex_literal::hex;

pub const IDM: [u8; 8] = hex!("0102030405060708");
pub const IDI: [u8; 8] = hex!("1020304050607080");
pub const PMI: [u8; 8] = hex!("a0a1a2a3a4a5a6a7");
pub const PMM: [u8; 8] = hex!("0100000000000000");
pub const SYSTEM_KEY: [u8; 8] = hex!("1122334455667788");
pub const AREA_KEY: [u8; 8] = hex!("21436587a9cbed0f");
pub const SERVICE_KEY: [u8; 8] = hex!("0102030405060708");
pub const SYSTEM_CODE: u16 = 0x0003;
pub const AREA: u16 = 0x0040;
pub const SERVICE: u16 = 0x0048;
pub const BLOCK: [u8; 16] = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
/// Deterministic stand-in for the holder's 32B CSPRNG blinding randomness.
pub const RANDOMNESS: [u8; 32] =
    hex!("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");
/// Fixed holder challenges for the pinning vectors (reader-driven flows use
/// fresh randomness instead).
pub const R1: [u8; 8] = hex!("0011223344556677");
pub const R1B: [u8; 8] = hex!("aabbccddeeff0011");
pub const ATTESTED_AT: u64 = 1_758_768_000;

pub type WireLog = Vec<(Vec<u8>, Vec<u8>)>;

/// Test driver: reader `transceive` straight into the emulator, logging every
/// wire frame. `detect_type_f` answers the fixed fixture card.
pub struct EmuDriver<'a> {
    pub emu: &'a mut FelicaStandardEmulator,
    pub log: WireLog,
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

pub fn setup_card() -> (FelicaStandardEmulator, [u8; 8], [u8; 8]) {
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

/// `(l, alpha, beta)` for this card (spec §4.1, derived outside the circuit).
pub fn session_keys(gsk: &[u8; 8], usk: &[u8; 8]) -> ([u8; 8], [u8; 8], [u8; 8]) {
    let mut l = [0u8; 8];
    for i in 0..8 {
        l[i] = gsk[i] ^ IDM[i];
    }
    let alpha = des_encrypt(usk, &l);
    let beta = des_encrypt(&l, &alpha);
    (l, alpha, beta)
}

/// Poll + DES mutual authentication. Returns the wire log, keys, and IDi.
pub fn auth_log() -> (WireLog, [u8; 8], [u8; 8], [u8; 8]) {
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
pub fn read_log() -> (WireLog, [u8; 8], [u8; 8], Vec<[u8; 16]>) {
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
pub fn auth_vectors(log: &WireLog) -> ([u8; 8], [u8; 8], [u8; 32]) {
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
/// to the circuit — so the pair is identified by frame codes. `0x14` / `0x15`
/// are the DES secure-messaging codes, cf. server `schedule`.)
pub fn read_frames(log: &WireLog) -> (Vec<u8>, Vec<u8>) {
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
pub fn mint_fixed(r1: &[u8; 8]) -> ([u8; 8], [u8; 8], [u8; 32], [u8; 8], [u8; 8], [u8; 32]) {
    let (mut card, gsk, usk) = setup_card();
    let (l, alpha, beta) = session_keys(&gsk, &usk);
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

pub fn prove_req(
    c1b: [u8; 8], c2a: [u8; 8], auth2: [u8; 32],
    cm: [u8; 32], gsk: [u8; 8], usk: [u8; 8],
) -> ProveRequest {
    ProveRequest {
        idm: IDM, c1b, c2a, auth2, cm,
        k_group: gsk, k_user: usk, attested_at: ATTESTED_AT,
    }
}

/// Setup-generated proving key for tests, loaded once per test binary.
///
/// Requires `FELICA_TEST_PK` to point at a proving-key file (setup ceremony
/// output). No key generation happens here.
pub fn test_key() -> &'static felica_prover::FelicaProvingKey {
    static KEY: std::sync::OnceLock<felica_prover::FelicaProvingKey> =
        std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        let path = std::env::var("FELICA_TEST_PK")
            .expect("FELICA_TEST_PK must point at a proving-key file");
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read proving key at {path}: {e}"));
        felica_prover::load_proving_key(&bytes).expect("deserialize proving key")
    })
}

/// Full R1CS witnesses for a genuine fixed-challenge session: everything
/// [`check_satisfiable`](felica_prover::check_satisfiable) consumes.
pub fn genuine_circuit(r1: &[u8; 8]) -> FelicaCircuit {
    let (c1b, c2a, auth2, gsk, usk, cm) = mint_fixed(r1);
    let (l, _, beta) = session_keys(&gsk, &usk);
    let r2 = tdes_decrypt(&c2a, &l, &beta);
    let pt = cbc_decrypt(&auth2, &r2).expect("genuine AUTH2 decrypts");
    assert_eq!(command_mac(0x13, &pt[..24]), pt[24..32], "genuine MAC holds");
    let mut idi = [0u8; 8];
    idi.copy_from_slice(&pt[8..16]);
    FelicaCircuit {
        r1: *r1,
        c1b,
        c2a,
        auth2,
        cm,
        idi,
        r2,
        attested_at: ATTESTED_AT,
        l,
        beta,
    }
}
