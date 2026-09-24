// Shared helpers across integration test binaries; each binary uses a
// subset, so unused warnings are noise.
#![allow(dead_code)]

use felica_oracle::api::types::{AttestRequest, ChallengeRequest, ReadSpec, SettleRequest};
use felica_oracle::api::OracleImpl;
use felica_oracle::oracle::fixture;

pub const R1_HEX: &str = "0011223344556677";
pub const R1B_HEX: &str = "aabbccddeeff0011";

pub type Emulator = felica::felica_standard::FelicaStandardEmulator;

/// Test oracle wired to the shared fixture card. Returns
/// `(oracle, card, gsk, usk)`; the card IDm is always [`fixture::IDM`].
pub fn setup() -> (OracleImpl, Emulator, [u8; 8], [u8; 8]) {
    let f = fixture::setup();
    let oracle = OracleImpl::new(fixture::app_config(&f));
    let fixture::Fixture { card, gsk, usk } = f;
    (oracle, card, gsk, usk)
}

/// challenge → card Authentication1, returning genuine `(c1b, c2a)` for `r1_hex`.
pub async fn auth1_flow(
    oracle: &OracleImpl,
    card: &mut Emulator,
    r1_hex: &str,
) -> ([u8; 8], [u8; 8]) {
    use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};

    let ch = oracle
        .challenge_impl(ChallengeRequest {
            idm: fixture::IDM_HEX.to_string(),
            r1: r1_hex.to_string(),
        })
        .await
        .expect("challenge");
    assert_eq!(ch.system_code, 0x0003, "challenge carries the node path");
    assert_eq!(ch.areas, vec![fixture::AREA]);
    assert_eq!(ch.services, vec![fixture::SERVICE]);
    let c1a: [u8; 8] = hex::decode(&ch.c1a).unwrap().try_into().unwrap();
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication1 {
            idm: fixture::IDM,
            areas: vec![fixture::AREA],
            services: vec![fixture::SERVICE],
            challenge_1a: c1a,
        })
        .expect("card answers authentication1");
    match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication1 {
            challenge_1b,
            challenge_2a,
            ..
        } => (challenge_1b, challenge_2a),
        other => panic!("unexpected response: {other:?}"),
    }
}

pub fn settle_req(c1b: [u8; 8], c2a: [u8; 8], read_spec: Option<ReadSpec>) -> SettleRequest {
    SettleRequest {
        idm: fixture::IDM_HEX.to_string(),
        r1: R1_HEX.to_string(),
        c1b: hex::encode(c1b),
        c2a: hex::encode(c2a),
        read_spec,
    }
}

pub fn attest_req(c1b: [u8; 8], c2a: [u8; 8], auth2_ct: [u8; 32]) -> AttestRequest {
    attest_req_cm(c1b, c2a, auth2_ct, None)
}

pub fn attest_req_cm(
    c1b: [u8; 8],
    c2a: [u8; 8],
    auth2_ct: [u8; 32],
    cm: Option<String>,
) -> AttestRequest {
    AttestRequest {
        idm: fixture::IDM_HEX.to_string(),
        c1b: hex::encode(c1b),
        c2a: hex::encode(c2a),
        auth2: hex::encode(auth2_ct),
        cm,
    }
}

/// Card Authentication2 → raw 32-byte AUTH2 ciphertext.
pub fn auth2_flow(card: &mut Emulator, c2b: [u8; 8]) -> [u8; 32] {
    use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};

    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: fixture::IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2");
    match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication2(_) => {},
        other => panic!("unexpected response: {other:?}"),
    }
    frame[2..34].try_into().expect("32B ciphertext")
}
