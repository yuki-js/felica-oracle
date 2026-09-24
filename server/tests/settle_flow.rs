use felica_oracle::api::types::{ChallengeRequest, ReadSpec, SettleRequest};
use felica_oracle::api::OracleImpl;
use felica_oracle::oracle::{OracleKeys, fixture, schedule};

const R1_HEX: &str = "0011223344556677";

type Emulator = felica::felica_standard::FelicaStandardEmulator;

/// Test oracle wired to the shared fixture card. Returns
/// `(oracle, card, gsk, usk)`; the card IDm is always [`fixture::IDM`].
fn setup() -> (OracleImpl, Emulator, [u8; 8], [u8; 8]) {
    let f = fixture::setup();
    let oracle = OracleImpl::new(fixture::app_config(&f));
    let fixture::Fixture { card, gsk, usk } = f;
    (oracle, card, gsk, usk)
}

/// challenge → card Authentication1, returning genuine `(c1b, c2a)`.
async fn auth1_flow(oracle: &OracleImpl, card: &mut Emulator) -> ([u8; 8], [u8; 8]) {
    use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};

    let ch = oracle
        .challenge_impl(ChallengeRequest {
            idm: fixture::IDM_HEX.to_string(),
            r1: R1_HEX.to_string(),
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

fn settle_req(c1b: [u8; 8], c2a: [u8; 8], read_spec: Option<ReadSpec>) -> SettleRequest {
    SettleRequest {
        idm: fixture::IDM_HEX.to_string(),
        r1: R1_HEX.to_string(),
        c1b: hex::encode(c1b),
        c2a: hex::encode(c2a),
        read_spec,
    }
}

/// Full holder flow through the real RPC-layer methods:
/// challenge → card Auth1 → settle → card Auth2 + ecmd → read verify.
#[tokio::test]
async fn settle_flow_reads_block_via_emulator() {
    use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};

    let (oracle, mut card, gsk, usk) = setup();
    let (c1b, c2a) = auth1_flow(&oracle, &mut card).await;

    let st = oracle
        .settle_impl(settle_req(
            c1b,
            c2a,
            Some(ReadSpec {
                service: fixture::SERVICE,
                block: 0,
            }),
        ))
        .await
        .expect("settle");
    let c2b: [u8; 8] = hex::decode(&st.c2b).unwrap().try_into().unwrap();
    let ecmd = hex::decode(st.ecmd.expect("ecmd present")).expect("ecmd hex");
    assert_eq!(ecmd.len(), 26, "len + 0x14 + 24B ciphertext");
    assert_eq!(ecmd[1], 0x14, "read command code");

    // Card accepts C2B and executes our ecmd.
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: fixture::IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2");
    assert!(matches!(
        FelicaStandardResponse::from_bytes(&frame).expect("parse"),
        FelicaStandardResponse::Authentication2(_)
    ));
    let enc_resp = card.handle_frame(&ecmd).expect("card executes ecmd");
    assert_eq!(enc_resp[1], 0x15, "read response code");

    // Read response verifies under the session key R2 with the TN chain intact.
    let r1: [u8; 8] = hex::decode(R1_HEX).unwrap().try_into().unwrap();
    let mut tid = [0u8; 6];
    tid.copy_from_slice(&r1[2..8]);
    let r2 = OracleKeys::new(gsk, usk)
        .session(&fixture::IDM)
        .open_r2(&c2a);
    let read = schedule::decrypt_read_response(&r2, &tid, &enc_resp[2..])
        .expect("read response verifies");
    assert_eq!(read.count, 1);
    assert_eq!(read.data, fixture::BLOCK);
}

#[tokio::test]
async fn settle_auth_only_omits_ecmd() {
    let (oracle, mut card, _, _) = setup();
    let (c1b, c2a) = auth1_flow(&oracle, &mut card).await;
    let st = oracle
        .settle_impl(settle_req(c1b, c2a, None))
        .await
        .expect("settle");
    assert!(st.ecmd.is_none());
    assert_eq!(st.c2b.len(), 16, "8-byte hex");
}

#[tokio::test]
async fn settle_rejects_forged_c1b() {
    let (oracle, mut card, _, _) = setup();
    let (_, c2a) = auth1_flow(&oracle, &mut card).await;
    let bad_c1b: [u8; 8] = hex::decode("aabbccddeeff0011").unwrap().try_into().unwrap();
    let err = oracle
        .settle_impl(settle_req(bad_c1b, c2a, None))
        .await
        .expect_err("forged c1b rejected");
    assert_eq!(err.code(), -32012);
}

#[tokio::test]
async fn settle_rejects_unknown_service() {
    let (oracle, mut card, _, _) = setup();
    let (c1b, c2a) = auth1_flow(&oracle, &mut card).await;
    let err = oracle
        .settle_impl(settle_req(
            c1b,
            c2a,
            Some(ReadSpec {
                service: 0x0999,
                block: 0,
            }),
        ))
        .await
        .expect_err("unknown service rejected");
    assert_eq!(err.code(), -32602);
}
