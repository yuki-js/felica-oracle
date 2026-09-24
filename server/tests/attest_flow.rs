mod common;

use common::{R1B_HEX, R1_HEX, attest_req, attest_req_cm, auth1_flow, auth2_flow, settle_req, setup};
use felica_oracle::api::types::ReadSpec;
use felica_oracle::oracle::{OracleKeys, fixture, verify_session};

/// challenge → Auth1 → settle → Auth2 → attest verification, end to end.
/// The RPC returns the Groth16 attestation binding the verified session.
#[tokio::test]
async fn attest_verifies_full_session() {
    let (oracle, mut card, gsk, usk) = setup();
    let (c1b, c2a) = auth1_flow(&oracle, &mut card, R1_HEX).await;
    let st = oracle
        .settle(settle_req(
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
    let auth2_ct = auth2_flow(&mut card, c2b);

    let keys = OracleKeys::new(gsk, usk);
    let v = verify_session(
        &keys,
        &fixture::IDM,
        &c1b,
        &c2a,
        &auth2_ct,
        &[0u8; 32],
    )
    .expect("session verifies");
    let r1: [u8; 8] = hex::decode(R1_HEX).unwrap().try_into().unwrap();
    assert_eq!(v.r1, r1);
    assert_eq!(v.tid, r1[2..8]);
    assert_eq!(v.idi, fixture::IDI);
    assert_eq!(v.cm, [0u8; 32]);
    // R2 matches the card's session key: it decrypts the read response.
    let r2 = keys.session(&fixture::IDM).open_r2(&c2a);
    assert_eq!(v.r2, r2);

    // Explicit commitment is echoed for the proof-to-come.
    let cm_hex = "b3d631c3c8dddff26f7e2b24b781307b4e4eca9ed4f7a5cdf716f36d82d0fde4";
    let v2 = verify_session(
        &keys,
        &fixture::IDM,
        &c1b,
        &c2a,
        &auth2_ct,
        &hex::decode(cm_hex).unwrap().try_into().unwrap(),
    )
    .expect("session verifies with cm");
    assert_eq!(v2.cm, hex::decode(cm_hex).unwrap()[..]);

    // RPC surface: Groth16 attestation binds the verified session.
    let resp = oracle
        .attest(attest_req_cm(c1b, c2a, auth2_ct, Some(cm_hex.to_string())))
        .await
        .expect("attest proves genuine session");
    assert_eq!(resp.idi, hex::encode(fixture::IDI));
    assert_eq!(resp.r2, hex::encode(v2.r2));
    assert!(resp.attested_at > 0);
    assert_eq!(resp.proof.alg, "groth16-bn254");
    assert_eq!(resp.proof.public_inputs.len(), 8, "Sui 8-input packing");
}

#[tokio::test]
async fn attest_rejects_tampered_auth2() {
    let (oracle, mut card, _, _) = setup();
    let (c1b, c2a) = auth1_flow(&oracle, &mut card, R1_HEX).await;
    let st = oracle
        .settle(settle_req(c1b, c2a, None))
        .await
        .expect("settle");
    let c2b: [u8; 8] = hex::decode(&st.c2b).unwrap().try_into().unwrap();
    let mut bad = auth2_flow(&mut card, c2b);
    bad[0] ^= 0xFF;
    let err = oracle
        .attest(attest_req(c1b, c2a, bad))
        .await
        .expect_err("tampered auth2 rejected");
    assert_eq!(err.code(), -32010);
}

#[tokio::test]
async fn attest_rejects_tid_mismatch() {
    let (oracle, mut card, gsk, usk) = setup();
    // AUTH2 bound to R1A's TID…
    let (c1b_a, c2a) = auth1_flow(&oracle, &mut card, R1_HEX).await;
    let st = oracle
        .settle(settle_req(
            c1b_a,
            c2a,
            Some(ReadSpec {
                service: fixture::SERVICE,
                block: 0,
            }),
        ))
        .await
        .expect("settle");
    let c2b: [u8; 8] = hex::decode(&st.c2b).unwrap().try_into().unwrap();
    let auth2_ct = auth2_flow(&mut card, c2b);
    // …paired with C1B from a different R1.
    let (c1b_b, _) = auth1_flow(&oracle, &mut card, R1B_HEX).await;
    let keys = OracleKeys::new(gsk, usk);
    let err = felica_oracle::oracle::verify_session(
        &keys,
        &fixture::IDM,
        &c1b_b,
        &c2a,
        &auth2_ct,
        &[0u8; 32],
    )
    .expect_err("tid mismatch rejected");
    assert_eq!(err, felica_oracle::oracle::AttestError::TidMismatch);
    // Same through the RPC surface.
    let rpc_err = oracle
        .attest(attest_req(c1b_b, c2a, auth2_ct))
        .await
        .expect_err("tid mismatch rejected");
    assert_eq!(rpc_err.code(), -32011);
}
