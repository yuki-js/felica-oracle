//! JSON-RPC over HTTP: spec `docs/spec.md` §8 surface test.
//!
//! The direct-call unit tests bypass serialization; this binary drives the real
//! HTTP server (same `ServerConfig` as `src/main.rs`, batch disabled) with
//! spec-shaped object params and asserts wire shapes, error codes, and the
//! prover connection (`attest` returns a verifying Groth16 attestation).
//!
//! NOTE: `settle` keeps the documented `r1` extension
//! (`src/api/types.rs::SettleRequest`): params are
//! `{idm, r1, c1b, c2a, read_spec?}`. `challenge` likewise returns the node
//! path (`system_code/areas/services`) alongside `c1a`.

use std::net::SocketAddr;

use felica_oracle::api::{OracleApiServer, OracleImpl};
use felica_oracle::oracle::fixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const R1_HEX: &str = "0011223344556677";

async fn start_server() -> (
    jsonrpsee::server::ServerHandle,
    SocketAddr,
    fixture::Fixture,
) {
    let f = fixture::setup();
    let module = OracleImpl::new(fixture::app_config(&f)).into_rpc();
    // Same config as `src/main.rs`: spec §8 forbids batch requests.
    let cfg = jsonrpsee::server::ServerConfig::builder()
        .set_batch_request_config(jsonrpsee::server::BatchRequestConfig::Disabled)
        .build();
    let server = jsonrpsee::server::Server::builder()
        .set_config(cfg)
        .build("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let handle = server.start(module);
    (handle, addr, f)
}

/// Raw HTTP/1.1 POST (no extra client deps); returns the parsed JSON body.
async fn rpc(addr: SocketAddr, body: serde_json::Value) -> serde_json::Value {
    let raw = serde_json::to_vec(&body).unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        raw.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&raw).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let start = text.find("\r\n\r\n").unwrap() + 4;
    serde_json::from_str(&text[start..]).unwrap()
}

fn call(method: &str, id: u64, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// challenge (HTTP, spec §8.1 object params) → card Authentication1.
async fn http_auth1(
    addr: SocketAddr,
    card: &mut felica::felica_standard::FelicaStandardEmulator,
    r1_hex: &str,
) -> ([u8; 8], [u8; 8]) {
    let resp = rpc(
        addr,
        call(
            "challenge",
            1,
            serde_json::json!({"idm": fixture::IDM_HEX, "r1": r1_hex}),
        ),
    )
    .await;
    let result = resp.get("result").expect("challenge result");
    assert_eq!(result["system_code"], fixture::SYSTEM_CODE);
    assert_eq!(result["areas"], serde_json::json!([fixture::AREA]));
    assert_eq!(result["services"], serde_json::json!([fixture::SERVICE]));
    let c1a: [u8; 8] = hex::decode(result["c1a"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let frame = card
        .handle_command(
            felica::felica_standard::FelicaStandardCommand::Authentication1 {
                idm: fixture::IDM,
                areas: vec![fixture::AREA],
                services: vec![fixture::SERVICE],
                challenge_1a: c1a,
            },
        )
        .expect("card answers authentication1");
    match felica::felica_standard::FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        felica::felica_standard::FelicaStandardResponse::Authentication1 {
            challenge_1b,
            challenge_2a,
            ..
        } => (challenge_1b, challenge_2a),
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Card Authentication2 → raw 32-byte AUTH2 ciphertext.
fn card_auth2(
    card: &mut felica::felica_standard::FelicaStandardEmulator,
    c2b: [u8; 8],
) -> [u8; 32] {
    let frame = card
        .handle_command(
            felica::felica_standard::FelicaStandardCommand::Authentication2 {
                idm: fixture::IDM,
                challenge_2b: c2b,
            },
        )
        .expect("card answers authentication2");
    frame[2..34].try_into().expect("32B ciphertext")
}

#[tokio::test]
async fn http_challenge_settle_flow_and_errors() {
    let (handle, addr, f) = start_server().await;
    let fixture::Fixture { mut card, gsk, usk } = f;

    // challenge → card Auth1 → settle with read → card executes ecmd.
    let (c1b, c2a) = http_auth1(addr, &mut card, R1_HEX).await;
    let resp = rpc(
        addr,
        call(
            "settle",
            2,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "r1": R1_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "read_spec": {"service": fixture::SERVICE, "block": 0},
            }),
        ),
    )
    .await;
    let result = resp.get("result").expect("settle result");
    let c2b: [u8; 8] = hex::decode(result["c2b"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let ecmd = hex::decode(result["ecmd"].as_str().unwrap()).unwrap();
    assert_eq!(ecmd.len(), 26, "len + 0x14 + 24B ciphertext");
    assert_eq!(ecmd[1], 0x14, "read command code");
    // Card accepts C2B (mutual auth completes), then executes our ecmd.
    let auth2_ct = card_auth2(&mut card, c2b);
    let enc_resp = card.handle_frame(&ecmd).expect("card executes ecmd");
    assert_eq!(enc_resp[1], 0x15, "read response code");
    // Session key R2 decrypts the read response (TN chain intact).
    let r1: [u8; 8] = hex::decode(R1_HEX).unwrap().try_into().unwrap();
    let mut tid = [0u8; 6];
    tid.copy_from_slice(&r1[2..8]);
    let r2 = felica_oracle::oracle::OracleKeys::new(gsk, usk)
        .session(&fixture::IDM)
        .open_r2(&c2a);
    let read = felica_oracle::oracle::schedule::decrypt_read_response(&r2, &tid, &enc_resp[2..])
        .expect("read response verifies");
    assert_eq!(read.data, fixture::BLOCK);
    assert_eq!(auth2_ct.len(), 32);
    // Auth-only settle omits `ecmd`.
    let resp = rpc(
        addr,
        call(
            "settle",
            3,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "r1": R1_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
            }),
        ),
    )
    .await;
    assert!(resp["result"]["ecmd"].is_null(), "auth-only omits ecmd");

    // Errors: bad hex → -32602; forged c1b → -32012; unknown service → -32602.
    let resp = rpc(
        addr,
        call(
            "challenge",
            4,
            serde_json::json!({"idm": "zzzz", "r1": R1_HEX}),
        ),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
    let resp = rpc(
        addr,
        call(
            "settle",
            5,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "r1": R1_HEX,
                "c1b": "aabbccddeeff0011",
                "c2a": hex::encode(c2a),
            }),
        ),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32012);
    let resp = rpc(
        addr,
        call(
            "settle",
            6,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "r1": R1_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "read_spec": {"service": 0x0999, "block": 0},
            }),
        ),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);

    // Batch is not supported (spec §8): the server must not answer with
    // per-call results.
    let batch = serde_json::json!([
        {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": []},
        {"jsonrpc": "2.0", "id": 8, "method": "ping", "params": []},
    ]);
    let resp = rpc(addr, batch).await;
    let ok = resp.get("error").is_some()
        || resp
            .as_array()
            .is_some_and(|a| a.iter().any(|e| e.get("error").is_some()));
    assert!(ok, "batch must be rejected: {resp}");

    handle.stop().unwrap();
}

/// Full holder flow over HTTP through `attest`: the response carries the
/// Groth16 attestation binding the verified session (prover connection).
/// Heavy: one real proof (~130k constraints).
#[tokio::test]
async fn http_attest_proves_session() {
    let (handle, addr, f) = start_server().await;
    let fixture::Fixture { mut card, .. } = f;

    let (c1b, c2a) = http_auth1(addr, &mut card, R1_HEX).await;
    let resp = rpc(
        addr,
        call(
            "settle",
            2,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "r1": R1_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "read_spec": {"service": fixture::SERVICE, "block": 0},
            }),
        ),
    )
    .await;
    let c2b: [u8; 8] = hex::decode(resp["result"]["c2b"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let auth2_ct = card_auth2(&mut card, c2b);

    // Explicit cm.
    let cm_hex = "b3d631c3c8dddff26f7e2b24b781307b4e4eca9ed4f7a5cdf716f36d82d0fde4";
    let resp = rpc(
        addr,
        call(
            "attest",
            3,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "auth2": hex::encode(auth2_ct),
                "cm": cm_hex,
            }),
        ),
    )
    .await;
    let result = resp.get("result").expect("attest result").clone();
    assert_eq!(result["idi"], hex::encode(fixture::IDI));
    assert_eq!(result["proof"]["alg"], "groth16-bn254");
    assert_eq!(
        result["proof"]["public_inputs"].as_array().unwrap().len(),
        8
    );
    assert!(result["attested_at"].as_u64().unwrap() > 0);
    // The public inputs pin the session limbs (r1/c1b/c2a/auth2 halves).
    let pi: Vec<Vec<u8>> = result["proof"]["public_inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| hex::decode(s.as_str().unwrap()).unwrap())
        .collect();
    let r1: [u8; 8] = hex::decode(R1_HEX).unwrap().try_into().unwrap();
    assert_eq!(&pi[0][..8], &r1, "pi0 = r1");
    assert_eq!(&pi[1][..8], &c1b, "pi1 = c1b");
    assert_eq!(&pi[6][..8], &fixture::IDI, "pi6 low = idi");

    // Omitted cm defaults to zeros (auth-only attestation).
    let resp = rpc(
        addr,
        call(
            "attest",
            4,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "auth2": hex::encode(auth2_ct),
            }),
        ),
    )
    .await;
    assert!(resp.get("result").is_some(), "cm defaults to zeros");

    // Tampered AUTH2 → MAC_MISMATCH (-32010).
    let mut bad = auth2_ct;
    bad[0] ^= 0xFF;
    let resp = rpc(
        addr,
        call(
            "attest",
            5,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "auth2": hex::encode(bad),
            }),
        ),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32010);

    handle.stop().unwrap();
}
