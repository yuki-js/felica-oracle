//! Temporary E2E: challenge → settle → attest over real HTTP RPC,
//! plus the single-block read flow with commitment and local verification.
//!
//! Run: `cargo run --manifest-path server/Cargo.toml --example rpc_attest`
//! Env: `RPC_ADDR` (default `127.0.0.1:3000`).
//!
//! Uses the shared emulator fixture as the card.

use std::net::SocketAddr;

use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};
use felica_oracle::oracle::fixture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const R1_HEX: &str = "0011223344556677";
const RANDOMNESS: [u8; 32] = [0xA5; 32];

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

fn hex8(v: &serde_json::Value) -> [u8; 8] {
    hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
}

fn to_attestation(result: &serde_json::Value) -> felica_prover::Attestation {
    let proof = &result["proof"];
    let pair = |v: &serde_json::Value| {
        let a = v.as_array().unwrap();
        (
            a[0].as_str().unwrap().to_string(),
            a[1].as_str().unwrap().to_string(),
        )
    };
    let b = proof["b"].as_array().unwrap();
    felica_prover::Attestation {
        idi: hex8(&result["idi"]),
        r2: hex8(&result["r2"]),
        cm_out: [0u8; 32],
        attested_at: result["attested_at"].as_u64().unwrap(),
        proof: felica_prover::Groth16Proof {
            alg: proof["alg"].as_str().unwrap().to_string(),
            a: pair(&proof["a"]),
            b: (pair(&b[0]), pair(&b[1])),
            c: pair(&proof["c"]),
            public_inputs: proof["public_inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect(),
        },
    }
}

#[tokio::main]
async fn main() {
    let addr: SocketAddr = std::env::var("RPC_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()
        .unwrap();
    let fixture::Fixture { mut card, .. } = fixture::setup();

    // --- auth-only attest ---
    let resp = rpc(
        addr,
        call(
            "challenge",
            1,
            serde_json::json!({"idm": fixture::IDM_HEX, "r1": R1_HEX}),
        ),
    )
    .await;
    let c1a: [u8; 8] = hex8(&resp["result"]["c1a"]);

    let frame = card
        .handle_command(FelicaStandardCommand::Authentication1 {
            idm: fixture::IDM,
            areas: vec![fixture::AREA],
            services: vec![fixture::SERVICE],
            challenge_1a: c1a,
        })
        .expect("card answers authentication1");
    let (c1b, c2a) = match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication1 {
            challenge_1b,
            challenge_2a,
            ..
        } => (challenge_1b, challenge_2a),
        other => panic!("unexpected response: {other:?}"),
    };

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
            }),
        ),
    )
    .await;
    let c2b: [u8; 8] = hex8(&resp["result"]["c2b"]);

    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: fixture::IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2");
    let auth2_ct = hex::encode(&frame[2..34]);

    let resp = rpc(
        addr,
        call(
            "attest",
            3,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "auth2": auth2_ct,
            }),
        ),
    )
    .await;
    let result = resp.get("result").expect("attest result").clone();
    println!("auth-only idi: {}", result["idi"]);
    assert_eq!(result["idi"], serde_json::Value::String(hex::encode(fixture::IDI)));

    // --- read flow with commitment + local verification (fresh card) ---
    // Note: the card mints a fresh R2 per Authentication1, so this session
    // has its own c2a/r2/c2b — reusing the auth-only vectors is rejected.
    let fixture::Fixture { mut card, .. } = fixture::setup();
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication1 {
            idm: fixture::IDM,
            areas: vec![fixture::AREA],
            services: vec![fixture::SERVICE],
            challenge_1a: c1a,
        })
        .expect("card answers authentication1");
    let (c1b, c2a) = match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication1 {
            challenge_1b,
            challenge_2a,
            ..
        } => (challenge_1b, challenge_2a),
        other => panic!("unexpected response: {other:?}"),
    };
    let resp = rpc(
        addr,
        call(
            "settle",
            4,
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
    let result = resp.get("result").expect("settle result").clone();
    let c2b: [u8; 8] = hex8(&result["c2b"]);
    let ecmd = hex::decode(result["ecmd"].as_str().unwrap()).unwrap();

    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: fixture::IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2 (read session)");
    let auth2_ct = hex::encode(&frame[2..34]);
    let enc_resp = card.handle_frame(&ecmd).expect("card executes ecmd");

    let cm = felica_prover::commit(&ecmd, &enc_resp, &RANDOMNESS);
    let resp = rpc(
        addr,
        call(
            "attest",
            5,
            serde_json::json!({
                "idm": fixture::IDM_HEX,
                "c1b": hex::encode(c1b),
                "c2a": hex::encode(c2a),
                "auth2": auth2_ct,
                "cm": hex::encode(cm),
            }),
        ),
    )
    .await;
    let result = resp.get("result").expect("read attest result").clone();
    let r2: [u8; 8] = hex8(&result["r2"]);

    // Local verification against the oracle-published vk.
    let resp = rpc(addr, call("get_verifying_key", 6, serde_json::json!([]))).await;
    let vk_bytes = hex::decode(resp["result"].as_str().unwrap()).unwrap();
    let vk = felica_prover::load_verifying_key(&vk_bytes).expect("vk loads");
    let mut att = to_attestation(&result);
    att.cm_out = cm;
    assert!(
        felica_prover::verify_attestation(&vk, &att),
        "read proof verifies against RPC vk"
    );

    // Block inspection: decrypt the read response with the published R2.
    let r1: [u8; 8] = hex::decode(R1_HEX).unwrap().try_into().unwrap();
    let mut tid = [0u8; 6];
    tid.copy_from_slice(&r1[2..8]);
    let read = felica_oracle::oracle::schedule::decrypt_read_response(&r2, &tid, &enc_resp[2..])
        .expect("read response verifies");
    assert_eq!(read.data, fixture::BLOCK, "block contents match");
    println!("read data: {}", hex::encode(read.data));
    println!("E2E OK (auth + read + verify)");
}
