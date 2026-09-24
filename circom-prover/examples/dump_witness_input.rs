//! Dump a genuine session witness-input JSON for the compiled circom circuit.
//!
//! Run from the crate root after `scripts/compile.sh --wasm`:
//! ```sh
//! cargo run --example dump_witness_input > build/input.json
//! node build/felica_js/generate_witness.js \
//!   build/felica_js/felica.wasm build/input.json build/witness.wtns
//! npx snarkjs wtns check build/felica.r1cs build/witness.wtns
//! ```
//! Uses the fixed-R1 fixture card (same as `tests/attest_prove.rs`), so the
//! input is deterministic. Signal names match `circuits/felica.circom`.

use ark_ff::PrimeField;
use felica::felica_standard::{
    EmulatedArea as EmuArea, EmulatedService as EmuSvc, EmulatedSystem as EmuSys,
    FelicaStandardEmulator, FelicaStandardCommand, FelicaStandardResponse, ServiceCode,
    generate_service_keys_des,
};
use felica_circom_prover::des::{des_encrypt, tdes_decrypt, tdes_encrypt};
use hex_literal::hex;

const IDM: [u8; 8] = hex!("0102030405060708");
const IDI: [u8; 8] = hex!("1020304050607080");
const PMI: [u8; 8] = hex!("a0a1a2a3a4a5a6a7");
const PMM: [u8; 8] = hex!("0100000000000000");
const SYSTEM_KEY: [u8; 8] = hex!("1122334455667788");
const AREA_KEY: [u8; 8] = hex!("21436587a9cbed0f");
const SERVICE_KEY: [u8; 8] = hex!("0102030405060708");
const R1: [u8; 8] = hex!("0011223344556677");

fn le_field_decimal(bytes: &[u8]) -> String {
    ark_bn254::Fr::from_le_bytes_mod_order(bytes)
        .into_bigint()
        .to_string()
}

fn main() {
    let (gsk, usk) = generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[SERVICE_KEY]);
    let mut emusys = EmuSys::new(0x0003, IDM, PMM).expect("system");
    emusys.set_system_key(SYSTEM_KEY);
    emusys.set_idi_pmi(IDI, PMI);
    let mut emuarea = EmuArea::new(0x0040, 0x00FF).expect("area");
    emuarea.set_key(AREA_KEY);
    let mut emusvc = EmuSvc::with_blocks(
        ServiceCode::new(0x0048),
        0x0000,
        vec![hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")],
    );
    emusvc.set_key(SERVICE_KEY);
    emuarea.add_service(emusvc).expect("service fits");
    emusys.add_area(emuarea).expect("area fits");
    let mut card = FelicaStandardEmulator::new();
    card.add_system(emusys);

    let mut l = [0u8; 8];
    for i in 0..8 {
        l[i] = gsk[i] ^ IDM[i];
    }
    let alpha = des_encrypt(&usk, &l);
    let beta = des_encrypt(&l, &alpha);
    let c1a = tdes_encrypt(&R1, &alpha, &l);
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication1 {
            idm: IDM,
            areas: vec![0x0040],
            services: vec![0x0048],
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
    let auth2: [u8; 32] = frame[2..34].try_into().expect("32B ciphertext");

    let cm = [0u8; 32];
    let mut idi_r2 = [0u8; 16];
    idi_r2[..8].copy_from_slice(&IDI);
    idi_r2[8..].copy_from_slice(&r2);

    let arr = |bs: &[u8]| bs.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(",");
    println!("{{");
    println!("  \"r1_bytes\": [{}],", arr(&R1));
    println!("  \"c1b_bytes\": [{}],", arr(&c1b));
    println!("  \"c2a_bytes\": [{}],", arr(&c2a));
    println!("  \"auth2_bytes\": [{}],", arr(&auth2));
    println!("  \"idi_bytes\": [{}],", arr(&IDI));
    println!("  \"r2_bytes\": [{}],", arr(&r2));
    println!("  \"l_bytes\": [{}],", arr(&l));
    println!("  \"beta_bytes\": [{}],", arr(&beta));
    println!("  \"r1\": \"{}\",", le_field_decimal(&R1));
    println!("  \"c1b\": \"{}\",", le_field_decimal(&c1b));
    println!("  \"c2a\": \"{}\",", le_field_decimal(&c2a));
    println!("  \"auth2_lo\": \"{}\",", le_field_decimal(&auth2[..16]));
    println!("  \"auth2_hi\": \"{}\",", le_field_decimal(&auth2[16..]));
    println!("  \"cm\": \"{}\",", le_field_decimal(&cm));
    println!("  \"idi_r2\": \"{}\",", le_field_decimal(&idi_r2));
    println!("  \"attested_at\": \"1758768000\"");
    println!("}}");
}
