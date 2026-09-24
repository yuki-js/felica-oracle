//! Session proving benchmarks (criterion).
//!
//! Run: `cargo bench --manifest-path circom-prover/Cargo.toml --bench session`
//! (`cargo bench` builds optimized, like release.)
//!
//! | bench | cost (release, i9-13900K, this backend) |
//! | `des/single_block` | ~1.19µs — native DES, criterion defaults |
//! | `des/session_precheck` | ~19.8µs — tdes recover + CBC + MAC natively |
//! | `r1cs/synthesize_blank` | ~88ms — constraint synthesis only, no key |
//! | `groth16_prove/prove` | ~1.21s/iter — full prove (first iter includes setup) |
//! | `groth16_verify/verify` | ~2.07ms — `verify_attestation` on a fixed proof |
//!
//! `groth16/prove` uses few samples on purpose: each iteration is a real
//! Groth16 prove (~0.6GB peak). The proving key is process-cached, so the
//! first iteration also pays setup (~0.7s).

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use felica::felica_standard::{
    EmulatedArea as EmuArea, EmulatedService as EmuSvc, EmulatedSystem as EmuSys,
    FelicaStandardEmulator, FelicaStandardCommand, FelicaStandardResponse, ServiceCode,
    generate_service_keys_des,
};
use felica_circom_prover::{
    ProveRequest, blank_constraint_counts, verify_attestation,
    des::{cbc_decrypt, command_mac, des_encrypt, tdes_decrypt, tdes_encrypt},
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
const R1: [u8; 8] = hex!("0011223344556677");
const RANDOMNESS: [u8; 32] =
    hex!("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5");

fn fixture_keys() -> ([u8; 8], [u8; 8], [u8; 8], [u8; 8]) {
    let (gsk, usk) = generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[SERVICE_KEY]);
    let mut l = [0u8; 8];
    for i in 0..8 {
        l[i] = gsk[i] ^ IDM[i];
    }
    let alpha = des_encrypt(&usk, &l);
    let beta = des_encrypt(&l, &alpha);
    (gsk, usk, l, beta)
}

fn setup_card() -> FelicaStandardEmulator {
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
    card
}

/// Genuine `(c1b, c2a, auth2)` for the fixed holder challenge `R1`.
fn mint() -> ([u8; 8], [u8; 8], [u8; 32]) {
    let mut card = setup_card();
    let (_, _, l, beta) = fixture_keys();
    let (gsk, usk) = generate_service_keys_des(&SYSTEM_KEY, &[AREA_KEY], &[SERVICE_KEY]);
    let alpha = des_encrypt(&usk, &l);
    let c1a = tdes_encrypt(&R1, &alpha, &l);
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
    let auth2: [u8; 32] = frame[2..34].try_into().expect("32B ciphertext");
    let _ = (gsk, usk);
    (c1b, c2a, auth2)
}

fn prove_request() -> ProveRequest {
    let (c1b, c2a, auth2) = mint();
    let (gsk, usk, _, _) = fixture_keys();
    let cm = felica_circom_prover::commit(&[0x1Au8; 26], &[0x2Au8; 42], &RANDOMNESS);
    ProveRequest {
        idm: IDM, c1b, c2a, auth2, cm,
        k_group: gsk, k_user: usk, attested_at: 1_758_768_000,
    }
}

fn session_precheck(req: &ProveRequest) {
    let (_, _, l, beta) = fixture_keys();
    let r1 = tdes_decrypt(&req.c1b, &l, &beta);
    let r2 = tdes_decrypt(&req.c2a, &l, &beta);
    let pt = cbc_decrypt(&req.auth2, &r2).expect("cbc");
    assert_eq!(command_mac(0x13, &pt[..24]), pt[24..32]);
    assert_eq!(&pt[2..8], &r1[2..8]);
}

fn benches(c: &mut Criterion) {
    // Native single DES block (spec vector key).
    let key: [u8; 8] = hex!("133457799bbcdff1");
    let pt: [u8; 8] = hex!("0123456789abcdef");
    c.bench_function("des/single_block", |b| {
        b.iter(|| des_encrypt(&pt, &key));
    });

    // Native session pre-check path (what prove() runs before the circuit).
    let req = prove_request();
    c.bench_function("des/session_precheck", |b| {
        b.iter(|| session_precheck(&req));
    });

    // Constraint synthesis only (no proving key).
    let mut g = c.benchmark_group("r1cs");
    g.sample_size(20);
    g.bench_function("synthesize_blank", |b| {
        b.iter(|| blank_constraint_counts());
    });
    g.finish();

    // Full Groth16 prove on a genuine vector (few samples: ~1.3s each).
    let mut g = c.benchmark_group("groth16_prove");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(30));
    g.bench_function("prove", |b| {
        b.iter(|| felica_circom_prover::prove(&req).expect("prove"));
    });
    g.finish();

    // Verify on a fixed proof (proving happens once, outside the loop).
    let att = felica_circom_prover::prove(&req).expect("fixture proof");
    c.bench_function("groth16_verify/verify", |b| {
        b.iter(|| verify_attestation(&att));
    });
}

criterion_group!(session, benches);
criterion_main!(session);
