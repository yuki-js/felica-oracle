use felica_oracle::oracle::{Auth2Error, OracleKeys, fixture, schedule, verify_auth2};

// Spec §7 DES vector (key `133457799bbcdff1`, pt `0123456789abcdef`,
// ct `85e813540f0ab405`), exercised through the public 3DES path: with
// K1 == K2, two-key EDE collapses to single DES.
#[test]
fn des_test_vector() {
    let key: [u8; 8] = hex::decode("133457799bbcdff1").unwrap().try_into().unwrap();
    let pt: [u8; 8] = hex::decode("0123456789abcdef").unwrap().try_into().unwrap();
    let ct: [u8; 8] = hex::decode("85e813540f0ab405").unwrap().try_into().unwrap();
    assert_eq!(schedule::tdes_encrypt(&pt, &key, &key), ct);
    assert_eq!(schedule::tdes_decrypt(&ct, &key, &key), pt);
}

#[test]
fn cmd_payload_layout_is_pinned() {
    let tid = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    assert_eq!(schedule::read_block_payload(0, 7), [0x01, 0x80, 0x07]);
    assert_eq!(schedule::read_block_payload(3, 0), [0x01, 0x83, 0x00]);
    assert_eq!(
        schedule::build_cmd_payload(&tid, &schedule::read_block_payload(0, 7)),
        vec![0x01, 0x00, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x01, 0x80, 0x07]
    );
}

/// Oracle↔card round trip against a real felica-rs emulated card.
///
/// The oracle side uses GSK/USK only; the card side is 100% felica-rs.
/// AUTH2 is verified twice: by felica-rs's public
/// `Authentication2Response::decrypt_payload` directly, and through the
/// oracle's felica-rs-backed [`verify_auth2`] path.
#[test]
fn oracle_card_round_trip_via_emulator() {
    use felica::felica_standard::{FelicaStandardCommand, FelicaStandardResponse};

    let f = fixture::setup();
    let mut card = f.card;
    let oracle = OracleKeys::new(f.gsk, f.usk).session(&fixture::IDM);

    // challenge: oracle C1A → card C1B/C2A.
    let r1: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let c1a = oracle.c1a(&r1);
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
    // Oracle mirror matches the felica-rs card.
    assert!(oracle.check_c1b(&r1, &c1b), "C1B mismatch");
    assert_eq!(oracle.recover_r1(&c1b), r1, "R1 recovery mismatch");

    // settle: oracle recovers R2, answers C2B → card returns AUTH2.
    let r2 = oracle.open_r2(&c2a);
    let c2b = oracle.c2b(&r2);
    let frame = card
        .handle_command(FelicaStandardCommand::Authentication2 {
            idm: fixture::IDM,
            challenge_2b: c2b,
        })
        .expect("card answers authentication2");
    let auth2 = match FelicaStandardResponse::from_bytes(&frame).expect("parse") {
        FelicaStandardResponse::Authentication2(payload) => payload,
        other => panic!("unexpected response: {other:?}"),
    };
    let payload = auth2.decrypt_payload(&r2).expect("auth2 MAC valid");
    assert_eq!(payload.len(), 24);
    assert_eq!(&payload[0..2], &0u16.to_le_bytes(), "TN starts at 0");
    assert_eq!(&payload[2..8], &r1[2..8], "TID == tail6(R1)");
    assert_eq!(payload[8..16], fixture::IDI, "payload carries IDi");
    assert_eq!(payload[16..24], fixture::PMI, "payload carries PMi");

    // Same verification through the oracle path: the holder submits the raw
    // 32-byte ciphertext from the card frame.
    let ct: [u8; 32] = frame[2..34].try_into().expect("32B ciphertext");
    let data = verify_auth2(&r2, &ct).expect("oracle AUTH2 verify");
    assert_eq!(data.tn, 0);
    assert_eq!(data.tid, r1[2..8]);
    assert_eq!(data.idi, fixture::IDI);
    assert_eq!(data.pmi, fixture::PMI);

    // Tampered ciphertext fails with MAC mismatch, not a panic.
    let mut bad = ct;
    bad[0] ^= 0xFF;
    assert_eq!(verify_auth2(&r2, &bad), Err(Auth2Error::MacMismatch));
}
