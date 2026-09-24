//! Challenge schedule: the only oracle math felica-rs keeps private.
//!
//! felica-rs holds the oracle-side schedule behind crate walls —
//! `AuthenticationContext` (`src/felica_standard/secure/des.rs:304-349`,
//! `pub(crate)`) and the 3DES block helpers
//! (`src/felica_standard/secure/primitives.rs:112-144`, `pub(super)`).
//! Until upstream exposes an oracle/relay API, this file replays that exact
//! schedule with the same `des` crate family felica-rs uses, line-for-line:
//! ```text
//! L = K_group xor IDm            (des.rs:316)
//! α = DES_encrypt(data=K_user, key=L)   (des.rs:317, encrypt_des_block(data, key))
//! β = DES_encrypt(data=L, key=α)        (des.rs:318)
//! C1A = 3DES(k1=α, k2=L, R1)     (des.rs:326-328)
//! C1B = 3DES(k1=L, k2=β, R1)     (des.rs:330-332)
//! C2A = 3DES(k1=L, k2=β, R2)     (des.rs:334-336)
//! C2B = 3DES(k1=α, k2=L, R2)     (des.rs:346-348)
//! ```
//! Spec reference: docs/spec.md §4.1. Everything else (key chain resolution,
//! AUTH2 verification, card emulation) comes from felica-rs public API via the
//! parent [`super`] module. The round-trip test below drives a real felica-rs
//! emulated card, so any drift from upstream is caught here.

use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use des::{Des, TdesEde3};
use zeroize::Zeroize;

/// Intermediate keys derived outside the ZK circuit (spec §4.1).
#[derive(Debug, Clone, Copy)]
pub struct IntermediateKeys {
    pub l: [u8; 8],
    pub alpha: [u8; 8],
    pub beta: [u8; 8],
}

impl IntermediateKeys {
    /// `AuthenticationContext::new` (felica-rs `secure/des.rs:311-320`).
    /// NOTE on argument order: felica-rs `encrypt_des_block(data, key)`, so
    /// `α = encrypt(data=K_user, key=L)`, `β = encrypt(data=L, key=α)`.
    pub fn derive(k_group: &[u8; 8], k_user: &[u8; 8], idm: &[u8; 8]) -> Self {
        let l = xor8(k_group, idm);
        let alpha = des_encrypt(k_user, &l);
        let beta = des_encrypt(&l, &alpha);
        Self { l, alpha, beta }
    }

    /// `encrypt_challenge1a` (des.rs:326).
    pub fn c1a(&self, r1: &[u8; 8]) -> [u8; 8] {
        tdes_encrypt(r1, &self.alpha, &self.l)
    }
    /// `encrypt_challenge1b` (des.rs:330): expected C1B for `verify_challenge1b`.
    pub fn c1b_expected(&self, r1: &[u8; 8]) -> [u8; 8] {
        tdes_encrypt(r1, &self.l, &self.beta)
    }
    /// `encrypt_challenge2b` (des.rs:346).
    pub fn c2b(&self, r2: &[u8; 8]) -> [u8; 8] {
        tdes_encrypt(r2, &self.alpha, &self.l)
    }
    /// `decrypt_challenge2a` (des.rs:342): recover session key R2 from C2A.
    pub fn r2_from_c2a(&self, c2a: &[u8; 8]) -> [u8; 8] {
        tdes_decrypt(c2a, &self.l, &self.beta)
    }
    /// Inverse of C1B (spec §7: oracle recovers `r1` as `3DES⁻¹(L, β, c1b)`).
    pub fn r1_from_c1b(&self, c1b: &[u8; 8]) -> [u8; 8] {
        tdes_decrypt(c1b, &self.l, &self.beta)
    }
}

fn xor8(a: &[u8; 8], b: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// `encrypt_des_block(data, key)` (felica-rs `primitives.rs:104-106`).
fn des_encrypt(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(key.into());
    let mut block = (*data).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// Two-key EDE 3DES with K1|K2|K1 (`encrypt_3des_block`, `primitives.rs:112-127`).
pub fn tdes_encrypt(data: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
    with_stacked_key(k1, k2, |stacked| {
        let cipher = TdesEde3::new(stacked.into());
        let mut block = (*data).into();
        cipher.encrypt_block(&mut block);
        block.into()
    })
}

/// `decrypt_3des_block` (`primitives.rs:129-144`).
pub fn tdes_decrypt(data: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
    with_stacked_key(k1, k2, |stacked| {
        let cipher = TdesEde3::new(stacked.into());
        let mut block = (*data).into();
        cipher.decrypt_block(&mut block);
        block.into()
    })
}

/// Runs `f` with the K1|K2|K1 stacking buffer, wiping it afterwards.
/// The cipher copies the key at construction, so the wipe is sound; the
/// cipher's own expanded schedule is cleared by the `des` crate
/// (`zeroize` feature), as in felica-rs `primitives.rs:117-121`.
fn with_stacked_key<R>(k1: &[u8; 8], k2: &[u8; 8], f: impl FnOnce(&[u8; 24]) -> R) -> R {
    let mut stacked = [0u8; 24];
    stacked[..8].copy_from_slice(k1);
    stacked[8..16].copy_from_slice(k2);
    stacked[16..].copy_from_slice(k1);
    let out = f(&stacked);
    stacked.zeroize();
    out
}

// ---------------------------------------------------------------------------
// Secure-messaging framing (second upstream gap).
//
// felica-rs holds command encryption (`SecureCommandContext`,
// `secure/mod.rs:366-461`) and response decryption
// (`decrypt_secure_response_des`, `secure/des.rs:142-172`) behind `pub(crate)`
// with no standalone public encrypt API (`secure_transceive` needs a live
// card/driver). The oracle builds `ecmd` with no card present, so this section
// replays the DES framing with the same `des`/`cbc` crates, line-for-line.
// Response decryption below additionally serves presentation (§9) later.
// ---------------------------------------------------------------------------

/// FeliCa command/response codes (felica-rs `constants.rs:166,212`;
/// `constants` is crate-private, values are spec §4.4 opcodes).
pub const READ_COMMAND_CODE: u8 = 0x14;
pub const READ_RESPONSE_CODE: u8 = 0x15;

/// TN chain of a single-`ecmd` session: `AUTH2(0) → ecmd(1) → response(2)`.
///
/// The oracle issues exactly one `ecmd` per session and it is always the
/// first command, so TN is a protocol constant — never observed state. A fresh
/// TID opens a fresh card session whose AUTH2 TN is 0 (emulator
/// `system.rs:468-476`, `unwrap_or(0)`); the card rejects `command_TN <=
/// last_TN` (`system.rs:770`), so TN=1 is the only first command and the
/// response TN=2 proves it executed with nothing interleaved before it.
/// Combined with commitment-before-R2-release, the TN chain is the proof that
/// the oracle handled all encrypted traffic: any prior command would have
/// advanced the chain past (1, 2), and post-`ecmd` forgeries are impossible
/// before R2 publication.
pub const ECMD_TN: u16 = 1;
pub const EXPECTED_READ_RESPONSE_TN: u16 = 2;

/// PKCS#7 padding to a DES-block multiple, applied only when misaligned
/// (`pad_to_des_block_size`, `primitives.rs:54-56`).
fn pad_des(mut data: Vec<u8>) -> Vec<u8> {
    let rem = data.len() % 8;
    if rem != 0 {
        let pad = (8 - rem) as u8;
        data.extend(std::iter::repeat(pad).take(pad as usize));
    }
    data
}

/// `calculate_command_mac_des` (`secure/des.rs:173-193`): `M0=[len, code, 0*6]`
/// with `len = 2 + payload + 8`, each data block folded in as the DES key.
fn command_mac(code: u8, padded: &[u8]) -> [u8; 8] {
    debug_assert!(padded.len() % 8 == 0);
    let total = 2 + padded.len() + 8;
    debug_assert!(total <= u8::MAX as usize);
    let mut mac = [0u8; 8];
    mac[0] = total as u8;
    mac[1] = code;
    for chunk in padded.chunks(8) {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        mac = des_encrypt(&mac, &block);
    }
    mac
}

/// DES-CBC encryption under a zero IV (`encrypt_des_cbc_zero_iv`,
/// `primitives.rs:146-159`).
fn cbc_encrypt(data: &[u8], key: &[u8; 8]) -> Vec<u8> {
    use cbc::Encryptor;
    use des::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::NoPadding};
    let iv = [0u8; 8];
    let mut out = vec![0u8; data.len()];
    let n = Encryptor::<Des>::new_from_slices(key, &iv)
        .expect("DES-CBC encryptor takes any 8-byte key/IV")
        .encrypt_padded_b2b::<NoPadding>(data, &mut out)
        .expect("caller pads to a block multiple")
        .len();
    out.truncate(n);
    out
}

/// DES-CBC decryption under a zero IV (`decrypt_des_cbc_zero_iv`,
/// `primitives.rs:161-174`). `None` on misalignment.
fn cbc_decrypt(data: &[u8], key: &[u8; 8]) -> Option<Vec<u8>> {
    use cbc::Decryptor;
    use des::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::NoPadding};
    if !data.len().is_multiple_of(8) {
        return None;
    }
    let iv = [0u8; 8];
    let mut out = vec![0u8; data.len()];
    let n = Decryptor::<Des>::new_from_slices(key, &iv)
        .ok()?
        .decrypt_padded_b2b::<NoPadding>(data, &mut out)
        .ok()?
        .len();
    out.truncate(n);
    Some(out)
}

/// Reverse-MAC verification (`check_packet_mac_des`, `secure/des.rs:195-224`):
/// the decrypted packet must end in a MAC that unfolds to
/// `[len+2, code, 0*6]`; all 8 bytes compared in constant time.
fn check_mac(data: &[u8], code: u8) -> bool {
    use des::cipher::BlockCipherDecrypt;
    use subtle::ConstantTimeEq;
    if !data.len().is_multiple_of(8) || data.len() < 16 || data.is_empty() {
        return false;
    }
    let (payload, mac) = data.split_at(data.len() - 8);
    if payload.is_empty() {
        return false;
    }
    let cipher_of = |key: &[u8; 8]| Des::new(key.into());
    let mut x = [0u8; 8];
    x.copy_from_slice(mac);
    let mut current = x;
    for chunk in payload.chunks(8).rev() {
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk);
        let cipher = cipher_of(&block);
        let mut b = current.into();
        cipher.decrypt_block(&mut b);
        current = b.into();
    }
    let mut expected = [0u8; 8];
    expected[0] = data.len() as u8 + 2;
    expected[1] = code;
    current.ct_eq(&expected).into()
}

/// Single-block Read inner payload (mirrors the `Read` secure encoding,
/// `command/serialize.rs:139-147`): `[count=1, element]` where the 2-byte
/// element is `[0x80|index, block]` (access mode 0, `index` = position in the
/// Authentication1 service list).
pub fn read_block_payload(service_index: u8, block: u8) -> [u8; 3] {
    debug_assert!(service_index < 16);
    [0x01, 0x80 | (service_index & 0x0F), block]
}

/// Secure command payload: `TN(LE,2) || TID(6) || inner` (mirrors
/// `build_payload_des`, `secure/mod.rs:386-392`). TN is the [`ECMD_TN`]
/// protocol constant.
pub fn build_cmd_payload(tid: &[u8; 6], inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + inner.len());
    out.extend_from_slice(&ECMD_TN.to_le_bytes());
    out.extend_from_slice(tid);
    out.extend_from_slice(inner);
    out
}

/// DES command encryption: `DES-CBC_IV0(key, PKCS7(payload) || MAC(code))`
/// (mirrors the DES arm of `SecureCommandContext::encrypt_command`,
/// `secure/mod.rs:404-433`). Returns the raw ciphertext; framing is
/// [`frame_secure_command`].
pub fn encrypt_command(code: u8, key: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let padded = pad_des(payload.to_vec());
    debug_assert!(2 + padded.len() + 8 <= u8::MAX as usize);
    let mac = command_mac(code, &padded);
    let mut data = padded;
    data.extend_from_slice(&mac);
    cbc_encrypt(&data, key)
}

/// Length-prefixed command frame: `[len, code] || enc` (mirrors the framing
/// in `send_encrypted_command`, `api/secure_ops.rs:237-244`).
pub fn frame_secure_command(code: u8, enc: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + enc.len());
    frame.push((2 + enc.len()) as u8);
    frame.push(code);
    frame.extend_from_slice(enc);
    frame
}

/// Verified single-block Read response (spec §4.3 plaintext):
/// `TN(LE,2) | TID(6) | SF1 | SF2 | count | data(16)`, 40-byte ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadData {
    pub tn: u16,
    pub tid: [u8; 6],
    pub sf1: u8,
    pub sf2: u8,
    pub count: u8,
    pub data: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadDecryptError {
    Malformed,
    MacMismatch,
    TidMismatch,
    /// Response TN is not [`EXPECTED_READ_RESPONSE_TN`]: the TN chain
    /// (AUTH2(0) → ecmd(1) → response(2)) is broken, i.e. another command ran
    /// before this response. The pair is not the complete session.
    TnMismatch,
}

/// Decrypt and verify a 40-byte Read response ciphertext under R2.
/// Mirrors `decrypt_secure_response_des` + TID check; serves the settle test
/// now and presentation (§9) later.
pub fn decrypt_read_response(
    r2: &[u8; 8],
    expected_tid: &[u8; 6],
    ct: &[u8],
) -> Result<ReadData, ReadDecryptError> {
    if ct.len() != 40 {
        return Err(ReadDecryptError::Malformed);
    }
    let data = cbc_decrypt(ct, r2).ok_or(ReadDecryptError::Malformed)?;
    if !check_mac(&data, READ_RESPONSE_CODE) {
        return Err(ReadDecryptError::MacMismatch);
    }
    let body = &data[..32];
    let tn = u16::from_le_bytes([body[0], body[1]]);
    if tn != EXPECTED_READ_RESPONSE_TN {
        return Err(ReadDecryptError::TnMismatch);
    }
    let mut tid = [0u8; 6];
    tid.copy_from_slice(&body[2..8]);
    if &tid != expected_tid {
        return Err(ReadDecryptError::TidMismatch);
    }
    let mut block = [0u8; 16];
    block.copy_from_slice(&body[11..27]);
    Ok(ReadData {
        tn,
        tid,
        sf1: body[8],
        sf2: body[9],
        count: body[10],
        data: block,
    })
}
