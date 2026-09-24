//! Native DES / 3DES-EDE / CBC / MAC (spec `docs/spec.md` §4.1, §4.4, §7).
//!
//! Single source of truth for DES bit-tables shared by the native witness
//! path and the R1CS gadget (`circuit.rs`). Tables follow FIPS 46-3 with
//! bit 1 = MSB of byte 0. Verified against the spec §7.1 vector
//! (key `133457799bbcdff1`, pt `0123456789abcdef` → ct `85e813540f0ab405`)
//! and cross-checked against the `des` crate family felica-rs uses.

/// Initial permutation (0-indexed DES bits).
pub const IP: [usize; 64] = [
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63,
    55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60,
    52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
];

/// Expansion E: 32 → 48 bits.
pub const E: [usize; 48] = [
    31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17,
    18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0,
];

/// Permutation P (32 bits).
pub const P: [usize; 32] = [
    15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18,
    12, 29, 5, 21, 10, 3, 24,
];

/// Permuted choice 1: 64 → 56 bits (drops parity bits 7,15,…,63 in 0-index).
pub const PC1: [usize; 56] = [
    56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44,
    36, 28, 20, 12, 4, 27, 19, 11, 3,
];

/// Permuted choice 2: 56 → 48 bits.
pub const PC2: [usize; 48] = [
    13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40,
    51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
];

/// Left-rotation schedule for C/D halves.
pub const SHIFTS: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// S-boxes in (row, col) layout: SBOX[b][row*16+col].
#[rustfmt::skip]
pub const SBOX: [[u8; 64]; 8] = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7, 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8, 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0, 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10, 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5, 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15, 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8, 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1, 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7, 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15, 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9, 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4, 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9, 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6, 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14, 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11, 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8, 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6, 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1, 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6, 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2, 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7, 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2, 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8, 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
];

/// S-box lookup: 6 input bits (b0..b5, b0 first) → 4-bit output value.
pub fn sbox_lookup(box_idx: usize, bits: [bool; 6]) -> u8 {
    let b = |i: usize| bits[i] as usize;
    let row = (b(0) << 1) | b(5);
    let col = (b(1) << 3) | (b(2) << 2) | (b(3) << 1) | b(4);
    SBOX[box_idx][row * 16 + col]
}

/// Mapped S-box table indexed by binary value (b0*32+…+b5) → output.
/// Used for R1CS interpolation so the polynomial input matches bit weights.
pub fn sbox_mapped(box_idx: usize) -> [u8; 64] {
    let mut out = [0u8; 64];
    for v in 0..64 {
        let bits = [
            (v >> 5) & 1 == 1,
            (v >> 4) & 1 == 1,
            (v >> 3) & 1 == 1,
            (v >> 2) & 1 == 1,
            (v >> 1) & 1 == 1,
            v & 1 == 1,
        ];
        out[v] = sbox_lookup(box_idx, bits);
    }
    out
}

/// Bytes → DES-ordered bits (bit 0 = MSB of byte 0 = DES bit 1).
pub fn bytes_to_des_bits(block: &[u8; 8]) -> [bool; 64] {
    let mut out = [false; 64];
    for k in 0..64 {
        let byte = block[k / 8];
        let bit = 7 - (k % 8);
        out[k] = ((byte >> bit) & 1) == 1;
    }
    out
}

/// DES-ordered bits → bytes.
pub fn des_bits_to_bytes(bits: &[bool; 64]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for k in 0..64 {
        if bits[k] {
            out[k / 8] |= 1 << (7 - (k % 8));
        }
    }
    out
}

fn permute<const N: usize, const M: usize>(bits: &[bool; N], table: &[usize; M]) -> [bool; M] {
    let mut out = [false; M];
    for (i, &j) in table.iter().enumerate() {
        out[i] = bits[j];
    }
    out
}

fn rotl28(v: [bool; 28], n: usize) -> [bool; 28] {
    let mut out = [false; 28];
    for i in 0..28 {
        out[i] = v[(i + n) % 28];
    }
    out
}

/// 16 round keys (48 bits each) from an 8-byte key.
pub fn round_keys(key: &[u8; 8]) -> [[bool; 48]; 16] {
    let kb = bytes_to_des_bits(key);
    let pc1 = permute(&kb, &PC1);
    let mut c: [bool; 28] = pc1[..28].try_into().unwrap();
    let mut d: [bool; 28] = pc1[28..].try_into().unwrap();
    let mut out = [[false; 48]; 16];
    for (i, k) in out.iter_mut().enumerate() {
        c = rotl28(c, SHIFTS[i]);
        d = rotl28(d, SHIFTS[i]);
        let mut cd = [false; 56];
        cd[..28].copy_from_slice(&c);
        cd[28..].copy_from_slice(&d);
        *k = permute(&cd, &PC2);
    }
    out
}

fn feistel(r: &[bool; 32], k: &[bool; 48]) -> [bool; 32] {
    let r_arr: [bool; 32] = *r;
    let expanded: [bool; 48] = permute(&r_arr, &E);
    let mut xored = [false; 48];
    for i in 0..48 {
        xored[i] = expanded[i] ^ k[i];
    }
    let mut s_out = [false; 32];
    for b in 0..8 {
        let chunk: [bool; 6] = xored[b * 6..b * 6 + 6].try_into().unwrap();
        let v = sbox_lookup(b, chunk);
        s_out[b * 4] = (v >> 3) & 1 == 1;
        s_out[b * 4 + 1] = (v >> 2) & 1 == 1;
        s_out[b * 4 + 2] = (v >> 1) & 1 == 1;
        s_out[b * 4 + 3] = v & 1 == 1;
    }
    let s_arr: [bool; 32] = s_out;
    permute(&s_arr, &P)
}

fn des_block(data: &[u8; 8], key: &[u8; 8], encrypt: bool) -> [u8; 8] {
    let mut keys = round_keys(key);
    if !encrypt {
        keys.reverse();
    }
    let bits = bytes_to_des_bits(data);
    let ip = permute(&bits, &IP);
    let mut l: [bool; 32] = ip[..32].try_into().unwrap();
    let mut r: [bool; 32] = ip[32..].try_into().unwrap();
    for k in keys.iter() {
        let f = feistel(&r, k);
        let new_r = {
            let mut v = [false; 32];
            for i in 0..32 {
                v[i] = l[i] ^ f[i];
            }
            v
        };
        l = r;
        r = new_r;
    }
    // No final swap: pre-output is R16 || L16.
    let mut pre = [false; 64];
    pre[..32].copy_from_slice(&r);
    pre[32..].copy_from_slice(&l);
    // FP = IP^{-1}.
    let mut fp_table = [0usize; 64];
    for (i, &v) in IP.iter().enumerate() {
        fp_table[v] = i;
    }
    let out = permute(&pre, &fp_table);
    des_bits_to_bytes(&out)
}

/// `encrypt_des_block(data, key)` — felica-rs `primitives.rs` argument order.
pub fn des_encrypt(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    des_block(data, key, true)
}

pub fn des_decrypt(data: &[u8; 8], key: &[u8; 8]) -> [u8; 8] {
    des_block(data, key, false)
}

/// Two-key EDE 3DES with K1|K2|K1.
pub fn tdes_encrypt(data: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
    let t1 = des_encrypt(data, k1);
    let t2 = des_decrypt(&t1, k2);
    des_encrypt(&t2, k1)
}

pub fn tdes_decrypt(data: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
    let t1 = des_decrypt(data, k1);
    let t2 = des_encrypt(&t1, k2);
    des_decrypt(&t2, k1)
}

/// DES-CBC decrypt under zero IV (returns `None` on misalignment).
pub fn cbc_decrypt(data: &[u8], key: &[u8; 8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(8) {
        return None;
    }
    let mut out = Vec::with_capacity(data.len());
    let mut prev = [0u8; 8];
    for chunk in data.chunks(8) {
        let ct: [u8; 8] = chunk.try_into().unwrap();
        let pt = des_decrypt(&ct, key);
        for i in 0..8 {
            out.push(pt[i] ^ prev[i]);
        }
        prev = ct;
    }
    Some(out)
}

/// `calculate_command_mac_des`: M0=[len,code,0*6], each data block as DES key.
pub fn command_mac(code: u8, padded: &[u8]) -> [u8; 8] {
    debug_assert!(padded.len() % 8 == 0);
    let total = 2 + padded.len() + 8;
    debug_assert!(total <= u8::MAX as usize);
    let mut mac = [0u8; 8];
    mac[0] = total as u8;
    mac[1] = code;
    for chunk in padded.chunks(8) {
        let block: [u8; 8] = chunk.try_into().unwrap();
        mac = des_encrypt(&mac, &block);
    }
    mac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_vector_single_des() {
        let key: [u8; 8] = hex::decode("133457799bbcdff1").unwrap().try_into().unwrap();
        let pt: [u8; 8] = hex::decode("0123456789abcdef").unwrap().try_into().unwrap();
        let ct: [u8; 8] = hex::decode("85e813540f0ab405").unwrap().try_into().unwrap();
        assert_eq!(des_encrypt(&pt, &key), ct);
        assert_eq!(des_decrypt(&ct, &key), pt);
        // Through the public 3DES path with K1 == K2 (collapses to single DES).
        assert_eq!(tdes_encrypt(&pt, &key, &key), ct);
        assert_eq!(tdes_decrypt(&ct, &key, &key), pt);
    }

    #[test]
    fn parity_bits_are_ignored() {
        // DES keys carry 56 effective bits; LSB of each byte is parity and
        // must not influence output (mirrored by PC-1 in-circuit). Flipping
        // any parity bit is an equivalent key, never a forgery.
        let key: [u8; 8] = hex::decode("133457799bbcdff1").unwrap().try_into().unwrap();
        let pt: [u8; 8] = hex::decode("0123456789abcdef").unwrap().try_into().unwrap();
        let ct = des_encrypt(&pt, &key);
        for i in 0..8 {
            let mut equiv = key;
            equiv[i] ^= 0x01;
            assert_eq!(des_encrypt(&pt, &equiv), ct, "parity bit {i} ignored");
            assert_eq!(tdes_encrypt(&pt, &equiv, &key), tdes_encrypt(&pt, &key, &key));
        }
    }

    #[test]
    fn sbox_mapped_matches_lookup() {
        for b in 0..8 {
            let m = sbox_mapped(b);
            for v in 0..64 {
                let bits = [
                    (v >> 5) & 1 == 1,
                    (v >> 4) & 1 == 1,
                    (v >> 3) & 1 == 1,
                    (v >> 2) & 1 == 1,
                    (v >> 1) & 1 == 1,
                    v & 1 == 1,
                ];
                assert_eq!(m[v], sbox_lookup(b, bits));
            }
        }
    }

    /// Differential fuzz vs the `des` crate (the same family felica-rs
    /// uses): a single mistranscribed table entry would diverge on random
    /// blocks with overwhelming probability (each case fans out over
    /// 16 rounds × 8 S-boxes; 2000 cases ≈ 256k S-box evaluations).
    #[test]
    fn differential_vs_des_crate() {
        use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
        use des::{Des, TdesEde3};

        fn ref_enc(pt: &[u8; 8], k: &[u8; 8]) -> [u8; 8] {
            let c = Des::new(k.into());
            let mut b = (*pt).into();
            c.encrypt_block(&mut b);
            b.into()
        }
        fn ref_dec(ct: &[u8; 8], k: &[u8; 8]) -> [u8; 8] {
            let c = Des::new(k.into());
            let mut b = (*ct).into();
            c.decrypt_block(&mut b);
            b.into()
        }
        fn ref_3enc(pt: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
            let mut k = [0u8; 24];
            k[..8].copy_from_slice(k1);
            k[8..16].copy_from_slice(k2);
            k[16..].copy_from_slice(k1);
            let c = TdesEde3::new((&k).into());
            let mut b = (*pt).into();
            c.encrypt_block(&mut b);
            b.into()
        }
        fn ref_3dec(ct: &[u8; 8], k1: &[u8; 8], k2: &[u8; 8]) -> [u8; 8] {
            let mut k = [0u8; 24];
            k[..8].copy_from_slice(k1);
            k[8..16].copy_from_slice(k2);
            k[16..].copy_from_slice(k1);
            let c = TdesEde3::new((&k).into());
            let mut b = (*ct).into();
            c.decrypt_block(&mut b);
            b.into()
        }
        // xorshift64* for case generation (deterministic seed).
        fn rng_next(s: &mut u64) -> u64 {
            let mut x = *s;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *s = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        let mut seed = 0xDE5CA1E_F00D_CAFE_u64;
        for _ in 0..2000 {
            let mut k1 = [0u8; 8];
            let mut k2 = [0u8; 8];
            let mut pt = [0u8; 8];
            for b in k1.iter_mut().chain(k2.iter_mut()).chain(pt.iter_mut()) {
                seed = rng_next(&mut seed);
                *b = (seed >> 56) as u8;
                seed = rng_next(&mut seed);
            }
            assert_eq!(des_encrypt(&pt, &k1), ref_enc(&pt, &k1));
            assert_eq!(des_decrypt(&ref_enc(&pt, &k1), &k1), pt);
            assert_eq!(tdes_encrypt(&pt, &k1, &k2), ref_3enc(&pt, &k1, &k2));
            assert_eq!(tdes_decrypt(&ref_3enc(&pt, &k1, &k2), &k1, &k2), pt);
        }
        // CBC + MAC chains against single-block references.
        let mut seed = 0x0BAD_F00D_5EED_1234_u64;
        for _ in 0..200 {
            let mut key = [0u8; 8];
            let mut data = [0u8; 32];
            for b in key.iter_mut().chain(data.iter_mut()) {
                seed = rng_next(&mut seed);
                *b = (seed >> 56) as u8;
                seed = rng_next(&mut seed);
            }
            // CBC decrypt, zero IV.
            let pt = cbc_decrypt(&data, &key).expect("aligned");
            let mut prev = [0u8; 8];
            for (i, chunk) in data.chunks(8).enumerate() {
                let ct: [u8; 8] = chunk.try_into().unwrap();
                let mut expect = ref_dec(&ct, &key);
                for j in 0..8 {
                    expect[j] ^= prev[j];
                }
                assert_eq!(&pt[i * 8..(i + 1) * 8], &expect);
                prev = ct;
            }
            // MAC over the first 24B with opcode 0x13.
            let mac = command_mac(0x13, &pt[..24]);
            let mut m = [34u8, 0x13, 0, 0, 0, 0, 0, 0];
            for chunk in pt[..24].chunks(8) {
                m = ref_enc(&m, &chunk.try_into().unwrap());
            }
            assert_eq!(mac, m);
        }
    }
}
