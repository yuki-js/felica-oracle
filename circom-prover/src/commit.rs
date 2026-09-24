//! Normative Poseidon commitment (spec `docs/spec.md` §4.5):
//! `cm = Poseidon(ecmd ‖ response ‖ randomness)`.
//!
//! Pinned choices (all deterministic; drift breaks `tests/attest_prove.rs`):
//! - Field: BN254 Fr (`r = 21888…95617`), S-box `x⁵`.
//! - Sponge: rate 2, capacity 1 (width 3), full rounds 8, partial rounds 57 —
//!   the Poseidon-paper 128-bit guidance for `t = 3` over ~254-bit fields
//!   (same round count as circomlib's BN254 Poseidon).
//! - `ark`/`mds`: arkworks Grain LFSR (`find_poseidon_ark_and_mds`, skip 1).
//!   NOT claimed compatible with circomlib constants — only self-consistent.
//! - Preimage: `ecmd` = settle frame (`[len, 0x14, ct24]`, 26B),
//!   `response` = card frame (`[len, 0x15, ct40]`, 42B), `randomness` 32B —
//!   exactly the wire bytes the holder sends/receives/stores. Split into
//!   consecutive 31-byte LE limbs, trailing chunk zero-padded (fixed 100B
//!   layout, so no framing ambiguity).
//! - Digest: LE canonical serialization of the single squeezed field.
//!
//! NOT yet normative for external verifiers: Sui Move / EVM reproduction
//! needs the exported `ark`/`mds` vectors plus the LE encoding stated above.
//! That export is a later, explicit step — see `prove` wiring.

use std::sync::LazyLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    CryptographicSponge,
    poseidon::{PoseidonConfig, PoseidonSponge, find_poseidon_ark_and_mds},
};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;

/// 31-byte limbs: `r > 2²⁵³`, so 248-bit chunks never wrap.
const LIMB_LEN: usize = 31;

static CONFIG: LazyLock<PoseidonConfig<Fr>> = LazyLock::new(|| {
    let (ark, mds) =
        find_poseidon_ark_and_mds((Fr::MODULUS_BIT_SIZE) as u64, 2, 8, 57, 1);
    PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
});

fn to_limbs(preimage: &[u8]) -> Vec<Fr> {
    preimage
        .chunks(LIMB_LEN)
        .map(|c| {
            let mut padded = [0u8; LIMB_LEN];
            padded[..c.len()].copy_from_slice(c);
            Fr::from_le_bytes_mod_order(&padded)
        })
        .collect()
}

/// `cm = Poseidon(ecmd ‖ response ‖ randomness)` as 32 bytes (LE canonical).
pub fn commit(ecmd: &[u8], response: &[u8], randomness: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(ecmd.len() + response.len() + 32);
    preimage.extend_from_slice(ecmd);
    preimage.extend_from_slice(response);
    preimage.extend_from_slice(randomness);
    let mut sponge = PoseidonSponge::new(&CONFIG);
    for limb in to_limbs(&preimage) {
        sponge.absorb(&limb);
    }
    let digest: Fr = sponge.squeeze_field_elements(1)[0];
    let mut out = [0u8; 32];
    digest
        .serialize_compressed(&mut out[..])
        .expect("Fr serializes to 32 bytes");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbs_pack_le_with_zero_pad() {
        let limbs = to_limbs(&[0x01, 0x02]);
        assert_eq!(limbs.len(), 1);
        assert_eq!(limbs[0], Fr::from(0x0201u16));
        // 31 full bytes + 1 trailing byte → 2 limbs.
        assert_eq!(to_limbs(&[0xFF; 32]).len(), 2);
    }

    #[test]
    fn commit_is_deterministic_and_binding() {
        let a = commit(&[1u8; 26], &[2u8; 42], &[3u8; 32]);
        assert_eq!(a, commit(&[1u8; 26], &[2u8; 42], &[3u8; 32]));
        assert_ne!(a, commit(&[9u8; 26], &[2u8; 42], &[3u8; 32]));
    }

    /// Param-drift pin: fixed synthetic inputs must hash to this exact digest.
    /// Any change to rate/rounds/ark/mds/limb packing/LE serialization fails
    /// here — see module docs. (Session vectors can't be pinned: R2 is fresh
    /// per session.)
    #[test]
    fn commitment_digest_is_pinned() {
        let cm = commit(&[1u8; 26], &[2u8; 42], &[3u8; 32]);
        assert_eq!(
            hex::encode(cm),
            "f815ef153c7cdf1800f49aca22b41281d246f76ba7e2a4699426b936d99db622"
        );
    }
}
