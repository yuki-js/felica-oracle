//! FeliCa DES oracle prover (spec `docs/spec.md` §7).
//!
//! TDD red phase: the prove API is fixed and testable, but the circuit is
//! not implemented yet — [`prove`] always returns [`ProverError::NotImplemented`].
//!
//! felica-rs research (v1.0.3, `default-features = false` to drop `usb/rusb`):
//! - Key chain: `felica::felica_standard::generate_service_keys_des(&system_key,
//!   &[area_key], &[service_key]) -> (gsk, usk)` — precedent is felica-rs's own
//!   `secure/test_util.rs`, mirrored by `server/src/oracle/fixture.rs`.
//! - Card: `FelicaStandardEmulator::{new, add_system}` +
//!   `EmulatedSystem::{new, set_system_key, set_idi_pmi, add_area}` +
//!   `EmulatedArea::{new, set_key, add_service}` +
//!   `EmulatedService::with_blocks(...).set_key(...)`.
//! - Auth flow (all sync, no driver needed):
//!   `card.handle_command(Authentication1 { idm, areas, services, challenge_1a })`
//!   → `FelicaStandardResponse::from_bytes(&frame)` → `(challenge_1b, challenge_2a)`;
//!   `card.handle_command(Authentication2 { idm, challenge_2b })` → 34-byte frame
//!   `[len=34, code=0x13, ciphertext(32B)]`, raw AUTH2 is `frame[2..34]`.
//! - The crate under test never talks to a card; the emulator lives only in
//!   `tests/` to mint genuine vectors. Production `prove` receives bytes.

use thiserror::Error;

mod commit;
pub use commit::commit;

/// Prover failure modes. Only `NotImplemented` is reachable until the
/// arkworks circuit (§7 constraints 1–7) lands; the rest reserve the
/// spec §8.4 mapping (`MAC_MISMATCH`, `TID_MISMATCH`, `PROVE_FAILED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProverError {
    #[error("circuit not yet implemented")]
    NotImplemented,
    #[error("AUTH2 MAC verification failed")]
    MacMismatch,
    #[error("transaction identifier mismatch")]
    TidMismatch,
    #[error("challenge response mismatch")]
    C1bMismatch,
}

/// Everything `prove` needs, as raw bytes (spec §7).
///
/// Key hierarchy (`k_group`/`k_user` = GSK/USK) is passed in so the prover can
/// derive `L/α/β` itself (spec §4.1); the caller never passes `l`/`beta`
/// directly. `r1` is intentionally absent — the prover recovers it as
/// `3DES⁻¹(L,β,c1b)`, mirroring `server/src/oracle/mod.rs::verify_session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveRequest {
    /// Card IDm (8B).
    pub idm: [u8; 8],
    /// Card auth response (8B).
    pub c1b: [u8; 8],
    /// Card challenge (8B).
    pub c2a: [u8; 8],
    /// AUTH2 ciphertext (32B).
    pub auth2: [u8; 32],
    /// Poseidon commitment, zeros when auth-only (32B).
    pub cm: [u8; 32],
    /// Resolved GSK from environment (8B, private).
    pub k_group: [u8; 8],
    /// Resolved USK from environment (8B, private).
    pub k_user: [u8; 8],
    /// Oracle Unix timestamp, seconds (certified as public output).
    pub attested_at: u64,
}

/// Groth16 proof over BN254, hex-encoded like the RPC surface (spec §8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    pub alg: String,
    pub a: (String, String),
    pub b: ((String, String), (String, String)),
    pub c: (String, String),
    pub public_inputs: Vec<String>,
}

/// Certified session: public outputs of the circuit (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Extracted card identifier (8B).
    pub idi: [u8; 8],
    /// Published session key (8B).
    pub r2: [u8; 8],
    /// Echoed commitment (32B, `cm_out == cm`).
    pub cm_out: [u8; 32],
    /// Echoed timestamp.
    pub attested_at: u64,
    /// Groth16 proof binding the above.
    pub proof: Groth16Proof,
}

/// Generate the attestation proof for one verified session.
///
/// RED: always returns `Err(ProverError::NotImplemented)`.
pub fn prove(_req: &ProveRequest) -> Result<Attestation, ProverError> {
    Err(ProverError::NotImplemented)
}
