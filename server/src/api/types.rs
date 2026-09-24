//! Fixed RPC data types (docs/spec.md §8).
//!
//! The holder builds `Authentication1` from the `challenge` response, so the
//! node path (system code, area list, service list) is part of the response —
//! `c1a` alone is not actionable.

use serde::{Deserialize, Serialize};

/// Strict hex → fixed array via the `hex` crate (spec §8: 8B/32B hex fields).
pub fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    v.try_into()
        .map_err(|v: Vec<u8>| format!("expected {N} bytes, got {}", v.len()))
}

/// `challenge` params (spec §8.1).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeRequest {
    /// Card IDm (8-byte hex).
    pub idm: String,
    /// Holder challenge (8-byte hex).
    pub r1: String,
}

impl ChallengeRequest {
    pub fn idm_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.idm)
    }
    pub fn r1_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.r1)
    }
}

/// `settle` params (spec §8.2 + `r1`).
///
/// DEVIATION from spec v2: `r1` is required. Without the true `r1`, C1B
/// verification is tautological (recover-then-re-encrypt always matches) and
/// settle cannot authenticate — the holder generated `r1` at challenge, so
/// sending it costs nothing and enables the genuine
/// `3DES(L,β,r1) == c1b` check (spec §8.4 `C1B_MISMATCH`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettleRequest {
    pub idm: String,
    /// Holder challenge (8-byte hex) from the `challenge` call.
    pub r1: String,
    pub c1b: String,
    pub c2a: String,
    pub read_spec: Option<ReadSpec>,
}

impl SettleRequest {
    pub fn idm_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.idm)
    }
    pub fn r1_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.r1)
    }
    pub fn c1b_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.c1b)
    }
    pub fn c2a_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.c2a)
    }
}

/// `attest` params (spec §8.3).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestRequest {
    pub idm: String,
    pub c1b: String,
    pub c2a: String,
    /// AUTH2 ciphertext (32-byte hex).
    pub auth2: String,
    /// Blinding commitment (32-byte hex); zeros when omitted.
    pub cm: Option<String>,
}

impl AttestRequest {
    pub fn idm_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.idm)
    }
    pub fn c1b_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.c1b)
    }
    pub fn c2a_bytes(&self) -> Result<[u8; 8], String> {
        parse_hex(&self.c2a)
    }
    pub fn auth2_bytes(&self) -> Result<[u8; 32], String> {
        parse_hex(&self.auth2)
    }
    pub fn cm_bytes(&self) -> Result<[u8; 32], String> {
        match &self.cm {
            Some(cm) => parse_hex(cm),
            None => Ok([0u8; 32]),
        }
    }
}

/// Single-block read target (spec §8.2). Multi-block requests are invalid.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadSpec {
    pub service: u16,
    pub block: u8,
}

/// `challenge` result: `c1a` plus the node path the holder must use.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChallengeResponse {
    /// Reader challenge block for the card (8-byte hex).
    pub c1a: String,
    /// System code the holder must poll/select before Authentication1.
    pub system_code: u16,
    /// Area code list for the Authentication1 command.
    pub areas: Vec<u16>,
    /// Service code list for the Authentication1 command.
    pub services: Vec<u16>,
}

/// `settle` result (spec §8.2).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SettleResponse {
    /// Final mutual-auth response for the card (8-byte hex).
    pub c2b: String,
    /// Encrypted single-block Read command (hex); present iff `read_spec`
    /// was given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecmd: Option<String>,
}

/// Groth16 proof over BN254 (spec §8.3 example layout).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Groth16Proof {
    pub alg: String,
    pub a: (String, String),
    pub b: ((String, String), (String, String)),
    pub c: (String, String),
    pub public_inputs: Vec<String>,
}

/// `attest` result (spec §8.3).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AttestResponse {
    /// Derived card identifier (8-byte hex).
    pub idi: String,
    /// Published session key (8-byte hex).
    pub r2: String,
    /// Oracle Unix timestamp in seconds.
    pub attested_at: u64,
    pub proof: Groth16Proof,
}
