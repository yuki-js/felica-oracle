//! Oracle domain logic: thin glue over felica-rs.
//!
//! The oracle consumes only resolved service keys — GSK (group) and USK
//! (user). Chain resolution (system/area/service → GSK/USK) is provisioning's
//! job, never the oracle's.
//! - AUTH2 verification → felica-rs public API (`FelicaStandardResponse::
//!   from_bytes` + `Authentication2Response::decrypt_payload`; all DES-CBC and
//!   MAC crypto stays inside felica-rs).
//! - Challenge schedule → [`schedule`]: a minimal, cited mirror of felica-rs's
//!   private `AuthenticationContext`. Only this file may go away upstream.

pub mod fixture;
pub mod schedule;

use std::fmt;

use felica::felica_standard::FelicaStandardResponse;

/// Master keys held by the oracle (spec §2: hierarchy "from environment").
///
/// Currently the already-resolved GSK/USK pair. No chain resolution here.
pub struct OracleKeys {
    k_group: [u8; 8],
    k_user: [u8; 8],
}

impl OracleKeys {
    pub fn new(k_group: [u8; 8], k_user: [u8; 8]) -> Self {
        Self { k_group, k_user }
    }

    /// Per-card session: derive `L/α/β` for this card's IDm (spec §4.1).
    pub fn session(&self, idm: &[u8; 8]) -> CardSession {
        CardSession {
            keys: schedule::IntermediateKeys::derive(&self.k_group, &self.k_user, idm),
        }
    }
}

/// One card's authentication session (stateless: rebuilt per RPC call).
pub struct CardSession {
    keys: schedule::IntermediateKeys,
}

impl CardSession {
    /// C1A response for the holder's R1 (spec §6 step 1).
    pub fn c1a(&self, r1: &[u8; 8]) -> [u8; 8] {
        self.keys.c1a(r1)
    }

    /// Constant-time C1B check (spec §8.4 `C1B_MISMATCH` source).
    pub fn check_c1b(&self, r1: &[u8; 8], c1b: &[u8; 8]) -> bool {
        use subtle::ConstantTimeEq;
        self.keys.c1b_expected(r1).ct_eq(c1b).into()
    }

    /// Recover R1 from C1B (spec §7: oracle recovers `r1` internally).
    pub fn recover_r1(&self, c1b: &[u8; 8]) -> [u8; 8] {
        self.keys.r1_from_c1b(c1b)
    }

    /// Recover session key R2 from the card's C2A.
    pub fn open_r2(&self, c2a: &[u8; 8]) -> [u8; 8] {
        self.keys.r2_from_c2a(c2a)
    }

    /// C2B response for the card (spec §6 step 3).
    pub fn c2b(&self, r2: &[u8; 8]) -> [u8; 8] {
        self.keys.c2b(r2)
    }
}

/// AUTH2 failure modes, mapped to spec §8.4 codes by the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth2Error {
    /// Framing/parse failure → `Invalid params`.
    Malformed,
    /// felica-rs MAC verification failure → `MAC_MISMATCH`.
    MacMismatch,
}

impl fmt::Display for Auth2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed AUTH2 response"),
            Self::MacMismatch => write!(f, "AUTH2 MAC verification failed"),
        }
    }
}

impl std::error::Error for Auth2Error {}

/// Verified AUTH2 contents: `TN(LE,2) | TID(6) | IDi(8) | PMi(8)` (spec §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth2Data {
    pub tn: u16,
    pub tid: [u8; 6],
    pub idi: [u8; 8],
    pub pmi: [u8; 8],
}

/// Verify the holder-submitted AUTH2 ciphertext with felica-rs.
///
/// The card response frame is `[len=34, code=0x13, ciphertext(32B)]`
/// (felica-rs `response/parse.rs: parse_authentication2` expects exactly 34
/// bytes; opcode `0x13` per spec §4.4). Rebuilding the 2-byte header is pure
/// framing — DES-CBC decryption under R2 and MAC verification happen inside
/// felica-rs `Authentication2Response::decrypt_payload`.
pub fn verify_auth2(r2: &[u8; 8], auth2_ct: &[u8; 32]) -> Result<Auth2Data, Auth2Error> {
    let mut frame = Vec::with_capacity(34);
    frame.push(34u8);
    frame.push(0x13);
    frame.extend_from_slice(auth2_ct);
    let resp =
        FelicaStandardResponse::from_bytes(&frame).map_err(|_| Auth2Error::Malformed)?;
    let payload = match resp {
        FelicaStandardResponse::Authentication2(r) => {
            r.decrypt_payload(r2).map_err(|e| match e {
                felica::FelicaStandardError::SecureSession(_) => Auth2Error::MacMismatch,
                _ => Auth2Error::Malformed,
            })?
        }
        _ => return Err(Auth2Error::Malformed),
    };
    if payload.len() != 24 {
        return Err(Auth2Error::Malformed);
    }
    let mut tid = [0u8; 6];
    let mut idi = [0u8; 8];
    let mut pmi = [0u8; 8];
    tid.copy_from_slice(&payload[2..8]);
    idi.copy_from_slice(&payload[8..16]);
    pmi.copy_from_slice(&payload[16..24]);
    Ok(Auth2Data {
        tn: u16::from_le_bytes([payload[0], payload[1]]),
        tid,
        idi,
        pmi,
    })
}
