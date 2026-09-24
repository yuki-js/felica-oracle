//! Server configuration: a single JSON object from the `APP_CONFIG`
//! environment variable.
//!
//! Spec reference: oracle holds the master key hierarchy "from environment"
//! (docs/spec.md §2) and stays stateless across calls (§8).
//! Single-node deployment: one GSK/USK pair plus the node path
//! (system code, area list, service list) it belongs to.
//!
//! Example:
//! ```json
//! {
//!   "bind_addr": "127.0.0.1:3000",
//!   "k_group": "1122334455667788",
//!   "k_user": "0102030405060708",
//!   "system_code": 3,
//!   "areas": [64],
//!   "services": [72]
//! }
//! ```

use anyhow::Context;
use serde::Deserialize;

use crate::api::parse_hex;

fn de_hex8<'de, D>(d: D) -> Result<[u8; 8], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    parse_hex::<8>(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub bind_addr: Option<String>,
    /// Resolved GSK (8-byte hex).
    #[serde(deserialize_with = "de_hex8")]
    pub k_group: [u8; 8],
    /// Resolved USK (8-byte hex).
    #[serde(deserialize_with = "de_hex8")]
    pub k_user: [u8; 8],
    /// System code the holder must poll/select.
    pub system_code: u16,
    /// Area code list for Authentication1.
    pub areas: Vec<u16>,
    /// Service code list for Authentication1.
    pub services: Vec<u16>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let raw =
            std::env::var("APP_CONFIG").context("APP_CONFIG env var is required")?;
        serde_json::from_str(&raw).context("invalid APP_CONFIG JSON")
    }
}
