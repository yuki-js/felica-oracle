//! JSON-RPC surface (docs/spec.md §8).
//!
//! `main.rs` stays thin: only server bootstrap lives there.

mod handler;
mod service;
pub mod types;

pub use handler::OracleApiServer;
pub use handler::OracleImpl;
pub use types::parse_hex;
