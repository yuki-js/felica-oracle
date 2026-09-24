//! Error codes: JSON-RPC standard codes come from jsonrpsee's `ErrorCode`;
//! only the spec §8.4 custom server errors (-32010…) are defined here.

use jsonrpsee::types::{ErrorCode, ErrorObjectOwned};

pub const MAC_MISMATCH: i32 = -32010;
pub const TID_MISMATCH: i32 = -32011;
pub const C1B_MISMATCH: i32 = -32012;
pub const PROVE_FAILED: i32 = -32020;
pub const NOT_IMPLEMENTED: i32 = -32000;

pub fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InvalidParams.code(), msg.into(), None::<String>)
}

pub fn not_implemented() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(NOT_IMPLEMENTED, "not implemented yet", None::<String>)
}

pub fn internal(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(ErrorCode::InternalError.code(), msg.into(), None::<String>)
}

pub fn mac_mismatch() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        MAC_MISMATCH,
        "AUTH2 MAC verification failed",
        None::<String>,
    )
}

pub fn tid_mismatch() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        TID_MISMATCH,
        "transaction identifier mismatch",
        None::<String>,
    )
}

pub fn c1b_mismatch() -> ErrorObjectOwned {
    ErrorObjectOwned::owned(C1B_MISMATCH, "challenge response mismatch", None::<String>)
}
