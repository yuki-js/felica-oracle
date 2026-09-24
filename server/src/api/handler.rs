//! RPC wire layer: trait, struct, and pure delegation to [`super::service`].
//! No deciding, validating, or computing happens here.

use std::sync::Arc;

use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};

use super::types::{
    AttestRequest, AttestResponse, ChallengeRequest, ChallengeResponse, ReadSpec, SettleRequest,
    SettleResponse,
};
use crate::config::AppConfig;

/// Wire params stay destructured: jsonrpsee maps spec's object-form params
/// (`{"idm": …, "r1": …}`) onto these by name. Each handler immediately folds
/// them into the corresponding `*Request` struct — the struct is the fixed
/// request type; validation lives on it.
#[rpc(server)]
pub trait OracleApi {
    #[method(name = "ping")]
    async fn ping(&self) -> RpcResult<String>;

    #[method(name = "challenge")]
    async fn challenge(&self, idm: String, r1: String) -> RpcResult<ChallengeResponse>;

    #[method(name = "settle")]
    async fn settle(
        &self,
        idm: String,
        r1: String,
        c1b: String,
        c2a: String,
        read_spec: Option<ReadSpec>,
    ) -> RpcResult<SettleResponse>;

    #[method(name = "attest")]
    async fn attest(
        &self,
        idm: String,
        c1b: String,
        c2a: String,
        auth2: String,
        cm: Option<String>,
    ) -> RpcResult<AttestResponse>;
}

pub struct OracleImpl {
    pub(crate) config: Arc<AppConfig>,
}

impl OracleImpl {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl OracleApiServer for OracleImpl {
    async fn ping(&self) -> RpcResult<String> {
        Ok("pong".to_string())
    }

    async fn challenge(&self, idm: String, r1: String) -> RpcResult<ChallengeResponse> {
        self.challenge(ChallengeRequest { idm, r1 }).await
    }

    async fn settle(
        &self,
        idm: String,
        r1: String,
        c1b: String,
        c2a: String,
        read_spec: Option<ReadSpec>,
    ) -> RpcResult<SettleResponse> {
        self.settle(SettleRequest {
            idm,
            r1,
            c1b,
            c2a,
            read_spec,
        })
        .await
    }

    async fn attest(
        &self,
        idm: String,
        c1b: String,
        c2a: String,
        auth2: String,
        cm: Option<String>,
    ) -> RpcResult<AttestResponse> {
        self.attest(AttestRequest {
            idm,
            c1b,
            c2a,
            auth2,
            cm,
        })
        .await
    }
}
