//! RPC wire layer: trait, struct, and pure delegation to [`super::service`].
//! No deciding, validating, or computing happens here.

use std::sync::{Arc, OnceLock};

use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};

use super::types::{
    AttestRequest, AttestResponse, ChallengeRequest, ChallengeResponse, ReadSpec, SettleRequest,
    SettleResponse,
};
use crate::config::AppConfig;
use crate::params::ProvingKeyBytes;

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

    #[method(name = "get_proving_key")]
    async fn get_proving_key(&self) -> RpcResult<String>;

    #[method(name = "get_verifying_key")]
    async fn get_verifying_key(&self) -> RpcResult<String>;
}

pub struct OracleImpl {
    pub(crate) config: Arc<AppConfig>,
    /// Setup-loaded proving-key bytes (one load at startup, shared read-only).
    pub(crate) proving_key: ProvingKeyBytes,
    /// Deserialized key, initialized once (startup warm or first attest).
    pk_cache: OnceLock<felica_prover::FelicaProvingKey>,
}

impl OracleImpl {
    /// Construction does no I/O; `main` loads via `ProvingKeyBytes::load`.
    pub fn new(config: AppConfig, proving_key: ProvingKeyBytes) -> Self {
        Self {
            config: Arc::new(config),
            proving_key,
            pk_cache: OnceLock::new(),
        }
    }

    /// Deserialize the preloaded bytes once. Called at startup for fail-fast
    /// validation; `attest` reuses the cache without per-request I/O.
    pub fn ensure_keys_loaded(&self) -> anyhow::Result<()> {
        self.load_cached()
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("invalid proving key: {e}"))
    }

    pub(crate) fn proving_key(
        &self,
    ) -> Result<&felica_prover::FelicaProvingKey, felica_prover::KeyLoadError> {
        self.load_cached()
    }

    /// Stable-only once-init (`OnceLock::get_or_try_init` is unavailable on
    /// this toolchain). A raced loser is dropped; the winner is reused.
    fn load_cached(
        &self,
    ) -> Result<&felica_prover::FelicaProvingKey, felica_prover::KeyLoadError> {
        if let Some(pk) = self.pk_cache.get() {
            return Ok(pk);
        }
        let pk = felica_prover::load_proving_key(self.proving_key.bytes())?;
        let _ = self.pk_cache.set(pk);
        Ok(self.pk_cache.get().expect("cache set above"))
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

    async fn get_proving_key(&self) -> RpcResult<String> {
        self.get_proving_key().await
    }

    async fn get_verifying_key(&self) -> RpcResult<String> {
        self.get_verifying_key().await
    }
}
