use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
    server::Server,
    types::ErrorObjectOwned,
};
use std::net::SocketAddr;

// JSON-RPC API definition.
// Spec (docs/spec.md §8): challenge / settle / attest over HTTP POST.
// Hello World段階では ping のみ実装し、3メソッドはスタブで形だけ用意する。
#[rpc(server)]
pub trait OracleApi {
    #[method(name = "ping")]
    async fn ping(&self) -> RpcResult<String>;

    #[method(name = "challenge")]
    async fn challenge(&self, idm: String, r1: String) -> RpcResult<serde_json::Value>;

    #[method(name = "settle")]
    async fn settle(
        &self,
        idm: String,
        c1b: String,
        c2a: String,
    ) -> RpcResult<serde_json::Value>;

    #[method(name = "attest")]
    async fn attest(
        &self,
        idm: String,
        c1b: String,
        c2a: String,
        auth2: String,
    ) -> RpcResult<serde_json::Value>;
}

pub struct OracleImpl;

#[async_trait]
impl OracleApiServer for OracleImpl {
    async fn ping(&self) -> RpcResult<String> {
        Ok("pong".to_string())
    }

    async fn challenge(&self, _idm: String, _r1: String) -> RpcResult<serde_json::Value> {
        Err(ErrorObjectOwned::owned(
            -32000,
            "not implemented yet",
            None::<String>,
        ))
    }

    async fn settle(
        &self,
        _idm: String,
        _c1b: String,
        _c2a: String,
    ) -> RpcResult<serde_json::Value> {
        Err(ErrorObjectOwned::owned(
            -32000,
            "not implemented yet",
            None::<String>,
        ))
    }

    async fn attest(
        &self,
        _idm: String,
        _c1b: String,
        _c2a: String,
        _auth2: String,
    ) -> RpcResult<serde_json::Value> {
        Err(ErrorObjectOwned::owned(
            -32000,
            "not implemented yet",
            None::<String>,
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("felica_oracle=debug".parse().unwrap()),
        )
        .init();

    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()?;

    let server = Server::builder().build(addr).await?;
    let module = OracleImpl.into_rpc();

    tracing::info!("JSON-RPC listening on http://{}", server.local_addr()?);
    server.start(module).stopped().await;
    Ok(())
}
