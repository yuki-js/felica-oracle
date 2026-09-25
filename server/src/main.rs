use std::net::SocketAddr;

use anyhow::Context;

use jsonrpsee::server::{BatchRequestConfig, ServerConfig};

use felica_oracle::api::{OracleApiServer, OracleImpl};
use felica_oracle::config::AppConfig;
use felica_oracle::params::{ProvingKeyBytes, ProvingKeySource};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("felica_oracle=debug".parse().unwrap()),
        )
        .init();

    let config = AppConfig::from_env()?;
    // Setup-loaded key only: one load here, never generated per request.
    let source = ProvingKeySource::new(config.proving_key_path.clone());
    source.ensure_present()?;
    let proving_key = ProvingKeyBytes::load(&source)?;
    tracing::info!(
        "proving key loaded: {} ({} bytes)",
        proving_key.path().display(),
        proving_key.len()
    );
    let addr: SocketAddr = config
        .bind_addr
        .as_deref()
        .unwrap_or("127.0.0.1:3000")
        .parse()
        .context("invalid bind_addr")?;
    let oracle = OracleImpl::new(config, proving_key);
    // Deserialize once here: corrupt keys fail the deploy, not first attest.
    oracle.ensure_keys_loaded()?;

    // Spec §8: the oracle does not support batch requests.
    let server_cfg = ServerConfig::builder()
        .set_batch_request_config(BatchRequestConfig::Disabled)
        .build();
    let server = jsonrpsee::server::Server::builder()
        .set_config(server_cfg)
        .build(addr)
        .await?;
    let module = oracle.into_rpc();

    tracing::info!("JSON-RPC listening on http://{}", server.local_addr()?);
    server.start(module).stopped().await;
    Ok(())
}
