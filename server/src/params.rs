//! Proving-key file source (server side).
//!
//! This module owns ONLY the path and raw-bytes reading. Deserialization
//! into an ark `ProvingKey` lives in the prover crate (future `setup.rs`),
//! keeping the `server -> prover` dependency one-way and `service.rs`
//! free of `fs`/`ark` imports.

use std::path::{Path, PathBuf};

/// Default image-baked path for the proving key (see Dockerfile).
pub const DEFAULT_PROVING_KEY_PATH: &str = "/app/proving-key/key.bin";

/// Fallback for `FELICA_PROVING_KEY_PATH` when the env var is unset.
pub fn default_proving_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_PROVING_KEY_PATH)
}

/// Upper bound for the raw key file (1 GiB). Guards against accidental
/// misconfiguration (e.g. pointing at an unbounded device).
const MAX_KEY_BYTES: u64 = 1024 * 1024 * 1024;

/// Filesystem source of the Groth16 proving key.
///
/// Construction does no I/O; call [`ProvingKeySource::ensure_present`] at
/// startup for fail-fast validation and [`ProvingKeySource::read_bytes`]
/// when the prover needs the raw bytes.
#[derive(Debug, Clone)]
pub struct ProvingKeySource {
    path: PathBuf,
}

impl ProvingKeySource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Fail-fast check that the key file exists and is a regular file.
    /// Call once at startup; per-request checks belong nowhere.
    pub fn ensure_present(&self) -> anyhow::Result<()> {
        let meta = std::fs::metadata(&self.path).map_err(|e| {
            anyhow::anyhow!("proving key not accessible at {}: {e}", self.path.display())
        })?;
        if !meta.is_file() {
            anyhow::bail!(
                "proving key at {} is not a regular file",
                self.path.display()
            );
        }
        if meta.len() == 0 {
            anyhow::bail!(
                "proving key at {} is empty",
                self.path.display()
            );
        }
        if meta.len() > MAX_KEY_BYTES {
            anyhow::bail!(
                "proving key at {} too large ({} bytes)",
                self.path.display(),
                meta.len()
            );
        }
        Ok(())
    }

    /// Read the raw key bytes. Deserialization stays in the prover crate.
    pub fn read_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            anyhow::anyhow!("failed to read proving key at {}: {e}", self.path.display())
        })?;
        if bytes.is_empty() {
            anyhow::bail!(
                "proving key at {} is empty",
                self.path.display()
            );
        }
        Ok(bytes)
    }
}

/// Proving-key bytes loaded once at startup from a [`ProvingKeySource`].
///
/// `attest` uses this loaded material only: no key generation and no
/// per-request file I/O happen in the request path. Deserialization of
/// `bytes` into an ark `ProvingKey` stays in the prover crate.
#[derive(Debug, Clone)]
pub struct ProvingKeyBytes {
    path: PathBuf,
    bytes: Vec<u8>,
}

impl ProvingKeyBytes {
    /// Load once via a source (startup path). Fails fast on missing/empty.
    pub fn load(source: &ProvingKeySource) -> anyhow::Result<Self> {
        let bytes = source.read_bytes()?;
        Ok(Self {
            path: source.path().to_path_buf(),
            bytes,
        })
    }

    /// In-memory constructor (no I/O). Used by tests and future transports.
    pub fn from_bytes(path: PathBuf, bytes: Vec<u8>) -> Self {
        Self { path, bytes }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}
