//! Trusted-setup material for the session circuit (spec `docs/spec.md` §7).
//!
//! Key generation ([`generate_keys`]) runs exactly once, offline, inside the
//! `felica-setup` ceremony binary. The oracle and tests only load
//! ([`load_proving_key`] / [`load_verifying_key`]) — generation never
//! happens on proving or verifying paths.

use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use thiserror::Error;

use crate::circuit::FelicaCircuit;

/// Concrete Groth16 key types for this circuit. Dependents name these
/// aliases and stay ark-free.
pub type FelicaProvingKey = ProvingKey<Bn254>;
/// Concrete verifying key (embedded into contracts out of band).
pub type FelicaVerifyingKey = VerifyingKey<Bn254>;

/// Key-loading failure modes. Separate from [`crate::ProverError`]: a bad key
/// is misprovisioning, never a client error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeyLoadError {
    #[error("proving key deserialization failed")]
    Deserialize,
}

/// Key-generation failure modes. Generation runs only in `felica-setup`.
#[derive(Debug, Error)]
pub enum GenerateError {
    #[error("circuit setup failed: {0}")]
    Failed(String),
}

/// Deserialize an externally generated proving key (ceremony output).
pub fn load_proving_key(bytes: &[u8]) -> Result<FelicaProvingKey, KeyLoadError> {
    use ark_serialize::CanonicalDeserialize;
    FelicaProvingKey::deserialize_compressed(bytes).map_err(|_| KeyLoadError::Deserialize)
}

/// Deserialize an externally generated verifying key (contract embedding).
pub fn load_verifying_key(bytes: &[u8]) -> Result<FelicaVerifyingKey, KeyLoadError> {
    use ark_serialize::CanonicalDeserialize;
    FelicaVerifyingKey::deserialize_compressed(bytes).map_err(|_| KeyLoadError::Deserialize)
}

/// Canonical encoding of a proving key (distribution format).
pub fn encode_proving_key(pk: &FelicaProvingKey) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .expect("proving key serializes");
    bytes
}

/// Canonical encoding of a verifying key (contract embedding / RPC).
pub fn encode_verifying_key(vk: &FelicaVerifyingKey) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)
        .expect("verifying key serializes");
    bytes
}

/// Generate a fresh keypair over the blank session circuit.
///
/// Call exactly once, offline (`felica-setup`, `OsRng`). Toxic waste dies
/// with the caller's RNG state — never persist or transmit it.
pub fn generate_keys<R: rand::Rng + rand::CryptoRng>(rng: &mut R) -> Result<(FelicaProvingKey, FelicaVerifyingKey), GenerateError> {
    ark_groth16::Groth16::<Bn254>::circuit_specific_setup(FelicaCircuit::blank(), rng)
        .map_err(|e| GenerateError::Failed(e.to_string()))
}
