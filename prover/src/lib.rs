//! FeliCa DES oracle prover (spec `docs/spec.md` §7).
//!
//! Groth16 over BN254 (`ark-groth16`). The circuit enforces spec §7.1
//! constraints 1–6 in R1CS (DES gadgets in [`circuit`], native tables in
//! [`des`]); constraint 7 (`cm_out == cm`) holds by public-input alias —
//! `cm` is a single public input serving as both input and output, so
//! tampering breaks the pairing equation without extra constraints.
//!
//! Public-input packing (8 Fr, Sui limit) is defined in
//! [`circuit::public_inputs_fr`]: `r1 | c1b | c2a | auth2_lo | auth2_hi |
//! cm | idi‖r2 | attested_at`. `auth2` splits into 2×16B halves (128 bits
//! each, strictly `< r`); `idi‖r2` packs two 8B values into one 128-bit
//! limb. `cm` is already a canonical Fr (< r). See `circuit.rs` docs.
//!
//! Proving key: test deployments use OS randomness
//! (`generate_random_parameters` equivalent via `circuit_specific_setup`).
//! Production MUST replace the cached key with a ceremony output — the
//! `vk` embedding into Move contracts is a later explicit step.

use std::sync::LazyLock;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use thiserror::Error;

mod commit;
pub use commit::commit;

pub mod circuit;
pub mod des;

use circuit::{FelicaCircuit, public_inputs_fr};

/// Prover failure modes (spec §8.4 mapping: `MAC_MISMATCH`, `TID_MISMATCH`,
/// `C1B_MISMATCH`, `PROVE_FAILED`). `NotImplemented` is retained so the
/// red-phase API test keeps passing; it is unreachable once green.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProverError {
    #[error("circuit not yet implemented")]
    NotImplemented,
    #[error("AUTH2 MAC verification failed")]
    MacMismatch,
    #[error("transaction identifier mismatch")]
    TidMismatch,
    #[error("challenge response mismatch")]
    C1bMismatch,
    #[error("proof generation failed")]
    ProveFailed,
}

/// Everything `prove` needs, as raw bytes (spec §7).
///
/// Key hierarchy (`k_group`/`k_user` = GSK/USK) is passed in so the prover can
/// derive `L/α/β` itself (spec §4.1); the caller never passes `l`/`beta`
/// directly. `r1` is intentionally absent — the prover recovers it as
/// `3DES⁻¹(L,β,c1b)`, mirroring `server/src/oracle/mod.rs::verify_session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProveRequest {
    /// Card IDm (8B).
    pub idm: [u8; 8],
    /// Card auth response (8B).
    pub c1b: [u8; 8],
    /// Card challenge (8B).
    pub c2a: [u8; 8],
    /// AUTH2 ciphertext (32B).
    pub auth2: [u8; 32],
    /// Poseidon commitment, zeros when auth-only (32B).
    pub cm: [u8; 32],
    /// Resolved GSK from environment (8B, private).
    pub k_group: [u8; 8],
    /// Resolved USK from environment (8B, private).
    pub k_user: [u8; 8],
    /// Oracle Unix timestamp, seconds (certified as public output).
    pub attested_at: u64,
}

/// Groth16 proof over BN254, hex-encoded like the RPC surface (spec §8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    pub alg: String,
    pub a: (String, String),
    pub b: ((String, String), (String, String)),
    pub c: (String, String),
    pub public_inputs: Vec<String>,
}

/// Certified session: public outputs of the circuit (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Extracted card identifier (8B).
    pub idi: [u8; 8],
    /// Published session key (8B).
    pub r2: [u8; 8],
    /// Echoed commitment (32B, `cm_out == cm`).
    pub cm_out: [u8; 32],
    /// Echoed timestamp.
    pub attested_at: u64,
    /// Groth16 proof binding the above.
    pub proof: Groth16Proof,
}

fn fr_to_hex(f: &Fr) -> String {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("Fr serializes");
    hex::encode(buf)
}

fn fq_to_hex<F: CanonicalSerialize>(f: &F) -> String {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("Fq serializes");
    hex::encode(buf)
}

static PARAMS: LazyLock<(ProvingKey<Bn254>, VerifyingKey<Bn254>)> = LazyLock::new(|| {
    let mut rng = rand::thread_rng();
    ark_groth16::Groth16::<Bn254>::circuit_specific_setup(FelicaCircuit::blank(), &mut rng)
        .expect("setup over blank circuit")
});

/// Verify a proof against the cached test VK (roundtrip check).
pub fn verify_proof(public_inputs: &[Fr], proof: &ark_groth16::Proof<Bn254>) -> bool {
    let vk = &PARAMS.1;
    let pvk = ark_groth16::prepare_verifying_key(vk);
    ark_groth16::Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof).unwrap_or(false)
}

/// Generate the attestation proof for one verified session.
///
/// Native pre-checks mirror the circuit (§7.1) so failures map to typed
/// §8.4 errors before proving; the circuit then re-enforces the same
/// relations in zero knowledge.
pub fn prove(req: &ProveRequest) -> Result<Attestation, ProverError> {
    use des::{cbc_decrypt, command_mac, des_encrypt, tdes_decrypt, tdes_encrypt};

    // Key schedule outside the circuit (spec §4.1).
    let mut l = [0u8; 8];
    for i in 0..8 {
        l[i] = req.k_group[i] ^ req.idm[i];
    }
    let alpha = des_encrypt(&req.k_user, &l);
    let beta = des_encrypt(&l, &alpha);

    // Recover r1/r2; re-encrypt checks are tautological natively but pin the
    // C1B mapping for callers.
    let r1 = tdes_decrypt(&req.c1b, &l, &beta);
    if tdes_encrypt(&r1, &l, &beta) != req.c1b {
        return Err(ProverError::C1bMismatch);
    }
    let r2 = tdes_decrypt(&req.c2a, &l, &beta);
    if tdes_encrypt(&r2, &l, &beta) != req.c2a {
        return Err(ProverError::C1bMismatch);
    }

    // Constraint 3+4: CBC decrypt + MAC (opcode 0x13, payload 24B).
    let pt = cbc_decrypt(&req.auth2, &r2).ok_or(ProverError::MacMismatch)?;
    if pt.len() != 32 {
        return Err(ProverError::MacMismatch);
    }
    let mac = command_mac(0x13, &pt[..24]);
    if mac != pt[24..32] {
        return Err(ProverError::MacMismatch);
    }
    // Constraint 5: TID binding.
    if pt[2..8] != r1[2..8] {
        return Err(ProverError::TidMismatch);
    }
    // Constraint 6: IDi extraction.
    let mut idi = [0u8; 8];
    idi.copy_from_slice(&pt[8..16]);

    let circuit = FelicaCircuit {
        r1,
        c1b: req.c1b,
        c2a: req.c2a,
        auth2: req.auth2,
        cm: req.cm,
        idi,
        r2,
        attested_at: req.attested_at,
        l,
        beta,
    };
    let (pk, _vk) = &*PARAMS;
    let mut rng = rand::thread_rng();
    let proof = ark_groth16::Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|_| ProverError::ProveFailed)?;

    let pis = public_inputs_fr(&r1, &req.c1b, &req.c2a, &req.auth2, &req.cm, &idi, &r2, req.attested_at);
    if !verify_proof(&pis, &proof) {
        return Err(ProverError::ProveFailed);
    }

    Ok(Attestation {
        idi,
        r2,
        cm_out: req.cm,
        attested_at: req.attested_at,
        proof: Groth16Proof {
            alg: "groth16-bn254".to_string(),
            a: (fq_to_hex(&proof.a.x), fq_to_hex(&proof.a.y)),
            b: (
                (fq_to_hex(&proof.b.x.c0), fq_to_hex(&proof.b.x.c1)),
                (fq_to_hex(&proof.b.y.c0), fq_to_hex(&proof.b.y.c1)),
            ),
            c: (fq_to_hex(&proof.c.x), fq_to_hex(&proof.c.y)),
            public_inputs: pis.iter().map(fr_to_hex).collect(),
        },
    })
}
