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

/// Constraint/variable counts of the blank circuit (perf-regression guard).
pub fn blank_constraint_counts() -> (usize, usize, usize) {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    let cs = ConstraintSystem::<Fr>::new_ref();
    FelicaCircuit::blank()
        .generate_constraints(cs.clone())
        .expect("blank synthesizes");
    (
        cs.num_constraints(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    )
}

/// Check raw circuit satisfiability for the given witnesses (no proof).
///
/// Unlike [`prove`], this bypasses the native pre-checks and feeds the
/// witnesses straight into the constraint system. Robustness tests use it
/// to assert that every §7 constraint actually constrains: a mutation that
/// violates exactly one constraint must come back unsatisfiable, which a
/// `prove`-only test could never distinguish from a native rejection.
pub fn check_satisfiable(c: FelicaCircuit) -> bool {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    let cs = ConstraintSystem::<Fr>::new_ref();
    if c.generate_constraints(cs.clone()).is_err() {
        return false;
    }
    cs.is_satisfied().unwrap_or(false)
}

/// Verify a proof against the cached test VK (roundtrip check).
pub fn verify_proof(public_inputs: &[Fr], proof: &ark_groth16::Proof<Bn254>) -> bool {
    let vk = &PARAMS.1;
    let pvk = ark_groth16::prepare_verifying_key(vk);
    ark_groth16::Groth16::<Bn254>::verify_with_processed_vk(&pvk, public_inputs, proof).unwrap_or(false)
}

fn parse_fq(s: &str) -> Option<ark_bn254::Fq> {
    use ark_serialize::CanonicalDeserialize;
    let raw = hex::decode(s).ok()?;
    ark_bn254::Fq::deserialize_compressed(&raw[..]).ok()
}

fn parse_fr(s: &str) -> Option<Fr> {
    use ark_serialize::CanonicalDeserialize;
    let raw = hex::decode(s).ok()?;
    Fr::deserialize_compressed(&raw[..]).ok()
}

/// Verify a hex-encoded [`Attestation`] against the cached test VK.
///
/// Returns `false` (never panics) on any malformed coordinate, off-curve
/// point, or pairing-equation failure. Tampering with any public input
/// breaks the Groth16 verification equation.
pub fn verify_attestation(att: &Attestation) -> bool {
    if att.proof.public_inputs.len() != circuit::PUBLIC_INPUT_ORDER.len() {
        return false;
    }
    let (ax, ay) = (&att.proof.a.0, &att.proof.a.1);
    let (cx, cy) = (&att.proof.c.0, &att.proof.c.1);
    let ((bx0, bx1), (by0, by1)) = (&att.proof.b.0, &att.proof.b.1);
    let (ax, ay, cx, cy) = match (parse_fq(ax), parse_fq(ay), parse_fq(cx), parse_fq(cy)) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return false,
    };
    let (bx0, bx1, by0, by1) =
        match (parse_fq(bx0), parse_fq(bx1), parse_fq(by0), parse_fq(by1)) {
            (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
            _ => return false,
        };
    let a = ark_bn254::G1Affine::new_unchecked(ax, ay);
    let c = ark_bn254::G1Affine::new_unchecked(cx, cy);
    let b = ark_bn254::G2Affine::new_unchecked(
        ark_bn254::Fq2::new(bx0, bx1),
        ark_bn254::Fq2::new(by0, by1),
    );
    for p in [&a, &c] {
        if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
            return false;
        }
    }
    if !b.is_on_curve() || !b.is_in_correct_subgroup_assuming_on_curve() {
        return false;
    }
    let proof = ark_groth16::Proof { a, b, c };
    let mut pis = Vec::with_capacity(att.proof.public_inputs.len());
    for s in &att.proof.public_inputs {
        match parse_fr(s) {
            Some(f) => pis.push(f),
            None => return false,
        }
    }
    verify_proof(&pis, &proof)
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
