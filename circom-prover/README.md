# felica-circom-prover

FeliCa DES oracle prover, circom-compatible mirror of `felica-prover`
(spec `docs/spec.md` §7).

- `felica-prover` (arkworks, hand-written R1CS): fastest prover, but the
  constraint code is hard to audit and tied to the Rust/arkworks toolchain.
- This crate: the **same relations** expressed as readable circom sources in
  `circuits/` (`des.circom`, `felica.circom`), plus a Rust R1CS that mirrors
  them 1:1 for fast proving with `ark-groth16` (no Node needed in
  `cargo test`). For snarkjs / Solidity / EVM / Sui-Move tooling, compile the
  `.circom` directly (`scripts/compile.sh`).

## API compatibility

Same public API as `felica-prover`: `ProveRequest`, `Attestation`,
`Groth16Proof`, `ProverError`, `prove`, `verify_attestation`, `verify_proof`,
`commit`, `blank_constraint_counts`, and the same `circuit::`
(`PUBLIC_INPUT_ORDER`, `public_inputs_fr`, gadgets) and `des::` items.
`tests/attest_prove.rs` is a 3-line shim (`extern crate as` + `#[path]`
include) executing the `prover` suite verbatim — same vectors, same packing
pins, same negatives, same constraint budget, zero mirroring.

Swapping backends (e.g. in `server/src/api/service.rs`) is a one-line
change of the `prove` path. One caveat: each crate runs its own test-only
Groth16 setup, so **proving/verification keys differ between crates** —
proofs are NOT interchangeable across backends. Public inputs, hex
encodings, and error mappings are identical; verifiers must pin the `vk`
of the backend they accept.

## Layout

- `circuits/des.circom` — DES / 3DES-EDE gadgets (`SBox`, `DesBlock`,
  `TdesEde`, `DesRoundKeys`). S-boxes use degree-63 interpolation polys
  over BN254 Fr, same as the Rust side; readable `(row, col)` tables sit
  next to the generated polys.
- `circuits/felica.circom` — main `FelicaAuth` template (§7 constraints
  1–6 + aliased 7) with exactly the 8 `PUBLIC_INPUT_ORDER` public inputs.
- `src/` — executable Rust mirror: `des.rs` / `commit.rs` are verbatim
  copies of `felica-prover`; `circuit.rs` keeps identical constraints and
  counts but is organized by circom template name (`cbc_decrypt_blocks`,
  `mac_verify`, `constrain_public_packing`, `constrain_challenges`).
- `tests/circom_consistency.rs` — machine-checked link between the two:
  circom tables/polys/public-inputs/M0 vs the Rust modules (independent
  re-interpolation, no private imports).
- `examples/gen_sbox_poly.rs` — regenerates the `S_POLY_*` blocks.
- `examples/dump_witness_input.rs` — deterministic session input for the
  compiled circuit (witness validation below).
- `scripts/compile.sh` — `circom` build (`--wasm` for witness gen).

## Head-to-head (same session, i9-13900K, `scripts/head_to_head.sh`)

| | circom frontend (snarkjs 0.7.6) | Rust mirror (ark-groth16, release) |
| constraints | 127,248 non-linear (R1CS) | 129,222 (instance 9, witness 127,248) |
| prove | 2.45s wall (6.56s user) | ~1.21s/iter (criterion median) |
| verify | OK | ~2.07ms |
| proof size | 806B (`proof.json`) | ~1KB hex (`Attestation` JSON) |
| public inputs | 8/8 agree decimal-for-decimal with Rust packing | — (reference) |

Both sides use test-only keys (local 2^18 ceremony + 1 contribution vs
`circuit_specific_setup` with OS randomness). Production replaces both with
ceremony outputs.

## Verification evidence

- `cargo test`: 13/13 `attest_prove` (shared suite) + 4/4 consistency +
  7/7 lib unit tests pass; `constraint_budget_is_pinned` confirms the
  refactored R1CS matches `felica-prover` counts exactly.
- circom end-to-end (`circom` 2.1.9, `snarkjs` 0.7.6,
  `scripts/head_to_head.sh`): the compiled `felica.r1cs` (127,248
  constraints, 8 public / 88 private inputs) accepts an emulator-minted
  genuine session (`wtns check`: WITNESS IS CORRECT) and rejects a tampered
  AUTH2 at the MAC assertion (`FelicaAuth` line 202, constraint 4) even when
  the packing publics are fixed up. Full snarkjs Groth16 on the same
  session: local test-only ceremony (powersoftau 2^18 + 1 contribution),
  `prove` 2.45s wall / `verify` OK, and all 8 public inputs agree
  decimal-for-decimal with the Rust `public_inputs_fr` packing
  (`scripts/compare_publics.py`: AGREE).
- `build/` (r1cs/wasm/witness/zkey/ptau) is git-ignored; regenerate locally.
