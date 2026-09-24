#!/bin/sh
# Head-to-head: snarkjs (circom frontend) vs arkworks (Rust mirror) on the
# SAME emulator-minted session.
#
# Test-only ceremony throughout (local `powersoftau new` + single
# contribution) — never production keys. All outputs land in `build/h2h/`
# (git-ignored). Idempotent: expensive steps are skipped when outputs exist.
#
# Usage: sh scripts/head_to_head.sh
# Then: python3 scripts/compare_publics.py
set -eu
cd "$(dirname "$0")/.."
H2H=build/h2h
mkdir -p "$H2H"
SNARKJS="npx --yes snarkjs@0.7.6"

[ -f build/felica_js/felica.wasm ] || sh scripts/compile.sh --wasm
[ -f build/input.json ] || cargo run -q --example dump_witness_input > build/input.json
[ -f build/witness.wtns ] || node build/felica_js/generate_witness.js \
  build/felica_js/felica.wasm build/input.json build/witness.wtns

if [ ! -f "$H2H/pot18_final.ptau" ]; then
  $SNARKJS powersoftau new bn128 18 "$H2H/pot18_0000.ptau"
  $SNARKJS powersoftau prepare phase2 "$H2H/pot18_0000.ptau" "$H2H/pot18_final.ptau"
fi
if [ ! -f "$H2H/felica_final.zkey" ]; then
  $SNARKJS groth16 setup build/felica.r1cs "$H2H/pot18_final.ptau" "$H2H/felica_0000.zkey"
  $SNARKJS zkey contribute "$H2H/felica_0000.zkey" "$H2H/felica_final.zkey" \
    --name="h2h-test-only" -e="felica-oracle-head-to-head"
fi
$SNARKJS zkey export verificationkey "$H2H/felica_final.zkey" "$H2H/vk.json"

echo "--- snarkjs groth16 prove (circom frontend) ---"
time $SNARKJS groth16 prove "$H2H/felica_final.zkey" \
  build/witness.wtns "$H2H/proof.json" "$H2H/public.json"

echo "--- snarkjs groth16 verify ---"
time $SNARKJS groth16 verify "$H2H/vk.json" "$H2H/public.json" "$H2H/proof.json"

echo "--- public-input agreement (circom vs Rust packing) ---"
python3 scripts/compare_publics.py build/input.json "$H2H/public.json"
