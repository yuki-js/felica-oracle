#!/bin/sh
# Compile the circom session circuit (needs `circom` 2.x on PATH).
# Output: build/felica.r1cs + build/felica.sym (git-ignored; regenerate here).
# With `--wasm`, also emits build/felica_js/ for witness generation:
#   cargo run --example dump_witness_input > build/input.json
#   node build/felica_js/generate_witness.js \
#     build/felica_js/felica.wasm build/input.json build/witness.wtns
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
if [ "${1:-}" = "--wasm" ]; then
  circom circuits/felica.circom --r1cs --wasm --sym -o build
else
  circom circuits/felica.circom --r1cs --sym -o build
fi
