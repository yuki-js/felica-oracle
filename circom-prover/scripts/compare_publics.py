#!/usr/bin/env python3
"""Check snarkjs `public.json` against the Rust packing in `input.json`.

Usage: python3 scripts/compare_publics.py build/input.json build/h2h/public.json

The circom public signals must equal the Rust `public_inputs_fr` packing
decimal-for-decimal: same session bytes, same LE limbs, same field.
"""
import json
import sys

ORDER = ["r1", "c1b", "c2a", "auth2_lo", "auth2_hi", "cm", "idi_r2", "attested_at"]

inp = json.load(open(sys.argv[1]))
pub = json.load(open(sys.argv[2]))
assert len(pub) == 8, pub

ok = True
for i, name in enumerate(ORDER):
    want = str(inp[name])
    got = str(pub[i])
    mark = "OK " if want == got else "DIFF"
    if want != got:
        ok = False
    print(f"{mark} pi{i} ({name}): {got[:40]}...")

if not ok:
    raise SystemExit("public-input mismatch between circom and Rust packing")
print("AGREE: all 8 public inputs match across toolchains")
