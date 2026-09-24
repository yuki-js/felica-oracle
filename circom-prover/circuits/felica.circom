pragma circom 2.1.9;

// FeliCa DES oracle session circuit (spec docs/spec.md §7).
//
// Human-readable companion to `circom-prover/src/circuit.rs::FelicaCircuit`:
// `PackPublicInputs` → `constrain_public_packing`, `CheckChallenges` →
// `constrain_challenges`, `CbcDecryptAuth2` → `cbc_decrypt_blocks`,
// `MacVerify13` → `mac_verify`, plus the TID / IDi equality checks
// (constraints 5–6). The Rust side is the executable mirror exercised by
// `cargo test`; this file compiles with `circom` 2.x for the snarkjs /
// Solidity / Move toolchains (`scripts/compile.sh`).
//
// Public inputs (exactly 8 field elements — the Sui packing limit — with
// names matching `PUBLIC_INPUT_ORDER` in `src/circuit.rs`):
//   r1, c1b, c2a           8-byte values as LE integers
//   auth2_lo, auth2_hi     16-byte halves of the AUTH2 ciphertext, LE
//   cm                     canonical Fr, doubles as cm_out (constraint 7 alias)
//   idi_r2                 16-byte LE packing (low 8 = idi, high 8 = r2)
//   attested_at            u64 timestamp, echoed (no bit linkage)
// Every packing is injective (limbs < r), so no wrap ambiguity. `cm` and
// `attested_at` carry no bit linkage: `cm` is aliased to `cm_out`
// (constraint 7 holds because tampering breaks the Groth16 pairing equation
// without extra constraints) and `attested_at` is echoed into the proof.

include "des.circom";

template FelicaAuth() {
    // Private byte inputs (range-checked to 8 bits by BytesToLeBits).
    signal input r1_bytes[8];
    signal input c1b_bytes[8];
    signal input c2a_bytes[8];
    signal input auth2_bytes[32];
    signal input idi_bytes[8];
    signal input r2_bytes[8];
    signal input l_bytes[8];
    signal input beta_bytes[8];

    // Public inputs (packed; see header).
    signal input r1;
    signal input c1b;
    signal input c2a;
    signal input auth2_lo;
    signal input auth2_hi;
    signal input cm;
    signal input idi_r2;
    signal input attested_at;

    // --- Bit witnesses (PackPublicInputs input side) ---
    component b_r1 = BytesToLeBits(8);
    component b_c1b = BytesToLeBits(8);
    component b_c2a = BytesToLeBits(8);
    component b_auth2 = BytesToLeBits(32);
    component b_idi = BytesToLeBits(8);
    component b_r2 = BytesToLeBits(8);
    component b_l = BytesToLeBits(8);
    component b_beta = BytesToLeBits(8);
    for (var i = 0; i < 8; i++) {
        b_r1.bytes[i] <== r1_bytes[i];
        b_c1b.bytes[i] <== c1b_bytes[i];
        b_c2a.bytes[i] <== c2a_bytes[i];
        b_idi.bytes[i] <== idi_bytes[i];
        b_r2.bytes[i] <== r2_bytes[i];
        b_l.bytes[i] <== l_bytes[i];
        b_beta.bytes[i] <== beta_bytes[i];
    }
    for (var i = 0; i < 32; i++) {
        b_auth2.bytes[i] <== auth2_bytes[i];
    }

    // --- PackPublicInputs: link bits to the 8 public inputs ---
    component pack_r1 = Bits2Num(64);
    component pack_c1b = Bits2Num(64);
    component pack_c2a = Bits2Num(64);
    component pack_a_lo = Bits2Num(128);
    component pack_a_hi = Bits2Num(128);
    component pack_idi_r2 = Bits2Num(128);
    for (var i = 0; i < 64; i++) {
        pack_r1.in[i] <== b_r1.bits[i];
        pack_c1b.in[i] <== b_c1b.bits[i];
        pack_c2a.in[i] <== b_c2a.bits[i];
    }
    for (var i = 0; i < 128; i++) {
        pack_a_lo.in[i] <== b_auth2.bits[i];
        pack_a_hi.in[i] <== b_auth2.bits[128+i];
    }
    for (var i = 0; i < 64; i++) {
        pack_idi_r2.in[i] <== b_idi.bits[i];
        pack_idi_r2.in[64+i] <== b_r2.bits[i];
    }
    pack_r1.out === r1;
    pack_c1b.out === c1b;
    pack_c2a.out === c2a;
    pack_a_lo.out === auth2_lo;
    pack_a_hi.out === auth2_hi;
    pack_idi_r2.out === idi_r2;
    // cm / attested_at: no bit linkage (constraint-7 alias / echo).

    // --- DES-ordered views (wiring) ---
    component r1_des = LeToDes(8);
    component c1b_des = LeToDes(8);
    component c2a_des = LeToDes(8);
    component r2_des = LeToDes(8);
    for (var i = 0; i < 64; i++) {
        r1_des.le[i] <== b_r1.bits[i];
        c1b_des.le[i] <== b_c1b.bits[i];
        c2a_des.le[i] <== b_c2a.bits[i];
        r2_des.le[i] <== b_r2.bits[i];
    }

    // --- CheckChallenges: constraints 1-2 ---
    // 1: 3DES(l,β,r1) == c1b. 2: 3DES(l,β,r2) == c2a.
    component chk1 = TdesEde();
    component chk2 = TdesEde();
    for (var i = 0; i < 64; i++) {
        chk1.data[i] <== r1_des.des[i];
        chk1.k1[i] <== b_l.bits[i];
        chk1.k2[i] <== b_beta.bits[i];
        chk2.data[i] <== r2_des.des[i];
        chk2.k1[i] <== b_l.bits[i];
        chk2.k2[i] <== b_beta.bits[i];
    }
    for (var i = 0; i < 64; i++) {
        chk1.out[i] === c1b_des.des[i];
        chk2.out[i] === c2a_des.des[i];
    }

    // --- CbcDecryptAuth2: constraint 3 (p = DES-CBC-decrypt(r2, auth2)) ---
    component blkDes[4];
    component dec[4];
    for (var i = 0; i < 4; i++) {
        blkDes[i] = LeToDes(8);
        dec[i] = DesBlock(0);
    }
    // One wiring stage per loop: component outputs may only be read after
    // all of that component's inputs are assigned.
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 64; j++) {
            blkDes[i].le[j] <== b_auth2.bits[i*64+j];
        }
    }
    for (var i = 0; i < 4; i++) {
        for (var j = 0; j < 64; j++) {
            dec[i].data[j] <== blkDes[i].des[j];
            dec[i].key[j] <== b_r2.bits[j];
        }
    }
    // XOR with previous ciphertext (DES order); block 0 uses zero IV.
    signal ptDes[4][64];
    for (var j = 0; j < 64; j++) {
        ptDes[0][j] <== dec[0].out[j];
    }
    for (var b = 1; b < 4; b++) {
        for (var j = 0; j < 64; j++) {
            ptDes[b][j] <== dec[b].out[j] + blkDes[b-1].des[j] - 2*dec[b].out[j]*blkDes[b-1].des[j];
        }
    }
    // Plaintext LE bits (256).
    signal ptDesFlat[256];
    for (var b = 0; b < 4; b++) {
        for (var j = 0; j < 64; j++) {
            ptDesFlat[b*64+j] <== ptDes[b][j];
        }
    }
    component ptLe = DesToLe(32);
    for (var i = 0; i < 256; i++) {
        ptLe.des[i] <== ptDesFlat[i];
    }

    // --- MacVerify13: constraint 4 (MAC over opcode 0x13) ---
    // M0 = [34, 0x13, 0,0,0,0,0,0], LE bits, hardcoded (length 34 = 2+24+8).
    // Byte 34 = 0x22 LSB-first: 0,1,0,0,0,1,0,0. Byte 0x13 LSB-first:
    // 1,1,0,0,1,0,0,0. Remaining 6 bytes are zero.
    var M0LE[64] = [0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    signal m0le[64];
    for (var i = 0; i < 64; i++) {
        m0le[i] <== M0LE[i];
    }
    component m0des = LeToDes(8);
    for (var i = 0; i < 64; i++) {
        m0des.le[i] <== m0le[i];
    }
    component mac[3];
    for (var i = 0; i < 3; i++) {
        mac[i] = DesBlock(1);
        for (var j = 0; j < 64; j++) {
            // Data input: M0 for i=0, previous output otherwise.
            if (i == 0) {
                mac[i].data[j] <== m0des.des[j];
            } else {
                mac[i].data[j] <== mac[i-1].out[j];
            }
            // Key input: plaintext block i (LE bits).
            mac[i].key[j] <== ptLe.le[i*64+j];
        }
    }
    // Compare against the MAC field pt[192..256] (DES view).
    component macDes = LeToDes(8);
    for (var i = 0; i < 64; i++) {
        macDes.le[i] <== ptLe.le[192+i];
    }
    for (var i = 0; i < 64; i++) {
        mac[2].out[i] === macDes.des[i];
    }

    // --- Constraint 5: p.tid == tail_6(r1): pt bits [16..64) vs r1 bits ---
    for (var i = 16; i < 64; i++) {
        ptLe.le[i] === b_r1.bits[i];
    }
    // --- Constraint 6: p.idi == idi: pt bits [64..128) vs idi bits ---
    for (var i = 0; i < 64; i++) {
        ptLe.le[64+i] === b_idi.bits[i];
    }
    // --- Constraint 7: cm_out == cm by public-input alias (no constraints;
    // the single public input `cm` serves as both, bound by Groth16). ---
}

component main {public [r1, c1b, c2a, auth2_lo, auth2_hi, cm, idi_r2, attested_at]} = FelicaAuth();
