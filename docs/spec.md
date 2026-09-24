# FeliCa DES Oracle Gate — Implementation Specification v2

Version: v2. Date: 2026-09-24. Status: Working Draft.

## 0. Background and Conventions

FeliCa is a contactless smart-card system developed by Sony. Each card contains an 8-byte manufacturer identifier (IDm), an 8-byte card identification (IDi), and an 8-byte package identifier (PMi). FeliCa cards perform mutual authentication with readers using a DES-based challenge-response protocol. During authentication, the reader generates challenge R1 and the card generates challenge R2 to establish a shared session key. Card data is structured in blocks addressed under specific service codes, and read operations execute on a per-block basis.

Unless stated as little-endian (LE), multi-byte values in this document use big-endian wire encoding. Uppercase identifiers (such as R1, IDm, and C1B) refer to protocol concepts in prose, whereas lowercase identifiers (such as r1, idm, and c1b) represent wire and circuit parameters. Both notations designate the same values.

This specification describes an oracle gate: a central key-holding server that participates in a mutual authentication session on behalf of a card holder. The oracle generates zero-knowledge proofs demonstrating that a session is authentic without disclosing the underlying card keys to verifiers or application layers.

## 1. Scope and Objectives

The oracle gate establishes FeliCa DES mutual authentication sessions without exposing card keys. It enables verifiable identification of the card (IDi) and presentation of data from a single designated Read target block. Multi-block read operations are outside the scope of this specification. Callers specify a single block to read. Verifier records do not retain read contents. Newer AES-based FeliCa cards (often designated as v2 cards) are outside the scope of this document.

## 2. Participating Parties

The protocol involves four primary parties:

* **Card:** The holder's physical FeliCa card. It generates a fresh 8-byte random value R2 for each session. The card's IDi and IDm are permanent hardware identifiers.

* **Holder Device:** The user's terminal, functioning simultaneously as card-holding equipment and NFC reader. It generates an 8-byte random value R1 using an operating system CSPRNG for every session.

* **Oracle:** A central server implemented in Rust (using the arkworks library). It manages the master key hierarchy, derives card-specific intermediate values, and produces zero-knowledge proofs. The oracle operates statelessly and never receives encrypted Read responses.

* **Verifier:** Any on-chain smart contract (such as on Sui, EVM, or other networks) or off-chain verifying entity. The verifier validates the zero-knowledge proof, checks public inputs, and matches commitments. A verifier never receives decrypted plaintext prior to explicit presentation by the holder.

R2 remains secret within the card and oracle until the oracle issues the attest response, at which point R2 becomes public.

| 

| **Party** | **Held Information** | **Information Kept Inaccessible** | 
| Card | Card keys, R2 | Oracle key hierarchy | 
| Holder Device | Card responses, R2 (after attestation), session randomness | Oracle key hierarchy | 
| Oracle | Key hierarchy (from environment), derived R2 | Encrypted Read responses | 
| Verifier | Proof, public inputs, commitment, IDi, R1, session records | Plaintext before presentation, oracle key hierarchy | 

## 3. Communication Channels

The protocol uses four distinct communication channels:

* **Channel 1 (Card ↔ Holder Device, NFC):** Transmits C1A, C1B, C2A, C2B, the 32-byte AUTH2 ciphertext, encrypted Read commands, and encrypted Read responses. All transfers on this channel conclude within a single continuous NFC tap.

* **Channel 2 (Holder Device ↔ Oracle, JSON-RPC 2.0 over HTTP, with HTTPS recommended):** Carries `challenge`, `settle`, and `attest` requests. Encrypted Read responses are never transmitted over this channel. The oracle server operates statelessly across these calls.

* **Channel 3 (Holder Device → Verifier):** Delivers the zero-knowledge proof, public inputs, commitment, IDi, R1, full ciphertexts, and blinding randomness once R2 is published.

* **Channel 4 (Holder Device → Presentation Recipient):** Transfers R2, full ciphertexts, and blinding randomness directly to the chosen recipient, allowing that party to independently verify the MAC and decrypt the target data.

## 4. Cryptographic Definitions and Frame Formats

### 4.1 Key Derivation and Challenge Exchanges

Triple-DES uses two-key EDE mode (`3DES(k1, k2, data)`). Key derivation proceeds through intermediate keys $L$, $\alpha$, and $\beta$, calculated outside the zero-knowledge circuit:

$$
L = K_{\text{group}} \oplus \text{IDm}
$$

$$
\alpha = \text{DES}(L, K_{\text{user}})
$$

$$
\beta = \text{DES}(\alpha, L)
$$

Authentication challenges and responses are defined as:

* $C1A = 3\text{DES}(\alpha, L, R1)$

* $C1B = 3\text{DES}(L, \beta, R1)$

* $C2A = 3\text{DES}(L, \beta, R2)$

* $C2B = 3\text{DES}(\alpha, L, R2)$

Here, R1 is 8 bytes of randomness supplied by the holder device, and R2 is 8 bytes generated by the card. R2 serves directly as the session key for subsequent payload encryption.

### 4.2 AUTH2 Frame Format

The AUTH2 plaintext consists of 32 bytes arranged into four 8-byte blocks:

```
+-----------+-----------+----------+----------+----------+
| TN (2B)   | TID (6B)  | IDi (8B) | PMi (8B) | MAC (8B) |
+-----------+-----------+----------+----------+----------+

```

* **TN:** Transaction Number, encoded as a 2-byte little-endian integer.

* **TID:** Transaction Identifier, matching the final 6 bytes of R1.

* **IDi:** Card identification (8 bytes).

* **PMi:** Card package parameter (8 bytes).

* **MAC:** Message Authentication Code (8 bytes).

The entire 32-byte plaintext is encrypted using DES-CBC with key R2 and an initialization vector of zero ($IV = 0$).

### 4.3 Read Response Format

The protocol strictly supports single-block Read operations. A single-block Read response consists of 27 unpadded payload bytes: TN (2B), TID (6B), SF1 (1B), SF2 (1B), block count (1B, set to 1), and data (16B). Five zero bytes are appended to pad the payload to 32 bytes, followed by an 8-byte MAC, producing a fixed 40-byte plaintext encrypted into 5 DES blocks:

```
+---------+---------+---------+---------+-----------+-----------+----------+----------+
| TN (2B) | TID (6B)| SF1 (1B)| SF2 (1B)| Count (1B)| Data (16B)| Pad (5B) | MAC (8B) |
+---------+---------+---------+---------+-----------+-----------+----------+----------+

```

### 4.4 MAC Construction

The MAC is computed over the plaintext using a MAC-then-encrypt structure:

* The initial vector $M_0$ is set to `[Length, Opcode, 0, 0, 0, 0, 0, 0]`, where `Length = 2 + payload_len + 8`.

* For AUTH2, `Opcode` is `0x13`.

* For Read responses, `Opcode` is `0x15`.

* Successive blocks are encrypted through DES, using each 8-byte data block as the DES key applied to the running state.

Verifiers must check all 8 bytes of the MAC after decryption. Restricting this check to fewer bytes drastically lowers resistance against forgery.

### 4.5 Normative Poseidon Commitment Construction

The presentation commitment cryptographically binds the encrypted command, encrypted response, and blinding randomness outside the zero-knowledge circuit:

$$
\text{cm} = \text{Poseidon}( \text{ecmd} \parallel \text{response} \parallel \text{randomness} )
$$

where `randomness` is 32 bytes generated by the holder device's CSPRNG.

Because the circuit enforces equivalence on the commitment value directly (`cm_out == cm`) without opening the hash preimage inside the circuit, interoperability between holder devices and verifiers requires a deterministic, normative commitment specification. Implementations of this protocol conform to the following normative parameters:

1. **Scalar Field:** BN254 scalar field ($\mathbb{F}_r$, where $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$).

2. **S-box and Permutation:** Standard Poseidon permutation with exponent $\alpha = 5$.

3. **Preimage Partitioning:** The concatenated preimage byte sequence ($\text{ecmd} \parallel \text{response} \parallel \text{randomness}$) is split into consecutive 31-byte segments, each interpreted as a field element in $\mathbb{F}_r$ in little-endian order. If the trailing segment is fewer than 31 bytes, it is zero-padded up to 31 bytes. Because the modulus $r > 2^{253}$, packing at 31 bytes (248 bits) strictly guarantees that no field element overflows or wraps modulo $r$.

By fixing these normative parameters at the specification level, all verifying environments (including native Sui Move, EVM precompiles/libraries, and client-side SDKs) produce identical commitment digests without runtime negotiation or dynamic profile identifiers.

## 5. Replay Protection and Verification Policy

The protocol generates the cryptographic primitives required for replay prevention:

* **TID Binding:** The transaction identifier (TID) corresponds to the trailing 6 bytes of fresh R1 entropy generated by the holder device CSPRNG.

* **Commitment Ordering:** The holder commits to the ciphertexts before R2 is disclosed.

Any additional deduplication, replay mitigation, or lifecycle constraints (such as logging accepted TIDs, managing short-lived deduplication windows, enforcing allowlists, or evaluating clock drift against `attested_at`) are determined and implemented at the verifier's discretion according to its operational, storage, or execution requirements. The oracle remains stateless and does not enforce verifier-side policies.

## 6. Protocol Flow

1. **Challenge Request:** The holder device generates 8 bytes of random data for R1 from its OS CSPRNG, submits `challenge(idm, r1)` to the oracle, and receives C1A.

2. **Card Initiation:** The holder sends C1A to the card over NFC. The card responds with C1B and its challenge C2A.

3. **Settlement Request:** The holder submits `settle(idm, c1b, c2a, read_spec)` to the oracle. When a read block is requested, the oracle constructs an encrypted Read command (`ecmd`) using a fixed Read-only template for the single specified block. The oracle does not generate Write commands, multi-block commands, or accept arbitrary command payloads. The oracle returns C2B and `ecmd`.

4. **Card Execution:** The holder forwards C2B to the card, which returns the AUTH2 ciphertext. For read flows, the holder immediately transmits `ecmd` and receives the fixed 40-byte encrypted Read response. All physical NFC interactions with the card conclude at this point, allowing the card to be safely removed from the reader before proceeding to subsequent network or verifier operations.

5. **Commitment Phase:** The holder generates 32 bytes of blinding randomness with its CSPRNG, computes the normative Poseidon commitment over the concatenation of the command, response, and blinding randomness, and registers this commitment with the verifier.

6. **Attestation Phase:** After logging the commitment with the verifier, the holder submits `attest` with the authentication inputs and commitment to the oracle. The oracle validates the session, publishes R2, and returns the IDi, published R2, timestamp, and Groth16 proof.

7. **Presentation Phase:** The holder provides the proof, public inputs, commitment, IDi, R1, ciphertexts, and blinding randomness to the verifier or designated recipient. The recipient decrypts the response using R2 and verifies both the 8-byte MAC and commitment preimage.

## 7. Zero-Knowledge Circuit Specification

The system uses a single Groth16 proof circuit over the BN254 curve, evaluated and proved by the oracle. Public inputs and outputs are visible to the verifier, while private inputs remain restricted to the oracle.

| **Category** | **Signal Name** | **Size** | **Description** | 
| Public Input | `r1` | 8 bytes | Holder challenge | 
| Public Input | `c1b` | 8 bytes | Card authentication response | 
| Public Input | `c2a` | 8 bytes | Card challenge | 
| Public Input | `auth2` | 32 bytes | AUTH2 ciphertext | 
| Public Input | `cm` | 32 bytes | Poseidon commitment value | 
| Private Input | `l` | 8 bytes | Intermediate derivation key | 
| Private Input | `beta` | 8 bytes | Intermediate derivation key | 
| Private Input | `r2` | 8 bytes | Card challenge / session key | 
| Public Output | `idi` | 8 bytes | Extracted card identifier | 
| Public Output | `r2` | 8 bytes | Published session key | 
| Public Output | `cm_out` | 32 bytes | Output commitment value | 
| Public Output | `attested_at` | 8 bytes | Oracle Unix timestamp (seconds) | 

The oracle recovers `r1` internally as $3\text{DES}^{-1}(L, \beta, c1b)$; `r1` is not an explicit parameter of the attest RPC.

### 7.1 Circuit Constraints and Field Conformance

The circuit enforces seven core constraints:

1. `3DES(l, beta, r1) == c1b`

2. `3DES_inv(l, beta, c2a) == r2`

3. `p = DES_CBC_decrypt(r2, auth2)`

4. `MAC_verify_8(p, 0x13) == true`

5. `p.tid == tail_6_bytes(r1)`

6. `p.idi == idi`

7. `cm_out == cm`

**Binding Mechanism:** The circuit asserts constraint 7 (`cm_out == cm`), copying the commitment input to the output. In the Groth16 verification equation:

$$
e(A, B) = e(\alpha, \beta) + \sum_{i} x_i \cdot e(K_i, \gamma) + e(C, \delta)
$$

the value `cm` enters directly as a public input scalar $x_i$. Substituting or tampering with `cm` breaks the pairing equation, mathematically binding the proof to that exact commitment value. Because generating a valid proof requires knowledge of intermediate keys $L$ and $\beta$ (derived from master keys $K_{\text{user}}$ and $K_{\text{group}}$), the proof cryptographically certifies that an authorized oracle inspected and approved the mutual authentication exchange associated with this commitment, without requiring per-oracle digital signatures.

The custom DES circuit implementation is validated against the test vector: key `133457799bbcdff1`, plaintext `0123456789abcdef`, and ciphertext `85e813540f0ab405`.

## 8. JSON-RPC Interface

The oracle exposes three JSON-RPC 2.0 endpoints over HTTP POST (with HTTPS recommended). The oracle does not support batch requests and does not persist session state between calls. Every request requires the target card's `idm`.

### 8.1 Method: `challenge`

Generates the initial mutual authentication challenge for the card.

* **Parameters:**

  * `idm` (string, 8-byte hex, required): Card IDm.

  * `r1` (string, 8-byte hex, required): Holder challenge.

* **Returns:**

  * `c1a` (string, 8-byte hex): Reader response block for the card.

**Request Example:**

```
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "challenge",
  "params": {
    "idm": "0102030405060708",
    "r1": "0011223344556677"
  }
}

```

**Response Example:**

```
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "c1a": "529f412dc82409c5"
  }
}

```

### 8.2 Method: `settle`

Computes card challenge response C2B from C2A, and optionally constructs an encrypted single-block Read command.

* **Parameters:**

  * `idm` (string, 8-byte hex, required)

  * `c1b` (string, 8-byte hex, required)

  * `c2a` (string, 8-byte hex, required)

  * `read_spec` (object, optional): Specifies a single target block. Contains `service` (u16) and `block` (u8). If omitted, the request serves as authentication only. Requests specifying multiple blocks are invalid.

* **Returns:**

  * `c2b` (string, 8-byte hex): Final mutual authentication response for the card.

  * `ecmd` (string, hex, optional): Encrypted Read command, present only when `read_spec` is provided.

**Request Example:**

```
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "settle",
  "params": {
    "idm": "0102030405060708",
    "c1b": "aabbccddeeff0011",
    "c2a": "1122334455667788",
    "read_spec": {
      "service": 1,
      "block": 0
    }
  }
}

```

**Response Example:**

```
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "c2b": "ffeeddccbbaa9988",
    "ecmd": "86341c1165447e5526aad64a72d3c06a"
  }
}

```

### 8.3 Method: `attest`

Validates the complete authentication exchange, releases R2, and generates the zero-knowledge proof.

* **Parameters:**

  * `idm` (string, 8-byte hex, required)

  * `c1b` (string, 8-byte hex, required)

  * `c2a` (string, 8-byte hex, required)

  * `auth2` (string, 32-byte hex, required): AUTH2 ciphertext returned by card.

  * `cm` (string, 32-byte hex, optional): Blinding commitment. Defaults to 32 zero bytes if omitted.

* **Returns:**

  * `idi` (string, 8-byte hex): Derived card identifier.

  * `r2` (string, 8-byte hex): Published session key.

  * `attested_at` (integer): Unix timestamp in seconds recorded by the oracle.

  * `proof` (object): Groth16 proof containing `alg`, curve coordinates `a`, `b`, `c`, and `public_inputs` (scalar array).

**Request Example:**

```
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "attest",
  "params": {
    "idm": "0102030405060708",
    "c1b": "aabbccddeeff0011",
    "c2a": "1122334455667788",
    "auth2": "59400c81edb813a7492a117b2487e96249c9e84eb1970ddeebca6d4a8b6de84d",
    "cm": "b3d631c3c8dddff26f7e2b24b781307b4e4eca9ed4f7a5cdf716f36d82d0fde4"
  }
}

```

**Response Example:**

```
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "idi": "1020304050607080",
    "r2": "a1b2c3d4e5f60708",
    "attested_at": 1758768000,
    "proof": {
      "alg": "groth16-bn254",
      "a": [
        "8c9b3a70dbd99dc395b73c3343f107f61ba521eba95377a35dc42632259fd7a0",
        "8ef9b44cf243394d755204838d664e7195ff71aa953d11e68a66b42b3a457ba9"
      ],
      "b": [
        [
          "ea169b3f00292784ef29ab4a22e121fec62d1a57d76bcfcc9aacf400fa995a51",
          "49f6f4189c3d3158018cf8d4c2e471569cbdfa004153c69eda2c241c548eb5c2"
        ],
        [
          "c367a8757ff140ef434a6169364a097110977a3b634ceee2da7b5916f19d1bb9",
          "99d6adf71441a61ff18f41f4f2c32c77f13d81535598e4fe1198e2d87e915a01"
        ]
      ],
      "c": [
        "8ae1b92901dfc10c04f8a4a57c9f074533e77c238385829e6b752dc81d5336e1",
        "6047554aaaa63f36347bbc613418a7eebf3d8d8fb58edcb79422a7eb267295fd"
      ],
      "public_inputs": [
        "f174fdc8bce35f551899541fc1e0b33409802536a7c055c6b7df045793df69cc",
        "b60c44214e09df14917b735d265afe75abca2e8efff1bf34cfc90d0e37cb4247",
        "07f1a7b8564dbcab44b1104e643f4be1e38a1bf20f2e0f0201edc071c52404f2",
        "8574e4b8d7da5a250a2ce88426808a6cb76c23ee28e30d5af80ad76bb7bc308b",
        "a56b00ff69a0b8e1046b73ba2dc42ddde1f669a2ed41395744c1e58390e19b30",
        "82dae6966fd1fbad08b53a85f2722ce606bca73f99e41433cbf6def6f62cf6e2",
        "092c0b27762e8d4238b356facc2be8079ac8292a55137772effe58504ba369bc",
        "90b89e7d5a659489549d37197e3c5e2fd3ffe36143591fb45b320a41da740d0d"
      ]
    }
  }
}

```

### 8.4 Error Responses

The oracle returns standard JSON-RPC 2.0 error objects. Specific protocol-level errors include:

| **Code** | **Message** | **Description** | 
| `-32602` | Invalid params | Invalid hex encoding, incorrect field length, multi-block request, or missing required field. | 
| `-32010` | MAC_MISMATCH | Verification of the 8-byte AUTH2 MAC failed. | 
| `-32011` | TID_MISMATCH | Transaction identifier in AUTH2 did not match R1. | 
| `-32012` | C1B_MISMATCH | Validation of challenge response C1B failed. | 
| `-32020` | PROVE_FAILED | Zero-knowledge proof generation encountered an internal failure. | 

## 9. Verification and Presentation Logic

Verifiers execute checks tailored to their specific system policies:

1. **Proof Validation:** Validate the Groth16 proof against the known verification key (`vk`) and public inputs.

2. **Challenge Alignment:** Confirm that the holder's presented R1 (8 bytes) exactly matches the proof's public input `r1`, and that the transaction identifier (TID) corresponds to the trailing 6 bytes of R1.

3. **Application Policies:** If configured by the verifier, confirm TID freshness, verify allowlists for IDi, and check that commitment registration occurred prior to presentation proof submission. The proof's `attested_at` timestamp assists verifiers in evaluating ordering against their own local or network clock.

If `cm` is all zeros, the session is evaluated as authentication-only, and data presentation checks are omitted.

During data presentation, the recipient decrypts the Read response using R2, confirms that the 8-byte MAC matches opcode `0x15`, verifies the embedded TID, and recomputes the Poseidon commitment over the command, response, and blinding randomness to confirm it matches the recorded commitment.

The verification key (`vk`) is bound to the circuit structure and is established upfront (e.g., embedded into smart contracts or distributed in repositories); it is never negotiated dynamically per session.

## 10. Security and Privacy Considerations

* **Binding Chain of Trust:** Security rests on an unbroken chain of cryptographic bindings:

  1. *Payload Binding:* Poseidon hash collision resistance binds the Read response and blinding randomness to `cm`.

  2. *Proof Binding:* The Groth16 public input equality constraint binds `cm` to the proof. Modifying `cm` invalidates the verification pairing equation.

  3. *Authority Binding:* Generating a valid proof requires intermediate keys $L$ and $\beta$, strictly binding the proof to knowledge of master keys $K_{\text{user}}$ and $K_{\text{group}}$. This eliminates the need for per-oracle signature schemes or dynamic validator registries.

* **Post-Attestation Forgery Prevention:** Once R2 is published during attestation, any party possessing R2 can produce syntactically valid ciphertexts with correct MACs. The protocol prevents post-attestation forgery by requiring the holder to register a cryptographic commitment to the ciphertexts before R2 is disclosed.

* **Minimal Oracle Processing Surface:** The oracle accepts only R1, IDm, C1B, C2A, the AUTH2 ciphertext, and the optional commitment. End-to-end authentication of C1B and AUTH2 is enforced inside the zero-knowledge circuit at attestation. During settlement, the oracle acts without full session verification, but its exposure is strictly contained: it emits Read commands exclusively using a fixed single-block template and never issues Write commands, multi-block operations, or accepts arbitrary command relaying, ruling out unauthorized state mutation on the card.

* **Brute-Force Mitigation:** Because single-block payloads (such as balances) may occupy small value spaces susceptible to brute-force preimage discovery, the holder incorporates 32 bytes of CSPRNG randomness into the commitment. The commitment preimage omits length prefixes safely because the fixed 40-byte frame layout and trailing 8-byte MAC eliminate framing ambiguities.

* **Eavesdropping and Disclosure Model:** Card master keys remain strictly protected within the oracle's environment and the card's secure hardware. However, NFC communication is susceptible to local RF interception. An eavesdropper recording the NFC exchange can decrypt the Read payload once R2 is published in the attestation phase. Applications requiring confidentiality against local eavesdroppers must recognize that R2 publication deliberately transitions payload secrecy into verifiable authenticity.

* **Public Ledger Visibility:** Presenting decrypted data or commitment openings to on-chain smart contracts exposes those values to public blockchain observers. The policy that "verifier records do not retain read contents" applies to off-chain storage architectures and oracle designs; public ledger transparency operates according to the underlying blockchain's execution model.

## 11. Implementation and Deployment Guidance

This non-normative section outlines operational considerations for production deployments:

* **Verifier Replay Protection Policy:** For systems requiring replay protection, verifiers must maintain a deduplication store for accepted TIDs and ensure that commitment registration is observed prior to presentation proof submission according to the verifier's own local observation clock. Because an untrusted oracle could theoretically assert arbitrary timestamps, the oracle's `attested_at` timestamp must not serve as an authoritative source of chronological ordering, but rather as an auxiliary metric for detecting severe clock drift.

* **Oracle Gateway Architecture:** The oracle server is designed as a stateless computational worker. In production environments, it is recommended to deploy the oracle behind an API gateway or reverse proxy that terminates TLS/HTTPS, enforces client authentication, and applies rate limiting to protect against denial-of-service attempts.

* **Reference Implementation and Test Suites:** Exact byte layouts for single-block Read command templates, multi-step DES/3DES test vectors, CBC mode validations, and MAC generation fixtures are maintained in the canonical implementation repository (`soltia48/felica-rs`). Specific commit references and release tags are bound at software release time.

## 12. Communication Round Trips

* **Oracle Transactions:** 3 round trips (`challenge`, `settle`, `attest`).

* **Card Transactions:** 2 round trips for identification only, or 3 round trips when executing a Read command.

* **Presentation:** Local handover to the verifier or recipient, conducted out-of-band.

## 13. References

* FeliCa cryptographic primitives and framing reference: `soltia48/felica-rs` (`des.rs`, `primitives.rs`, `secure_ops.rs`).

* Smart contract verification implementations: `serkenn/sui-de-asobu` (`felica_auth.move`, `gate.move`, `zk_verifier.move`).