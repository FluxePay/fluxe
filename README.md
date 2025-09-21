# FLUXE — Privacy-Preserving & Compliance-Aware Stablecoin Protocol

> A Rust / Arkworks zero-knowledge codebase for confidential payments, explicit compliance, and deterministic server verification.

---

## Table of Contents
- [What is Fluxe?](#what-is-fluxe)
- [Design Goals](#design-goals)
- [High-Level Architecture](#high-level-architecture)
- [Core Protocol Objects](#core-protocol-objects)
- [Cryptographic Primitives](#cryptographic-primitives)
- [Circuit Suite](#circuit-suite)
- [Merkle Structures & State](#merkle-structures--state)
- [Server-Side Deterministic Verifier](#server-side-deterministic-verifier)
- [HTTP API (axum)](#http-api-axum)
- [Project Layout](#project-layout)
- [Build, Run, and Benchmarks](#build-run-and-benchmarks)
- [Integration Guide](#integration-guide)
- [Protcol Details](#protocol-details)
- [Security Notes & Limitations](#security-notes--limitations)
- [Testing Tips](#testing-tips)
- [References](#references)

---

## What is Fluxe?

**Fluxe** is a modular ZK protocol for private stablecoin payments with **explicit, auditable compliance constraints** baked into its state model. It combines:

- Confidential **UTXO-like notes** with value commitments and owner authentication.
- Sorted & append-only Merkle structures for **nullifiers**, **note commitments**, **ingress/exit receipts**, **objects** (compliance state), **callbacks**, and **sanctions** proofs.
- A set of Groth16 circuits (Arkworks) that prove correct **mint**, **transfer**, **burn**, and **object-update** transitions.
- A **deterministic server verifier** that replays all Merkle updates and supply accounting, enabling trust-minimized batch processing.

---

## Design Goals

- **Privacy**: Hide values, owners, and memos; reveal only commitments & roots.
- **Compliance**: First-class compliance state, sanctions non-membership proofs, pool policy checks, callback workflows (e.g., freeze/unfreeze, risk updates).
- **Determinism**: Server recomputes all state transitions from client-provided proofs.
- **Modularity**: Circuits, gadgets, and state layers are independent but composable.
- **Auditability**: Every root transition can be replayed and verified.

---

## High-Level Architecture
```
fluxe-circuits/
├─ fluxe-core/ # Core types, trees, crypto, state manager
├─ fluxe-circuits/ # ZK circuits + gadgets
└─ fluxe-api/ # Axum HTTP service exposing endpoints
```

Key flows:

1. **Client constructs proofs** using circuits (e.g., `MintCircuit`, `TransferCircuit`).
2. **Client submits proof + public inputs** to the API.
3. **ServerVerifier** checks proof with verifying key, **replays Merkle ops** and **updates supply**, producing a block header for batches.

---

## Core Protocol Objects

### Notes (Confidential UTXO)
- File: `fluxe-core/src/data_structures/note.rs`
- Commitment:
  - Inputs: domain sep `DOM_NOTE`, asset type, **value commitment x-coord**, owner address, per-note entropy `psi`, chain hint, compliance hash, lineage hash, pool id, callbacks head, memo hash.
  - Hash: Poseidon with **rate=8** everywhere for consistency.

### Nullifiers
- Prevent double spends.
- Computed per note:
  - `NF = H(DOM_NF, nk, psi_field, cm)`, where `nk` is the nullifier key (private), `psi_field` is `psi` packed to field, `cm` is note commitment.

### Ingress/Exit Receipts
- Modeled as leaf items:
  - Ingress: binds asset & amount to **beneficiary commitments** (hash chain of outputs).
  - Exit: binds asset & amount to **burned nullifier**.
- Both hashed via Poseidon with domain separation.

### zk-Object (Compliance State Machine)
- `ZkObject { state_hash, serial, cb_head_hash }` with **append-only** serial increases.
- Compliance state includes `level`, `risk_score`, `frozen`, `jurisdiction_bits`, and limits.

### Callbacks
- Attach off-chain actions or on-chain flags:
  - `CallbackEntry { method_id, expiry, provider_key, user_rand }`
  - `CallbackInvocation { ticket, payload, timestamp, signature? }`
- Support Signature verification (**Schnorr on BLS12-381 G1**) and **sorted CB tree** membership proofs.

---

## Cryptographic Primitives

- **Curve**: BLS12-381 (Scalar field `Fr`), plus **BabyJubJub** / Jubjub for in-circuit EC operations.
- **Hash**: Poseidon (rate=8), identical configs in native and circuit code (see `fluxe-core/src/crypto/poseidon.rs` and `fluxe-circuits/src/gadgets/poseidon.rs`).
- **Commitments**:
  - Value commitments in core: Pedersen (`fluxe-core/src/crypto/pedersen.rs`).
  - In-circuit EC Pedersen variant: `gadgets/pedersen_ec.rs` (**correct opening in-circuit**).
  - A **simple** Poseidon pseudo-commitment gadget (for demos): `gadgets/pedersen_simple.rs` (non-homomorphic; do not treat as a real Pedersen scheme).
- **Signatures**: Schnorr over G1 (native) and Schnorr gadget over Jubjub (circuit).
- **Memo encryption**: ChaCha20-Poly1305 (native) for off-chain memo ciphertexts; separate Poseidon-based toy encryption for field elements (tests).

**Important**: The disabled module `gadgets/pedersen.rs` intentionally fails compilation to avoid insecure use. Use `pedersen_ec` gadge**t** or treat the commitment x-coord as opaque in-circuit (as the code currently does in `NoteVar`).

---

## Circuit Suite

### Common Circuit Trait
- `FluxeCircuit` exposes:
  - `public_inputs(&self) -> Vec<F>`
  - `verify_public_inputs(&self) -> Result<(), FluxeError>`
- Generic setup/prove/verify wrapper: `circuits.rs::CircuitSetup<C>`.

### Circuits

1. **MintCircuit**
   - Verifies:
     - Ingress receipt matches outputs: hash chain of `cm_out` equals `IngressReceipt.beneficiary_cm`.
     - Sum(outputs) == amount.
     - Output asset types match.
     - Range checks for 64-bit values.
     - Proper **Incremental Merkle Tree (I-IMT) append proofs** for:
       - Each output to `CMT_ROOT`.
       - Ingress receipt to `INGRESS_ROOT`.

2. **TransferCircuit**
   - Verifies:
     - Inputs membership in `CMT_ROOT_old`.
     - Nullifier correctness for each input note.
     - **Owner authentication**: derive pk from `owner_sk` in-circuit on Jubjub, hash to owner address and match note’s `owner_addr`.
     - Sum in == sum out + fee, asset type uniformity.
     - Range checks on outputs.
     - **Sanctions** non-membership proofs (S-IMT gap proofs) for sender/recipient when provided.
     - **Pool policy** membership and constraints (with proofs when provided), fallback rules otherwise.
     - **CMT append** proofs for outputs (I-IMT with pre-siblings).
     - **NFT insert** proofs for nullifiers (S-IMT sorted insert gadget with chaining).
     - Lineage updates on outputs.

   Two variants:
   - `transfer.rs`: full proof plumbing (NFT insert witnesses required).
   - `transfer_backup.rs`: simplified/legacy. Use the primary one for production logic.

3. **BurnCircuit**
   - Verifies:
     - Input membership in `CMT_ROOT`.
     - Nullifier correctness against public `nf_in`.
     - EC owner authentication (same as transfer).
     - Amount ≤ note value; asset type match.
     - Nullifier **non-membership** in `NFT_ROOT_old` (gap proof).
     - NFT **insert** proof for `NFT_ROOT_old → NFT_ROOT_new`.
     - EXIT append proof for exit receipt into `EXIT_ROOT`.

4. **ObjectUpdateCircuit**
   - Verifies:
     - Old object membership in `OBJ_ROOT_old`.
     - Compliance state hashes (`state_old.hash()` / `state_new.hash()`).
     - Serial increment.
     - Optional: callback invocation membership in `CB_ROOT`, Schnorr signature verification over callback payload (with Fq inputs).
     - Policy for state progression: monotonic risk, level in range, time monotone, frozen semantics.
     - `OBJ_ROOT_old → OBJ_ROOT_new` transition (append-style demo).

### Gadgets (selected)

- **EC Auth**: derive pk as `sk·G` (Jubjub), hash (Poseidon) to address. Circuit uses Fq→Fr conversion by **bit decomposition** to match a native helper (`utils/ec_helpers.rs`).
- **Merkle**:
  - `ImtAppendProofVar` (append witness; verifies old-root and new-root recomputation from pre-siblings).
  - `MerklePathVar` (membership).
  - **Sorted S-IMT**:
    - `RangePathVar` (gap proofs, i.e., non-membership).
    - `SimtInsertVar` (insertion from old-root → new-root with predecessor update).
- **Sanctions**: gap proof enforcement with range bounds, positive-difference checks.
- **Pool Policy**: membership & cross-pool constraints with bitmap-style lists, time & amount gates.

---

## Merkle Structures & State

### Trees
- **Commitment Tree** (I-IMT): append-only (`CMT_ROOT`).
- **Nullifier Tree** (S-IMT): sorted with predecessor links (`NFT_ROOT`).
- **Object Board** (I-IMT): append (compliance objects).
- **Callback Board** (S-IMT): sorted, for callback invocations.
- **Ingress** / **Exit** (I-IMT): receipts.

### State Manager
- File: `fluxe-core/src/state_manager.rs`
- Offers pure, replayable operations:
  - `process_mint`, `process_transfer`, `process_burn`, `process_object_update`.
  - Maintains **supply map** per asset type.
  - Computes new `StateRoots` deterministically.

---

## Server-Side Deterministic Verifier

- File: `fluxe-core/src/server_verifier.rs`
- Inputs: `VerifiedTransaction { proof, public_inputs, old_roots, new_roots, transaction_data }`.
- Verifies the Groth16 proof with the appropriate verifying key.
- Replays **canonical sequence** (per batch):
  1. **Ingress** appends
  2. **CMT** appends
  3. **NFT** inserts
  4. **CB** inserts
  5. **OBJ** appends
  6. **EXIT** appends
- Updates supply and produces a `BlockHeader { prev_roots, new_roots, batch_id, agg_proof?, timestamp }`.

*Note*: `agg_proof` is a placeholder; aggregation pipeline is left to implementers.

---

## HTTP API (axum)

- File: `fluxe-api/src/api.rs`
- Endpoints (preview; proof deserialization is stubbed in this version):
  - ```http
    POST /submit/mint
    POST /submit/burn
    POST /submit/transfer
    POST /submit/object_update

    GET  /state/roots
    GET  /state/supply/:asset_type

    GET  /proofs/commitment/:cm
    GET  /proofs/nullifier/:nf
    GET  /proofs/object/:obj
    GET  /proofs/sanctions/:addr

    POST /batch/process
    GET  /batch/status

    GET  /health
    GET  /info
  ```
- JSON request models mirror core types with hex encoding for public inputs and field elements where relevant.

---

## Project Layout

- `fluxe-core/`
  - **crypto/**: Poseidon, Pedersen, Schnorr, memo, lineage, domain separators.
  - **data_structures/**: Note, receipts, compliance state, callbacks, zk-object.
  - **merkle/**: Incremental I-IMT, Sorted S-IMT, params, errors.
  - **state_manager.rs**: pure state transitions and supply.
  - **server_verifier.rs**: deterministic batch verifier.
  - **types.rs**: type aliases (Amount, F, Roots, etc.)
- `fluxe-circuits/`
  - **gadgets/**: EC auth, Merkle paths/append, sorted insert, sanctions, pool policies, Schnorr, range proofs, note/memo, Poseidon gadget.
  - **mint.rs, transfer.rs, burn.rs, object_update.rs**: circuits.
  - **setup.rs**: Groth16 setup helpers per circuit type.
  - **benches/**: client-side proving, verification, constraints analysis.
- `fluxe-api/`
  - Axum router and handlers.

---

## Build, Run, and Benchmarks

### Prerequisites
- Rust toolchain (stable) and `cargo`
- For best performance: enable `--release`
- No external parameters are downloaded; Poseidon parameters are generated from code.

### Build
- **All crates**
  - ```sh
    cd fluxe-circuits
    cargo build --workspace
  ```
- **With parallel features (default)**:
  - Arkworks parallel feature is enabled in `Cargo.toml` features `parallel`.

### Run the API
- ```sh
  cd fluxe-circuits/fluxe-api
  cargo run --release
  # Server binds to the configured address in code (e.g., 127.0.0.1:3000)
```

**Notes**:
- Proof parsing in `api.rs` is currently a placeholder (`parse_proof_from_bytes` returns `Err`).
- Integrators should wire real proof/public input serialization (Ark `CanonicalDeserialize` / `CanonicalSerialize`).

### Benchmarks
- Constraint counts, client proving, and verification:
  - ```sh
    cd fluxe-circuits/fluxe-circuits
    cargo bench --bench circuit_constraints
    cargo bench --bench proof_generation
    cargo bench --bench proof_verification
  ```

The benches use `criterion` and print constraint growth, proving times, and verification performance. They include simplified circuits and small trees (e.g., height 16) for speed.

---

## Integration Guide

### 1) Generate Trusted Setup (Groth16) Keys
The project ships helpers to generate per-circuit proving/verifying keys:

- ```rust
  use fluxe_circuits::setup::{SetupManager, CircuitType, test_rng};

  let mut rng = test_rng();
  let mut mgr = SetupManager::new();
  mgr.generate_all_setups(&mut rng).unwrap();

  // Save to disk
  use std::path::PathBuf;
  let dir = PathBuf::from("./keys");
  mgr.save_all(&dir).unwrap();

  // Load later
  let mut mgr2 = SetupManager::new();
  mgr2.load_all(&dir).unwrap();
```

*Tip*: In production, use a secure MPC or universal setup and **never** keep the toxic waste.

### 2) Build Client Public Inputs
Each circuit defines its own public input vector ordering (see `public_inputs()` in the circuit). For example, `TransferCircuit::public_inputs()`:

- Roots: `cmt_root_old, cmt_root_new, nft_root_old, nft_root_new, sanctions_root, pool_rules_root`
- Then: `nf_list...`
- Then: `cm_list...`
- Finally: `fee`

Your client must:
- Construct witnesses (notes, paths, non-membership proofs).
- Pass consistent **pre-insertion siblings** for append proofs (CMT).
- Chain S-IMT inserts correctly (NFT).
- Compute **public inputs** in the exact order expected.

### 3) Prove & Submit
- Prove with `CircuitSetup::prove`.
- Send proof bytes + hex-encoded public inputs to the API (extend `parse_proof_from_bytes()` in `api.rs` to deserialize).

- ```json
  POST /submit/transfer
  {
    "nullifiers": ["0x...","0x..."],
    "proof": "<bytes>",
    "public_inputs": ["0x..","0x..", "..."],
    "notes_out": [{
      "asset_type": 1,
      "owner_addr": "0x...",
      "psi": [..32 bytes..],
      "chain_hint": 1,
      "pool_id": 1
    }]
  }
```

### 4) Batch Processing
- The server accumulates `VerifiedTransaction`s and applies them deterministically on `POST /batch/process`.

### 5) State Queries
- Fetch current roots: `GET /state/roots`
- Asset supply snapshot: `GET /state/supply/:asset_type`

---

## Protocol Details

### Poseidon (rate=8; matching native & gadget)
- Configs are generated internally. **Never change the sponge rate** in any part of the system without updating all sides; mismatch breaks soundness.
- Hashes are of the form `H(x₁, x₂, …) := Poseidonᵣ=8(x₁, x₂, …)`.

### Note Commitment
- (```math
  cm = H( DOM_NOTE,
           asset_type,
           v_comm_x,
           owner_addr,
           ψ_field,
           chain_hint,
           compliance_hash,
           lineage_hash,
           pool_id,
           callbacks_hash,
           memo_hash )
  ```)
- `ψ_field` is the 31-byte truncation/packing of `psi` (see `bytes_to_field`). Circuit reconstructs `ψ_field` by **bit packing** (RangeProofGadget::le_bits_to_fp) — this ensures native and circuit conversions match exactly.

### Nullifier
- (```math
  nf = H( DOM_NF,
          nk,
          ψ_field,
          cm )
  ```)
- `nk` (nullifier key) is private; knowledge prevents others from synthesizing valid spends.

### Sorted-Tree Non-Membership (Gap Proof)
- Let `low_leaf.key < target < low_leaf.next_key` or `next_key = 0` (∞).
- Proof shows:
  1) `low_leaf` is in the tree (membership path).
  2) The inequalities hold.
- In circuit we:
  - Range-check the involved values (64-bit in the demo).
  - Enforce positivity of `target - low_key` and either `next_key == 0` or positivity of `next_key - target`.

### S-IMT Insert Witness
- Captures both:
  - Original predecessor path (for old root consistency).
  - New leaf path after update (for new root).
- Linking constraints:
  - `updated_pred_leaf.next_key == new_leaf.key`
  - `new_leaf.next_key == old_pred.next_key`
  - Paths’ heights equal tree height
  - The new root computed from the **post-insertion** path matches public `nft_root_new`.

### I-IMT Append Proof
- Proves an append at the current leaf index using **pre-insertion siblings**:
  - Recompute old root with an **empty leaf** at position.
  - Recompute new root with the **appended leaf**.
  - Ensure index fits under `2^height`.

### EC Authentication (Owner Address)
- On Jubjub:
  - Compute `PK = sk·G`.
  - Convert Fq → Fr via **bit decomposition** (not by bytes mod p) in both native and circuit (see `utils/ec_helpers.rs`).
  - Address `addr = H(pk_x_fr, pk_y_fr)`.

---

## Testing Tips

- Use the benches in `fluxe-circuits/benches` to:
  - Inspect constraint counts & growth.
  - Validate proving/verification stubs with small circuits.
- Unit tests exist across modules (crypto primitives, trees, gadgets). Run:
  - ```sh
    cargo test --workspace
  ```

---

## Example: End-to-End Developer Flow (Local)

1) **Generate keys** for all circuits:
   - ```sh
     cd fluxe-circuits/fluxe-circuits
     cargo test -- fluxe_circuits::setup::tests::test_trusted_setup_generation --ignored
   ```
   Or directly call `SetupManager` in a small helper bin as shown earlier.

2) **Build a sample transfer proof** (client app):
   - Build `TransferCircuit` witnesses (notes, paths, non-membership, append & insert witnesses).
   - Create public inputs vector using `circuit.public_inputs()`.
   - ```rust
     use fluxe_circuits::{transfer::TransferCircuit, circuits::CircuitSetup};
     // ... build circuit instance "circuit"
     let setup = CircuitSetup::setup(circuit.clone(), &mut rng)?;
     let proof = setup.prove(circuit.clone(), &mut rng)?;
     let public_inputs = circuit.public_inputs();
     // serialize proof + inputs; submit to API
   ```

3) **Run the API** and **submit**:
   - ```sh
     cd fluxe-circuits/fluxe-api
     cargo run --release
   ```
   - Submit to `/submit/transfer` (ensure you wired `parse_proof_from_bytes`).

4) **Process a batch**:
   - ```sh
     curl -X POST http://127.0.0.1:3000/batch/process
   ```

---

## References

- zk-promises paper: https://eprint.iacr.org/2024/1260
- Payy Network (UTXO model, sparse Merkle trees)
- Tornado Cash (note/nullifier model)
- Aztec Protocol (privacy primitives)
- Arkworks libraries: algebraic structures, SNARKs, and R1CS gadgets (used extensively throughout).
- Poseidon hash: algebraic sponge construction (consistent param gen in both native & circuit).
- Pedersen commitments: homomorphic EC commitments (real in core and EC gadget, simplified version for demos).
- Schnorr signatures: implemented over BLS12-381 G1 (native) and verified on Jubjub in the circuit gadget path.

