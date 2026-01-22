# FLUXE Batch Aggregation (Trustless)

SP1 zkVM-based proof aggregation for FLUXE batches. This module **VERIFIES** all Groth16 proofs inside the zkVM, making it a trustless zk rollup.

## Architecture

```
fluxe-aggregation/
├── lib/           # Shared types + Groth16 verifier (no_std compatible)
├── program/       # SP1 guest program (runs in zkVM)
├── script/        # Host-side proof generation
└── elf/           # Compiled SP1 program binary
```

## Why Trustless Matters

A zk rollup must be **trustless** - the sequencer cannot forge state transitions. This requires:

1. **Groth16 proofs are VERIFIED inside the zkVM** (not just committed to)
2. **State transition rules are enforced inside the zkVM**
3. **On-chain verifier only trusts the SP1 proof**

Our implementation achieves this using:
- `substrate-bn-succinct`: SP1-patched BN254 pairing library
- BN254 pairing precompiles in SP1 for efficient verification (~10M cycles per proof)

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                     HOST (Script)                           │
├─────────────────────────────────────────────────────────────┤
│  1. Load circuit VKs (mint, burn, transfer, object_update)  │
│  2. Convert arkworks proofs to gnark byte format            │
│  3. Build BatchInput with VKs + proofs                      │
│  4. Send to SP1 zkVM for proving                            │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   SP1 GUEST (zkVM)                          │
├─────────────────────────────────────────────────────────────┤
│  1. Parse verifying keys from input                         │
│  2. For each proof: VERIFY using BN254 pairing precompiles  │
│  3. Verify state transition constraints:                    │
│     - sanctions_root unchanged                              │
│     - pool_rules_root unchanged                             │
│     - State actually changed if proofs present              │
│  4. Commit: old_hash, new_hash, vk_hash, proof_count        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    ON-CHAIN (~300k gas)                     │
├─────────────────────────────────────────────────────────────┤
│  1. Verify SP1 Groth16 proof                                │
│  2. Check old_roots_hash matches contract state             │
│  3. Verify vk_hash matches registered circuit VKs           │
│  4. Update state to new_roots_hash                          │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### lib/src/groth16.rs - Groth16 Verifier

The core Groth16 verification module using the `bn` crate:

```rust
use fluxe_aggregation_lib::groth16::{
    Groth16Proof,
    Groth16VerifyingKey,
    verify as verify_groth16
};

// Inside SP1 zkVM, this uses BN254 pairing precompiles
let is_valid = verify_groth16(&vk, &proof, &public_inputs)?;
```

### program/src/main.rs - SP1 Guest Program

The SP1 program that runs inside the zkVM:

1. Parses all VKs from input
2. For each proof, calls `verify_groth16()` (uses precompiles)
3. Enforces state transition constraints
4. Commits public outputs

### script/src/main.rs - Host Script

Converts arkworks proofs/VKs to gnark format and generates SP1 proofs:

```rust
use fluxe_aggregation_script::BatchAggregator;

// Load VKs
let mint_vk = load_vk(&PathBuf::from("keys/mint_vk.bin"))?;
// ... load other VKs

// Create aggregator
let aggregator = BatchAggregator::new(&mint_vk, &burn_vk, &transfer_vk, &object_update_vk);

// Convert proofs
let proof_entries = vec![
    BatchAggregator::create_proof_entry(TxType::Mint, &mint_proof, &mint_inputs),
    // ... more proofs
];

// Generate SP1 proof (verifies all Groth16 proofs inside zkVM)
let result = aggregator.aggregate(
    batch_id,
    chain_id,
    timestamp,
    old_roots,
    new_roots,
    proof_entries,
)?;

// Submit to chain
submit_to_chain(result.sp1_proof_bytes, result.output);
```

## Building

```bash
# Install SP1 toolchain (if not already)
curl -L https://sp1up.succinct.xyz | bash
sp1up

# Build the SP1 program
cd fluxe-aggregation
cargo prove build

# The ELF will be generated in ./elf/
```

## On-Chain Verification

The SP1 proof can be verified on:
- **Ethereum**: Using SP1's Groth16 verifier contract (~300k gas)
- **Solana**: Using sp1-solana crate

## Security Properties

1. **Trustless**: Every Groth16 proof is verified inside the zkVM
2. **Binding**: VK hash commits to specific circuit verifying keys
3. **State integrity**: old_roots_hash and new_roots_hash are committed
4. **Immutability**: Sanctions and pool rules roots cannot change within a batch

## Performance

- **Per-proof verification**: ~10M cycles (with BN254 precompiles)
- **Batch of 100 proofs**: ~1B cycles
- **SP1 proving time**: ~2-5 minutes on modern hardware
- **On-chain verification**: ~300k gas (Ethereum)

## Dependencies

- `sp1-sdk` 4.0 / `sp1-zkvm` 4.0: SP1 proving system
- `substrate-bn-succinct` 0.6.0: BN254 pairing library (SP1-patched)
- `ark-bn254` / `ark-groth16`: Arkworks libraries for host-side conversion
