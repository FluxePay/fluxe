# Fluxe - Privacy & Compliance Protocol for Stablecoins

Fluxe is a privacy-preserving compliance protocol for stablecoin payments, implementing the concepts from the zk-promises paper adapted for financial transactions. It enables private UTXO-based transfers while maintaining regulatory compliance through zero-knowledge proofs and asynchronous callback mechanisms.

## Overview

Fluxe combines:
- **Privacy**: UTXO model with note commitments and nullifiers
- **Compliance**: zk-promises based callback system for asynchronous compliance checks
- **Scalability**: Efficient Merkle tree structures (I-IMT and S-IMT)
- **Flexibility**: Support for multiple asset types and compliance pools

## Architecture

### Core Components

1. **Cryptographic Primitives** (`fluxe-core/src/crypto/`)
   - Poseidon-2 hash over BN254 for circuit-native operations
   - Pedersen commitments for value hiding with range proofs
   - Blake2b for entropy derivation and key generation

2. **Data Structures** (`fluxe-core/src/data_structures/`)
   - `Note`: Confidential UTXO with compliance metadata
   - `ZkObject`: Per-user compliance state machine
   - `ComplianceState`: User KYC/AML status and transaction limits
   - `Receipts`: Ingress/Exit receipts for boundary transactions

3. **Merkle Trees** (`fluxe-core/src/merkle/`)
   - I-IMT: Incremental append-only tree for commitments
   - S-IMT: Sorted tree with range proofs for non-membership

4. **Transaction Types**
   - **Mint**: Deposit external assets, create new notes
   - **Transfer**: Private value transfer between notes
   - **Burn**: Withdraw to external systems
   - **ObjectUpdate**: Compliance state transitions

## Key Features

### Privacy Features
- Note commitments hide values and ownership
- Nullifiers prevent double-spending
- Lineage tracking with bounded accumulator
- Encrypted memos for metadata

### Compliance Features
- Multi-level KYC (unverified, basic, enhanced, institutional)
- Transaction limits (daily, monthly, yearly)
- Asset freezing capabilities
- Sanctions list checking via non-membership proofs
- Pool-based policy enforcement

### zk-Promises Callbacks
- Asynchronous compliance checks
- Time-bounded callback expiry
- Provider-specific invocation tickets
- State machine transitions via callbacks

## State Structure

The protocol maintains several authenticated data structures:

```
Global State:
├── CMT_ROOT     (Note commitments)
├── NFT_ROOT     (Nullifiers)
├── OBJ_ROOT     (zk-Objects)
├── CB_ROOT      (Callbacks)
├── INGRESS_ROOT (Deposit receipts)
├── EXIT_ROOT    (Withdrawal receipts)
├── SANCTIONS_ROOT (Sanctioned entities)
└── POOL_RULES_ROOT (Pool policies)
```

## Transaction Flow

### Deposit (Mint)
1. External deposit triggers ingress receipt
2. Create new note(s) with total value
3. Add commitments to CMT_ROOT
4. Update INGRESS_ROOT
5. Increase supply counter

### Transfer
1. Consume input notes (add nullifiers)
2. Create output notes (add commitments)
3. Verify compliance gates
4. Check sanctions non-membership
5. Enforce pool policies

### Withdrawal (Burn)
1. Consume input note
2. Create exit receipt
3. Update EXIT_ROOT
4. Decrease supply counter
5. Trigger external withdrawal

## Compliance Integration

The system supports various compliance operations:

- **Freeze/Unfreeze**: Emergency asset freezing
- **Limit Updates**: Adjust transaction limits
- **Risk Scoring**: Update risk profiles
- **Level Changes**: Upgrade/downgrade KYC status
- **Attestations**: Bind compliance proofs to notes

## Building

```bash
# Build all components
cargo build --workspace

# Run tests
cargo test --workspace

# Build with optimizations
cargo build --release
```

## Project Structure

```
fluxe-circuits/
├── fluxe-core/          # Core cryptography and data structures
├── fluxe-circuits/      # ZK circuit implementations
├── fluxe-api/           # REST API and node implementation
└── zk-promises/         # Reference implementation study
```

## Security Considerations

- This is a prototype implementation for demonstration purposes
- Cryptographic parameters need careful selection for production
- Range proofs require bulletproofs or similar for efficiency
- Signature schemes need proper implementation
- Compliance callbacks require secure provider infrastructure

## Future Work

- [ ] Add SP1 verification layer
- [ ] Build REST API endpoints
- [ ] Create client SDK
- [ ] Implement batching and aggregation
- [ ] Add cross-chain support

## References

- zk-promises paper: https://eprint.iacr.org/2024/1260
- Payy Network (UTXO model, sparse Merkle trees)
- Tornado Cash (note/nullifier model)
- Aztec Protocol (privacy primitives)

## License

This implementation is for research and development purposes.