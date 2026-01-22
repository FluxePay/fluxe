# FLUXE Security Audit Scope

**Version**: 1.0
**Date**: January 2026
**Prepared for**: External Security Auditors

## Executive Summary

FLUXE is a privacy-preserving multi-chain Layer 2 protocol utilizing zero-knowledge proofs for private transactions. The system comprises:

1. **Ethereum Smart Contracts** - Rollup state management and bridge operations
2. **Solana Program** - Alternative L1 bridge implementation
3. **ZK Circuits** - Groth16 circuits for transaction privacy (Mint, Burn, Transfer, ObjectUpdate)
4. **Proof Aggregation** - SP1 zkVM for batch proof aggregation

---

## In-Scope Components

### 1. Ethereum Smart Contracts

| File | Lines | Description | Priority |
|------|-------|-------------|----------|
| `contracts/ethereum/FluxeRollup.sol` | 315 | Batch submission and state root management | **CRITICAL** |
| `contracts/ethereum/FluxeBridge.sol` | 406 | Deposit/withdrawal bridge operations | **CRITICAL** |
| `contracts/ethereum/Groth16Verifier.sol` | 289 | BN254 Groth16 proof verification | **CRITICAL** |
| `contracts/ethereum/interfaces/IGroth16Verifier.sol` | 28 | Verifier interface | LOW |

**Total Ethereum Lines**: ~1,038

#### Critical Functions Requiring Extra Scrutiny

**FluxeRollup.sol**:
- `submitBatch()` (Lines 147-187) - Sequencer-only batch submission with proof verification
- `_constructPublicInputs()` (Lines 287-314) - Public input encoding for proof verification
- `_rootsMatch()` (Lines 274-284) - State root comparison

**FluxeBridge.sol**:
- `deposit()` (Lines 149-203) - Token deposits with ingress receipt creation
- `withdraw()` (Lines 212-271) - Exit receipt verification and token release
- `_computeMerkleRoot()` (Lines 386-405) - Merkle proof verification

**Groth16Verifier.sol**:
- `verifyProof()` (Lines 86-115) - Main proof verification entry point
- `_verifyProofInternal()` (Lines 130-172) - Core pairing verification logic
- `_verifyPairing()` (Lines 227-288) - BN254 pairing precompile calls

---

### 2. Solana Bridge Program

| File | Lines | Description | Priority |
|------|-------|-------------|----------|
| `contracts/solana/programs/fluxe_bridge/src/lib.rs` | 617 | Main bridge program logic | **CRITICAL** |
| `contracts/solana/programs/fluxe_bridge/src/state.rs` | 201 | Account state structures | HIGH |
| `contracts/solana/programs/fluxe_bridge/src/error.rs` | 85 | Error types | MEDIUM |
| `contracts/solana/programs/fluxe_bridge/src/utils.rs` | 111 | Merkle verification utilities | HIGH |

**Total Solana Lines**: ~1,014

#### Critical Functions Requiring Extra Scrutiny

**lib.rs**:
- `deposit()` (Lines 73-143) - Token deposit with nonce validation
- `submit_batch()` (Lines 146-187) - Sequencer batch submission
- `withdraw()` (Lines 190-268) - Exit receipt verification and withdrawal
- `compute_ingress_hash()` (Lines 531-549) - Ingress receipt hashing

**utils.rs**:
- `verify_merkle_proof()` (Lines 18-36) - Critical Merkle proof verification

---

### 3. ZK Circuits (Groth16)

| File | Lines | Description | Priority |
|------|-------|-------------|----------|
| `fluxe-circuits/src/transfer.rs` | 798 | Private value transfer circuit | **CRITICAL** |
| `fluxe-circuits/src/mint.rs` | 369 | Deposit (boundary-in) circuit | **CRITICAL** |
| `fluxe-circuits/src/burn.rs` | 313 | Withdrawal (boundary-out) circuit | **CRITICAL** |
| `fluxe-circuits/src/object_update.rs` | 445 | Compliance state update circuit | HIGH |
| `fluxe-circuits/src/circuits.rs` | 231 | Circuit trait definitions | MEDIUM |
| `fluxe-circuits/src/setup.rs` | 1,470 | Trusted setup utilities | HIGH |

**Total Core Circuit Lines**: ~3,626

#### Circuit Gadgets (Supporting Components)

| File | Lines | Description | Priority |
|------|-------|-------------|----------|
| `gadgets/pool_policy.rs` | 512 | Pool transfer policy enforcement | HIGH |
| `gadgets/sorted_insert.rs` | 405 | S-IMT nullifier insertion | **CRITICAL** |
| `gadgets/sanctions.rs` | 379 | Sanctions list non-membership | HIGH |
| `gadgets/auth.rs` | 371 | EC-based owner authentication | **CRITICAL** |
| `gadgets/pedersen_ec.rs` | 378 | EC Pedersen commitments | HIGH |
| `gadgets/merkle_append.rs` | 251 | I-IMT append proofs | **CRITICAL** |
| `gadgets/note.rs` | 248 | Note structure constraints | HIGH |
| `gadgets/pedersen_simple.rs` | 238 | Simple Pedersen commitments | MEDIUM |
| `gadgets/comparison.rs` | 233 | Value comparison gadgets | MEDIUM |
| `gadgets/range_proof.rs` | 212 | Range proof constraints | HIGH |
| `gadgets/callbacks.rs` | 167 | Callback verification | HIGH |
| `gadgets/sorted_tree.rs` | 156 | Sorted tree structures | HIGH |
| `gadgets/merkle.rs` | 148 | Basic Merkle gadgets | HIGH |
| `gadgets/schnorr.rs` | 119 | Schnorr signature verification | HIGH |
| `gadgets/zk_object.rs` | 109 | ZK object commitment | MEDIUM |
| `gadgets/receipts.rs` | 84 | Receipt hashing gadgets | MEDIUM |

**Total Gadget Lines**: ~4,010

---

### 4. Proof Aggregation (SP1 zkVM)

| File | Lines | Description | Priority |
|------|-------|-------------|----------|
| `fluxe-aggregation/lib/src/lib.rs` | 237 | Shared types and batch I/O | HIGH |
| `fluxe-aggregation/lib/src/groth16.rs` | 894 | BN254 Groth16 verification | **CRITICAL** |
| `fluxe-aggregation/program/src/main.rs` | 147 | SP1 guest program | **CRITICAL** |
| `fluxe-aggregation/script/src/main.rs` | 516 | Host aggregation script | MEDIUM |

**Total Aggregation Lines**: ~1,794

#### Critical Functions Requiring Extra Scrutiny

**groth16.rs**:
- `verify()` (Lines 197-232) - Groth16 pairing verification
- `parse_g1_be()` / `parse_g2_be()` (Lines 58-100) - Point parsing from bytes
- `verify_bytes()` (Lines 235-250) - Byte-level verification

**program/main.rs**:
- `main()` (Lines 28-135) - SP1 guest program verifying all batch proofs
- VK commitment computation (Lines 139-146)

---

## Out-of-Scope Components

The following components are explicitly **OUT OF SCOPE** for this audit:

### 1. Third-Party Dependencies
- OpenZeppelin contracts (`contracts/ethereum/lib/openzeppelin-contracts/`)
- Forge-std testing library (`contracts/ethereum/lib/forge-std/`)
- Anchor framework (imported via Cargo)
- arkworks cryptographic libraries
- SP1 zkVM infrastructure

### 2. Test Files
- All files in `tests/` directories
- All files in `benches/` directories
- `contracts/ethereum/test/FluxeRollup.t.sol`

### 3. Build Artifacts
- `target/` directories
- Compiled outputs

### 4. Infrastructure Code
- Deployment scripts (unless affecting security)
- CI/CD configurations
- Documentation generation

### 5. Frontend/Client Code
- Any web interfaces
- SDK implementations (except core library)

---

## Audit Focus Areas

### Priority 1: Critical Security

1. **Double-Spend Prevention**
   - Nullifier uniqueness enforcement
   - S-IMT insertion correctness
   - Non-membership proof verification

2. **Proof Verification**
   - Groth16 pairing equation correctness
   - Public input binding
   - Malleability prevention

3. **Access Control**
   - Sequencer-only operations
   - Owner authentication in circuits
   - Admin function protection

### Priority 2: High Security

1. **Value Conservation**
   - Input sum equals output sum plus fee
   - Range proof correctness
   - No value creation from thin air

2. **State Transitions**
   - Merkle root update correctness
   - Batch ID sequentiality
   - Cross-chain synchronization

3. **Compliance Enforcement**
   - Sanctions screening
   - Pool policy verification
   - Callback processing

### Priority 3: Medium Security

1. **Gas Optimization Risks**
   - Assembly code correctness
   - Precompile usage
   - Loop bounds

2. **Cryptographic Correctness**
   - Hash function usage
   - Curve operations
   - Randomness handling

---

## Deliverables Expected

1. **Vulnerability Report** - All identified issues with severity ratings
2. **Code Quality Assessment** - Best practices evaluation
3. **Gas Optimization Suggestions** - Efficiency improvements
4. **Architecture Review** - Design pattern assessment

---

## Contact Information

For audit-related questions, please contact the FLUXE security team.

**Audit Coordinator**: [To be provided]
**Technical Lead**: [To be provided]
