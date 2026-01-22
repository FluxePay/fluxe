# FLUXE Threat Model

**Version**: 1.0
**Date**: January 2026

## Overview

This document outlines the security threats, attack vectors, and assumptions for the FLUXE privacy-preserving multi-chain L2 protocol.

---

## System Components and Trust Boundaries

```
+------------------+     +------------------+     +------------------+
|   L1 Chains      |     |   FLUXE L2       |     |   Users          |
|  (Ethereum,      |<--->|  (Sequencer,     |<--->|  (Wallets,       |
|   Solana)        |     |   State Trees)   |     |   Clients)       |
+------------------+     +------------------+     +------------------+
        ^                        ^                        ^
        |                        |                        |
   Trust Boundary 1         Trust Boundary 2         Trust Boundary 3
```

### Trust Assumptions

1. **Sequencer** - Semi-trusted; can censor but cannot steal funds
2. **L1 Chains** - Trusted for finality and smart contract execution
3. **ZK Proof System** - Trusted (Groth16 with proper trusted setup)
4. **Users** - Untrusted; may attempt to exploit the system

---

## Threat Categories

### 1. Bridge Attack Vectors

#### 1.1 Reentrancy Attacks

**Location**: `FluxeBridge.sol` - `withdraw()` (Lines 212-271)

**Threat**: An attacker could exploit reentrancy in the withdrawal flow to drain funds.

**Current Mitigations**:
- `ReentrancyGuard` modifier from OpenZeppelin (Line 12)
- `nonReentrant` modifier applied to `deposit()` and `withdraw()`
- State updates before external calls (CEI pattern, Lines 255-259)

**Residual Risk**: LOW - Standard mitigations in place

```solidity
// FluxeBridge.sol:212-271
function withdraw(...) external nonReentrant whenNotPaused {
    // ... validation ...

    // Mark as processed BEFORE transfer
    processedWithdrawals[exitReceiptHash] = true;  // Line 256
    poolBalances[assetType] -= amount;              // Line 259

    // External call AFTER state updates
    IERC20(token).safeTransfer(recipient, amount);  // Line 262
}
```

#### 1.2 Access Control Bypass

**Locations**:
- `FluxeRollup.sol` - `submitBatch()` requires `onlySequencer` (Line 153)
- `FluxeBridge.sol` - `registerAsset()`, `updateAsset()` require `onlyOwner`
- Solana `lib.rs` - Various `has_one = authority` constraints

**Threats**:
- Unauthorized batch submission leading to state corruption
- Malicious asset registration enabling fake token deposits
- Sequencer key compromise

**Current Mitigations**:
- Modifier-based access control
- Two-step sequencer transfer (Lines 231-249)
- PDA-based authority in Solana

**Residual Risk**: MEDIUM - Centralized sequencer is a single point of failure

#### 1.3 Double-Spend via Exit Receipt Replay

**Location**: `FluxeBridge.sol` - `withdraw()` (Lines 228-231)

**Threat**: Replaying the same exit receipt to withdraw multiple times.

**Current Mitigations**:
```solidity
// FluxeBridge.sol:228-231
if (processedWithdrawals[exitReceiptHash]) {
    revert WithdrawalAlreadyProcessed();
}
```

**Residual Risk**: LOW - Exit receipt hash uniqueness enforced

#### 1.4 Merkle Proof Forgery

**Location**: `FluxeBridge.sol` - `_computeMerkleRoot()` (Lines 386-405)

**Threat**: Crafting invalid Merkle proofs to claim non-existent exit receipts.

**Current Mitigations**:
- Standard sorted Merkle proof verification
- Root comparison against finalized batch state

**Attack Scenario**:
```
Attacker creates fake exit receipt E' with:
- exit_receipt_hash = H(attacker_data)
- merkle_proof = [p1, p2, ..., pn]

Attack succeeds if: compute_merkle_root(E', proof) == exitRoot
```

**Residual Risk**: LOW if hash function and tree construction are correct

---

### 2. Proof System Threats

#### 2.1 Soundness Attacks

**Threat**: Generating valid proofs for invalid statements (e.g., creating money from nothing).

**Locations**:
- All circuit files in `fluxe-circuits/src/`
- `Groth16Verifier.sol` - pairing verification

**Attack Vectors**:
1. **Constraint Under-specification** - Missing constraints allowing invalid witnesses
2. **Public Input Manipulation** - Incorrect public input binding
3. **Trusted Setup Compromise** - Toxic waste not properly destroyed

**Critical Constraints to Verify**:

| Circuit | Constraint | File:Line |
|---------|------------|-----------|
| Transfer | Value conservation | `transfer.rs:397-410` |
| Transfer | Nullifier correctness | `transfer.rs:369-376` |
| Transfer | Non-membership proof | `transfer.rs:440-461` |
| Mint | Sum equals amount | `mint.rs:185-189` |
| Burn | Amount <= note value | `burn.rs:180-185` |

**Example - Value Conservation (transfer.rs)**:
```rust
// Lines 397-410
let mut sum_in = FpVar::zero();
for note_var in &notes_in_var {
    sum_in += &note_var.value;
}

let mut sum_out = FpVar::zero();
for note_var in &notes_out_var {
    sum_out += &note_var.value;
}
sum_out += &fee_var;

// CRITICAL: This must be enforced, not just computed
sum_in.enforce_equal(&sum_out)?;
```

#### 2.2 Completeness Attacks

**Threat**: Valid transactions being rejected, causing denial of service.

**Locations**: Circuit constraint generation

**Attack Scenario**: Over-constrained circuits that reject valid inputs

**Residual Risk**: LOW - Primarily a liveness issue, not safety

#### 2.3 Public Input Binding

**Location**: `Groth16Verifier.sol` - `_constructPublicInputs()` (Lines 287-314)

**Threat**: Misalignment between on-chain and circuit public inputs.

**Current Implementation**:
```solidity
// FluxeRollup.sol:287-314
function _constructPublicInputs(
    StateRoots calldata prevRoots,
    StateRoots calldata newRoots
) internal pure returns (uint256[] memory) {
    uint256[] memory inputs = new uint256[](16);

    // Previous roots (0-7)
    inputs[0] = uint256(prevRoots.cmtRoot);
    // ...

    // New roots (8-15)
    inputs[8] = uint256(newRoots.cmtRoot);
    // ...
}
```

**Risk**: Mismatch with circuit's `public_inputs()` method could allow proof reuse.

---

### 3. Cross-Chain Synchronization Risks

#### 3.1 Finality Assumptions

**Threat**: L1 reorgs invalidating FLUXE state transitions.

**Ethereum Considerations**:
- Post-merge finality: ~15 minutes (2 epochs)
- Bridge should wait for finality before processing exits

**Solana Considerations**:
- Optimistic confirmation: ~400ms
- Finalized confirmation: ~30 blocks

**Current Implementation**:
- No explicit finality waiting in contracts
- Relies on sequencer behavior

**Residual Risk**: HIGH - Reorg handling not explicitly implemented

#### 3.2 Cross-Chain State Inconsistency

**Threat**: Different L1 chains having inconsistent views of FLUXE state.

**Scenario**:
1. Batch N finalized on Ethereum
2. Batch N submitted to Solana
3. Ethereum reorgs, Batch N reverted
4. Solana still has Batch N finalized

**Current Mitigations**: None explicit

**Residual Risk**: HIGH - Multi-chain consistency not guaranteed

#### 3.3 Message Replay Across Chains

**Threat**: Exit receipt valid on Ethereum being replayed on Solana.

**Current Mitigations**:
- Chain ID embedded in exit receipts
- Separate bridge contracts per chain

**Exit Receipt Format** (from `FluxeBridge.sol:244-248`):
```solidity
// Exit receipt format: keccak256(destinationChain || assetType || amount || nullifier || nonce)
bytes32 expectedPrefix = keccak256(abi.encodePacked(chainId, assetType, amount));
```

**Residual Risk**: LOW if chain ID properly enforced

---

### 4. Supply Accounting Attack Vectors

#### 4.1 Inflation Attack (Creating Money)

**Threat**: Minting more tokens than deposited.

**Invariant**: `Total L2 Supply == Sum of all bridge pool balances`

**Locations**:
- `FluxeBridge.sol:191` - `poolBalances[assetType] += amount`
- `MintCircuit` - Sum of outputs equals ingress amount

**Attack Scenario**:
```
1. Deposit 100 tokens (pool balance = 100)
2. Mint proof with fabricated amount = 1000
3. If proof accepted: L2 supply = 1000, bridge has only 100
4. Withdraw 1000: pool underflow!
```

**Mitigations**:
- `MintCircuit` constraint (Line 185-189): `sum_var.enforce_equal(&amount_var)`
- Ingress receipt hash includes amount
- Bridge verifies amount during deposit

#### 4.2 Deflation Attack (Destroying Money)

**Threat**: Funds stuck in bridge due to failed state transitions.

**Scenario**: Batch accepted but withdrawal impossible.

**Residual Risk**: MEDIUM - Requires proper emergency procedures

#### 4.3 Pool Balance Manipulation

**Location**: `FluxeBridge.sol` - `poolBalances` mapping

**Threats**:
1. Integer overflow in balance tracking
2. Race conditions in balance updates

**Mitigations**:
- Solidity 0.8+ built-in overflow checks
- `nonReentrant` prevents race conditions

---

### 5. Nullifier Tree (S-IMT) Attacks

#### 5.1 Double-Spend via Nullifier Omission

**Threat**: Spending a note twice by not inserting its nullifier.

**Location**: `transfer.rs` - Lines 689-750

**Critical Code**:
```rust
// Lines 737-748
// Verify the insertion matches our nullifier
insert_gadget.target.enforce_equal(nf_var)?;

// Verify the insertion is valid
insert_gadget.enforce()?;

// Update current root for next iteration
current_nft = insert_gadget.new_root.clone();
```

**Residual Risk**: LOW if insertion witness properly verified

#### 5.2 Nullifier Collision

**Threat**: Two different notes having the same nullifier.

**Nullifier Computation** (`note.rs`):
```rust
pub fn nullifier(&self, nk_var: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
    // nf = H(nk, cm, position)
    poseidon_hash_zk(&[nk_var.clone(), self.commitment()?, self.position.clone()])
}
```

**Residual Risk**: NEGLIGIBLE - Poseidon collision resistance

---

### 6. Compliance and Sanctions Bypass

#### 6.1 Sanctions Screening Bypass

**Location**: `transfer.rs` - Lines 466-509

**Threat**: Transacting with sanctioned addresses.

**Critical Check**:
```rust
// Lines 478-486
if let Some(ref nm_proof) = self.sanctions_nm_proofs_in[i] {
    nm_proof_var.target.enforce_equal(&note_var.owner_addr)?;
    nm_proof_var.enforce_valid(&sanctions_root_var)?;
} else {
    // SECURITY: Required - return error
    return Err(SynthesisError::Unsatisfiable);
}
```

**Residual Risk**: LOW - Mandatory non-membership proofs

#### 6.2 Pool Policy Bypass

**Location**: `transfer.rs` - Lines 530-604

**Threat**: Cross-pool transfers violating policy rules.

**Mitigations**:
- Pool ID validation
- Cross-pool transfer restrictions
- Merkle membership proofs for policy

---

## Known Limitations and Assumptions

### Cryptographic Assumptions

1. **Groth16 Security** - Relies on discrete log hardness in BN254
2. **Poseidon Hash** - Assumed collision-resistant
3. **BN254 Curve** - Not post-quantum secure
4. **Trusted Setup** - Requires ceremony with proper toxic waste disposal

### Operational Assumptions

1. **Sequencer Liveness** - System halts if sequencer goes offline
2. **Sequencer Honesty** - Can censor but cannot forge proofs
3. **L1 Finality** - Assumes L1 chains provide final settlement
4. **Clock Synchronization** - Timestamp-based checks assume honest time

### Known Weaknesses

| ID | Weakness | Severity | Status |
|----|----------|----------|--------|
| W1 | Single sequencer (centralization) | MEDIUM | By design |
| W2 | No explicit reorg handling | HIGH | To be addressed |
| W3 | VK constants are placeholders in Groth16Verifier | **CRITICAL** | Requires trusted setup |
| W4 | Callback signature verification incomplete | MEDIUM | In development |

---

## Attack Surfaces Summary

| Surface | Risk Level | Primary Threats |
|---------|------------|-----------------|
| Bridge Contracts | HIGH | Reentrancy, access control, proof forgery |
| Proof Verification | CRITICAL | Soundness, public input binding |
| State Trees | CRITICAL | Double-spend, root manipulation |
| Cross-Chain | HIGH | Reorgs, inconsistency |
| Supply Accounting | HIGH | Inflation, deflation |
| Compliance | MEDIUM | Sanctions bypass |

---

## Recommendations

### Immediate Actions

1. Complete trusted setup ceremony for production VK values
2. Implement explicit finality waiting for cross-chain operations
3. Add emergency pause mechanisms with timelocks

### Medium-Term Improvements

1. Decentralize sequencer role
2. Add formal verification for critical circuits
3. Implement watchtower monitoring

### Long-Term Considerations

1. Post-quantum migration path
2. Cross-chain atomic operations
3. Decentralized governance for parameter updates
