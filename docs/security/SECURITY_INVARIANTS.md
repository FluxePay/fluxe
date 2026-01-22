# FLUXE Security Invariants

**Version**: 1.0
**Date**: January 2026

## Overview

This document specifies the critical security invariants that must hold for FLUXE to maintain its security guarantees. Auditors should verify that these invariants cannot be violated under any circumstances.

---

## Notation

- `CMT` - Commitment Tree (I-IMT, append-only)
- `NFT` - Nullifier Tree (S-IMT, sorted)
- `OBJ` - Object Tree (I-IMT, append-only)
- `EXIT` - Exit Receipt Tree (I-IMT, append-only)
- `INGRESS` - Ingress Receipt Tree (I-IMT, append-only)
- `H()` - Poseidon hash function
- `nf(note, nk)` - Nullifier derived from note and nullifier key

---

## Global Invariants

### INV-1: Supply Conservation

**Statement**: The total L2 supply for any asset type equals the sum of all deposited amounts minus all withdrawn amounts.

```
For all asset_type a:
  L2_Supply(a) == Sum(deposits(a)) - Sum(withdrawals(a))
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeBridge.sol:191` | `poolBalances[assetType] += amount` on deposit |
| `FluxeBridge.sol:259` | `poolBalances[assetType] -= amount` on withdraw |
| `MintCircuit:185-189` | Output sum equals ingress amount |
| `TransferCircuit:397-410` | Input sum equals output sum plus fee |
| `BurnCircuit:180-185` | Burn amount <= note value |

**Code Reference (MintCircuit)**:
```rust
// fluxe-circuits/src/mint.rs:185-189
let mut sum_var = FpVar::zero();
for note_var in &notes_out_vars {
    sum_var += &note_var.value;
}
sum_var.enforce_equal(&amount_var)?;
```

---

### INV-2: Nullifier Uniqueness (No Double-Spend)

**Statement**: Every nullifier can only be inserted into the NFT tree once. A spent note cannot be spent again.

```
For all nullifiers nf:
  inserted(nf, NFT) => not insertable(nf, NFT')  where NFT' includes nf
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:440-461` | Non-membership proof required before spend |
| `transfer.rs:689-750` | S-IMT insertion proof verifies correct update |
| `burn.rs:197-209` | Non-membership proof for burn nullifier |
| `FluxeBridge.sol:228-231` | Processed withdrawals cannot repeat |

**Code Reference (TransferCircuit)**:
```rust
// fluxe-circuits/src/transfer.rs:440-461
for (i, nf_var) in nf_vars.iter().enumerate() {
    if let Some(ref nm_proof) = self.nf_nonmembership_proofs[i] {
        let nm_proof_var = RangePathVar::new_witness(cs.clone(), || Ok(nm_proof.clone()))?;

        // Verify the proof target matches our nullifier
        nm_proof_var.target.enforce_equal(nf_var)?;

        // Verify the non-membership proof is valid
        nm_proof_var.enforce_valid(&nft_root_old_var)?;
    } else {
        // SECURITY: Non-membership proof is REQUIRED
        return Err(SynthesisError::Unsatisfiable);
    }
}
```

---

### INV-3: Exit Receipt Uniqueness

**Statement**: Each exit receipt can only be claimed once on the destination chain.

```
For all exit_receipts e:
  claimed(e, chain_c) => not claimable(e, chain_c)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeBridge.sol:228-231` | `processedWithdrawals` mapping check |
| `FluxeBridge.sol:256` | Marking as processed before transfer |
| Solana `lib.rs:208` | `!withdrawal_record.processed` check |
| Solana `lib.rs:250` | `withdrawal_record.processed = true` |

**Code Reference (Ethereum)**:
```solidity
// FluxeBridge.sol:228-231
if (processedWithdrawals[exitReceiptHash]) {
    revert WithdrawalAlreadyProcessed();
}

// FluxeBridge.sol:256
processedWithdrawals[exitReceiptHash] = true;
```

**Code Reference (Solana)**:
```rust
// fluxe_bridge/src/lib.rs:207-208
require!(!withdrawal_record.processed, FluxeError::AlreadyWithdrawn);

// fluxe_bridge/src/lib.rs:250
withdrawal_record.processed = true;
```

---

### INV-4: Batch ID Sequentiality

**Statement**: Batch IDs must be strictly sequential with no gaps.

```
For all batches B:
  batch_id(B) == batch_id(B_prev) + 1
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeRollup.sol:154-157` | `batchId != lastFinalizedBatchId + 1` reverts |
| Solana `lib.rs:161-164` | `batch_id == bridge.last_finalized_batch + 1` required |

**Code Reference (Ethereum)**:
```solidity
// FluxeRollup.sol:154-157
if (batchId != lastFinalizedBatchId + 1) {
    revert InvalidBatchId(lastFinalizedBatchId + 1, batchId);
}
```

---

### INV-5: Proof Verification Before State Update

**Statement**: State roots can only be updated after successful proof verification.

```
For all state transitions S -> S':
  verify_proof(proof, public_inputs) == true
  BEFORE
  finalized_state = S'
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeRollup.sol:168-171` | Proof verification before state storage |
| `FluxeRollup.sol:173-175` | State stored only after verification passes |

**Code Reference**:
```solidity
// FluxeRollup.sol:168-175
// Verify the aggregated proof
if (!verifier.verifyProof(proof, publicInputs)) {
    revert InvalidProof();
}

// Store new finalized state (ONLY IF PROOF VALID)
finalizedBatches[batchId] = newRoots;
lastFinalizedBatchId = batchId;
```

---

### INV-6: Previous State Consistency

**Statement**: Each batch must build on the exact previous finalized state.

```
For batch B with prev_roots:
  prev_roots == finalized_state(batch_id - 1)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeRollup.sol:159-163` | `_rootsMatch()` validation |
| `FluxeRollup.sol:274-284` | All 8 roots must match |

**Code Reference**:
```solidity
// FluxeRollup.sol:159-163
StateRoots storage lastRoots = finalizedBatches[lastFinalizedBatchId];
if (!_rootsMatch(prevRoots, lastRoots)) {
    revert InvalidPreviousRoots();
}

// FluxeRollup.sol:274-284
function _rootsMatch(StateRoots calldata a, StateRoots storage b) internal view returns (bool) {
    return a.cmtRoot == b.cmtRoot &&
           a.nftRoot == b.nftRoot &&
           a.objRoot == b.objRoot &&
           a.cbRoot == b.cbRoot &&
           a.ingressRoot == b.ingressRoot &&
           a.exitRoot == b.exitRoot &&
           a.sanctionsRoot == b.sanctionsRoot &&
           a.poolRulesRoot == b.poolRulesRoot;
}
```

---

## Circuit-Specific Invariants

### INV-C1: Note Commitment Integrity

**Statement**: A note commitment uniquely binds all note fields.

```
cm(note) = H(asset_type, value_commit, owner_addr, pool_id, ...)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `gadgets/note.rs` | `commitment()` function |
| `transfer.rs:362-366` | Commitment matches path leaf |

---

### INV-C2: Nullifier Derivation

**Statement**: Nullifier is deterministically derived from note and nullifier key.

```
nf = H(nk, cm, position)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `gadgets/note.rs` | `nullifier()` function |
| `transfer.rs:369-376` | Computed nullifier matches public input |

**Code Reference**:
```rust
// transfer.rs:369-376
for ((note_var, nk_var), expected_nf_var) in notes_in_var.iter()
    .zip(nks_var.iter())
    .zip(nf_vars.iter())
{
    let computed_nf = note_var.nullifier(nk_var)?;
    computed_nf.enforce_equal(expected_nf_var)?;
}
```

---

### INV-C3: Owner Authentication

**Statement**: Only the owner of a note can spend it.

```
For note N with owner_addr = A:
  spend(N) requires knowledge of sk where H(PK(sk)) == A
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:380-394` | EC-based authentication |
| `gadgets/auth.rs` | `scalar_mult_generator()` and address derivation |
| `burn.rs:166-177` | Owner authentication for burns |

**Code Reference**:
```rust
// transfer.rs:380-394
for (i, note_var) in notes_in_var.iter().enumerate() {
    if i < self.owner_sks.len() {
        let owner_sk_var = FpVar::new_witness(cs.clone(), || Ok(self.owner_sks[i]))?;

        // Derive the public key from the secret key
        let (derived_pk_x_fq, derived_pk_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk_var)?;

        // Compute owner address: addr = H(pk_x, pk_y)
        let computed_owner_addr = AuthGadget::compute_owner_address_from_fq(cs.clone(), &derived_pk_x_fq, &derived_pk_y_fq)?;

        // Enforce match
        computed_owner_addr.enforce_equal(&note_var.owner_addr)?;
    }
}
```

---

### INV-C4: Asset Type Consistency

**Statement**: All notes in a transaction must have the same asset type.

```
For transaction T with inputs I and outputs O:
  asset_type(i) == asset_type(o) for all i in I, o in O
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:413-426` | Asset type enforcement loop |
| `mint.rs:192-194` | Output asset type matches ingress |

**Code Reference**:
```rust
// transfer.rs:413-426
if !notes_in_var.is_empty() {
    let asset_type = &notes_in_var[0].asset_type;

    // Check all inputs have same asset type
    for note_var in &notes_in_var[1..] {
        note_var.asset_type.enforce_equal(asset_type)?;
    }

    // Check all outputs have same asset type as inputs
    for note_var in &notes_out_var {
        note_var.asset_type.enforce_equal(asset_type)?;
    }
}
```

---

### INV-C5: Range Proof Validity

**Statement**: All values must be within valid range (0 to 2^64 - 1).

```
For all values v in notes:
  0 <= v < 2^64
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:429-433` | 64-bit range proof for outputs |
| `mint.rs:206-208` | 64-bit range proof for mint outputs |
| `burn.rs:218-219` | 64-bit range proof for burn amount |
| `gadgets/range_proof.rs` | `prove_range_bits()` implementation |

**Code Reference**:
```rust
// transfer.rs:429-433
use crate::gadgets::range_proof::RangeProofGadget;
for note_var in &notes_out_var {
    RangeProofGadget::prove_range_bits(cs.clone(), &note_var.value, 64)?;
}
```

---

### INV-C6: Merkle Tree Transition Validity

**Statement**: Tree root updates must follow valid append (I-IMT) or insert (S-IMT) operations.

**For CMT (I-IMT)**:
```
CMT_new = append(CMT_old, new_commitments)
```

**For NFT (S-IMT)**:
```
NFT_new = insert_sorted(NFT_old, new_nullifiers)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:653-685` | CMT append proof verification |
| `transfer.rs:689-750` | NFT sorted insert verification |
| `gadgets/merkle_append.rs` | I-IMT append gadget |
| `gadgets/sorted_insert.rs` | S-IMT insert gadget |

---

### INV-C7: Sanctions Compliance

**Statement**: No transaction can involve a sanctioned address.

```
For all addresses A in transaction T:
  A not in SANCTIONS_LIST
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `transfer.rs:466-509` | Sender and recipient sanctions checks |
| `gadgets/sanctions.rs` | Non-membership proof gadget |

**Code Reference**:
```rust
// transfer.rs:466-509
// Check sender addresses not sanctioned
for (i, note_var) in notes_in_var.iter().enumerate() {
    if let Some(ref nm_proof) = self.sanctions_nm_proofs_in[i] {
        nm_proof_var.target.enforce_equal(&note_var.owner_addr)?;
        nm_proof_var.enforce_valid(&sanctions_root_var)?;
    } else {
        return Err(SynthesisError::Unsatisfiable);
    }
}

// Check recipient addresses not sanctioned
for (i, note_var) in notes_out_var.iter().enumerate() {
    // Similar check for output note owners
}
```

---

## Bridge Invariants

### INV-B1: Deposit-Ingress Binding

**Statement**: Each deposit creates exactly one ingress receipt with matching parameters.

```
deposit(asset_type, amount, beneficiary_cm, nonce)
  => ingress_hash = H(chain_id, asset_type, amount, beneficiary_cm, nonce)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeBridge.sol:174-182` | Ingress hash computation |
| `mint.rs:180-182` | Beneficiary commitment verification |

---

### INV-B2: Withdrawal-Exit Binding

**Statement**: A withdrawal can only occur with a valid exit receipt proven in a finalized batch.

```
withdraw(exit_hash, merkle_proof, batch_id)
  => verify_merkle_proof(exit_hash, proof, finalized_exit_root[batch_id])
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeBridge.sol:237-241` | Merkle proof verification |
| `burn.rs:255-275` | Exit append proof in circuit |

---

### INV-B3: Pool Balance Solvency

**Statement**: Bridge pool balance must always be >= sum of valid outstanding withdrawals.

```
pool_balance(asset) >= sum(pending_valid_exits(asset))
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `FluxeBridge.sol:250-253` | Insufficient balance check |
| Solana `lib.rs:217-220` | Liquidity check before transfer |

---

## Aggregation Invariants

### INV-A1: All Proofs Verified

**Statement**: The aggregated proof is only valid if all individual Groth16 proofs are valid.

```
aggregate_valid(proofs[]) => for all p in proofs: groth16_valid(p)
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `program/src/main.rs:52-81` | Proof verification loop |
| `program/src/main.rs:74-78` | Assert on verification failure |

**Code Reference**:
```rust
// fluxe-aggregation/program/src/main.rs:68-78
let is_valid = verify_groth16(vk, &proof, &public_inputs)
    .expect("Verification error");

assert!(
    is_valid,
    "Proof {} (type {:?}) failed verification",
    i, entry.tx_type
);
```

---

### INV-A2: State Transition Immutability

**Statement**: Reference roots (sanctions, pool_rules) must not change within a batch.

```
batch.old_roots.sanctions_root == batch.new_roots.sanctions_root
batch.old_roots.pool_rules_root == batch.new_roots.pool_rules_root
```

**Verification Points**:

| Location | Check |
|----------|-------|
| `program/src/main.rs:85-97` | Sanctions and pool rules root assertions |

**Code Reference**:
```rust
// fluxe-aggregation/program/src/main.rs:85-97
assert_eq!(
    batch.old_roots.sanctions_root,
    batch.new_roots.sanctions_root,
    "Sanctions root changed unexpectedly"
);

assert_eq!(
    batch.old_roots.pool_rules_root,
    batch.new_roots.pool_rules_root,
    "Pool rules root changed unexpectedly"
);
```

---

## Invariant Testing Recommendations

### Automated Testing

1. **Property-Based Testing**: Use fuzzing to test invariants with random inputs
2. **Symbolic Execution**: Formally verify constraint satisfaction
3. **Mutation Testing**: Verify tests catch constraint removals

### Manual Review Checklist

- [ ] All `enforce_equal()` calls are present, not just `is_eq()`
- [ ] No missing non-membership proofs
- [ ] Range proofs cover all value-carrying fields
- [ ] Public input order matches between circuits and contracts
- [ ] No integer overflow in balance tracking
