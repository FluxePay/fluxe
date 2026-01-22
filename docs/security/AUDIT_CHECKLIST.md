# FLUXE Security Audit Checklist

**Version**: 1.0
**Date**: January 2026

## How to Use This Checklist

For each item:
- **[PASS]** - Verified secure
- **[FAIL]** - Vulnerability identified
- **[N/A]** - Not applicable
- **[REVIEW]** - Requires further investigation

---

## Part 1: Smart Contract Security (Ethereum)

### 1.1 Access Control

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| AC-1 | Sequencer-only functions properly protected | `FluxeRollup.sol:97-100` | | |
| AC-2 | Owner-only functions properly protected | `FluxeRollup.sol:102-105` | | |
| AC-3 | Two-step ownership transfer implemented | `FluxeRollup.sol:231-249` | | |
| AC-4 | Pause mechanism functional | `FluxeRollup.sol:261-270` | | |
| AC-5 | No privilege escalation paths | All contracts | | |
| AC-6 | Modifier order is correct | All functions | | |

### 1.2 Reentrancy Protection

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| RE-1 | ReentrancyGuard used on state-changing externals | `FluxeBridge.sol:12` | | |
| RE-2 | CEI pattern followed (Checks-Effects-Interactions) | `FluxeBridge.sol:212-271` | | |
| RE-3 | No external calls before state updates | `withdraw()`, `deposit()` | | |
| RE-4 | SafeERC20 used for token transfers | `FluxeBridge.sol:13` | | |

### 1.3 Integer Overflow/Underflow

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| IO-1 | Solidity version >= 0.8.0 (built-in checks) | All contracts | | |
| IO-2 | Explicit unchecked blocks reviewed | None expected | | |
| IO-3 | Pool balance updates don't overflow | `FluxeBridge.sol:191, 259` | | |
| IO-4 | Batch ID increment doesn't overflow | `FluxeRollup.sol:175` | | |

### 1.4 Input Validation

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| IV-1 | Zero address checks | Constructors | | |
| IV-2 | Zero amount checks | `deposit()`, `withdraw()` | | |
| IV-3 | Array length checks | Merkle proof arrays | | |
| IV-4 | Batch ID sequentiality check | `submitBatch()` | | |
| IV-5 | Proof length validation | `Groth16Verifier.sol:92` | | |
| IV-6 | Public input count validation | `Groth16Verifier.sol:137-139` | | |

### 1.5 External Calls

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| EC-1 | Return values checked | All external calls | | |
| EC-2 | Low-level calls have proper error handling | Precompiles in verifier | | |
| EC-3 | Callback attack vectors considered | No callbacks | | |
| EC-4 | Token approval races handled | SafeERC20 | | |

### 1.6 Cryptographic Operations

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| CR-1 | Pairing equation correct | `Groth16Verifier.sol:162-172` | | |
| CR-2 | Point negation correct | `_negate()` function | | |
| CR-3 | Field modulus correct | `PRIME_Q` constant | | |
| CR-4 | Precompile addresses correct | Lines 25-27 | | |
| CR-5 | IC array indexing correct | Lines 152-153 | | |
| CR-6 | Public input encoding matches circuit | `_constructPublicInputs()` | | |

### 1.7 Business Logic

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| BL-1 | Deposits correctly update pool balance | `FluxeBridge.sol:191` | | |
| BL-2 | Withdrawals correctly update pool balance | `FluxeBridge.sol:259` | | |
| BL-3 | Exit receipt cannot be reused | `processedWithdrawals` mapping | | |
| BL-4 | Merkle proof verification correct | `_computeMerkleRoot()` | | |
| BL-5 | State root transition atomic | `submitBatch()` | | |
| BL-6 | Minimum/maximum deposit enforced | Lines 161-166 | | |

---

## Part 2: Smart Contract Security (Solana)

### 2.1 Account Validation

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| SA-1 | PDAs properly derived | All `seeds` constraints | | |
| SA-2 | Bump seeds stored and reused | `bump = bridge.bump` | | |
| SA-3 | Account ownership verified | `has_one` constraints | | |
| SA-4 | Token account ownership verified | `lib.rs:410-411` | | |
| SA-5 | Mint account verified | `MintMismatch` checks | | |

### 2.2 Signer Verification

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| SS-1 | Authority signer required for admin | `AdminAction` context | | |
| SS-2 | Sequencer signer required for batches | `SubmitBatch` context | | |
| SS-3 | User signer required for deposits | `Deposit` context | | |
| SS-4 | No missing signer checks | All instructions | | |

### 2.3 State Management

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| SM-1 | Account size correctly calculated | `*::LEN` constants | | |
| SM-2 | Nonce increments atomically | `lib.rs:95-96` | | |
| SM-3 | Pool balance overflow checked | `checked_add()` | | |
| SM-4 | Pool balance underflow checked | `checked_sub()` | | |
| SM-5 | Withdrawal record initialized correctly | Lines 250-257 | | |

### 2.4 CPI Security

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| CP-1 | Token program CPI correct | `token::transfer` calls | | |
| CP-2 | Signer seeds correct for PDA signing | Lines 226-230 | | |
| CP-3 | CPI context correctly constructed | All CPI calls | | |

---

## Part 3: ZK Circuit Security

### 3.1 Constraint Completeness

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| CC-1 | Value conservation enforced | `transfer.rs:397-410` | | |
| CC-2 | Nullifier correctly derived | `transfer.rs:369-376` | | |
| CC-3 | Commitment correctly computed | `note.rs:commitment()` | | |
| CC-4 | Owner authentication enforced | `transfer.rs:380-394` | | |
| CC-5 | Non-membership proofs mandatory | Multiple locations | | |
| CC-6 | Merkle tree updates verified | Lines 653-750 | | |
| CC-7 | Range proofs present for all values | Lines 429-433 | | |
| CC-8 | Asset type consistency enforced | Lines 413-426 | | |

### 3.2 Constraint Correctness

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| CX-1 | `enforce_equal()` used, not just `is_eq()` | All equality checks | | |
| CX-2 | Boolean constraints properly enforced | `enforce_equal(&Boolean::TRUE)` | | |
| CX-3 | Field overflow prevented | Implicit in arkworks | | |
| CX-4 | No constraint variable reuse bugs | All circuits | | |
| CX-5 | Witness allocation matches constraints | All `new_witness()` calls | | |

### 3.3 Public Input Handling

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| PI-1 | Public inputs created in correct order | `transfer.rs:297-317` | | |
| PI-2 | `public_inputs()` matches constraint order | `transfer.rs:757-777` | | |
| PI-3 | All security-critical values are public | Roots, nullifiers, commitments | | |
| PI-4 | No private inputs leaked as public | Review all `new_input()` | | |

### 3.4 Witness Security

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| WS-1 | Witnesses cannot influence public inputs | All circuits | | |
| WS-2 | No witness grinding attacks | Random blinding factors | | |
| WS-3 | Witness consistency verified | Merkle paths, proofs | | |

### 3.5 Circuit-Specific Checks

#### Transfer Circuit

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| TC-1 | Input note membership in CMT | | |
| TC-2 | Nullifier non-membership in NFT (old) | | |
| TC-3 | Nullifier inserted into NFT (new) | | |
| TC-4 | Output commitments appended to CMT | | |
| TC-5 | Sanctions compliance for senders | | |
| TC-6 | Sanctions compliance for recipients | | |
| TC-7 | Pool policy enforcement | | |
| TC-8 | Lineage hash correctly computed | | |
| TC-9 | Compliance gates (frozen, callbacks) | | |

#### Mint Circuit

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| MC-1 | Output sum equals ingress amount | | |
| MC-2 | Beneficiary CM matches output CMs | | |
| MC-3 | Asset type matches ingress | | |
| MC-4 | Ingress receipt appended correctly | | |
| MC-5 | Pool ID is valid (non-zero) | | |

#### Burn Circuit

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| BC-1 | Input note membership verified | | |
| BC-2 | Nullifier correctly derived | | |
| BC-3 | Burn amount <= note value | | |
| BC-4 | Exit receipt correctly formed | | |
| BC-5 | Exit receipt appended to tree | | |
| BC-6 | Owner authentication verified | | |

#### ObjectUpdate Circuit

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| OU-1 | Old object membership verified | | |
| OU-2 | State hash consistency | | |
| OU-3 | Serial increment correct | | |
| OU-4 | Callback processing valid | | |
| OU-5 | State transition rules enforced | | |
| OU-6 | New object appended correctly | | |

---

## Part 4: Proof Aggregation Security

### 4.1 SP1 Guest Program

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| AG-1 | All proofs verified (no skipping) | `program/src/main.rs:52-81` | | |
| AG-2 | Verification failure causes panic | Lines 74-78 | | |
| AG-3 | VK selection by tx_type correct | Lines 54-55 | | |
| AG-4 | Public inputs correctly parsed | Lines 62-66 | | |
| AG-5 | State transition constraints verified | Lines 85-113 | | |
| AG-6 | Output commitment is binding | Lines 123-134 | | |

### 4.2 Groth16 Verification (bn crate)

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| GV-1 | Pairing equation correct | `groth16.rs:197-232` | | |
| GV-2 | Point parsing handles edge cases | `parse_g1_be`, `parse_g2_be` | | |
| GV-3 | Point at infinity handled | Lines 64-66, 84-86 | | |
| GV-4 | IC length validation | Lines 204-206 | | |
| GV-5 | Gnark format parsing correct | All parse functions | | |

---

## Part 5: Cross-Chain Security

### 5.1 Chain Isolation

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| CI-1 | Chain ID embedded in receipts | `FluxeBridge.sol:176-181` | | |
| CI-2 | Chain ID verified on withdrawal | Implicit in Merkle proof | | |
| CI-3 | No cross-chain receipt replay | Separate bridges | | |
| CI-4 | State roots are chain-specific | `ingressRoot`, `exitRoot` | | |

### 5.2 Finality Handling

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| FH-1 | Reorg risk documented | Threat model | | |
| FH-2 | Finality assumptions clear | | | |
| FH-3 | No finality waiting in contracts | Known limitation | | |

---

## Part 6: Common Vulnerability Patterns

### 6.1 OWASP Smart Contract Top 10

| ID | Vulnerability | Status | Notes |
|----|--------------|--------|-------|
| OW-1 | Reentrancy | | |
| OW-2 | Access Control | | |
| OW-3 | Arithmetic Issues | | |
| OW-4 | Unchecked Return Values | | |
| OW-5 | Denial of Service | | |
| OW-6 | Bad Randomness | | |
| OW-7 | Front-Running | | |
| OW-8 | Time Manipulation | | |
| OW-9 | Short Address Attack | | |
| OW-10 | Unknown Unknowns | | |

### 6.2 ZK-Specific Vulnerabilities

| ID | Vulnerability | Status | Notes |
|----|--------------|--------|-------|
| ZK-1 | Under-constrained circuits | | |
| ZK-2 | Witness grinding | | |
| ZK-3 | Trusted setup compromise | | |
| ZK-4 | Public input manipulation | | |
| ZK-5 | Malleability attacks | | |
| ZK-6 | Side-channel leakage | | |
| ZK-7 | Constraint duplication/missing | | |
| ZK-8 | Field overflow in constraints | | |

---

## Part 7: Gas and Performance

### 7.1 Gas Optimization Review

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| GO-1 | Storage reads minimized | All contracts | | |
| GO-2 | Loops bounded | Merkle proof iteration | | |
| GO-3 | Calldata vs memory usage | Function parameters | | |
| GO-4 | Assembly gas savings | Verifier precompiles | | |
| GO-5 | Event emission efficient | All emit statements | | |

### 7.2 DoS Resistance

| ID | Check | Location | Status | Notes |
|----|-------|----------|--------|-------|
| DS-1 | Unbounded loops prevented | Proof verification | | |
| DS-2 | Storage growth bounded | Mappings not arrays | | |
| DS-3 | Gas griefing mitigated | No external call loops | | |

---

## Part 8: Documentation and Testing

### 8.1 Code Quality

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| CQ-1 | NatSpec comments present | | |
| CQ-2 | Error messages descriptive | | |
| CQ-3 | Events emitted for state changes | | |
| CQ-4 | Constants documented | | |
| CQ-5 | Complex logic explained | | |

### 8.2 Test Coverage

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| TS-1 | Unit tests for all functions | | |
| TS-2 | Integration tests for flows | | |
| TS-3 | Fuzzing for edge cases | | |
| TS-4 | Invariant testing | | |
| TS-5 | Circuit constraint tests | | |

---

## Audit Summary Template

### Findings Summary

| Severity | Count |
|----------|-------|
| Critical | |
| High | |
| Medium | |
| Low | |
| Informational | |

### Critical Findings

(List any CRITICAL findings here)

### High Findings

(List any HIGH findings here)

### Medium Findings

(List any MEDIUM findings here)

### Low Findings

(List any LOW findings here)

### Informational

(List any informational findings here)

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Lead Auditor | | | |
| Reviewer 1 | | | |
| Reviewer 2 | | | |
| Project Lead | | | |
