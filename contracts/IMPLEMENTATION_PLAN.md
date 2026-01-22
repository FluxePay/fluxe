# FLUXE Contracts Implementation Plan

## Current State Analysis

### Ethereum Contracts ✓ Mostly Complete

| Contract | Status | Notes |
|----------|--------|-------|
| `FluxeBridge.sol` | ✓ Complete | Deposit/withdraw with merkle verification |
| `FluxeRollupV2.sol` | ✓ Complete | Commit→Prove→Execute lifecycle (zkSync-style) |
| `FluxeMailbox.sol` | ✓ Complete | L1→L2 messaging |
| `Groth16Verifier.sol` | ⚠️ Placeholder | VK constants need generation |
| `Merkle.sol` | ✓ Complete | Library |
| `PriorityQueue.sol` | ✓ Complete | Library |

**What's Missing:**
1. SP1 aggregate proof verifier (different from Groth16)
2. Verifier key generation from trusted setup
3. Integration tests for full flow

### Solana Contracts ✓ Mostly Complete

| Contract | Status | Notes |
|----------|--------|-------|
| `lib.rs` (fluxe_bridge) | ✓ Complete | Deposit, withdraw, batch submission |
| `state.rs` | ✓ Complete | All account structures |
| `error.rs` | ✓ Complete | Error codes |
| `utils.rs` | ⚠️ Basic | Merkle verification placeholder |

**What's Missing:**
1. Groth16 proof verification (native or via syscall)
2. SP1 aggregate proof verification
3. Vault initialization instruction
4. Integration tests

---

## Implementation Plan

### Phase 1: Ethereum Contract Finalization

#### 1.1 Generate Real Groth16 Verifier (~2 hours)

The current `Groth16Verifier.sol` has placeholder VK values. Need to:

```bash
# Generate verifier from SP1 aggregation VK
cd fluxe-aggregation
snarkjs zkey export solidityverifier aggregation_vk.json Groth16Verifier.sol
```

**Alternative: SP1 Verifier**
Since we use SP1 for aggregation, we may want a dedicated SP1 verifier instead:

```solidity
// SP1Verifier.sol - Verifies SP1 proofs on-chain
contract SP1Verifier {
    // Uses Succinct's on-chain verifier
    function verify(bytes32 vkHash, bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}
```

**Decision needed:** Use Groth16 verifier for individual proofs OR SP1 verifier for aggregated batch?

#### 1.2 Update FluxeRollupV2 for SP1 (if using SP1 on-chain)

```solidity
// Changes needed:
// 1. Replace IGroth16Verifier with ISP1Verifier
// 2. Update public inputs format
// 3. Adjust proveBatches() to accept SP1 proof format
```

#### 1.3 Bridge-Rollup Integration

Current `FluxeBridge.sol` references `FluxeRollup.sol` (V1). Update to V2:

```solidity
// FluxeBridge.sol line 137
rollup = FluxeRollup(_rollup);  // Change to FluxeRollupV2
```

#### 1.4 Add Missing Tests

- [ ] Full deposit→proof→execute→withdraw cycle
- [ ] Multi-batch proof verification
- [ ] Priority queue draining
- [ ] Revert scenarios

---

### Phase 2: Solana Contract Finalization

#### 2.1 Vault Initialization Instruction

Currently missing instruction to initialize token vaults:

```rust
/// Initialize vault for an asset type
pub fn initialize_vault(ctx: Context<InitializeVault>, asset_type: u32) -> Result<()> {
    // Create PDA token account for holding deposits
    Ok(())
}

#[derive(Accounts)]
#[instruction(asset_type: u32)]
pub struct InitializeVault<'info> {
    #[account(
        seeds = [b"bridge"],
        bump = bridge.bump,
        has_one = authority,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(
        init,
        payer = authority,
        seeds = [b"vault", asset_type.to_le_bytes().as_ref()],
        bump,
        token::mint = mint,
        token::authority = bridge,
    )]
    pub vault: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}
```

#### 2.2 Proper Merkle Verification

Current `utils.rs` has basic placeholder. Implement proper verification:

```rust
/// Verify Merkle proof for exit receipt
pub fn verify_merkle_proof(
    proof: &[[u8; 32]],
    root: [u8; 32],
    leaf: [u8; 32],
) -> bool {
    let mut computed = leaf;

    for sibling in proof.iter() {
        computed = if computed <= *sibling {
            hash_pair(&computed, sibling)
        } else {
            hash_pair(sibling, &computed)
        };
    }

    computed == root
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use solana_program::keccak::hashv;
    hashv(&[left, right]).0
}
```

#### 2.3 Groth16 Verification (Optional)

For on-chain Groth16 verification on Solana, options:
1. **Alt_bn128 syscall** (not yet available on mainnet)
2. **Light Protocol's verifier** (uses compute units heavily)
3. **Skip on-chain verification** - Trust sequencer, rely on SP1 aggregation

**Recommendation:** Skip individual Groth16 verification on Solana. The sequencer verifies proofs off-chain, and SP1 aggregation provides the cryptographic guarantee.

#### 2.4 Add Tests

```rust
// tests/fluxe_bridge.rs
#[tokio::test]
async fn test_deposit_withdraw_cycle() {
    // 1. Initialize bridge
    // 2. Register USDC asset
    // 3. Initialize vault
    // 4. User deposits
    // 5. Sequencer submits batch
    // 6. User withdraws with merkle proof
}
```

---

### Phase 3: Cross-Chain Consistency

#### 3.1 Unified Receipt Format

Ensure ingress/exit receipt hashing matches between chains:

**Ethereum (keccak256):**
```solidity
bytes32 exitReceiptHash = keccak256(abi.encodePacked(
    chainId,      // uint32
    assetType,    // uint32
    amount,       // uint256
    nullifier,    // bytes32
    nonce         // uint64
));
```

**Solana (keccak256):**
```rust
let hash = hashv(&[
    &chain_id.to_le_bytes(),     // 4 bytes
    &asset_type.to_le_bytes(),   // 4 bytes
    &amount.to_le_bytes(),       // 8 bytes (u64 on Solana!)
    &nullifier,                  // 32 bytes
    &nonce.to_le_bytes(),        // 8 bytes
]);
```

**Issue:** Ethereum uses uint256 for amount, Solana uses u64. Need alignment:
- Option A: Solana pads amount to 32 bytes
- Option B: Ethereum truncates to u64 (USDC has 6 decimals, u64 is plenty)

**Recommendation:** Use u64 for amounts everywhere (sufficient for any realistic token amount).

#### 3.2 State Roots Alignment

Both chains use identical `StateRoots` structure - ✓ Already aligned.

---

### Phase 4: Deployment Scripts

#### 4.1 Ethereum Deployment

```bash
# contracts/ethereum/script/Deploy.s.sol
forge script script/Deploy.s.sol:DeployScript \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER_KEY \
    --broadcast \
    --verify
```

Deploy order:
1. Groth16Verifier (or SP1Verifier)
2. FluxeRollupV2(verifier, sequencer)
3. FluxeBridge(rollup, chainId)
4. Register assets (USDC, etc.)

#### 4.2 Solana Deployment

```bash
# Deploy program
anchor build
anchor deploy --provider.cluster devnet

# Initialize
anchor run initialize -- --sequencer <SEQUENCER_PUBKEY>

# Register USDC
anchor run register-asset -- --asset-type 1 --mint <USDC_MINT>
```

---

## Priority Order

1. **High Priority (Do First)**
   - [ ] Generate real Groth16/SP1 verifier with actual VK
   - [ ] Add vault initialization to Solana
   - [ ] Fix Merkle verification in Solana utils.rs
   - [ ] Align receipt hash format between chains

2. **Medium Priority**
   - [ ] Integration tests (Ethereum)
   - [ ] Integration tests (Solana)
   - [ ] Update FluxeBridge to use RollupV2

3. **Lower Priority**
   - [ ] Gas optimizations
   - [ ] Upgrade patterns (proxy contracts)
   - [ ] Multi-sig admin controls

---

## Decision Points

### 1. On-Chain Proof Verification Strategy

**Option A: Groth16 on Ethereum + Trust Sequencer on Solana**
- Ethereum: Verify aggregated Groth16 proof on-chain
- Solana: Sequencer submits batches, no on-chain proof verification
- Pro: Simpler Solana implementation
- Con: Different trust models per chain

**Option B: SP1 Verification on Both Chains**
- Use Succinct's SP1 verifier contracts
- Pro: Uniform verification across chains
- Con: SP1 Solana verifier may not be production-ready

**Recommendation:** Option A for initial deployment. Can upgrade Solana to SP1 verification later.

### 2. Amount Encoding

**Option A: u64 everywhere**
- Sufficient for USDC (max ~18 quintillion with 6 decimals)
- Simpler cross-chain alignment
- Slight limitation for tokens with high supplies

**Option B: u256 on Ethereum, u128 on Solana**
- More complex bridging
- Handles all edge cases

**Recommendation:** u64 for MVP. Add u256 support if needed for specific tokens.

---

## Estimated Timeline

| Phase | Task | Estimate |
|-------|------|----------|
| 1.1 | Generate verifier | 2 hours |
| 1.2-1.4 | Ethereum updates | 4 hours |
| 2.1-2.4 | Solana updates | 4 hours |
| 3.1-3.2 | Cross-chain alignment | 2 hours |
| 4.1-4.2 | Deployment scripts | 2 hours |
| Testing | Full integration tests | 4 hours |
| **Total** | | **~18 hours** |

---

## Files to Modify/Create

### Ethereum
- [ ] `contracts/ethereum/Groth16Verifier.sol` - Replace VK constants
- [ ] `contracts/ethereum/FluxeBridge.sol` - Update rollup reference
- [ ] `contracts/ethereum/test/Integration.t.sol` - New integration tests
- [ ] `contracts/ethereum/script/Deploy.s.sol` - Update deployment

### Solana
- [ ] `programs/fluxe_bridge/src/lib.rs` - Add `initialize_vault`
- [ ] `programs/fluxe_bridge/src/utils.rs` - Fix merkle verification
- [ ] `tests/fluxe_bridge.rs` - New integration tests
- [ ] `Anchor.toml` - Add deployment scripts
