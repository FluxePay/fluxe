# FLUXE Solana Bridge Deployment Guide

## Prerequisites

1. **Solana CLI** - Install from https://docs.solana.com/cli/install-solana-cli-tools
2. **Anchor** - Install from https://www.anchor-lang.com/docs/installation
3. **SOL for deployment** - Fund your wallet with Devnet SOL

## Quick Start

### 1. Install dependencies

```bash
# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# Install Anchor
cargo install --git https://github.com/coral-xyz/anchor anchor-cli --locked

# Verify installations
solana --version
anchor --version
```

### 2. Configure wallet

```bash
# Generate new keypair (or use existing)
solana-keygen new -o ~/.config/solana/id.json

# Switch to devnet
solana config set --url devnet

# Fund wallet with devnet SOL
solana airdrop 5

# Verify balance
solana balance
```

### 3. Generate program keypair

```bash
cd contracts/solana

# Generate program keypair
solana-keygen new -o target/deploy/fluxe_bridge-keypair.json

# Get program ID
solana address -k target/deploy/fluxe_bridge-keypair.json
# Output: e.g., FLuXe7J8Pf9CkL2Q3R4s5T6u7V8w9XyZaBcDeFgHiJkL
```

### 4. Update program ID

Update these files with the generated program ID:

**Anchor.toml:**
```toml
[programs.devnet]
fluxe_bridge = "YOUR_PROGRAM_ID"
```

**lib.rs:**
```rust
declare_id!("YOUR_PROGRAM_ID");
```

### 5. Build and deploy

```bash
# Build the program
anchor build

# Deploy to devnet
anchor deploy --provider.cluster devnet

# Verify deployment
solana program show YOUR_PROGRAM_ID
```

### 6. Initialize the bridge

```typescript
// TypeScript client initialization
import * as anchor from "@coral-xyz/anchor";
import { FluxeBridge } from "./target/types/fluxe_bridge";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const program = anchor.workspace.FluxeBridge as Program<FluxeBridge>;

// Initialize bridge
const [bridgePda] = await PublicKey.findProgramAddress(
  [Buffer.from("bridge")],
  program.programId
);

await program.methods
  .initialize(sequencerPubkey)
  .accounts({
    bridge: bridgePda,
    authority: provider.wallet.publicKey,
    systemProgram: SystemProgram.programId,
  })
  .rpc();
```

## Program Architecture

```
fluxe_bridge/
├── src/
│   ├── lib.rs       # Main program with instructions
│   ├── state.rs     # Account structures (BridgeState, AssetConfig, etc.)
│   ├── error.rs     # Custom error types
│   └── utils.rs     # Helper functions (Merkle verification)
```

## Account Structure

### BridgeState (PDA)
```rust
pub struct BridgeState {
    pub authority: Pubkey,           // Admin authority
    pub sequencer: Pubkey,           // Batch submitter
    pub last_finalized_batch: u64,   // Latest batch ID
    pub paused: bool,                // Emergency pause flag
    pub deposit_nonce: u64,          // Deposit counter
    pub pool_balances: [u64; 256],   // Per-asset balances
    pub bump: u8,                    // PDA bump seed
}
```

### AssetConfig (PDA per asset type)
```rust
pub struct AssetConfig {
    pub asset_type: u32,
    pub mint: Pubkey,
    pub min_deposit: u64,
    pub max_deposit: u64,
    pub enabled: bool,
    pub bump: u8,
}
```

## Instructions

| Instruction | Authority | Description |
|-------------|-----------|-------------|
| `initialize` | Admin | Initialize bridge with sequencer |
| `register_asset` | Admin | Register new asset type |
| `update_asset` | Admin | Update asset configuration |
| `deposit` | User | Deposit tokens to L2 |
| `withdraw` | User | Withdraw tokens from L2 |
| `submit_batch` | Sequencer | Submit finalized batch |
| `pause` | Admin | Emergency pause |
| `unpause` | Admin | Resume operations |
| `update_sequencer` | Admin | Change sequencer address |

## Deployment Commands

```bash
# Build only
anchor build

# Deploy to devnet
anchor deploy --provider.cluster devnet

# Deploy to mainnet (use with caution)
anchor deploy --provider.cluster mainnet

# Upgrade existing program
anchor upgrade target/deploy/fluxe_bridge.so --program-id YOUR_PROGRAM_ID

# Verify program
anchor verify YOUR_PROGRAM_ID
```

## Testing

```bash
# Run local tests
anchor test

# Test on devnet
anchor test --provider.cluster devnet
```

## Security Considerations

1. **Program Authority** - The deployer becomes the upgrade authority
2. **Sequencer Role** - Only sequencer can submit batches
3. **Admin Functions** - Only authority can pause/register assets
4. **Compute Units** - Groth16 verification requires ~2M CU (may need optimistic verification)

## Compute Budget

For instructions requiring heavy computation:

```typescript
import { ComputeBudgetProgram } from "@solana/web3.js";

const modifyComputeUnits = ComputeBudgetProgram.setComputeUnitLimit({
  units: 2_000_000,
});

await program.methods
  .submitBatch(...)
  .preInstructions([modifyComputeUnits])
  .rpc();
```

## Monitoring

### Events to track:
- `BridgeInitialized` - Bridge setup complete
- `AssetRegistered` - New asset available
- `Deposited` - User deposit processed
- `Withdrawn` - User withdrawal processed
- `BatchSubmitted` - New batch finalized

### View accounts:
```bash
# View bridge state
solana account BRIDGE_PDA_ADDRESS --output json

# View asset config
solana account ASSET_CONFIG_PDA_ADDRESS --output json
```

## Devnet Addresses

After deployment, update these:

```
Program ID: <YOUR_PROGRAM_ID>
Bridge PDA: <DERIVED_FROM_PROGRAM_ID>
Authority: <YOUR_WALLET>
Sequencer: <SEQUENCER_ADDRESS>
```

## Troubleshooting

### Common Issues

1. **"Insufficient funds"** - Airdrop more devnet SOL
2. **"Program failed to complete"** - Increase compute units
3. **"Custom program error"** - Check FluxeError codes in error.rs

### Error Codes

| Code | Error | Description |
|------|-------|-------------|
| 6000 | BridgePaused | Bridge is paused |
| 6001 | Unauthorized | Not authorized |
| 6002 | InvalidAssetType | Asset not registered |
| 6003 | AssetDisabled | Asset is disabled |
| 6004 | ZeroAmount | Amount must be > 0 |
| 6005 | AmountBelowMinimum | Below min deposit |
| 6006 | AmountAboveMaximum | Above max deposit |
