# Circuit Key Architecture - Multi-Chain Deployment

## Key Principle

**Circuits and keys are CHAIN-AGNOSTIC. The same verification keys work on all chains.**

## Why Keys Don't Need Chain-Specific Versions

1. **Mathematics is universal**: Groth16 on BN254 produces the same proofs regardless of which chain verifies them
2. **Same proof → same keys**: The aggregated proof posted to both Ethereum and Solana is identical
3. **Verifier contracts just implement the math**: Ethereum's Solidity verifier and Solana's Rust verifier both implement the same Groth16 verification algorithm with the SAME verification key

## Correct Key Organization

```
keys/
  mint_pk.bin           # Proving key for MintCircuit
  mint_vk.bin           # Verifying key for MintCircuit (used on ALL chains)
  burn_pk.bin           # Proving key for BurnCircuit
  burn_vk.bin           # Verifying key for BurnCircuit (used on ALL chains)
  transfer_pk.bin
  transfer_vk.bin
  object_update_pk.bin
  object_update_vk.bin
  aggregation_pk.bin
  aggregation_vk.bin    # THE MOST IMPORTANT - this goes to all chains
```

## Multi-Chain Deployment Process

### Step 1: Generate Keys Once
```bash
# Generate keys for all circuits (one-time trusted setup)
cargo run --bin generate_keys
```

### Step 2: Generate Chain-Specific Verifier Contracts

**For Ethereum:**
```bash
# Generate Solidity verifier with embedded VK
circom export-verifier aggregation_vk.bin > contracts/ethereum/AggregationVerifier.sol
```

**For Solana:**
```rust
// Embed the same VK in Solana program
pub const AGGREGATION_VK: VerifyingKey = include_bytes!("../../keys/aggregation_vk.bin");
```

### Step 3: Deploy Verifiers to Each Chain

**Ethereum:**
```bash
forge create AggregationVerifier --rpc-url $ETH_RPC
# Address: 0x1234... (Ethereum verifier contract)
```

**Solana:**
```bash
anchor build && anchor deploy
# Program ID: FLUXverif... (Solana verifier program)
```

## What IS Chain-Specific

| Component | Chain-Specific? | Why |
|-----------|-----------------|-----|
| Circuit definition | ❌ No | Same constraints for all chains |
| Proving keys | ❌ No | Math is universal |
| Verifying keys | ❌ No | Math is universal |
| Verifier contract CODE | ✅ Yes | Solidity vs Rust implementation |
| Verifier contract ADDRESS | ✅ Yes | Different address on each chain |
| Bridge contract | ✅ Yes | ERC20 vs SPL token handling |

## Configuration Updates

Instead of per-chain keys, we just need per-chain verifier addresses:

```toml
[chains.ethereum]
chain_id = 1
verifier_address = "0x1234..."  # Ethereum contract address
bridge_address = "0x5678..."

[chains.solana]  
chain_id = 501
verifier_address = "FLUXverif..."  # Solana program ID
bridge_address = "FLUXbridge..."
```

## Key Management in Code

```rust
pub struct CircuitSetupManager {
    // Single set of keys for all chains
    pub mint_keys: TrustedSetup,
    pub burn_keys: TrustedSetup,
    pub transfer_keys: TrustedSetup,
    pub object_update_keys: TrustedSetup,
    pub aggregation_keys: TrustedSetup,
}

impl CircuitSetupManager {
    pub fn load_all() -> Result<Self> {
        Ok(Self {
            mint_keys: TrustedSetup::load("keys/mint")?,
            burn_keys: TrustedSetup::load("keys/burn")?,
            transfer_keys: TrustedSetup::load("keys/transfer")?,
            object_update_keys: TrustedSetup::load("keys/object_update")?,
            aggregation_keys: TrustedSetup::load("keys/aggregation")?,
        })
    }
    
    // No chain_id parameter needed!
    pub fn get_vk(&self, circuit_type: CircuitType) -> &VerifyingKey<Bn254> {
        match circuit_type {
            CircuitType::Mint => &self.mint_keys.verifying_key,
            CircuitType::Burn => &self.burn_keys.verifying_key,
            // ...
        }
    }
}
```

## Verifier Contract Generation

The ONLY chain-specific step is generating the verifier contract/program:

```rust
// build.rs or separate tool
fn generate_ethereum_verifier(vk: &VerifyingKey) -> String {
    // Generate Solidity code with VK embedded
}

fn generate_solana_verifier(vk: &VerifyingKey) -> TokenStream {
    // Generate Rust code with VK embedded  
}
```

## Summary

**DO NOT:**
- ❌ Create per-chain circuit keys
- ❌ Store keys in `keys/chain_1/`, `keys/chain_501/` directories
- ❌ Pass `chain_id` to proof generation or verification

**DO:**
- ✅ Use single global key set for all circuits
- ✅ Deploy same VK to verifier contracts on each chain
- ✅ Store chain-specific verifier CONTRACT addresses in config
- ✅ Keep key management simple and chain-agnostic

---

**Correction Applied**: Circuit key management does NOT need chain-specific organization. Keys are universal, only deployment addresses differ.
