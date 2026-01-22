# Quick Start: Multi-Chain Circuit Key Management

Get up and running with multi-chain circuit keys in 5 minutes.

## Installation

No new dependencies required. The system uses existing arkworks libraries.

```bash
cd fluxe-circuits
cargo build --release
```

## Generate Keys for Your Chains

### Option 1: Generate Global Circuits Only (Single Chain)

For deployments running on a single blockchain:

```bash
cargo run --bin keygen -- target/keys 12345
```

Output:
```
target/keys/
└── global/
    ├── v1_Transfer_1_2_pk.bin
    ├── v1_Transfer_1_2_vk.bin
    ├── v1_ObjectUpdate_pk.bin
    └── v1_ObjectUpdate_vk.bin
```

### Option 2: Generate for Multiple Chains

For Ethereum and Solana:

```bash
# Generate for Ethereum (chain_id = 1)
cargo run --bin keygen -- target/keys 12345 1

# Generate for Solana (chain_id = 501)
cargo run --bin keygen -- target/keys 12345 501
```

Output:
```
target/keys/
├── global/
│   ├── v1_Transfer_1_2_pk.bin
│   ├── v1_Transfer_1_2_vk.bin
│   ├── v1_ObjectUpdate_pk.bin
│   └── v1_ObjectUpdate_vk.bin
├── chain_1/
│   ├── v1_Mint_pk.bin
│   ├── v1_Mint_vk.bin
│   ├── v1_Burn_pk.bin
│   └── v1_Burn_vk.bin
└── chain_501/
    ├── v1_Mint_pk.bin
    ├── v1_Mint_vk.bin
    ├── v1_Burn_pk.bin
    └── v1_Burn_vk.bin
```

## Using Keys in Your Code

### Load All Keys

```rust
use fluxe_circuits::setup::{CircuitSetupManager, CircuitSetupConfig};

let config = CircuitSetupConfig {
    base_dir: "target/keys".to_string(),
    ..Default::default()
};

let mut manager = CircuitSetupManager::new(config);
manager.load_all()?;

// All keys are now loaded and ready to use
```

### Get Keys for a Circuit

```rust
// Get keys for Ethereum Mint circuit
if let Some(setup) = manager.get(Some(1), CircuitType::Mint) {
    let proving_key = &setup.proving_key;
    let verifying_key = &setup.verifying_key;
    // Use keys to generate/verify proofs
}

// Get keys for Transfer (global, shared by all chains)
if let Some(setup) = manager.get(None, CircuitType::Transfer) {
    let proving_key = &setup.proving_key;
    // Use for all Transfer proofs regardless of chain
}

// Shortcut methods
if let Some(pk) = manager.get_pk(Some(1), CircuitType::Burn) {
    // Use proving key directly
}

if let Some(vk) = manager.get_vk(Some(501), CircuitType::Mint) {
    // Use verifying key directly
}
```

## Real-World Example: Proof Verification

### Before (Single Chain)

```rust
pub fn verify_proof(proof: &[u8], inputs: &[Fr]) -> Result<bool> {
    // Always uses the same setup
    let setup = manager.get_setup(CircuitType::Mint)?;
    Groth16::<Bn254>::verify(&setup.verifying_key, inputs, proof)
}
```

### After (Multi-Chain)

```rust
pub fn verify_proof(chain_id: u32, circuit_type: CircuitType,
                   proof: &[u8], inputs: &[Fr]) -> Result<bool> {
    // Use chain-specific keys
    let setup = manager.get(Some(chain_id), circuit_type)
        .ok_or(format!("Keys not found for chain {}", chain_id))?;

    Groth16::<Bn254>::verify(&setup.verifying_key, inputs, proof)
}

// Usage
verify_proof(1, CircuitType::Mint, &proof, &inputs)?;      // Ethereum
verify_proof(501, CircuitType::Mint, &proof, &inputs)?;    // Solana
```

## Migration from Single-Chain

### Step 1: Backup Existing Keys

```bash
cp -r target/keys target/keys.backup
```

### Step 2: Migrate to New Format

```bash
cargo run --bin keygen -- target/keys 12345 --migrate --from target/keys.backup
```

### Step 3: Verify Structure

```bash
tree target/keys
# Should show:
# target/keys/
# ├── global/
# │   ├── v1_Transfer_1_2_pk.bin
# │   └── ...
# └── chain_0/      # (all circuits migrated as global)
#     └── ...
```

### Step 4: Update Your Code (Optional)

The old API still works, but you can update to the new pattern:

```rust
// Old API (still works)
let setup = manager.get_setup(CircuitType::Mint)?;

// New API (recommended)
let setup = manager.get(None, CircuitType::Mint)?;  // For global
let setup = manager.get(Some(1), CircuitType::Mint)?;  // For chain-specific
```

## Troubleshooting

### Keys Not Found

**Problem**: Error "Setup not found for Mint on chain 1"

**Solution**:
```bash
# Generate missing keys
cargo run --bin keygen -- target/keys 12345 1

# Verify keys were created
ls -la target/keys/chain_1/
```

### Compilation Error: Cannot Find Type `ChainId`

Make sure you're using the latest version of fluxe-circuits:

```bash
cargo update -p fluxe-circuits
```

### Wrong Key Format Error

Old keys won't work with new format. Migrate them:

```bash
cargo run --bin keygen -- target/keys 12345 --migrate --from old_keys_dir
```

## Common Tasks

### Check Key Directory Size

```bash
du -sh target/keys/
du -sh target/keys/chain_*/
```

### List Available Chains

```bash
ls -d target/keys/chain_*/ | sed 's/.*chain_//;s/\///'
```

### Regenerate Keys (Fresh Start)

```bash
rm -rf target/keys
cargo run --bin keygen -- target/keys 12345 1 501
```

### Copy Keys to Production

```bash
# Create tarball
tar -czf fluxe-keys.tar.gz target/keys/

# Transfer to server
scp fluxe-keys.tar.gz user@prod-server:/var/lib/fluxe/

# Extract
ssh user@prod-server "cd /var/lib/fluxe && tar -xzf fluxe-keys.tar.gz"
```

## Performance Tips

1. **Load keys once at startup**
   ```rust
   let manager = Arc::new(RwLock::new(manager));  // Share across threads
   ```

2. **Verify on fast storage** (SSD, not HDD)
   ```bash
   # Check where keys are stored
   ls -la target/keys/
   # Ensure it's on fast storage
   ```

3. **Use batch verification when possible**
   ```rust
   // Verify 100 proofs with appropriate keys
   let results = manager.verify_batch(proofs)?;
   ```

## What's Next?

1. **Generate keys for your chains**
   ```bash
   cargo run --bin keygen -- production/keys 12345 1 501
   ```

2. **Update ServerVerifier** (see SERVERVERIFIER_INTEGRATION_GUIDE.md)
   ```rust
   let vk = manager.get_vk(chain_id, circuit_type)?;
   ```

3. **Deploy to production** with confidence

## Full Documentation

For more details:
- [CIRCUIT_KEY_MANAGEMENT.md](./CIRCUIT_KEY_MANAGEMENT.md) - Complete reference
- [SERVERVERIFIER_INTEGRATION_GUIDE.md](./SERVERVERIFIER_INTEGRATION_GUIDE.md) - Integration patterns
- [IMPLEMENTATION_STATUS.md](./IMPLEMENTATION_STATUS.md) - Technical details

## Support

1. Check the troubleshooting section above
2. Review test cases in `fluxe-circuits/src/setup.rs`
3. Read full documentation in `/docs`
4. Open an issue with key details and logs

---

**Last Updated**: 2026-01-22
**Version**: 1.0
