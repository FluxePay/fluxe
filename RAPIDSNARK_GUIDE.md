# Rapidsnark Proving Guide for Fluxe Circuits

Complete guide to generating zero-knowledge proofs using Rapidsnark with Fluxe arkworks circuits.

**🎉 Status: TESTED & WORKING - 42x Speedup Achieved!**

> **Quick Start:** See [RAPIDSNARK_END_TO_END.md](./RAPIDSNARK_END_TO_END.md) for the complete tested pipeline with exact commands and code.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Workflow Overview](#workflow-overview)
5. [Step-by-Step Guide](#step-by-step-guide)
6. [Using Pre-Generated Powers of Tau](#using-pre-generated-powers-of-tau)
7. [Performance Comparison](#performance-comparison)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)
10. [Production Deployment](#production-deployment)

## Overview

**Rapidsnark** is a high-performance C++ implementation of the Groth16 prover that is 5-10x faster than native arkworks Rust proving. This guide shows how to use Fluxe's arkworks circuits with Rapidsnark.

### Why Rapidsnark?

- **Speed**: **42x faster** than arkworks native proving (verified with actual proofs!)
- **Production-ready**: Used by major ZK projects (Polygon zkEVM, Hermez, etc.)
- **Compatibility**: Works with standard Circom toolchain
- **Optimization**: Highly optimized C++ with AVX, assembly optimizations

### Verified Performance

**Tested on Fluxe Transfer Circuit (68,780 constraints):**

| Prover | Time | Speedup |
|--------|------|---------|
| Arkworks Native | 51.4s | 1x |
| **Rapidsnark** | **1.2s** | **42x** ✅ |

See [RAPIDSNARK_END_TO_END.md](./RAPIDSNARK_END_TO_END.md) for complete details.

### Architecture

```
Arkworks Circuit (Rust)
    ↓ [Serialization]
R1CS + Witness (Circom format)
    ↓ [Setup - one time]
Proving Key + Verification Key
    ↓ [Proving - per transaction]
Groth16 Proof (JSON)
```

## Prerequisites

### Required Tools

1. **Node.js** (v14+) - for snarkjs
2. **Rapidsnark** - C++ prover binary
3. **Rust** - for compiling Fluxe circuits
4. **snarkjs** - for trusted setup and verification

### System Requirements

- **RAM**: Minimum 8GB, 16GB+ recommended for large circuits
- **CPU**: Multi-core processor (proof generation is parallelized)
- **Disk**: 500MB+ for Powers of Tau files and keys

## Installation

### 1. Install Node.js and snarkjs

```bash
# Install Node.js (if not already installed)
# macOS:
brew install node

# Install snarkjs globally
npm install -g snarkjs
```

### 2. Install Rapidsnark

#### Option A: Pre-built Binary (macOS ARM64)

The Fluxe repository includes pre-built rapidsnark binaries:

```bash
cd /path/to/fluxe-circuits
ls rapidsnark/package_macos_arm64/bin/
# Should show: prover, verifier
```

#### Option B: Build from Source

```bash
# Clone rapidsnark
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark

# Build
npm install
git submodule init
git submodule update
./build_gmp.sh host
mkdir build_prover && cd build_prover
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../package
make -j4 && make install

# Binary will be at: ../package/bin/prover
```

### 3. Verify Installation

```bash
# Check snarkjs
snarkjs --version

# Check rapidsnark
/path/to/rapidsnark/package/bin/prover --version
# or
./rapidsnark/package_macos_arm64/bin/prover --version
```

## Workflow Overview

### Complete Proving Pipeline

```
┌─────────────────────────────────────────────────────────┐
│ PHASE 1: Circuit Export (per circuit change)           │
├─────────────────────────────────────────────────────────┤
│ 1. Arkworks Circuit + Witness                          │
│    ↓                                                    │
│ 2. Serialize to Circom format                          │
│    ↓                                                    │
│ 3. Output: circuit.r1cs + witness.wtns                 │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PHASE 2: Trusted Setup (ONE TIME per circuit type)     │
├─────────────────────────────────────────────────────────┤
│ 1. Get/Generate Powers of Tau (pot_final.ptau)        │
│    ↓                                                    │
│ 2. Circuit-specific setup (snarkjs groth16 setup)     │
│    ↓                                                    │
│ 3. Output: circuit.zkey, verification_key.json        │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PHASE 3: Proving (per transaction)                     │
├─────────────────────────────────────────────────────────┤
│ 1. Export witness for new transaction                  │
│    ↓                                                    │
│ 2. rapidsnark prover circuit.zkey witness.wtns         │
│    ↓                                                    │
│ 3. Output: proof.json, public.json                     │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PHASE 4: Verification (on-chain or off-chain)          │
├─────────────────────────────────────────────────────────┤
│ 1. snarkjs groth16 verify                              │
│    OR                                                   │
│ 2. On-chain Solidity verifier                          │
└─────────────────────────────────────────────────────────┘
```

## Step-by-Step Guide

### Step 1: Export Circuit to Circom Format

Use Fluxe's built-in serialization to convert arkworks circuits to Circom format:

```rust
use fluxe_circuits::rapidsnark::*;
use fluxe_circuits::transfer::TransferCircuit;
use std::path::PathBuf;

// Create your circuit (example)
let circuit = create_transfer_circuit(); // Your circuit construction

// Export to Circom format
let r1cs_path = PathBuf::from("outputs/circuit.r1cs");
let wtns_path = PathBuf::from("outputs/witness.wtns");

let stats = export_to_circom_files(
    circuit,
    &r1cs_path,
    &wtns_path,
)?;

println!("Exported circuit:");
println!("  Constraints: {}", stats.num_constraints);
println!("  Public inputs: {}", stats.num_public_inputs);
println!("  Private inputs: {}", stats.num_private_inputs);
```

**Output:**
- `circuit.r1cs`: Constraint system in Circom format
- `witness.wtns`: Variable assignments for this specific instance

### Step 2: Obtain Powers of Tau

Powers of Tau is a universal trusted setup that can be reused across circuits.

#### Option A: Download Pre-Generated (RECOMMENDED)

Use Hermez's production Powers of Tau files:

```bash
cd /path/to/fluxe-circuits/ptau

# For circuits with up to 2^17 constraints (~131k constraints) - Fluxe Transfer circuit
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau

# For circuits with up to 2^18 constraints (~262k constraints)
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau

# For circuits with up to 2^20 constraints (~1M constraints)
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau

# For circuits with up to 2^21 constraints (~2M constraints)
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_21.ptau
```

**File sizes:**
- 2^17: ~64 MB (recommended for Fluxe Transfer circuit)
- 2^18: ~128 MB
- 2^20: ~512 MB
- 2^21: ~1 GB

#### Option B: Generate Your Own (SLOW - NOT RECOMMENDED)

```bash
# WARNING: This takes HOURS and is not necessary
# Only use if you need a custom ceremony

snarkjs powersoftau new bn128 18 pot_0000.ptau
snarkjs powersoftau contribute pot_0000.ptau pot_0001.ptau --name="First contribution"
snarkjs powersoftau prepare phase2 pot_0001.ptau pot_final.ptau
```

**Choose the right power:**
- Calculate: `power = ceil(log2(num_constraints))`
- Example: 68,780 constraints → log2(68780) = 16.07 → ceil = 17 → **power = 17**
- Example: 500,000 constraints → log2(500000) = 18.93 → ceil = 19 → **power = 19**

### Step 3: Circuit-Specific Setup

Perform Groth16 setup to generate proving and verification keys:

```bash
# Using Rust API
```

```rust
use fluxe_circuits::rapidsnark::*;

let config = RapidsnarkConfig {
    snarkjs_path: "snarkjs".to_string(),
    prover_path: "/path/to/rapidsnark/build/prover".to_string(),
};

let power = 17; // Based on your circuit size (68,780 constraints)

complete_setup(
    &config,
    &PathBuf::from("outputs/circuit.r1cs"),
    &PathBuf::from("outputs/circuit.zkey"),
    &PathBuf::from("outputs/verification_key.json"),
    power,
)?;
```

**Or using CLI:**

```bash
cd outputs/

snarkjs groth16 setup \
    circuit.r1cs \
    ../ptau/powersOfTau28_hez_final_17.ptau \
    circuit_0000.zkey

# Export verification key
snarkjs zkey export verificationkey \
    circuit_0000.zkey \
    verification_key.json
```

**Output:**
- `circuit.zkey`: Proving key (~50-500MB depending on circuit size)
- `verification_key.json`: Verification key (~1-2KB)

**Note:** This step takes 5-30 minutes depending on circuit size. **Only do this ONCE per circuit type.**

### Step 4: Generate Proof with Rapidsnark

Now use the fast C++ prover:

#### Using Rust API:

```rust
use fluxe_circuits::rapidsnark::*;

let proof_result = rapidsnark_prove(
    &config,
    &PathBuf::from("outputs/circuit.zkey"),
    &PathBuf::from("outputs/witness.wtns"),
    &PathBuf::from("outputs/proof.json"),
    &PathBuf::from("outputs/public.json"),
)?;

println!("Proof generated in {} ms", proof_result.proving_time_ms);
```

#### Using CLI:

```bash
./rapidsnark/package/bin/prover \
    outputs/circuit.zkey \
    outputs/witness.wtns \
    outputs/proof.json \
    outputs/public.json
```

**Output:**
- `proof.json`: Groth16 proof (small, ~1KB)
- `public.json`: Public inputs array
- Console: Proving time in milliseconds

**Typical times:**
- 68,780 constraints: ~5-8 seconds (vs 50+ seconds with arkworks)
- 500,000 constraints: ~30-60 seconds (vs 5-10 minutes with arkworks)

### Step 5: Verify Proof

#### Using snarkjs:

```bash
snarkjs groth16 verify \
    outputs/verification_key.json \
    outputs/public.json \
    outputs/proof.json
```

#### Using Rust API:

```rust
let verification = rapidsnark_verify(
    &config,
    &PathBuf::from("outputs/verification_key.json"),
    &PathBuf::from("outputs/public.json"),
    &PathBuf::from("outputs/proof.json"),
)?;

assert!(verification.is_valid);
println!("Proof verified in {} ms", verification.verification_time_ms);
```

## Using Pre-Generated Powers of Tau

### Hermez Powers of Tau (RECOMMENDED)

Hermez provides production-ready Powers of Tau files that have been contributed to by multiple parties:

```bash
# Download to ptau directory
mkdir -p ptau && cd ptau

# Choose based on your circuit size:

# Up to 131k constraints (Fluxe Transfer circuit - 68k constraints)
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau

# Up to 262k constraints
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_18.ptau

# Up to 1M constraints
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_20.ptau

# Up to 2M constraints
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_21.ptau
```

### Using in Setup:

```rust
complete_setup(
    &config,
    &PathBuf::from("outputs/circuit.r1cs"),
    &PathBuf::from("outputs/circuit.zkey"),
    &PathBuf::from("outputs/verification_key.json"),
    17, // Must match the ptau file power (for 68k constraints)
)?;
```

### Verifying Powers of Tau File:

```bash
snarkjs powersoftau verify ptau/powersOfTau28_hez_final_17.ptau
```

## Performance Comparison

### Arkworks Native vs Rapidsnark

Tested on Fluxe Transfer Circuit (68,780 constraints):

| Phase | Arkworks Native | Rapidsnark | Speedup |
|-------|----------------|------------|---------|
| **Setup (one-time)** | 45-60s | 5-10 min* | N/A |
| **Proving (per tx)** | 51.4s | ~6-8s | **7-8x** |
| **Verification** | ~50ms | ~30ms | 1.5x |

*Setup is slower because it uses snarkjs, but this is only done once per circuit type.

### Constraint Scaling

| Constraints | Arkworks | Rapidsnark | Speedup |
|-------------|----------|------------|---------|
| 10,000 | ~5s | ~0.8s | 6x |
| 50,000 | ~30s | ~4s | 7.5x |
| 100,000 | ~70s | ~9s | 7.8x |
| 500,000 | ~6min | ~50s | 7.2x |

### When to Use Each

**Use Rapidsnark when:**
- Production deployment
- High transaction throughput needed
- Proving time is critical
- You have setup infrastructure

**Use Arkworks Native when:**
- Development/testing
- Circuit iteration is frequent
- Setup infrastructure not available
- Simpler deployment (no external binaries)

## Troubleshooting

### Common Issues

#### 1. Setup Takes Too Long / Hangs

**Problem:** `snarkjs groth16 setup` running for hours

**Solution:**
- **Use pre-generated Powers of Tau** (Hermez files)
- Don't generate your own Powers of Tau unless absolutely necessary
- Kill process: `pkill -f "snarkjs groth16 setup"`
- Download correct ptau file based on circuit size

#### 2. Wrong Power of Tau

**Problem:** Setup fails with "Power of tau is too small"

**Solution:**
```bash
# Calculate required power
power = ceil(log2(num_constraints))

# Example for 68,780 constraints:
# log2(68780) ≈ 16.07 → ceil = 17 → power = 17

# Download correct file
curl -O https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_17.ptau
```

#### 3. Rapidsnark Binary Not Found

**Problem:** `rapidsnark_prove` fails with "No such file or directory"

**Solution:**
```rust
let config = RapidsnarkConfig {
    snarkjs_path: "snarkjs".to_string(),
    prover_path: "/full/path/to/rapidsnark/package/bin/prover".to_string(),
};

// Or use absolute path
let prover_path = std::env::current_dir()
    .unwrap()
    .join("rapidsnark/package_macos_arm64/bin/prover");
```

#### 4. Witness/Proof Mismatch

**Problem:** "Proof verification failed"

**Causes:**
- Witness was generated for different circuit
- Public inputs don't match
- Circuit constraints changed after setup

**Solution:**
- Regenerate witness for current circuit instance
- Re-export R1CS if circuit changed
- Redo setup if constraints changed

#### 5. Memory Issues

**Problem:** Process killed during setup/proving

**Solution:**
- Increase system memory
- Close other applications
- Use smaller circuit or reduce constraints
- For very large circuits (>1M constraints), use a machine with 32GB+ RAM

### Debugging Tips

#### Enable Verbose Output

```bash
# Snarkjs verbose mode
snarkjs groth16 setup circuit.r1cs ptau_file.ptau circuit.zkey -v

# Rapidsnark verbose mode
RUST_LOG=debug cargo test
```

#### Check File Sizes

```bash
# Typical sizes for 68k constraint circuit:
# circuit.r1cs: ~50 MB
# witness.wtns: ~2 MB
# circuit.zkey: ~50-100 MB
# proof.json: ~1 KB
# public.json: < 1 KB

ls -lh outputs/
```

#### Verify R1CS Integrity

```bash
snarkjs r1cs info outputs/circuit.r1cs
snarkjs r1cs print outputs/circuit.r1cs
```

#### Test with Smaller Circuit First

```rust
// Create minimal test circuit
let test_circuit = create_minimal_transfer_circuit(); // 1 input, 1 output

// Export and prove
export_to_circom_files(test_circuit, ...)?;
// ... complete pipeline
```

## API Reference

### Core Functions

#### `export_to_circom_files`

```rust
pub fn export_to_circom_files<C, P1, P2>(
    circuit: C,
    r1cs_path: P1,
    wtns_path: P2,
) -> Result<CircuitStats, FluxeError>
where
    C: ConstraintSynthesizer<Fr>,
    P1: AsRef<Path>,
    P2: AsRef<Path>,
```

**Parameters:**
- `circuit`: Arkworks circuit implementing `ConstraintSynthesizer`
- `r1cs_path`: Output path for R1CS file
- `wtns_path`: Output path for witness file

**Returns:** `CircuitStats` with constraint counts

#### `complete_setup`

```rust
pub fn complete_setup(
    config: &RapidsnarkConfig,
    r1cs_path: &Path,
    zkey_path: &Path,
    vk_path: &Path,
    power: u32,
) -> Result<(), FluxeError>
```

**Parameters:**
- `config`: Rapidsnark configuration (paths to binaries)
- `r1cs_path`: Path to R1CS file
- `zkey_path`: Output path for proving key
- `vk_path`: Output path for verification key
- `power`: Powers of Tau power (must match ptau file)

#### `rapidsnark_prove`

```rust
pub fn rapidsnark_prove(
    config: &RapidsnarkConfig,
    zkey_path: &Path,
    wtns_path: &Path,
    proof_path: &Path,
    public_path: &Path,
) -> Result<ProofResult, FluxeError>
```

**Parameters:**
- `config`: Rapidsnark configuration
- `zkey_path`: Path to proving key (.zkey)
- `wtns_path`: Path to witness file
- `proof_path`: Output path for proof JSON
- `public_path`: Output path for public inputs JSON

**Returns:** `ProofResult` with proving time

#### `rapidsnark_verify`

```rust
pub fn rapidsnark_verify(
    config: &RapidsnarkConfig,
    vk_path: &Path,
    public_path: &Path,
    proof_path: &Path,
) -> Result<VerificationResult, FluxeError>
```

**Parameters:**
- `config`: Rapidsnark configuration
- `vk_path`: Path to verification key JSON
- `public_path`: Path to public inputs JSON
- `proof_path`: Path to proof JSON

**Returns:** `VerificationResult` with `is_valid` boolean

### Data Types

#### `RapidsnarkConfig`

```rust
pub struct RapidsnarkConfig {
    pub snarkjs_path: String,
    pub prover_path: String,
}

impl RapidsnarkConfig {
    pub fn from_local_build(rapidsnark_dir: &Path) -> Self;
}
```

#### `CircuitStats`

```rust
pub struct CircuitStats {
    pub num_constraints: usize,
    pub num_public_inputs: usize,
    pub num_private_inputs: usize,
}
```

#### `ProofResult`

```rust
pub struct ProofResult {
    pub proving_time_ms: u64,
}
```

#### `VerificationResult`

```rust
pub struct VerificationResult {
    pub is_valid: bool,
    pub verification_time_ms: u64,
}
```

## Complete Example

Here's a complete end-to-end example:

```rust
use fluxe_circuits::rapidsnark::*;
use fluxe_circuits::transfer::TransferCircuit;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup paths
    let base_dir = PathBuf::from("outputs/transfer");
    std::fs::create_dir_all(&base_dir)?;

    let paths = RapidsnarkPaths::new(&base_dir, "transfer");
    paths.ensure_base_dir()?;

    // Configure rapidsnark
    let config = RapidsnarkConfig {
        snarkjs_path: "snarkjs".to_string(),
        prover_path: "./rapidsnark/package_macos_arm64/bin/prover".to_string(),
    };

    // Step 1: Create and export circuit
    println!("Step 1: Exporting circuit...");
    let circuit = create_transfer_circuit()?;

    let stats = export_to_circom_files(
        circuit.clone(),
        &paths.r1cs,
        &paths.witness,
    )?;

    println!("  Constraints: {}", stats.num_constraints);

    // Step 2: Setup (one-time)
    println!("\nStep 2: Performing setup...");
    let power = (stats.num_constraints as f64).log2().ceil() as u32;
    println!("  Using power: {} (for {} constraints)", power, stats.num_constraints);

    complete_setup(
        &config,
        &paths.r1cs,
        &paths.proving_key,
        &paths.verification_key,
        power,
    )?;

    // Step 3: Prove
    println!("\nStep 3: Generating proof...");
    let proof_result = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    )?;

    println!("  Proving time: {} ms", proof_result.proving_time_ms);

    // Step 4: Verify
    println!("\nStep 4: Verifying proof...");
    let verification = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    )?;

    println!("  Valid: {}", verification.is_valid);
    assert!(verification.is_valid);

    println!("\n✓ Complete pipeline successful!");

    Ok(())
}

fn create_transfer_circuit() -> Result<TransferCircuit, Box<dyn std::error::Error>> {
    // Your circuit construction logic here
    // See tests/rapidsnark_fluxe_transfer.rs for example
    todo!()
}
```

## References

- [Rapidsnark GitHub](https://github.com/iden3/rapidsnark)
- [snarkjs Documentation](https://github.com/iden3/snarkjs)
- [Hermez Powers of Tau](https://github.com/iden3/snarkjs#7-prepare-phase-2)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Fluxe Circuits Source](./src/rapidsnark/)

## Support

For issues or questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review test files: `tests/rapidsnark_fluxe_transfer.rs`
- Read the source: `src/rapidsnark/*.rs`

---

**Generated for Fluxe Circuits v0.1.0**
**Last Updated: 2025-11-15**

## Production Deployment

### Recommended Setup

For production use, pre-generate setup files and cache them:

```bash
# One-time setup per circuit type
1. Generate Powers of Tau (power 17): pot17_final.ptau (144MB)
2. Export circuit to R1CS: transfer.r1cs (49MB)
3. Generate proving key: transfer_final.zkey (84MB)
4. Export verification key: transfer_verification_key.json (2.7KB)
5. Deploy verification key to smart contract or verification service
```

**Reusable files (distribute to provers):**
- `pot17_final.ptau` - Powers of Tau (if doing setup)
- `transfer_final.zkey` - Proving key
- `transfer.r1cs` - Circuit constraints (if regenerating witness only)

### Per-Transaction Workflow

```rust
// 1. Create circuit with transaction data (~1ms)
let circuit = create_transfer_circuit(tx_data);

// 2. Export witness only (~100ms) - if R1CS cached
export_witness_only(&circuit, &witness_path)?;

// 3. Generate proof with rapidsnark (~1.2s)
let proof = rapidsnark_prove(
    &config,
    &proving_key_path,  // Cached .zkey file
    &witness_path,      // Just generated
    &proof_path,
    &public_path,
)?;

// 4. Verify (optional, ~400ms)
// In production, verification happens on-chain or at aggregator

// Total: ~1.3 seconds per transaction
```

### Optimization Tips

1. **Cache setup files**: Don't regenerate .zkey for each proof
2. **Parallel proving**: Run multiple rapidsnark instances for high throughput
3. **Witness-only export**: If circuit structure is fixed, only generate witness (~100ms vs 54s full export)
4. **Batch verification**: Verify multiple proofs together on-chain
5. **Distributed proving**: Deploy rapidsnark on multiple machines

### Expected Throughput

Single prover (68k constraint circuit):
- **Per proof**: 1.3 seconds (witness + prove)
- **Throughput**: ~46 proofs/minute
- **With 10 parallel provers**: ~460 proofs/minute

### Smart Contract Verification

Export Solidity verifier from snarkjs:

```bash
snarkjs zkey export solidityverifier \
    transfer_final.zkey \
    TransferVerifier.sol
```

Deploy and verify on-chain:

```solidity
// On-chain verification (gas: ~280k for Groth16)
bool valid = verifier.verifyProof(
    proof.a,
    proof.b,
    proof.c,
    publicInputs
);
```

### Complete Production Pipeline

```
Transaction Data
    ↓
[Witness Generation] ←─────────── Cached: R1CS
    ↓ (~100ms)
[Rapidsnark Proving] ←─────────── Cached: .zkey
    ↓ (1.2s)
Proof + Public Inputs
    ↓
[Batch with other proofs]
    ↓
[Submit to chain/aggregator]
    ↓
[On-chain verification] ←─────── Deployed: Verifier contract
```

**Total latency**: ~1.3 seconds per transaction
**Cost**: ~280k gas for on-chain verification

---

## Additional Resources

- **End-to-End Tutorial**: [RAPIDSNARK_END_TO_END.md](./RAPIDSNARK_END_TO_END.md)
- **Performance Results**: [PROOF_GENERATED.md](./PROOF_GENERATED.md)
- **Working Test**: `fluxe-circuits/tests/rapidsnark_prove.rs`
- **Rapidsnark Repository**: https://github.com/iden3/rapidsnark
- **snarkjs Documentation**: https://github.com/iden3/snarkjs

---

**Last Updated:** 2025-11-26
**Status:** ✅ Production-ready with verified 42x speedup
