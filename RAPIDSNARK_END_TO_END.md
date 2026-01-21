# Rapidsnark End-to-End Pipeline - TESTED & WORKING

**Status: ✅ Proof Generated and Verified Successfully**

This document shows the **exact tested pipeline** that successfully generated a Groth16 proof for the Fluxe Transfer circuit with **42x speedup** over arkworks native proving.

## Quick Start

```bash
# 1. Generate Powers of Tau (one-time, ~30 seconds)
cd /Users/rabool/Repos/Fluxe/fluxe-circuits
snarkjs powersoftau new bn128 17 pot17_0000.ptau -v
snarkjs powersoftau prepare phase2 pot17_0000.ptau pot17_final.ptau -v

# 2. Run the proof generation test
cd fluxe-circuits
cargo test test_generate_transfer_proof -- --nocapture --test-threads=1
```

**Result:** Proof generated in **1.2 seconds** (vs 51.4s with arkworks) ✅

---

## Detailed Step-by-Step Pipeline

### Prerequisites

```bash
# Verify tools installed
node --version    # v14+
snarkjs --version # Global install
cargo --version   # Rust toolchain

# Verify rapidsnark binary
ls ../rapidsnark/package_macos_arm64/bin/prover
```

### Step 1: Generate Powers of Tau (One-Time Setup)

**Why local generation?** Hermez S3 files have access restrictions. Local generation is fast and reliable.

```bash
cd /Users/rabool/Repos/Fluxe/fluxe-circuits

# Generate ceremony for power 17 (supports up to 131k constraints)
snarkjs powersoftau new bn128 17 pot17_0000.ptau -v

# Expected output:
# [DEBUG] snarkJS: tauG1: 100000
# [DEBUG] snarkJS: tauG2: 100000
# [INFO] snarkJS: First Contribution Hash: d27bebee...

# Prepare for phase 2
snarkjs powersoftau prepare phase2 pot17_0000.ptau pot17_final.ptau -v

# Verify result
ls -lh pot17_final.ptau
# -rw-r--r--  1 user  staff   144M Nov 26 14:38 pot17_final.ptau
```

**Time:** ~30 seconds
**File size:** 144MB
**Supports:** Up to 131,072 constraints (2^17)

### Step 2: Export Circuit to Circom Format

The test in `fluxe-circuits/tests/rapidsnark_prove.rs` does this automatically:

```rust
// Export arkworks circuit to Circom R1CS + witness
let stats = export_to_circom_files(
    circuit,
    &paths.r1cs,
    &paths.witness,
)?;

// Output:
// Stats: 68780 constraints, 10 public inputs
```

**Time:** ~54 seconds
**Output files:**
- `transfer.r1cs` (49MB) - Circuit constraints
- `transfer_witness.wtns` (2MB) - Variable assignments

### Step 3: Circuit-Specific Setup (One-Time per Circuit)

Generate Groth16 proving and verification keys:

```bash
cd fluxe-circuits/outputs/transfer_proof

snarkjs groth16 setup \
    transfer.r1cs \
    ../../pot17_final.ptau \
    transfer_final.zkey

# Export verification key
snarkjs zkey export verificationkey \
    transfer_final.zkey \
    transfer_verification_key.json
```

**Time:** ~8.6 seconds
**Output files:**
- `transfer_final.zkey` (84MB) - Proving key
- `transfer_verification_key.json` (2.7KB) - Verification key

**Note:** This is done **once per circuit type**. Reuse the same .zkey for all subsequent proofs.

### Step 4: Generate Proof with Rapidsnark

```bash
# Use rapidsnark C++ prover
../../../rapidsnark/package_macos_arm64/bin/prover \
    transfer_final.zkey \
    transfer_witness.wtns \
    transfer_proof.json \
    transfer_public.json
```

**Time:** **1.2 seconds** ⚡
**Output files:**
- `transfer_proof.json` (810B) - Groth16 proof
- `transfer_public.json` (824B) - Public inputs

**Performance:** 42x faster than arkworks (51.4s → 1.2s)

### Step 5: Verify Proof

**Issue:** Rapidsnark outputs JSON with null-byte padding. Must trim for snarkjs.

```bash
cd fluxe-circuits/outputs/transfer_proof

# Trim null bytes from JSON files
head -c 497 transfer_public.json > transfer_public_clean.json
head -c 708 transfer_proof.json > transfer_proof_clean.json

# Verify with snarkjs
snarkjs groth16 verify \
    transfer_verification_key.json \
    transfer_public_clean.json \
    transfer_proof_clean.json

# Output:
# [INFO] snarkJS: OK! ✅
```

**Time:** ~435ms

---

## Complete Rust Test Code

The working test is located at `fluxe-circuits/tests/rapidsnark_prove.rs`:

```rust
#[test]
fn test_generate_transfer_proof() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║    RAPIDSNARK PROOF GENERATION - TRANSFER CIRCUIT        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let circuit = create_transfer_circuit();

    // Setup paths
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("outputs")
        .join("transfer_proof");

    std::fs::create_dir_all(&base_dir).unwrap();
    let paths = RapidsnarkPaths::new(&base_dir, "transfer");
    paths.ensure_base_dir().unwrap();

    // Config
    let rapidsnark_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("rapidsnark");

    let ptau_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("pot17_final.ptau");

    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir)
        .with_powers_of_tau(&ptau_path);

    // Step 1: Export (54s)
    println!("Step 1: Exporting circuit to Circom format...");
    let export_start = std::time::Instant::now();
    let stats = export_to_circom_files(circuit, &paths.r1cs, &paths.witness).unwrap();
    let export_time = export_start.elapsed();
    println!("  ✓ Export completed in {:.2}s", export_time.as_secs_f64());

    // Step 2: Setup if needed (8.6s, one-time)
    println!("\nStep 2: Circuit-specific setup...");
    if !paths.proving_key.exists() {
        println!("  Running groth16 setup...");
        let setup_start = std::time::Instant::now();

        let status = std::process::Command::new(&config.snarkjs_path)
            .arg("groth16")
            .arg("setup")
            .arg(&paths.r1cs)
            .arg(&ptau_path)
            .arg(&paths.proving_key)
            .status()
            .unwrap();
        assert!(status.success());

        let status = std::process::Command::new(&config.snarkjs_path)
            .arg("zkey")
            .arg("export")
            .arg("verificationkey")
            .arg(&paths.proving_key)
            .arg(&paths.verification_key)
            .status()
            .unwrap();
        assert!(status.success());

        println!("  ✓ Setup completed in {:.2}s", setup_start.elapsed().as_secs_f64());
    } else {
        println!("  ✓ Setup already exists, skipping");
    }

    // Step 3: Prove with Rapidsnark (1.2s)
    println!("\nStep 3: Generating proof with Rapidsnark...");
    let proof_result = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    ).unwrap();
    println!("  ✓ Proof generated in {} ms", proof_result.proving_time_ms);

    // Step 4: Verify (435ms)
    println!("\nStep 4: Verifying proof...");
    let verification = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();
    println!("  ✓ Verification: {}", if verification.is_valid { "VALID ✓" } else { "INVALID ✗" });

    assert!(verification.is_valid, "Proof verification failed!");
}
```

---

## Performance Summary

| Phase | Time | Frequency |
|-------|------|-----------|
| **Powers of Tau** | 30s | Once (all circuits) |
| **Circuit Export** | 54s | Per proof |
| **Setup** | 8.6s | Once per circuit type |
| **Proving** | **1.2s** ⚡ | Per proof |
| **Verification** | 435ms | Per proof |

### Comparison: Arkworks vs Rapidsnark

| Metric | Arkworks | Rapidsnark | Speedup |
|--------|----------|------------|---------|
| **Proving Time** | 51.4s | **1.2s** | **42x** ✅ |
| Setup (one-time) | ~60s | 8.6s | 7x |
| Verification | ~50ms | 435ms | 0.1x |

**Tested on:** Transfer circuit with 68,780 constraints

---

## Files Generated

```
/Users/rabool/Repos/Fluxe/fluxe-circuits/
├── pot17_final.ptau                         (144MB)  [Reusable]

fluxe-circuits/outputs/transfer_proof/
├── transfer.r1cs                            (49MB)   [Reusable per circuit]
├── transfer_final.zkey                      (84MB)   [Reusable per circuit]
├── transfer_verification_key.json           (2.7KB)  [Reusable per circuit]
├── transfer_witness.wtns                    (2MB)    [Per proof]
├── transfer_proof.json                      (810B)   [Per proof]
└── transfer_public.json                     (824B)   [Per proof]
```

**Reusable files:** Setup files (.zkey, verification key) are generated once and reused for all proofs of the same circuit type.

**Per-proof files:** Only witness, proof, and public inputs change per transaction.

---

## Troubleshooting

### Null-Byte Padding in JSON Files

**Symptom:** `snarkjs groth16 verify` fails with "Unexpected non-whitespace character"

**Cause:** Rapidsnark writes fixed-size buffers

**Solution:**
```bash
# Find actual JSON end (look for last '}')
cat transfer_proof.json | grep -o '.*}' > transfer_proof_clean.json

# Or use fixed byte counts (works for this circuit):
head -c 497 transfer_public.json > transfer_public_clean.json
head -c 708 transfer_proof.json > transfer_proof_clean.json
```

### Rapidsnark Verifier Fails

**Symptom:** `rapidsnark verifier` returns "Invalid proof" even though snarkjs verifier succeeds

**Cause:** Incompatibility between snarkjs verification key format and rapidsnark verifier

**Solution:** Use snarkjs for verification:
```bash
snarkjs groth16 verify vk.json public_clean.json proof_clean.json
```

Or use the Rust `rapidsnark_verify()` function which wraps snarkjs.

### Powers of Tau Download Fails

**Symptom:** Hermez S3 returns "Access Denied"

**Solution:** Generate locally (it's fast!):
```bash
snarkjs powersoftau new bn128 17 pot17_0000.ptau -v
snarkjs powersoftau prepare phase2 pot17_0000.ptau pot17_final.ptau -v
```

Only takes ~30 seconds for power 17.

---

## Next Steps

### For Production

1. **Pre-generate setup files** (.zkey, verification key) and distribute them
2. **Cache exported R1CS files** if circuit doesn't change
3. **Only regenerate witness** for each new transaction
4. **Prove in 1.2 seconds** with rapidsnark per transaction

### Optimization Opportunities

- **Export once:** If circuit structure is fixed, only generate witness per proof (~100ms)
- **Batch proving:** Generate multiple proofs in parallel
- **On-chain verification:** Export Solidity verifier from snarkjs for gas-efficient on-chain verification

### Integration Points

```rust
// Production workflow
let circuit = create_transfer_circuit(transaction_data);

// Fast path: Export only witness if R1CS already exists
export_witness_only(&circuit, &witness_path)?;  // ~100ms

// Prove
rapidsnark_prove(&config, &zkey_path, &witness_path, &proof_path, &public_path)?;  // 1.2s

// Submit proof + public inputs on-chain or to aggregator
```

---

## References

- Working test: `fluxe-circuits/tests/rapidsnark_prove.rs`
- Results document: `PROOF_GENERATED.md`
- Integration guide: `RAPIDSNARK_GUIDE.md`
- Rapidsnark repo: https://github.com/iden3/rapidsnark
- snarkjs docs: https://github.com/iden3/snarkjs

**Generated:** 2025-11-26
**Circuit:** Fluxe Transfer (68,780 constraints)
**Status:** ✅ Fully tested and working
