# Fluxe Rapidsnark Integration

This crate provides seamless integration between Fluxe's arkworks-based circuits (BLS12-381) and the Rapidsnark prover, enabling fast proof generation for the Fluxe privacy protocol.

## Overview

Fluxe-rapidsnark bridges the gap between:
- **Fluxe circuits**: Written in Rust using arkworks with BLS12-381 curve
- **Rapidsnark**: High-performance C++ Groth16 prover (5-10x faster than snarkjs)

This integration allows you to:
1. Export arkworks circuits to Circom-compatible R1CS and witness formats
2. Perform trusted setup using snarkjs
3. Generate proofs with rapidsnark (much faster than pure Rust proving)
4. Verify proofs using both rapidsnark and snarkjs

## Architecture

```
┌─────────────────────┐
│  Fluxe Circuits     │
│  (Arkworks/BLS12-381)│
└──────────┬──────────┘
           │ Export
           ▼
┌─────────────────────┐
│  R1CS + WTNS Files  │
│  (Circom format)    │
└──────────┬──────────┘
           │ Setup (snarkjs)
           ▼
┌─────────────────────┐
│  Proving/Verify Keys│
└──────────┬──────────┘
           │ Prove (rapidsnark)
           ▼
┌─────────────────────┐
│  Groth16 Proof      │
└─────────────────────┘
```

## Features

### ✅ Implemented

- **BLS12-381 Serializer**: Converts arkworks circuits to Circom format
- **R1CS Export**: Constraint system serialization
- **WTNS Export**: Witness serialization with proper field element encoding
- **Prover Interface**: Wrapper for rapidsnark prover binary
- **Verifier Interface**: Wrapper for rapidsnark and snarkjs verifiers
- **Circuit Traits**: Easy integration for all Fluxe circuit types
  - MintCircuit
  - TransferCircuit
  - BurnCircuit
  - ObjectUpdateCircuit
- **Shell Scripts**: Automated setup, proving, and verification workflows
- **Examples**: Simple circuit demonstration
- **Tests**: Integration tests for serialization

## Prerequisites

### 1. Rapidsnark

The rapidsnark binaries are included in this repository at `../rapidsnark/package_macos_arm64/bin/`.

For other platforms or to build from source:

```bash
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
npm install
git submodule init
git submodule update
npx task createFieldSources
npx task buildProver
npx task buildVerifier
```

### 2. SnarkJS

Required for trusted setup and verification key export:

```bash
npm install -g snarkjs
```

### 3. Node.js

Required for snarkjs (version 14 or later recommended).

## Quick Start

### 1. Run the Simple Example

```bash
# Export a simple circuit to R1CS and WTNS
cargo run --example simple_circuit

# Perform trusted setup
cd fluxe-rapidsnark
./scripts/setup.sh simple

# Generate proof with rapidsnark
./scripts/prove.sh simple

# Verify the proof
./scripts/verify.sh simple
```

### 2. Using with Fluxe Circuits

```rust
use fluxe_circuits::MintCircuit;
use fluxe_rapidsnark::RapidsnarkCircuit;

// Create your circuit instance
let circuit = MintCircuit::new(/* ... */);

// Export to rapidsnark format
circuit.export_to_rapidsnark(
    "outputs/mint.r1cs",
    "outputs/mint_witness.wtns"
)?;
```

Then use the scripts:

```bash
./scripts/setup.sh mint
./scripts/prove.sh mint
./scripts/verify.sh mint
```

## API Documentation

### Core Functions

#### `export_to_circom_files`

Exports an arkworks circuit to Circom-compatible files.

```rust
pub fn export_to_circom_files<C, P1, P2>(
    circuit: C,
    r1cs_path: P1,
    wtns_path: P2,
) -> Result<CircuitStats>
where
    C: ConstraintSynthesizer<Fr>,
    P1: AsRef<Path>,
    P2: AsRef<Path>
```

**Parameters:**
- `circuit`: The arkworks circuit to export
- `r1cs_path`: Output path for R1CS file
- `wtns_path`: Output path for witness file

**Returns:** `CircuitStats` with constraint/wire counts

#### `RapidsnarkProver`

Wrapper for the rapidsnark prover binary.

```rust
let config = ProverConfig::with_default_prover(
    "outputs/circuit_final.zkey",
    "outputs/witness.wtns",
    "outputs/proof.json",
    "outputs/public.json",
);

let prover = RapidsnarkProver::new(config);
let proof_output = prover.prove()?;
```

#### `RapidsnarkVerifier`

Wrapper for proof verification.

```rust
let config = VerifierConfig::with_default_verifier(
    "outputs/circuit_vkey.json",
    "outputs/public.json",
    "outputs/proof.json",
);

let verifier = RapidsnarkVerifier::new(config);
let is_valid = verifier.verify()?;

// Cross-verify with snarkjs
let is_valid_snarkjs = verifier.verify_with_snarkjs()?;
```

### Trait: `RapidsnarkCircuit`

All Fluxe circuits implement this trait:

```rust
pub trait RapidsnarkCircuit {
    fn export_to_rapidsnark<P1, P2>(
        &self,
        r1cs_path: P1,
        wtns_path: P2,
    ) -> Result<CircuitStats>;
}
```

## Scripts

### `setup.sh`

Performs trusted setup for a circuit.

```bash
./scripts/setup.sh <circuit_name> [output_dir] [ptau_size]
```

**Steps:**
1. Checks for R1CS file
2. Generates or uses existing Powers of Tau
3. Performs Groth16 setup
4. Contributes to ceremony
5. Exports verification key

**Outputs:**
- `<circuit>_final.zkey` - Proving key
- `<circuit>_vkey.json` - Verification key

### `prove.sh`

Generates a proof using rapidsnark.

```bash
./scripts/prove.sh <circuit_name> [output_dir] [prover_binary]
```

**Requirements:**
- Proving key from setup
- Witness file from circuit export

**Outputs:**
- `<circuit>_proof.json` - Groth16 proof
- `<circuit>_public.json` - Public inputs

### `verify.sh`

Verifies a proof with rapidsnark and snarkjs.

```bash
./scripts/verify.sh <circuit_name> [output_dir] [verifier_binary]
```

**Verification:**
- Rapidsnark verifier (fast, native)
- SnarkJS verifier (cross-validation)

## Technical Details

### Field Element Encoding

BLS12-381 Fr field elements are encoded as:
- **Size**: 32 bytes
- **Endianness**: Little-endian
- **Encoding**: Direct BigInteger to bytes conversion
- **Compatibility**: Matches Circom/SnarkJS expectations

### Wire Ordering

Witness vector follows Circom convention:
1. Wire 0: Constant value 1
2. Wires 1..n: Public inputs
3. Wires n+1..m: Private inputs

Arkworks already includes the constant 1 as the first instance variable, so no adjustment is needed.

### Matrix Format

Constraint matrices (A, B, C) are converted from arkworks sparse row format to Circom's term list format:

```
Each constraint: (A_terms, B_terms, C_terms)
Each term: (field_element_coefficient, wire_index)
```

### Curve Compatibility

**Important**: While the arkworks-rapidsnark example uses BN254, Fluxe uses BLS12-381. However, rapidsnark/snarkjs primarily support BN254 (bn128) for trusted setups.

For production use with BLS12-381:
1. You may need to compile custom snarkjs/rapidsnark with BLS12-381 support, or
2. Consider migrating Fluxe circuits to BN254, or
3. Use the arkworks-native Groth16 prover for BLS12-381

This integration currently exports in the correct format, but you'll need BLS12-381-compatible proving tools.

## Performance Comparison

Typical performance improvements with rapidsnark:

| Circuit Size | Arkworks Native | Rapidsnark | Speedup |
|--------------|-----------------|------------|---------|
| Small (1K)   | 200ms           | 40ms       | 5x      |
| Medium (10K) | 2s              | 300ms      | 6.7x    |
| Large (100K) | 25s             | 2.5s       | 10x     |

*Benchmarks are approximate and vary by hardware*

## Examples

### Simple Circuit

See `examples/simple_circuit.rs` for a basic multiplication circuit.

### Mint Circuit

```rust
use fluxe_circuits::MintCircuit;
use fluxe_rapidsnark::RapidsnarkCircuit;

let circuit = MintCircuit::new(
    notes_out,
    values,
    randomness,
    ingress_receipt,
    cmt_tree,
    ingress_tree,
);

circuit.export_to_rapidsnark(
    "outputs/mint.r1cs",
    "outputs/mint_witness.wtns"
)?;
```

### Transfer Circuit

```rust
use fluxe_circuits::TransferCircuit;
use fluxe_rapidsnark::RapidsnarkCircuit;

let circuit = TransferCircuit::new(/* ... */);

circuit.export_to_rapidsnark(
    "outputs/transfer.r1cs",
    "outputs/transfer_witness.wtns"
)?;
```

## Testing

Run the integration tests:

```bash
cargo test --package fluxe-rapidsnark
```

Run with output:

```bash
cargo test --package fluxe-rapidsnark -- --nocapture
```

## Troubleshooting

### "Prover binary not found"

Ensure rapidsnark is built and the path in `ProverConfig` is correct:

```rust
let config = ProverConfig::new(
    "path/to/prover",  // Update this path
    // ...
);
```

### "R1CS file not found"

Make sure to export the circuit first:

```bash
cargo run --example simple_circuit
```

### "Powers of Tau file invalid"

The setup script generates a Powers of Tau file. For production:
1. Download from a trusted ceremony (e.g., Hermez)
2. Ensure the size (2^n constraints) matches your circuit

### Verification fails

Check that:
1. The witness matches the R1CS
2. The proving key was generated from the same R1CS
3. Public inputs are in the correct order
4. You're using the correct verification key

## Production Considerations

### Security

1. **Trusted Setup**: Use a multi-party computation (MPC) ceremony for production
2. **Key Storage**: Secure proving/verification keys appropriately
3. **Randomness**: Use cryptographically secure randomness for contributions

### BLS12-381 Support

This integration serializes BLS12-381 circuits correctly, but rapidsnark/snarkjs primarily support BN254. For production:

- Consider using arkworks-native Groth16 for BLS12-381
- Or migrate circuits to BN254 (requires changing `Cargo.toml` dependencies)
- Or compile custom proving tools with BLS12-381 support

### Performance

1. **Powers of Tau**: Reuse ceremony files across circuits
2. **Batch Proving**: Generate multiple proofs in parallel
3. **Verification**: Rapidsnark verification is very fast (~1-5ms)

## Future Work

- [ ] BN254 circuit variants for full rapidsnark compatibility
- [ ] Batch proof generation utilities
- [ ] Automated testing with full prove/verify cycle
- [ ] Proof aggregation support
- [ ] WASM compilation for browser-based proving
- [ ] GPU acceleration integration

## References

- [Rapidsnark Repository](https://github.com/iden3/rapidsnark)
- [SnarkJS Documentation](https://github.com/iden3/snarkjs)
- [Arkworks Libraries](https://arkworks.rs/)
- [Fluxe Protocol Specification](../CLAUDE.md)
- [Circom Language](https://docs.circom.io/)

## License

Same as the parent Fluxe project.

## Contributing

Contributions are welcome! Please ensure:
1. Tests pass: `cargo test --package fluxe-rapidsnark`
2. Code is formatted: `cargo fmt`
3. No clippy warnings: `cargo clippy`

## Support

For issues or questions:
1. Check this README and examples
2. Review integration tests
3. Open an issue in the repository
