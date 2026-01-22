//! FLUXE Proof Aggregation Host Script
//!
//! This script runs on the host machine and:
//! 1. Loads individual Groth16 proofs from arkworks
//! 2. Converts them to gnark format
//! 3. Passes them to the SP1 zkVM guest program
//! 4. Generates a recursive SNARK proving all proofs are valid

use anyhow::{Context, Result};
use fluxe_aggregation_lib::{BatchInput, BatchOutput, ProofEntry, StateRoots, TxType};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::path::PathBuf;
use tracing::{info, warn};

/// The ELF binary of the SP1 guest program
pub const AGGREGATOR_ELF: &[u8] = include_elf!("fluxe-aggregation-program");

/// Arkworks proof conversion utilities
mod arkworks_convert {
    use ark_bn254::{Bn254, Fr as ArkFr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::{Proof, VerifyingKey};

    /// Convert arkworks G1Affine point to gnark big-endian format (64 bytes)
    pub fn g1_to_gnark(point: &G1Affine) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        if point.is_zero() {
            return bytes;
        }

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        // Convert to big-endian
        let x_le = x.into_bigint().to_bytes_le();
        let y_le = y.into_bigint().to_bytes_le();

        // Copy and reverse for big-endian
        bytes[..32].copy_from_slice(&x_le[..32]);
        bytes[..32].reverse();
        bytes[32..64].copy_from_slice(&y_le[..32]);
        bytes[32..64].reverse();

        bytes
    }

    /// Convert arkworks G2Affine point to gnark big-endian format (128 bytes)
    ///
    /// Gnark uses (x.c1, x.c0, y.c1, y.c0) ordering for G2 points
    pub fn g2_to_gnark(point: &G2Affine) -> [u8; 128] {
        let mut bytes = [0u8; 128];

        if point.is_zero() {
            return bytes;
        }

        let x = point.x().unwrap();
        let y = point.y().unwrap();

        // Get components
        let x_c0_le = x.c0.into_bigint().to_bytes_le();
        let x_c1_le = x.c1.into_bigint().to_bytes_le();
        let y_c0_le = y.c0.into_bigint().to_bytes_le();
        let y_c1_le = y.c1.into_bigint().to_bytes_le();

        // Gnark ordering: x.c1, x.c0, y.c1, y.c0 (all big-endian)
        bytes[0..32].copy_from_slice(&x_c1_le[..32]);
        bytes[0..32].reverse();
        bytes[32..64].copy_from_slice(&x_c0_le[..32]);
        bytes[32..64].reverse();
        bytes[64..96].copy_from_slice(&y_c1_le[..32]);
        bytes[64..96].reverse();
        bytes[96..128].copy_from_slice(&y_c0_le[..32]);
        bytes[96..128].reverse();

        bytes
    }

    /// Convert arkworks Fr to big-endian bytes (32 bytes)
    pub fn fr_to_be(fr: &ArkFr) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        let le_bytes = fr.into_bigint().to_bytes_le();
        bytes.copy_from_slice(&le_bytes[..32]);
        bytes.reverse();
        bytes
    }

    /// Convert arkworks Groth16 proof to gnark format (256 bytes)
    ///
    /// Layout: A (64 bytes) || B (128 bytes) || C (64 bytes)
    pub fn proof_to_gnark(proof: &Proof<Bn254>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);

        bytes.extend_from_slice(&g1_to_gnark(&proof.a));
        bytes.extend_from_slice(&g2_to_gnark(&proof.b));
        bytes.extend_from_slice(&g1_to_gnark(&proof.c));

        bytes
    }

    /// Convert arkworks verifying key to gnark format
    ///
    /// Layout:
    /// - alpha (64 bytes, G1)
    /// - beta (128 bytes, G2)
    /// - gamma (128 bytes, G2)
    /// - delta (128 bytes, G2)
    /// - ic length (4 bytes, u32 LE)
    /// - ic points (64 bytes each, G1)
    pub fn vk_to_gnark(vk: &VerifyingKey<Bn254>) -> Vec<u8> {
        let ic_len = vk.gamma_abc_g1.len();
        let total_len = 64 + 128 + 128 + 128 + 4 + (ic_len * 64);
        let mut bytes = Vec::with_capacity(total_len);

        bytes.extend_from_slice(&g1_to_gnark(&vk.alpha_g1));
        bytes.extend_from_slice(&g2_to_gnark(&vk.beta_g2));
        bytes.extend_from_slice(&g2_to_gnark(&vk.gamma_g2));
        bytes.extend_from_slice(&g2_to_gnark(&vk.delta_g2));

        // IC length as u32 LE
        bytes.extend_from_slice(&(ic_len as u32).to_le_bytes());

        // IC points
        for ic in &vk.gamma_abc_g1 {
            bytes.extend_from_slice(&g1_to_gnark(ic));
        }

        bytes
    }

    /// Convert public inputs to big-endian bytes
    pub fn public_inputs_to_bytes(inputs: &[ArkFr]) -> Vec<[u8; 32]> {
        inputs.iter().map(fr_to_be).collect()
    }
}

/// A batch of FLUXE proofs to aggregate
#[derive(Debug, Clone)]
pub struct ProofBatch {
    pub batch_id: u64,
    pub chain_id: u64,
    pub timestamp: u64,
    pub old_roots: StateRoots,
    pub new_roots: StateRoots,
    pub proofs: Vec<FluxeProof>,
}

/// A single FLUXE proof with its metadata
#[derive(Debug, Clone)]
pub struct FluxeProof {
    pub tx_type: TxType,
    pub proof_bytes: Vec<u8>,
    pub vk_bytes: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
}

/// The FLUXE proof aggregator
pub struct Aggregator {
    client: ProverClient,
}

impl Aggregator {
    /// Create a new aggregator
    pub fn new() -> Self {
        Self {
            client: ProverClient::from_env(),
        }
    }

    /// Aggregate a batch of proofs
    pub fn aggregate(&self, batch: ProofBatch) -> Result<AggregatedProof> {
        info!(
            batch_id = batch.batch_id,
            chain_id = batch.chain_id,
            proof_count = batch.proofs.len(),
            "Starting proof aggregation"
        );

        // Build the batch input for the guest program
        let mut verifying_keys = Vec::new();
        let mut proofs = Vec::new();

        for fluxe_proof in &batch.proofs {
            verifying_keys.push(fluxe_proof.vk_bytes.clone());

            proofs.push(ProofEntry {
                tx_type: fluxe_proof.tx_type.clone(),
                proof_bytes: fluxe_proof.proof_bytes.clone(),
                public_inputs: fluxe_proof.public_inputs.clone(),
            });
        }

        let batch_input = BatchInput {
            batch_id: batch.batch_id,
            chain_id: batch.chain_id,
            timestamp: batch.timestamp,
            old_roots: batch.old_roots.clone(),
            new_roots: batch.new_roots.clone(),
            verifying_keys,
            proofs,
        };

        // Prepare SP1 stdin
        let mut stdin = SP1Stdin::new();
        stdin.write(&batch_input);

        // Execute and prove
        info!("Executing guest program...");
        let (public_values, report) = self
            .client
            .execute(AGGREGATOR_ELF, &stdin)
            .run()
            .context("Failed to execute guest program")?;

        info!(
            cycles = report.total_instruction_count(),
            "Guest execution complete"
        );

        // Decode the output
        let output: BatchOutput = bincode::deserialize(public_values.as_slice())
            .context("Failed to deserialize batch output")?;

        info!(
            verified_count = output.proof_count,
            "All proofs verified successfully"
        );

        // Generate the proof
        info!("Generating SP1 proof...");
        let proof = self
            .client
            .prove(AGGREGATOR_ELF, &stdin)
            .run()
            .context("Failed to generate SP1 proof")?;

        info!("Proof generation complete");

        Ok(AggregatedProof {
            batch_id: batch.batch_id,
            chain_id: batch.chain_id,
            proof_count: output.proof_count,
            old_roots_hash: batch.old_roots.hash(),
            new_roots_hash: batch.new_roots.hash(),
            sp1_proof: proof.bytes(),
            public_values: public_values.to_vec(),
        })
    }

    /// Execute the guest program without generating a proof (for testing)
    pub fn execute_only(&self, batch: ProofBatch) -> Result<BatchOutput> {
        info!(
            batch_id = batch.batch_id,
            proof_count = batch.proofs.len(),
            "Executing guest program (no proof)"
        );

        // Build the batch input
        let mut verifying_keys = Vec::new();
        let mut proofs = Vec::new();

        for fluxe_proof in &batch.proofs {
            verifying_keys.push(fluxe_proof.vk_bytes.clone());

            proofs.push(ProofEntry {
                tx_type: fluxe_proof.tx_type.clone(),
                proof_bytes: fluxe_proof.proof_bytes.clone(),
                public_inputs: fluxe_proof.public_inputs.clone(),
            });
        }

        let batch_input = BatchInput {
            batch_id: batch.batch_id,
            chain_id: batch.chain_id,
            timestamp: batch.timestamp,
            old_roots: batch.old_roots.clone(),
            new_roots: batch.new_roots.clone(),
            verifying_keys,
            proofs,
        };

        let mut stdin = SP1Stdin::new();
        stdin.write(&batch_input);

        let (public_values, report) = self
            .client
            .execute(AGGREGATOR_ELF, &stdin)
            .run()
            .context("Failed to execute guest program")?;

        info!(
            cycles = report.total_instruction_count(),
            "Execution complete"
        );

        let output: BatchOutput = bincode::deserialize(public_values.as_slice())
            .context("Failed to deserialize batch output")?;

        Ok(output)
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of proof aggregation
#[derive(Debug, Clone)]
pub struct AggregatedProof {
    pub batch_id: u64,
    pub chain_id: u64,
    pub proof_count: u32,
    pub old_roots_hash: [u8; 32],
    pub new_roots_hash: [u8; 32],
    pub sp1_proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

impl AggregatedProof {
    /// Save the proof to a file
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let json = serde_json::json!({
            "batch_id": self.batch_id,
            "chain_id": self.chain_id,
            "proof_count": self.proof_count,
            "old_roots_hash": hex::encode(&self.old_roots_hash),
            "new_roots_hash": hex::encode(&self.new_roots_hash),
            "sp1_proof": hex::encode(&self.sp1_proof),
            "public_values": hex::encode(&self.public_values),
        });

        std::fs::write(path, serde_json::to_string_pretty(&json)?)
            .context("Failed to write proof file")?;

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    info!("FLUXE Proof Aggregator v0.1.0");

    // For now, just demonstrate that the system works
    // In production, this would:
    // 1. Load proofs from a file or receive them via RPC
    // 2. Aggregate them
    // 3. Submit the aggregated proof to L1

    // Example usage (would be replaced with actual proof loading)
    warn!("No proofs provided - running in demo mode");

    // Create an empty batch for demonstration
    let batch = ProofBatch {
        batch_id: 1,
        chain_id: 1, // Ethereum mainnet
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        old_roots: StateRoots::default(),
        new_roots: StateRoots::default(),
        proofs: vec![], // No proofs in demo mode
    };

    if batch.proofs.is_empty() {
        info!("No proofs to aggregate. In production, proofs would be loaded from:");
        info!("  - RPC endpoint: POST /aggregate");
        info!("  - File: --input <proofs.json>");
        info!("  - Directory: --batch-dir <./pending_batches/>");
        return Ok(());
    }

    // Aggregate
    let aggregator = Aggregator::new();
    let result = aggregator.aggregate(batch)?;

    info!(
        batch_id = result.batch_id,
        proof_count = result.proof_count,
        proof_size = result.sp1_proof.len(),
        "Aggregation complete"
    );

    // Save the proof
    let output_path = PathBuf::from(format!("aggregated_proof_{}.json", result.batch_id));
    result.save(&output_path)?;
    info!(path = ?output_path, "Proof saved");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{Bn254, Fr as ArkFr};
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Simple cubic circuit for testing: x^3 + x + 5 = output
    #[derive(Clone)]
    struct CubicCircuit {
        x: Option<ArkFr>,
    }

    impl ConstraintSynthesizer<ArkFr> for CubicCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ArkFr>,
        ) -> Result<(), SynthesisError> {
            use ark_relations::r1cs::Variable;
            use ark_ff::Field;

            let x = cs.new_witness_variable(|| {
                self.x.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let x_squared = cs.new_witness_variable(|| {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val)
            })?;

            let x_cubed = cs.new_witness_variable(|| {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val * x_val)
            })?;

            // Constraint: x * x = x_squared
            cs.enforce_constraint(
                ark_relations::lc!() + x,
                ark_relations::lc!() + x,
                ark_relations::lc!() + x_squared,
            )?;

            // Constraint: x * x_squared = x_cubed
            cs.enforce_constraint(
                ark_relations::lc!() + x,
                ark_relations::lc!() + x_squared,
                ark_relations::lc!() + x_cubed,
            )?;

            // Constraint: x_cubed + x + 5 = output (public)
            let output = cs.new_input_variable(|| {
                let x_val = self.x.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(x_val * x_val * x_val + x_val + ArkFr::from(5u64))
            })?;

            cs.enforce_constraint(
                ark_relations::lc!() + x_cubed + x + (ArkFr::from(5u64), Variable::One),
                ark_relations::lc!() + Variable::One,
                ark_relations::lc!() + output,
            )?;

            Ok(())
        }
    }

    #[test]
    #[ignore] // Requires SP1 toolchain
    fn test_aggregator_with_single_proof() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);

        // Generate a test proof
        let circuit = CubicCircuit { x: Some(ArkFr::from(3u64)) };
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            CubicCircuit { x: None },
            &mut rng,
        ).unwrap();

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();
        let x = ArkFr::from(3u64);
        let output = x * x * x + x + ArkFr::from(5u64);

        // Convert to FLUXE format
        let proof_bytes = arkworks_convert::proof_to_gnark(&proof);
        let vk_bytes = arkworks_convert::vk_to_gnark(&vk);
        let public_inputs = arkworks_convert::public_inputs_to_bytes(&[output]);

        let fluxe_proof = FluxeProof {
            tx_type: TxType::Transfer,
            proof_bytes,
            vk_bytes,
            public_inputs,
        };

        let batch = ProofBatch {
            batch_id: 1,
            chain_id: 1,
            timestamp: 1234567890,
            old_roots: StateRoots::default(),
            new_roots: StateRoots::default(),
            proofs: vec![fluxe_proof],
        };

        let aggregator = Aggregator::new();
        let output = aggregator.execute_only(batch).unwrap();

        assert_eq!(output.proof_count, 1);
        assert_eq!(output.batch_id, 1);
    }
}
