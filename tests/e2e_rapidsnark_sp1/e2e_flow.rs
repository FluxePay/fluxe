//! End-to-End Flow: Deposit → Transfer → Withdrawal with Rapidsnark + SP1
//!
//! This module orchestrates the complete proof generation and verification pipeline:
//! 1. Generate witness data for each circuit
//! 2. Generate proofs using rapidsnark
//! 3. Aggregate and VERIFY proofs using SP1 with real BN254 pairing verification
//!
//! The SP1 aggregation uses fluxe-aggregation-lib which implements Groth16 verification
//! using the bn crate for BN254 pairing operations (~10M cycles per proof in SP1).

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use ark_bn254::Fr as F;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use fluxe_circuits::{MintCircuit, TransferCircuit, BurnCircuit};
use fluxe_rapidsnark::{ProverConfig, RapidsnarkProver, export_to_circom_files};

// Import real Groth16 verification from fluxe-aggregation-lib
use fluxe_aggregation_lib::groth16::{
    Groth16Proof as GnarkProof, Groth16VerifyingKey as GnarkVK,
    verify as verify_groth16_bn, parse_fr_be, Groth16Error,
};

use crate::{
    TestConfig, CircuitType, CircuitPaths, SetupManager, ProofResult, BatchResult,
    circuit_setup,
    mock_sequencer::{
        MockSequencer, DepositResult, TransferResult, WithdrawalResult,
        CHAIN_ETHEREUM, CHAIN_SOLANA,
    },
};

// ============================================================================
// snarkjs to gnark format conversion functions
// ============================================================================

/// Convert a decimal string to a 32-byte big-endian field element
fn decimal_to_be32(s: &str) -> Result<[u8; 32], String> {
    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or_else(|| format!("Invalid decimal string: {}", s))?;
    let bytes = n.to_bytes_be();

    let mut result = [0u8; 32];
    if bytes.len() > 32 {
        return Err(format!("Number too large: {} bytes", bytes.len()));
    }
    // Right-align in the 32-byte array
    result[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(result)
}

/// Convert snarkjs G1 point [x, y, z] to gnark bytes (64 bytes)
/// snarkjs uses projective coordinates where z=1 for affine
fn snarkjs_g1_to_gnark(point: &[String]) -> Result<[u8; 64], String> {
    if point.len() != 3 {
        return Err(format!("G1 point must have 3 coordinates, got {}", point.len()));
    }
    // Check z coordinate - must be "1" for valid affine point
    if point[2] != "1" && point[2] != "0" {
        return Err(format!("G1 point has non-trivial z: {}", point[2]));
    }
    // Handle point at infinity (z=0)
    if point[2] == "0" {
        return Ok([0u8; 64]);
    }

    let x = decimal_to_be32(&point[0])?;
    let y = decimal_to_be32(&point[1])?;

    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&x);
    result[32..64].copy_from_slice(&y);
    Ok(result)
}

/// Convert snarkjs G2 point [[x0, x1], [y0, y1], [z0, z1]] to gnark bytes (128 bytes)
/// snarkjs uses Fq2 = c0 + c1*u, gnark format is: x.c1 || x.c0 || y.c1 || y.c0
fn snarkjs_g2_to_gnark(point: &[Vec<String>]) -> Result<[u8; 128], String> {
    if point.len() != 3 {
        return Err(format!("G2 point must have 3 coordinate pairs, got {}", point.len()));
    }
    for (i, pair) in point.iter().enumerate() {
        if pair.len() != 2 {
            return Err(format!("G2 coordinate {} must be Fq2, got {} elements", i, pair.len()));
        }
    }
    // Handle point at infinity
    if point[2][0] == "0" && point[2][1] == "0" {
        return Ok([0u8; 128]);
    }

    // snarkjs format: [[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]
    // gnark format: x.c1 || x.c0 || y.c1 || y.c0
    let x_c0 = decimal_to_be32(&point[0][0])?;
    let x_c1 = decimal_to_be32(&point[0][1])?;
    let y_c0 = decimal_to_be32(&point[1][0])?;
    let y_c1 = decimal_to_be32(&point[1][1])?;

    let mut result = [0u8; 128];
    result[0..32].copy_from_slice(&x_c1);
    result[32..64].copy_from_slice(&x_c0);
    result[64..96].copy_from_slice(&y_c1);
    result[96..128].copy_from_slice(&y_c0);
    Ok(result)
}

/// Convert snarkjs proof JSON to gnark binary format (256 bytes)
fn snarkjs_proof_to_gnark(proof: &SnarkjsProof) -> Result<Vec<u8>, String> {
    let a = snarkjs_g1_to_gnark(&proof.pi_a)?;
    let b = snarkjs_g2_to_gnark(&proof.pi_b)?;
    let c = snarkjs_g1_to_gnark(&proof.pi_c)?;

    let mut result = Vec::with_capacity(256);
    result.extend_from_slice(&a);
    result.extend_from_slice(&b);
    result.extend_from_slice(&c);
    Ok(result)
}

/// snarkjs verification key structure
#[derive(Debug, Clone, Deserialize)]
pub struct SnarkjsVK {
    pub protocol: String,
    pub curve: String,
    #[serde(rename = "nPublic")]
    pub n_public: usize,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

/// Convert snarkjs VK JSON to gnark binary format
/// Format: alpha (64) || beta (128) || gamma (128) || delta (128) || ic_len (4) || ic[...] (64 each)
fn snarkjs_vk_to_gnark(vk: &SnarkjsVK) -> Result<Vec<u8>, String> {
    let alpha = snarkjs_g1_to_gnark(&vk.vk_alpha_1)?;
    let beta = snarkjs_g2_to_gnark(&vk.vk_beta_2)?;
    let gamma = snarkjs_g2_to_gnark(&vk.vk_gamma_2)?;
    let delta = snarkjs_g2_to_gnark(&vk.vk_delta_2)?;

    let ic_len = vk.ic.len();
    let mut result = Vec::with_capacity(448 + 4 + ic_len * 64);

    result.extend_from_slice(&alpha);
    result.extend_from_slice(&beta);
    result.extend_from_slice(&gamma);
    result.extend_from_slice(&delta);

    // IC length as big-endian u32
    result.extend_from_slice(&(ic_len as u32).to_be_bytes());

    // IC points
    for ic_point in &vk.ic {
        let ic = snarkjs_g1_to_gnark(ic_point)?;
        result.extend_from_slice(&ic);
    }

    Ok(result)
}

/// Convert public inputs from snarkjs format (decimal strings) to gnark format ([u8; 32] each)
fn snarkjs_public_inputs_to_gnark(inputs: &[String]) -> Result<Vec<[u8; 32]>, String> {
    inputs.iter().map(|s| decimal_to_be32(s)).collect()
}

/// Export a snarkjs VK JSON file to gnark binary format
/// This is used to create the embedded VK files for the SP1 program
pub fn export_vk_to_gnark_binary(json_path: &std::path::Path, binary_path: &std::path::Path) -> Result<(), String> {
    let json_content = fs::read_to_string(json_path)
        .map_err(|e| format!("Failed to read VK JSON: {}", e))?;

    let snarkjs_vk: SnarkjsVK = serde_json::from_str(&json_content)
        .map_err(|e| format!("Failed to parse VK JSON: {}", e))?;

    let gnark_bytes = snarkjs_vk_to_gnark(&snarkjs_vk)?;

    fs::write(binary_path, &gnark_bytes)
        .map_err(|e| format!("Failed to write gnark VK: {}", e))?;

    println!("[VK Export] {} -> {} ({} bytes)",
        json_path.display(),
        binary_path.display(),
        gnark_bytes.len()
    );

    Ok(())
}

// ============================================================================
// Proof structures
// ============================================================================

/// snarkjs Groth16 proof structure (JSON format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    pub protocol: String,
    #[serde(default)]
    pub curve: String,
}

/// Generate rapidsnark proof from paths
pub fn generate_rapidsnark_proof(
    config: &TestConfig,
    paths: &CircuitPaths,
) -> Result<ProofResult, String> {
    let start = Instant::now();

    // Create prover config
    let prover_config = ProverConfig::new(
        &config.prover_binary,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    );

    // Create prover and generate proof
    let prover = RapidsnarkProver::new(prover_config);
    let output = prover.prove().map_err(|e| format!("Proof generation failed: {}", e))?;

    let proving_time = start.elapsed();

    // Verify the proof using snarkjs
    let verify_result = verify_snarkjs_proof(paths)?;
    if !verify_result {
        return Err("Proof verification failed".to_string());
    }

    Ok(ProofResult {
        circuit_type: paths.circuit_type,
        proof_json: output.proof_json().map_err(|e| e.to_string())?,
        public_inputs_json: output.public_json().map_err(|e| e.to_string())?,
        proving_time_ms: proving_time.as_millis() as u64,
    })
}

/// Verify proof using snarkjs
pub fn verify_snarkjs_proof(paths: &CircuitPaths) -> Result<bool, String> {
    let output = Command::new("snarkjs")
        .args([
            "groth16",
            "verify",
            paths.verification_key.to_str().unwrap(),
            paths.public_inputs.to_str().unwrap(),
            paths.proof.to_str().unwrap(),
        ])
        .output()
        .map_err(|e| format!("Failed to run snarkjs verify: {}", e))?;

    // snarkjs verify outputs "OK!" on success
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("OK!") || output.status.success())
}

/// Export circuit and witness for a deposit
pub fn export_mint_for_deposit(
    paths: &CircuitPaths,
    deposit: &DepositResult,
) -> Result<(), String> {
    use fluxe_core::merkle::IncrementalTree;

    // Create new trees for the circuit
    let mut cmt_tree = IncrementalTree::new(16);
    let mut ingress_tree = IncrementalTree::new(16);

    let circuit = MintCircuit::new(
        vec![deposit.note.clone()],
        vec![deposit.note_record.value],
        vec![deposit.note_record.randomness],
        deposit.ingress.clone(),
        &mut cmt_tree,
        &mut ingress_tree,
    );

    // Export to R1CS and witness files
    export_to_circom_files(circuit, &paths.r1cs, &paths.witness)
        .map_err(|e| format!("Export failed: {}", e))?;

    Ok(())
}

/// Export circuit and witness for a transfer
pub fn export_transfer_for_transfer(
    paths: &CircuitPaths,
    transfer: &TransferResult,
) -> Result<(), String> {
    use fluxe_core::types::Amount;

    let circuit = TransferCircuit::new_with_nft_witnesses(
        vec![transfer.input_note.clone()],
        vec![transfer.input_record.value],
        vec![transfer.input_record.randomness],
        vec![transfer.output_note.clone()],
        vec![transfer.output_record.value],
        vec![transfer.output_record.randomness],
        vec![transfer.input_record.nk],
        vec![transfer.input_record.owner_sk],
        vec![transfer.input_record.owner_pk],
        vec![transfer.cm_path.clone()],
        vec![Some(transfer.nf_nm.clone())],
        vec![transfer.nf_insert.clone()],
        vec![Some(transfer.sanctions_nm_in.clone())],
        vec![Some(transfer.sanctions_nm_out.clone())],
        vec![],  // source_pool_policies
        vec![],  // dest_pool_policies
        vec![],  // pool_policy_paths
        vec![transfer.cmt_append.clone()],
        transfer.cmt_root_old,
        transfer.cmt_root_new,
        transfer.nft_root_old,
        transfer.nft_root_new,
        transfer.sanctions_root,
        transfer.pool_rules_root,
        transfer.fee,
    );

    export_to_circom_files(circuit, &paths.r1cs, &paths.witness)
        .map_err(|e| format!("Export failed: {}", e))?;

    Ok(())
}

/// Export circuit and witness for a withdrawal
pub fn export_burn_for_withdrawal(
    paths: &CircuitPaths,
    withdrawal: &WithdrawalResult,
) -> Result<(), String> {
    let circuit = BurnCircuit::new(
        withdrawal.input_note.clone(),
        withdrawal.input_record.value,
        withdrawal.input_record.randomness,
        withdrawal.input_record.nk,
        withdrawal.input_record.owner_sk,
        withdrawal.input_record.owner_pk.0,
        withdrawal.input_record.owner_pk.1,
        withdrawal.cm_path.clone(),
        Some(withdrawal.nf_nm.clone()),
        Some(withdrawal.nf_insert.clone()),
        withdrawal.exit_receipt.clone(),
        withdrawal.exit_append.clone(),
        withdrawal.cmt_root,
        withdrawal.nft_root_old,
        withdrawal.nft_root_new,
        withdrawal.exit_root_old,
        withdrawal.exit_root_new,
    );

    export_to_circom_files(circuit, &paths.r1cs, &paths.witness)
        .map_err(|e| format!("Export failed: {}", e))?;

    Ok(())
}

/// SP1 batch aggregation input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1BatchInput {
    pub batch_id: u64,
    pub proofs: Vec<SP1ProofInput>,
    pub old_roots: Vec<String>,
    pub new_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SP1ProofInput {
    pub circuit_type: String,
    pub proof: Value,
    pub public_inputs: Vec<String>,
}

/// Proof with binary VK for SP1 aggregation
#[derive(Debug, Clone)]
pub struct ProofWithVK {
    pub proof_result: ProofResult,
    /// VK in gnark binary format (same as embedded in SP1 program)
    pub vk_bytes: Vec<u8>,
}

/// Execute SP1 aggregation with REAL Groth16 proof verification
///
/// This performs actual BN254 pairing-based verification using the bn crate,
/// simulating what SP1 zkVM would do. Each proof verification costs ~10M cycles
/// when running in SP1 due to pairing precompile costs.
///
/// VKs are loaded from gnark binary format files (same format as embedded in SP1).
///
/// Steps:
/// 1. Convert each proof from snarkjs JSON to gnark binary format
/// 2. Load pre-converted VK from binary file (mirrors SP1's embedded VKs)
/// 3. Verify each proof using BN254 pairings (the bn crate)
/// 4. Compute aggregated state hash
pub fn execute_sp1_aggregation(
    proofs_with_vks: &[ProofWithVK],
    old_roots_hash: [u8; 32],
    new_roots_hash: [u8; 32],
    batch_id: u64,
) -> Result<BatchResult, String> {
    let start = Instant::now();

    println!("[SP1] Starting aggregation for batch {}...", batch_id);
    println!("[SP1] Aggregating and VERIFYING {} proofs with real BN254 pairings", proofs_with_vks.len());

    // Estimated SP1 cycle costs (realistic for BN254 pairings):
    // - Pairing verification: ~10M cycles per proof (4 pairings)
    // - Public input processing: ~100k cycles per input
    // - State hash computation: ~100k cycles
    const PAIRING_CYCLES: u64 = 10_000_000; // ~10M cycles for Groth16 verification
    const INPUT_CYCLES_PER: u64 = 100_000;  // ~100k cycles per public input MSM
    const STATE_CYCLES: u64 = 100_000;      // ~100k cycles for state hash

    let mut total_cycles: u64 = 0;
    let mut verified_count = 0u32;

    for proof_with_vk in proofs_with_vks {
        let proof = &proof_with_vk.proof_result;
        let verify_start = Instant::now();

        // Parse snarkjs proof JSON
        let snarkjs_proof: SnarkjsProof = serde_json::from_str(&proof.proof_json)
            .map_err(|e| format!("Invalid proof JSON for {:?}: {}", proof.circuit_type, e))?;

        // Parse public inputs
        let public_inputs: Vec<String> = serde_json::from_str(&proof.public_inputs_json)
            .map_err(|e| format!("Invalid public inputs for {:?}: {}", proof.circuit_type, e))?;

        // Convert proof to gnark binary format
        let gnark_proof_bytes = snarkjs_proof_to_gnark(&snarkjs_proof)
            .map_err(|e| format!("Proof conversion failed for {:?}: {}", proof.circuit_type, e))?;

        // Convert public inputs to gnark format
        let gnark_inputs = snarkjs_public_inputs_to_gnark(&public_inputs)
            .map_err(|e| format!("Input conversion failed for {:?}: {}", proof.circuit_type, e))?;

        // Parse VK from binary format (same as embedded in SP1)
        let vk = GnarkVK::from_bytes(&proof_with_vk.vk_bytes)
            .map_err(|e| format!("VK parsing failed for {:?}: {:?}", proof.circuit_type, e))?;

        // Parse proof
        let parsed_proof = GnarkProof::from_bytes(&gnark_proof_bytes)
            .map_err(|e| format!("Proof parsing failed for {:?}: {:?}", proof.circuit_type, e))?;

        // Convert inputs to bn::Fr
        let bn_inputs: Vec<bn::Fr> = gnark_inputs
            .iter()
            .map(|bytes| parse_fr_be(bytes))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Fr parsing failed for {:?}: {:?}", proof.circuit_type, e))?;

        // PERFORM ACTUAL GROTH16 VERIFICATION using BN254 pairings
        let is_valid = verify_groth16_bn(&vk, &parsed_proof, &bn_inputs)
            .map_err(|e| format!("Verification error for {:?}: {:?}", proof.circuit_type, e))?;

        let verify_time = verify_start.elapsed();

        if !is_valid {
            return Err(format!(
                "Proof verification FAILED for {:?}! Invalid proof.",
                proof.circuit_type
            ));
        }

        verified_count += 1;

        // Calculate cycle estimate for this proof
        let proof_cycles = PAIRING_CYCLES + (public_inputs.len() as u64) * INPUT_CYCLES_PER;
        total_cycles += proof_cycles;

        println!(
            "[SP1] ✓ Verified {:?} proof: {} public inputs, ~{}M cycles, verification took {:?}",
            proof.circuit_type,
            public_inputs.len(),
            proof_cycles / 1_000_000,
            verify_time
        );
    }

    // Add state transition verification cycles
    total_cycles += STATE_CYCLES;

    let execution_time = start.elapsed();

    println!(
        "[SP1] Aggregation complete: {} proofs verified, ~{}M total cycles in {:?}",
        verified_count,
        total_cycles / 1_000_000,
        execution_time
    );

    Ok(BatchResult {
        batch_id,
        proof_count: verified_count,
        old_roots_hash,
        new_roots_hash,
        execution_cycles: total_cycles,
        execution_time_ms: execution_time.as_millis() as u64,
    })
}

/// Execute SP1 aggregation by loading VKs from binary files
/// This mirrors how the SP1 program uses embedded VKs
pub fn execute_sp1_aggregation_with_vk_paths(
    proofs: &[ProofResult],
    vk_bin_paths: &HashMap<CircuitType, PathBuf>,
    old_roots_hash: [u8; 32],
    new_roots_hash: [u8; 32],
    batch_id: u64,
) -> Result<BatchResult, String> {
    let proofs_with_vks: Vec<ProofWithVK> = proofs
        .iter()
        .map(|proof| {
            let vk_path = vk_bin_paths
                .get(&proof.circuit_type)
                .ok_or_else(|| format!("Missing binary VK path for {:?}", proof.circuit_type))?;
            let vk_bytes = fs::read(vk_path)
                .map_err(|e| format!("Failed to read binary VK for {:?}: {}", proof.circuit_type, e))?;
            Ok(ProofWithVK {
                proof_result: proof.clone(),
                vk_bytes,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    execute_sp1_aggregation(&proofs_with_vks, old_roots_hash, new_roots_hash, batch_id)
}

/// Full E2E test orchestrator
pub struct E2ETestRunner {
    pub config: TestConfig,
    pub setup_manager: SetupManager,
    pub sequencer: MockSequencer,
    pub proofs: Vec<ProofResult>,
}

impl E2ETestRunner {
    pub fn new() -> Self {
        let config = TestConfig::new();
        let setup_manager = SetupManager::new(config.clone());
        let sequencer = MockSequencer::new(16);

        Self {
            config,
            setup_manager,
            sequencer,
            proofs: Vec::new(),
        }
    }

    /// Setup all circuits (R1CS + proving keys)
    pub fn setup(&mut self) -> Result<(), String> {
        println!("\n=== SETUP PHASE ===\n");
        circuit_setup::setup_all_circuits(&mut self.setup_manager)
    }

    /// Execute full E2E flow
    pub fn run_e2e_flow(&mut self) -> Result<BatchResult, String> {
        println!("\n=== E2E FLOW: Deposit → Transfer → Withdrawal ===\n");

        // Get initial state
        let initial_roots = self.sequencer.get_roots();
        let old_roots_hash = initial_roots.hash();

        // Step 1: Deposit on Ethereum
        println!("\n--- Step 1: Deposit 1000 USDC on Ethereum ---\n");
        let deposit = self.execute_deposit()?;

        // Step 2: Transfer within FLUXE
        println!("\n--- Step 2: Transfer 900 USDC (100 fee) ---\n");
        let transfer = self.execute_transfer(
            deposit.note.commitment(),
            900,
            100,
        )?;

        // Step 3: Withdraw to Solana
        println!("\n--- Step 3: Withdraw 900 USDC to Solana ---\n");
        let _withdrawal = self.execute_withdrawal(
            transfer.output_note.commitment(),
            CHAIN_SOLANA,
            900,
        )?;

        // Get final state
        let final_roots = self.sequencer.get_roots();
        let new_roots_hash = final_roots.hash();

        // Verify supply invariant
        self.sequencer.verify_supply_invariant()?;

        // Finalize batch
        let batch_id = self.sequencer.finalize_batch();

        // Step 4: SP1 Aggregation with REAL Groth16 verification
        println!("\n--- Step 4: SP1 Proof Aggregation (Real BN254 Pairing Verification) ---\n");

        // Build binary VK paths map (same format as embedded in SP1 program)
        let mut vk_bin_paths = HashMap::new();
        for ct in CircuitType::all() {
            if let Some(paths) = self.setup_manager.get_paths(ct) {
                vk_bin_paths.insert(ct, paths.verification_key_bin.clone());
            }
        }

        let batch_result = execute_sp1_aggregation_with_vk_paths(
            &self.proofs,
            &vk_bin_paths,
            old_roots_hash,
            new_roots_hash,
            batch_id,
        )?;

        // Print summary
        self.print_summary(&batch_result);

        Ok(batch_result)
    }

    /// Execute deposit and generate proof
    fn execute_deposit(&mut self) -> Result<DepositResult, String> {
        let recipient = F::from(12345u64);

        // Create deposit in sequencer
        let deposit = self.sequencer.create_deposit(
            CHAIN_ETHEREUM,
            1, // USDC
            1000,
            recipient,
        )?;

        println!("[Deposit] Note commitment: {:?}", deposit.note.commitment());
        println!("[Deposit] Ingress hash: {:?}", deposit.ingress.hash());

        // Generate proof if setup is complete
        if self.setup_manager.is_setup_complete(CircuitType::Mint) {
            let paths = self.setup_manager.get_paths(CircuitType::Mint).unwrap().clone();

            // Export circuit and witness for this specific deposit
            export_mint_for_deposit(&paths, &deposit)?;
            println!("[Deposit] Circuit exported to R1CS and witness");

            // Generate proof
            let proof = generate_rapidsnark_proof(&self.config, &paths)?;
            println!(
                "[Deposit] Proof generated in {} ms",
                proof.proving_time_ms
            );
            self.proofs.push(proof);
        } else {
            println!("[Deposit] Skipping proof generation (setup not complete)");
        }

        Ok(deposit)
    }

    /// Execute transfer and generate proof
    fn execute_transfer(
        &mut self,
        input_cm: F,
        output_value: u64,
        fee: u64,
    ) -> Result<TransferResult, String> {
        let recipient = F::from(67890u64);

        // Create transfer in sequencer
        let transfer = self.sequencer.create_transfer(
            input_cm,
            output_value,
            recipient,
            fee,
        )?;

        println!("[Transfer] Input nullifier: {:?}", transfer.input_note.nullifier(&transfer.input_record.nk));
        println!("[Transfer] Output commitment: {:?}", transfer.output_note.commitment());
        println!("[Transfer] Fee: {} base units", fee);

        // Generate proof if setup is complete
        if self.setup_manager.is_setup_complete(CircuitType::Transfer) {
            let paths = self.setup_manager.get_paths(CircuitType::Transfer).unwrap().clone();

            // Export circuit and witness for this specific transfer
            export_transfer_for_transfer(&paths, &transfer)?;
            println!("[Transfer] Circuit exported to R1CS and witness");

            // Generate proof
            let proof = generate_rapidsnark_proof(&self.config, &paths)?;
            println!(
                "[Transfer] Proof generated in {} ms",
                proof.proving_time_ms
            );
            self.proofs.push(proof);
        } else {
            println!("[Transfer] Skipping proof generation (setup not complete)");
        }

        Ok(transfer)
    }

    /// Execute withdrawal and generate proof
    fn execute_withdrawal(
        &mut self,
        input_cm: F,
        destination_chain: u32,
        amount: u64,
    ) -> Result<WithdrawalResult, String> {
        // Create withdrawal in sequencer
        let withdrawal = self.sequencer.create_withdrawal(
            input_cm,
            destination_chain,
            amount,
        )?;

        println!("[Withdrawal] Exit receipt hash: {:?}", withdrawal.exit_receipt.hash());
        println!("[Withdrawal] Destination chain: {}", destination_chain);
        println!("[Withdrawal] Amount: {} base units", amount);

        // Generate proof if setup is complete
        if self.setup_manager.is_setup_complete(CircuitType::Burn) {
            let paths = self.setup_manager.get_paths(CircuitType::Burn).unwrap().clone();

            // Export circuit and witness for this specific withdrawal
            export_burn_for_withdrawal(&paths, &withdrawal)?;
            println!("[Withdrawal] Circuit exported to R1CS and witness");

            // Generate proof
            let proof = generate_rapidsnark_proof(&self.config, &paths)?;
            println!(
                "[Withdrawal] Proof generated in {} ms",
                proof.proving_time_ms
            );
            self.proofs.push(proof);
        } else {
            println!("[Withdrawal] Skipping proof generation (setup not complete)");
        }

        Ok(withdrawal)
    }

    /// Print test summary
    fn print_summary(&self, batch_result: &BatchResult) {
        println!("\n=== TEST SUMMARY ===\n");
        println!("Batch ID: {}", batch_result.batch_id);
        println!("Proofs generated: {}", batch_result.proof_count);
        println!("SP1 execution cycles: {}", batch_result.execution_cycles);
        println!("Total execution time: {} ms", batch_result.execution_time_ms);

        // Chain supply summary
        println!("\n--- Chain Supply ---");
        for (chain_id, chain) in &self.sequencer.chains {
            let net = chain.net_balance(1);
            println!(
                "Chain {}: deposited={:?}, withdrawn={:?}, net={}",
                chain_id,
                chain.deposited.get(&1),
                chain.withdrawn.get(&1),
                net
            );
        }

        println!("\n=== TEST COMPLETE ===\n");
    }
}

impl Default for E2ETestRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_runner_creation() {
        let runner = E2ETestRunner::new();
        assert!(runner.proofs.is_empty());
    }

    #[test]
    fn test_mock_flow_no_proofs() {
        // Test the flow without actual proof generation
        let mut sequencer = MockSequencer::new(16);
        let recipient = F::from(12345u64);

        // Deposit
        let deposit = sequencer.create_deposit(
            CHAIN_ETHEREUM,
            1,
            1000,
            recipient,
        ).unwrap();

        // Transfer
        let transfer = sequencer.create_transfer(
            deposit.note.commitment(),
            900,
            F::from(67890u64),
            100,
        ).unwrap();

        // Withdraw
        let _withdrawal = sequencer.create_withdrawal(
            transfer.output_note.commitment(),
            CHAIN_SOLANA,
            900,
        ).unwrap();

        // Verify state
        sequencer.verify_supply_invariant().unwrap();

        // Check final state
        let eth = sequencer.chains.get(&CHAIN_ETHEREUM).unwrap();
        assert_eq!(eth.deposited.get(&1).unwrap().0, 1000);

        let sol = sequencer.chains.get(&CHAIN_SOLANA).unwrap();
        assert_eq!(sol.withdrawn.get(&1).unwrap().0, 900);
    }

    #[test]
    #[ignore = "Requires snarkjs, rapidsnark, and takes time"]
    fn test_full_e2e_with_proofs() {
        let mut runner = E2ETestRunner::new();

        // Setup circuits
        runner.setup().expect("Setup should succeed");

        // Run E2E flow
        let result = runner.run_e2e_flow().expect("E2E flow should succeed");

        assert_eq!(result.proof_count, 3);
        assert!(result.execution_cycles > 0);
    }

    // Note: Real aggregation tests require actual VKs and proofs
    // The test_full_e2e_with_proofs test above covers the full flow

    #[test]
    fn test_convert_existing_vks_to_binary() {
        // Convert existing JSON VKs to binary format
        let config = TestConfig::new();
        let circuits = vec![CircuitType::Mint, CircuitType::Transfer, CircuitType::Burn];

        for ct in circuits {
            let paths = CircuitPaths::new(&config, ct);
            if paths.verification_key.exists() {
                match export_vk_to_gnark_binary(&paths.verification_key, &paths.verification_key_bin) {
                    Ok(_) => println!("Converted {:?} VK to binary", ct),
                    Err(e) => println!("Failed to convert {:?} VK: {}", ct, e),
                }
            } else {
                println!("VK for {:?} not found, skipping", ct);
            }
        }
    }
}
