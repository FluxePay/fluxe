//! FLUXE Genesis Ceremony Script
//!
//! Generates the genesis proof (batch_id = 0) and submits it to settlement chains.
//!
//! Usage:
//!   cargo run --release --bin genesis [OPTIONS]
//!
//! Options:
//!   --mock          Use mock prover (no actual proof generation)
//!   --output PATH   Write proof to file
//!   --submit-eth    Submit genesis to Ethereum (requires ETH_RPC_URL, ETH_ROLLUP_ADDRESS)
//!   --submit-sol    Submit genesis to Solana (requires SOLANA_PROGRAM_ID)

use anyhow::{Context, Result};
use fluxe_aggregation_lib::{BatchInput, HistoricalRoots, StateRoots, EMPTY_TREE_ROOT, FLUXE_L2_CHAIN_ID};
use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient, SP1Stdin};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// The ELF binary of the SP1 guest program
pub const AGGREGATOR_ELF: &[u8] = include_elf!("fluxe-aggregation-program");

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("=== FLUXE Genesis Ceremony ===");

    // Parse arguments
    let args: Vec<String> = env::args().collect();
    let use_mock = args.iter().any(|a| a == "--mock");
    let submit_eth = args.iter().any(|a| a == "--submit-eth");
    let submit_sol = args.iter().any(|a| a == "--submit-sol");

    let output_path = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.to_string());

    // Create genesis state roots (all empty)
    let genesis_roots = StateRoots {
        cmt_root: EMPTY_TREE_ROOT,
        nft_root: EMPTY_TREE_ROOT,
        obj_root: EMPTY_TREE_ROOT,
        cb_root: EMPTY_TREE_ROOT,
        ingress_root: EMPTY_TREE_ROOT,
        exit_root: EMPTY_TREE_ROOT,
        // Reference roots can be set to predefined values
        sanctions_root: EMPTY_TREE_ROOT,
        pool_rules_root: EMPTY_TREE_ROOT,
    };

    let genesis_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    info!("Genesis Configuration:");
    info!("  Chain ID: 0x{:X} ({})", FLUXE_L2_CHAIN_ID, FLUXE_L2_CHAIN_ID);
    info!("  Timestamp: {}", genesis_timestamp);
    info!("  State Roots Hash: 0x{}", hex::encode(genesis_roots.hash()));

    // Create genesis batch input
    let genesis_input = BatchInput {
        batch_id: 0,
        chain_id: FLUXE_L2_CHAIN_ID,
        timestamp: genesis_timestamp,
        prev_public_values: None,
        historical_roots: HistoricalRoots::new(), // Empty for genesis
        old_roots: genesis_roots.clone(),
        new_roots: genesis_roots.clone(), // No change for genesis
        proofs: vec![],                    // No transactions in genesis
    };

    info!("");
    info!("Generating genesis proof...");

    // Create prover client
    let prover = if use_mock {
        info!("Using mock prover (no actual proof generation)");
        ProverClient::builder().mock().build()
    } else {
        info!("Using SP1 network prover");
        ProverClient::builder().cpu().build()
    };

    // Setup keys
    info!("Setting up proving/verifying keys...");
    let (pk, vk) = prover.setup(AGGREGATOR_ELF);

    info!("Verification Key: 0x{}", vk.bytes32());
    info!("VKey Hash (u32): {:?}", vk.hash_u32());

    // Prepare stdin
    let mut stdin = SP1Stdin::new();
    stdin.write(&genesis_input);

    // Generate proof
    info!("");
    info!("Generating SP1 proof (this may take a while)...");

    let proof_result = prover
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .context("Failed to generate genesis proof")?;

    info!("Genesis proof generated successfully!");

    // Extract public values
    let public_values_bytes = proof_result.public_values.as_slice();
    let proof_bytes = proof_result.bytes();

    info!("");
    info!("=== Genesis Proof Output ===");
    info!("Public Values ({} bytes):", public_values_bytes.len());
    info!("  Raw: 0x{}", hex::encode(public_values_bytes));

    // Decode and display public values
    if public_values_bytes.len() >= 80 {
        let old_roots_hash = &public_values_bytes[0..32];
        let new_roots_hash = &public_values_bytes[32..64];
        let batch_id = u64::from_be_bytes(public_values_bytes[64..72].try_into().unwrap());
        let chain_id = u32::from_be_bytes(public_values_bytes[72..76].try_into().unwrap());
        let proof_count = u32::from_be_bytes(public_values_bytes[76..80].try_into().unwrap());

        info!("");
        info!("Decoded Public Values:");
        info!("  old_roots_hash: 0x{}", hex::encode(old_roots_hash));
        info!("  new_roots_hash: 0x{}", hex::encode(new_roots_hash));
        info!("  batch_id: {}", batch_id);
        info!("  chain_id: 0x{:X} ({})", chain_id, chain_id);
        info!("  proof_count: {}", proof_count);

        // Verify genesis constraints
        assert_eq!(batch_id, 0, "Genesis batch_id must be 0");
        assert_eq!(chain_id, FLUXE_L2_CHAIN_ID, "Chain ID mismatch");
        assert_eq!(proof_count, 0, "Genesis proof_count must be 0");
        assert_eq!(old_roots_hash, new_roots_hash, "Genesis must have no state change");
    }

    info!("");
    info!("Proof ({} bytes):", proof_bytes.len());
    info!("  First 64 bytes: 0x{}", hex::encode(&proof_bytes[..64.min(proof_bytes.len())]));

    // Write output if requested
    if let Some(path) = &output_path {
        let output = GenesisOutput {
            vkey: format!("0x{}", vk.bytes32()),
            public_values: format!("0x{}", hex::encode(public_values_bytes)),
            proof: format!("0x{}", hex::encode(&proof_bytes)),
            roots_hash: format!("0x{}", hex::encode(genesis_roots.hash())),
            chain_id: FLUXE_L2_CHAIN_ID,
            timestamp: genesis_timestamp,
        };

        let json = serde_json::to_string_pretty(&output)?;
        fs::write(path, &json)?;
        info!("");
        info!("Genesis proof written to: {}", path);
    }

    // Submit to Ethereum if requested
    if submit_eth {
        info!("");
        info!("=== Submitting to Ethereum ===");
        warn!("Ethereum submission not yet implemented in this script");
        warn!("Use the generated proof with cast or a deployment script:");
        warn!("  cast send $ROLLUP_ADDRESS 'finalizeGenesis(bytes,bytes)' \\");
        warn!("    0x{} \\", hex::encode(public_values_bytes));
        warn!("    0x{}", hex::encode(&proof_bytes));
    }

    // Submit to Solana if requested
    if submit_sol {
        info!("");
        info!("=== Submitting to Solana ===");
        warn!("Solana submission not yet implemented in this script");
        warn!("Use the generated proof with anchor client");
    }

    info!("");
    info!("=== Genesis Ceremony Complete ===");
    info!("");
    info!("Next steps:");
    info!("  1. Deploy contracts to testnets (if not done)");
    info!("  2. Submit genesis proof to Ethereum: finalizeGenesis(publicValues, proof)");
    info!("  3. Submit genesis proof to Solana: finalize_genesis(public_values, proof)");
    info!("  4. Verify genesis finalized on both chains");
    info!("  5. Start sequencer and begin accepting transactions");

    Ok(())
}

#[derive(serde::Serialize)]
struct GenesisOutput {
    vkey: String,
    public_values: String,
    proof: String,
    roots_hash: String,
    chain_id: u32,
    timestamp: u64,
}
