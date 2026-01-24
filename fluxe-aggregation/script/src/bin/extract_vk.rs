//! Batch VK Extraction Tool
//!
//! Extracts the SP1 verifying key for the FLUXE aggregation program.
//! This VK is used for on-chain verification of batch proofs.
//!
//! Usage:
//!   cargo run --release --bin extract_vk [OPTIONS]
//!
//! Options:
//!   --json         Output in JSON format (includes vkey_hash and program_id)
//!   --sol          Output Solidity constants for on-chain verifier
//!   --rust         Output Rust constants for Solana verifier
//!   --output PATH  Write output to file instead of stdout

use anyhow::{Context, Result};
use sp1_sdk::{include_elf, HashableKey, Prover, ProverClient};
use std::env;
use std::fs;

/// The ELF binary of the SP1 guest program
pub const AGGREGATOR_ELF: &[u8] = include_elf!("fluxe-aggregation-program");

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut output_json = false;
    let mut output_sol = false;
    let mut output_rust = false;
    let mut output_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => output_json = true,
            "--sol" => output_sol = true,
            "--rust" => output_rust = true,
            "--output" => {
                if i + 1 < args.len() {
                    output_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Default to json if no format specified
    if !output_json && !output_sol && !output_rust {
        output_json = true;
    }

    eprintln!("FLUXE Batch VK Extraction Tool");
    eprintln!("==============================");
    eprintln!("ELF size: {} bytes", AGGREGATOR_ELF.len());

    // Create prover client and extract VK
    eprintln!("Setting up prover client...");
    let prover = ProverClient::builder().cpu().build();

    eprintln!("Extracting verifying key...");
    let (_, vk) = prover.setup(AGGREGATOR_ELF);

    // Get the vkey bytes32 (hex string)
    let vkey_bytes32 = vk.bytes32();
    eprintln!("VKey extracted successfully!");
    eprintln!();

    let mut output = String::new();

    if output_json {
        output.push_str(&generate_json_output(&vkey_bytes32));
    }

    if output_sol {
        if !output.is_empty() {
            output.push_str("\n\n");
        }
        output.push_str(&generate_solidity_output(&vkey_bytes32));
    }

    if output_rust {
        if !output.is_empty() {
            output.push_str("\n\n");
        }
        output.push_str(&generate_rust_output(&vkey_bytes32));
    }

    // Write output
    if let Some(path) = output_path {
        fs::write(&path, &output).context("Failed to write output file")?;
        eprintln!("Output written to: {}", path);
    } else {
        println!("{}", output);
    }

    Ok(())
}

fn print_help() {
    println!("FLUXE Batch VK Extraction Tool");
    println!();
    println!("Extracts the SP1 verifying key for the FLUXE aggregation program.");
    println!("This VK is used for on-chain verification of batch proofs.");
    println!();
    println!("USAGE:");
    println!("    cargo run --release --bin extract_vk [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    --json         Output in JSON format (default)");
    println!("    --sol          Output Solidity constants for Ethereum verifier");
    println!("    --rust         Output Rust constants for Solana verifier");
    println!("    --output PATH  Write output to file instead of stdout");
    println!("    -h, --help     Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    # Extract VK in JSON format");
    println!("    cargo run --release --bin extract_vk");
    println!();
    println!("    # Generate Solidity constants");
    println!("    cargo run --release --bin extract_vk -- --sol");
    println!();
    println!("    # Generate both Solidity and Rust, save to file");
    println!("    cargo run --release --bin extract_vk -- --sol --rust --output vk_constants.txt");
}

fn generate_json_output(vkey_bytes32: &str) -> String {
    format!(
        r#"{{
  "program": "fluxe-aggregation",
  "description": "FLUXE batch proof verification key for SP1 zkVM",
  "vkey_bytes32": "{}",
  "public_inputs": [
    "old_roots_hash (bytes32) - SHA256 hash of old state tree roots",
    "new_roots_hash (bytes32) - SHA256 hash of new state tree roots",
    "proof_count (uint32) - Number of individual proofs verified",
    "batch_id (uint64) - Batch identifier",
    "chain_id (uint64) - Target chain identifier"
  ],
  "usage": {{
    "ethereum": "Use with SP1 Groth16 verifier contract",
    "solana": "Use with SP1 verifier program via groth16-solana"
  }}
}}"#,
        vkey_bytes32
    )
}

fn generate_solidity_output(vkey_bytes32: &str) -> String {
    format!(
        r#"// SPDX-License-Identifier: MIT
// FLUXE Batch Verification Key Constants
// Generated by: cargo run --release --bin extract_vk -- --sol
//
// This is the SP1 program verification key for the FLUXE batch aggregator.
// Use with the SP1 Groth16 verifier contract for on-chain verification.

/// @notice The verification key for the FLUXE batch aggregation program
/// @dev This is the bytes32 hash of the SP1 program's verification key
bytes32 constant FLUXE_BATCH_VKEY = {};

/// @notice Number of public outputs from the batch proof
/// @dev Public outputs: old_roots_hash, new_roots_hash, proof_count, batch_id, chain_id
uint256 constant FLUXE_BATCH_PUBLIC_VALUES_COUNT = 5;"#,
        vkey_bytes32
    )
}

fn generate_rust_output(vkey_bytes32: &str) -> String {
    // Convert bytes32 hex string to byte array
    let hex_str = vkey_bytes32.trim_start_matches("0x");
    let bytes: Vec<String> = (0..32)
        .map(|i| format!("0x{}", &hex_str[i * 2..i * 2 + 2]))
        .collect();

    format!(
        r#"//! FLUXE Batch Verification Key Constants
//! Generated by: cargo run --release --bin extract_vk -- --rust
//!
//! This is the SP1 program verification key for the FLUXE batch aggregator.
//! Use with the SP1 verifier for on-chain verification on Solana.

/// The verification key for the FLUXE batch aggregation program
/// This is the bytes32 hash of the SP1 program's verification key
pub const FLUXE_BATCH_VKEY: [u8; 32] = [
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
    {}, {}, {}, {},
];

/// The verification key as a hex string (for reference)
pub const FLUXE_BATCH_VKEY_HEX: &str = "{}";"#,
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
        bytes[16], bytes[17], bytes[18], bytes[19],
        bytes[20], bytes[21], bytes[22], bytes[23],
        bytes[24], bytes[25], bytes[26], bytes[27],
        bytes[28], bytes[29], bytes[30], bytes[31],
        vkey_bytes32
    )
}
