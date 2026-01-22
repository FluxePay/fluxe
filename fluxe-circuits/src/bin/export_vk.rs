//! VK Export Tool
//!
//! Exports Groth16 verification keys from gnark binary format to:
//! - Rust format (groth16-solana compatible)
//! - Solidity format (Ethereum compatible)

use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: export_vk <vk_file.bin> [--rust | --sol | --both] [--name NAME]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --rust     Output Rust format for groth16-solana");
        eprintln!("  --sol      Output Solidity format for Ethereum");
        eprintln!("  --both     Output both formats (default)");
        eprintln!("  --name     Name prefix for constants (default: FLUXE)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  export_vk mint_vk.bin --rust --name MINT");
        eprintln!("  export_vk mint_vk.bin --sol");
        eprintln!("  export_vk mint_vk.bin --both > vk_exports.txt");
        std::process::exit(1);
    }

    let vk_path = &args[1];
    let mut output_rust = false;
    let mut output_sol = false;
    let mut name = "FLUXE".to_string();

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--rust" => output_rust = true,
            "--sol" => output_sol = true,
            "--both" => {
                output_rust = true;
                output_sol = true;
            }
            "--name" => {
                if i + 1 < args.len() {
                    name = args[i + 1].clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Default to both if neither specified
    if !output_rust && !output_sol {
        output_rust = true;
        output_sol = true;
    }

    // Read VK file
    let vk_bytes = fs::read(vk_path)?;
    println!("// Loaded VK from: {}", vk_path);
    println!("// VK size: {} bytes", vk_bytes.len());

    // Parse VK
    let vk = parse_gnark_vk(&vk_bytes)?;
    println!("// Number of public inputs: {}", vk.ic.len() - 1);
    println!();

    if output_rust {
        println!("{}", generate_rust_vk(&vk, &name));
    }

    if output_sol {
        if output_rust {
            println!();
            println!("// ============================================================");
            println!();
        }
        println!("{}", generate_solidity_vk(&vk, &name));
    }

    Ok(())
}

/// Parsed Groth16 VK
struct ParsedVK {
    alpha_g1: [u8; 64],
    beta_g2: [u8; 128],
    gamma_g2: [u8; 128],
    delta_g2: [u8; 128],
    ic: Vec<[u8; 64]>,
}

/// Parse gnark VK binary format
fn parse_gnark_vk(bytes: &[u8]) -> Result<ParsedVK, Box<dyn std::error::Error>> {
    if bytes.len() < 452 {
        return Err("VK file too small (minimum 452 bytes for header)".into());
    }

    let mut alpha_g1 = [0u8; 64];
    let mut beta_g2 = [0u8; 128];
    let mut gamma_g2 = [0u8; 128];
    let mut delta_g2 = [0u8; 128];

    alpha_g1.copy_from_slice(&bytes[0..64]);
    beta_g2.copy_from_slice(&bytes[64..192]);
    gamma_g2.copy_from_slice(&bytes[192..320]);
    delta_g2.copy_from_slice(&bytes[320..448]);

    // Read IC length (4 bytes big-endian at offset 448)
    let ic_len = u32::from_be_bytes([bytes[448], bytes[449], bytes[450], bytes[451]]) as usize;

    let expected_len = 452 + ic_len * 64;
    if bytes.len() < expected_len {
        return Err(format!(
            "VK file too small: expected {} bytes for {} IC points, got {}",
            expected_len, ic_len, bytes.len()
        ).into());
    }

    let mut ic = Vec::with_capacity(ic_len);
    for i in 0..ic_len {
        let offset = 452 + i * 64;
        let mut point = [0u8; 64];
        point.copy_from_slice(&bytes[offset..offset + 64]);
        ic.push(point);
    }

    Ok(ParsedVK {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Generate Rust format for groth16-solana
fn generate_rust_vk(vk: &ParsedVK, name: &str) -> String {
    let mut output = String::new();

    output.push_str(&format!("use groth16_solana::groth16::Groth16Verifyingkey;\n\n"));
    output.push_str(&format!("/// Number of public inputs for {} circuit\n", name));
    output.push_str(&format!("pub const {}_NR_PUBLIC_INPUTS: usize = {};\n\n", name, vk.ic.len() - 1));

    output.push_str(&format!("/// {} Circuit Verification Key\n", name));
    output.push_str(&format!("pub const {}_VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {{\n", name));
    output.push_str(&format!("    nr_pubinputs: {}_NR_PUBLIC_INPUTS,\n\n", name));

    // Alpha G1
    output.push_str("    // Alpha (G1)\n");
    output.push_str("    vk_alpha_g1: [\n        ");
    output.push_str(&bytes_to_rust_array(&vk.alpha_g1));
    output.push_str("\n    ],\n\n");

    // Beta G2
    output.push_str("    // Beta (G2)\n");
    output.push_str("    vk_beta_g2: [\n        ");
    output.push_str(&bytes_to_rust_array(&vk.beta_g2));
    output.push_str("\n    ],\n\n");

    // Gamma G2
    output.push_str("    // Gamma (G2)\n");
    output.push_str("    vk_gamma_g2: [\n        ");
    output.push_str(&bytes_to_rust_array(&vk.gamma_g2));
    output.push_str("\n    ],\n\n");

    // Delta G2
    output.push_str("    // Delta (G2)\n");
    output.push_str("    vk_delta_g2: [\n        ");
    output.push_str(&bytes_to_rust_array(&vk.delta_g2));
    output.push_str("\n    ],\n\n");

    // IC points
    output.push_str(&format!("    // IC points ({} total)\n", vk.ic.len()));
    output.push_str(&format!("    vk_ic: &{}_VK_IC,\n", name));
    output.push_str("};\n\n");

    // IC array
    output.push_str(&format!("/// IC points for {} verification key\n", name));
    output.push_str(&format!("pub const {}_VK_IC: [[u8; 64]; {}] = [\n", name, vk.ic.len()));
    for (i, ic_point) in vk.ic.iter().enumerate() {
        output.push_str(&format!("    // IC[{}]\n", i));
        output.push_str("    [\n        ");
        output.push_str(&bytes_to_rust_array(ic_point));
        output.push_str("\n    ],\n");
    }
    output.push_str("];\n");

    output
}

/// Generate Solidity format for Ethereum
fn generate_solidity_vk(vk: &ParsedVK, name: &str) -> String {
    let mut output = String::new();

    output.push_str(&format!("// SPDX-License-Identifier: MIT\n"));
    output.push_str(&format!("// {} Verification Key Constants\n", name));
    output.push_str(&format!("// Number of public inputs: {}\n\n", vk.ic.len() - 1));

    // Alpha G1
    let alpha_x = bytes_to_hex_uint256(&vk.alpha_g1[0..32]);
    let alpha_y = bytes_to_hex_uint256(&vk.alpha_g1[32..64]);
    output.push_str(&format!("// Alpha (G1 point)\n"));
    output.push_str(&format!("uint256 constant VK_ALPHA_X = {};\n", alpha_x));
    output.push_str(&format!("uint256 constant VK_ALPHA_Y = {};\n\n", alpha_y));

    // Beta G2 - Gnark format: x.c1 || x.c0 || y.c1 || y.c0
    let beta_x1 = bytes_to_hex_uint256(&vk.beta_g2[0..32]);
    let beta_x2 = bytes_to_hex_uint256(&vk.beta_g2[32..64]);
    let beta_y1 = bytes_to_hex_uint256(&vk.beta_g2[64..96]);
    let beta_y2 = bytes_to_hex_uint256(&vk.beta_g2[96..128]);
    output.push_str(&format!("// Beta (G2 point - Fq2 coordinates)\n"));
    output.push_str(&format!("uint256 constant VK_BETA_X1 = {};\n", beta_x1));
    output.push_str(&format!("uint256 constant VK_BETA_X2 = {};\n", beta_x2));
    output.push_str(&format!("uint256 constant VK_BETA_Y1 = {};\n", beta_y1));
    output.push_str(&format!("uint256 constant VK_BETA_Y2 = {};\n\n", beta_y2));

    // Gamma G2
    let gamma_x1 = bytes_to_hex_uint256(&vk.gamma_g2[0..32]);
    let gamma_x2 = bytes_to_hex_uint256(&vk.gamma_g2[32..64]);
    let gamma_y1 = bytes_to_hex_uint256(&vk.gamma_g2[64..96]);
    let gamma_y2 = bytes_to_hex_uint256(&vk.gamma_g2[96..128]);
    output.push_str(&format!("// Gamma (G2 point)\n"));
    output.push_str(&format!("uint256 constant VK_GAMMA_X1 = {};\n", gamma_x1));
    output.push_str(&format!("uint256 constant VK_GAMMA_X2 = {};\n", gamma_x2));
    output.push_str(&format!("uint256 constant VK_GAMMA_Y1 = {};\n", gamma_y1));
    output.push_str(&format!("uint256 constant VK_GAMMA_Y2 = {};\n\n", gamma_y2));

    // Delta G2
    let delta_x1 = bytes_to_hex_uint256(&vk.delta_g2[0..32]);
    let delta_x2 = bytes_to_hex_uint256(&vk.delta_g2[32..64]);
    let delta_y1 = bytes_to_hex_uint256(&vk.delta_g2[64..96]);
    let delta_y2 = bytes_to_hex_uint256(&vk.delta_g2[96..128]);
    output.push_str(&format!("// Delta (G2 point)\n"));
    output.push_str(&format!("uint256 constant VK_DELTA_X1 = {};\n", delta_x1));
    output.push_str(&format!("uint256 constant VK_DELTA_X2 = {};\n", delta_x2));
    output.push_str(&format!("uint256 constant VK_DELTA_Y1 = {};\n", delta_y1));
    output.push_str(&format!("uint256 constant VK_DELTA_Y2 = {};\n\n", delta_y2));

    // IC points
    output.push_str(&format!("// IC points ({} total: IC[0] + {} for public inputs)\n", vk.ic.len(), vk.ic.len() - 1));
    output.push_str(&format!("uint256 constant IC_LENGTH = {};\n\n", vk.ic.len()));

    for (i, ic_point) in vk.ic.iter().enumerate() {
        let ic_x = bytes_to_hex_uint256(&ic_point[0..32]);
        let ic_y = bytes_to_hex_uint256(&ic_point[32..64]);
        output.push_str(&format!("// IC[{}]\n", i));
        output.push_str(&format!("uint256 constant IC_{}_X = {};\n", i, ic_x));
        output.push_str(&format!("uint256 constant IC_{}_Y = {};\n", i, ic_y));
        if i < vk.ic.len() - 1 {
            output.push_str("\n");
        }
    }

    output
}

/// Convert bytes to Rust array format
fn bytes_to_rust_array(bytes: &[u8]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for chunk in bytes.chunks(16) {
        let line: Vec<String> = chunk.iter().map(|b| format!("{}u8", b)).collect();
        parts.push(line.join(", "));
    }
    parts.join(",\n        ")
}

/// Convert bytes to hex uint256 format
fn bytes_to_hex_uint256(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
