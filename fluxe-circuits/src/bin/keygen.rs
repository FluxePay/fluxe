use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;
use std::env;

use fluxe_circuits::setup::{CircuitType, CircuitSetupManager, CircuitSetupConfig, TrustedSetup};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let keys_dir = if args.len() > 1 {
        args[1].clone()
    } else {
        "target/keys".to_string()
    };

    let seed = if args.len() > 2 {
        args[2].parse::<u64>().unwrap_or(12345)
    } else {
        12345
    };

    // Check for migration flag
    let migrate_legacy = args.contains(&"--migrate".to_string());
    let legacy_dir = if args.len() > 3 && args[args.len() - 2] == "--from" {
        Some(args[args.len() - 1].clone())
    } else {
        None
    };

    println!("Fluxe Circuit Key Generation");
    println!("============================");
    println!("Output directory: {}", keys_dir);
    println!("Random seed: {}", seed);

    if migrate_legacy {
        if let Some(ref legacy) = legacy_dir {
            println!("Migration mode: Migrating from {} to new format", legacy);
        }
    }
    println!();

    // Create configuration
    let config = CircuitSetupConfig {
        base_dir: keys_dir.clone(),
        key_version: 1,
        allow_global_fallback: true,
    };

    // Initialize setup manager
    let mut setup_manager = CircuitSetupManager::new(config);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    // Option 1: Migrate legacy keys if requested
    if migrate_legacy {
        if let Some(ref legacy_path) = legacy_dir {
            println!("Migrating keys from legacy format...");
            println!("Source: {}", legacy_path);
            println!("Destination: {}", keys_dir);
            println!();

            CircuitSetupManager::migrate_legacy_keys(
                Path::new(&legacy_path),
                Path::new(&keys_dir),
            )?;

            println!("Migration completed successfully!");
            return Ok(());
        }
    }

    // Option 2: Generate new keys (for single chain or global)
    let generate_for_chain = if args.len() > 3 && args[2] != "12345" {
        // Check if third argument looks like a chain ID
        args[3].parse::<u32>().ok()
    } else {
        None
    };

    if let Some(chain_id) = generate_for_chain {
        println!("Generating keys for chain_id={}", chain_id);
        println!();

        // Generate chain-specific circuits
        println!("Chain-Specific Circuits");
        println!("----------------------");
        setup_manager.generate_chain_circuits(chain_id, &mut rng)?;

        // Generate global circuits (if not already generated)
        println!();
        println!("Global Circuits (shared across all chains)");
        println!("------------------------------------------");
        setup_manager.generate_global_circuits(&mut rng)?;

        // Save all generated keys
        println!();
        println!("Saving keys...");
        setup_manager.save_all()?;
        print_key_sizes(&keys_dir)?;

        println!();
        println!("Keys generated successfully!");
        println!("Directory structure:");
        println!("  {}/", keys_dir);
        println!("  ├── chain_{}/", chain_id);
        println!("  │   ├── v1_Mint_pk.bin");
        println!("  │   ├── v1_Mint_vk.bin");
        println!("  │   ├── v1_Burn_pk.bin");
        println!("  │   └── v1_Burn_vk.bin");
        println!("  └── global/");
        println!("      ├── v1_Transfer_1_2_pk.bin");
        println!("      ├── v1_Transfer_1_2_vk.bin");
        println!("      ├── v1_ObjectUpdate_pk.bin");
        println!("      └── v1_ObjectUpdate_vk.bin");
    } else {
        // Generate global circuits only (legacy behavior)
        println!("Generating global circuits (Transfer, ObjectUpdate)");
        println!("---------------------------------------------------");
        setup_manager.generate_global_circuits(&mut rng)?;

        // Save all generated keys
        println!();
        println!("Saving keys...");
        setup_manager.save_all()?;
        print_key_sizes(&keys_dir)?;

        println!();
        println!("Global keys generated successfully!");
        println!("Keys are stored in: {}/global", keys_dir);
        println!();
        println!("To generate chain-specific keys (Mint, Burn), use:");
        println!("  cargo run --bin keygen -- {} {} <chain_id>", keys_dir, seed);
        println!();
        println!("Examples:");
        println!("  cargo run --bin keygen -- target/keys 12345 1      # Generate for Ethereum");
        println!("  cargo run --bin keygen -- target/keys 12345 501    # Generate for Solana");
    }

    Ok(())
}

fn print_key_sizes(keys_dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!();
    println!("Key file sizes:");

    let base_path = Path::new(keys_dir);

    // Print global keys
    if let Ok(global_dir) = std::fs::read_dir(base_path.join("global")) {
        for entry in global_dir.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    if let Some(file_name) = path.file_name() {
                        println!(
                            "  global/{}: {} bytes",
                            file_name.to_string_lossy(),
                            metadata.len()
                        );
                    }
                }
            }
        }
    }

    // Print chain-specific keys
    if let Ok(entries) = std::fs::read_dir(base_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(dir_name) = path.file_name() {
                    let dir_name_str = dir_name.to_string_lossy();
                    if dir_name_str.starts_with("chain_") {
                        if let Ok(files) = std::fs::read_dir(&path) {
                            for file_entry in files.flatten() {
                                let file_path = file_entry.path();
                                if file_path.is_file() {
                                    if let Ok(metadata) = std::fs::metadata(&file_path) {
                                        if let Some(file_name) = file_path.file_name() {
                                            println!(
                                                "  {}/{}: {} bytes",
                                                dir_name_str,
                                                file_name.to_string_lossy(),
                                                metadata.len()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}