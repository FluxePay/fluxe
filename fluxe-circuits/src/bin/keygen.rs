use ark_std::rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::Path;
use std::env;

use fluxe_circuits::setup::{CircuitType, SetupManager, TrustedSetup};
use ark_serialize::CanonicalSerialize;
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    let keys_dir = if args.len() > 1 {
        &args[1]
    } else {
        "target/keys"
    };
    
    let seed = if args.len() > 2 {
        args[2].parse::<u64>().unwrap_or(12345)
    } else {
        12345
    };
    
    println!("Fluxe Circuit Key Generation");
    println!("============================");
    println!("Output directory: {}", keys_dir);
    println!("Random seed: {}", seed);
    println!();
    
    let dir = Path::new(keys_dir);
    std::fs::create_dir_all(dir)?;
    
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let setup_manager = SetupManager::new();
    
    // Helper function to save setup to files
    fn save_setup_to_files(setup: &TrustedSetup, dir: &Path, circuit_type: CircuitType) -> Result<(), Box<dyn std::error::Error>> {
        let pk_path = dir.join(format!("{:?}_pk.bin", circuit_type));
        let vk_path = dir.join(format!("{:?}_vk.bin", circuit_type));
        
        let mut pk_file = File::create(pk_path)?;
        let mut pk_bytes = Vec::new();
        setup.proving_key.serialize_compressed(&mut pk_bytes)?;
        pk_file.write_all(&pk_bytes)?;
        
        let mut vk_file = File::create(vk_path)?;
        let mut vk_bytes = Vec::new();
        setup.verifying_key.serialize_compressed(&mut vk_bytes)?;
        vk_file.write_all(&vk_bytes)?;
        
        Ok(())
    }
    
    // Generate Mint circuit keys
    println!("Generating Mint circuit keys...");
    let mint_setup = setup_manager.generate_mint_setup(&mut rng)?;
    save_setup_to_files(&mint_setup, dir, CircuitType::Mint)?;
    println!("  ✓ Mint circuit keys saved");
    
    // Generate Burn circuit keys
    println!("Generating Burn circuit keys...");
    let burn_setup = setup_manager.generate_burn_setup(&mut rng)?;
    save_setup_to_files(&burn_setup, dir, CircuitType::Burn)?;
    println!("  ✓ Burn circuit keys saved");
    
    // Generate Transfer circuit keys
    println!("Generating Transfer circuit keys...");
    let transfer_setup = setup_manager.generate_transfer_setup(&mut rng)?;
    save_setup_to_files(&transfer_setup, dir, CircuitType::Transfer)?;
    println!("  ✓ Transfer circuit keys saved");
    
    // Generate ObjectUpdate circuit keys
    println!("Generating ObjectUpdate circuit keys...");
    let object_update_setup = setup_manager.generate_object_update_setup(&mut rng)?;
    save_setup_to_files(&object_update_setup, dir, CircuitType::ObjectUpdate)?;
    println!("  ✓ ObjectUpdate circuit keys saved");
    
    println!();
    println!("All keys generated successfully!");
    println!("Keys are stored in: {}", dir.display());
    
    // Print key sizes for reference
    println!();
    println!("Key file sizes:");
    for circuit_type in &[CircuitType::Mint, CircuitType::Burn, CircuitType::Transfer, CircuitType::ObjectUpdate] {
        let pk_path = dir.join(format!("{:?}_pk.bin", circuit_type));
        let vk_path = dir.join(format!("{:?}_vk.bin", circuit_type));
        
        if let Ok(pk_meta) = std::fs::metadata(&pk_path) {
            println!("  {:?} proving key: {} bytes", circuit_type, pk_meta.len());
        }
        if let Ok(vk_meta) = std::fs::metadata(&vk_path) {
            println!("  {:?} verifying key: {} bytes", circuit_type, vk_meta.len());
        }
    }
    
    Ok(())
}