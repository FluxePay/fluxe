//! End-to-End Integration Test: Rapidsnark Proving + SP1 Recursion
//!
//! This test suite verifies the complete proof generation and aggregation pipeline:
//! 1. Convert arkworks circuits to circom-compatible R1CS
//! 2. Generate proving keys using snarkjs + Powers of Tau
//! 3. Generate user proofs using rapidsnark (fast C++ prover)
//! 4. Aggregate proofs using SP1 zkVM (execution-only mode)
//!
//! The test simulates a full cross-chain flow:
//! - Deposit on Chain A (MintCircuit)
//! - Private transfer within FLUXE (TransferCircuit)
//! - Withdrawal to Chain B (BurnCircuit)

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

// Re-export test modules
pub mod circuit_setup;
pub mod mock_sequencer;
pub mod e2e_flow;

/// Test configuration
#[derive(Clone)]
pub struct TestConfig {
    /// Base directory for test outputs
    pub output_dir: PathBuf,
    /// Path to rapidsnark prover binary
    pub prover_binary: PathBuf,
    /// Path to powers of tau file
    pub ptau_path: PathBuf,
    /// Power of tau (determines max constraints)
    pub ptau_power: u32,
}

impl TestConfig {
    pub fn new() -> Self {
        // CARGO_MANIFEST_DIR is tests/e2e_rapidsnark_sp1, go up two levels to repo root
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()  // tests/
            .unwrap()
            .parent()  // fluxe/
            .unwrap()
            .to_path_buf();

        Self {
            output_dir: repo_root.join("tests/e2e_rapidsnark_sp1/outputs"),
            prover_binary: repo_root.join("rapidsnark/package/bin/prover"),
            ptau_path: repo_root.join("tests/e2e_rapidsnark_sp1/pot17_final.ptau"),
            ptau_power: 17, // Supports up to 131k constraints
        }
    }

    pub fn ensure_output_dir(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.output_dir)
    }

    /// Check if snarkjs is available
    pub fn check_snarkjs(&self) -> bool {
        Command::new("snarkjs")
            .arg("--version")
            .output()
            .map(|o| o.status.success() || o.status.code() == Some(99))
            .unwrap_or(false)
    }

    /// Check if rapidsnark prover is available
    pub fn check_prover(&self) -> bool {
        self.prover_binary.exists()
    }

    /// Check if powers of tau file exists
    pub fn check_ptau(&self) -> bool {
        self.ptau_path.exists()
    }
}

impl Default for TestConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Circuit type identifiers
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum CircuitType {
    Mint,
    Transfer,
    Burn,
    ObjectUpdate,
}

impl CircuitType {
    pub fn name(&self) -> &'static str {
        match self {
            CircuitType::Mint => "mint",
            CircuitType::Transfer => "transfer",
            CircuitType::Burn => "burn",
            CircuitType::ObjectUpdate => "object_update",
        }
    }

    pub fn all() -> Vec<CircuitType> {
        vec![
            CircuitType::Mint,
            CircuitType::Transfer,
            CircuitType::Burn,
            CircuitType::ObjectUpdate,
        ]
    }
}

/// Paths for a single circuit's artifacts
#[derive(Clone, Debug)]
pub struct CircuitPaths {
    pub circuit_type: CircuitType,
    pub r1cs: PathBuf,
    pub witness: PathBuf,
    pub proving_key: PathBuf,
    pub verification_key: PathBuf,
    /// Gnark binary format VK for SP1 embedding
    pub verification_key_bin: PathBuf,
    pub proof: PathBuf,
    pub public_inputs: PathBuf,
}

impl CircuitPaths {
    pub fn new(config: &TestConfig, circuit_type: CircuitType) -> Self {
        let name = circuit_type.name();
        let base = &config.output_dir;

        Self {
            circuit_type,
            r1cs: base.join(format!("{}.r1cs", name)),
            witness: base.join(format!("{}_witness.wtns", name)),
            proving_key: base.join(format!("{}_final.zkey", name)),
            verification_key: base.join(format!("{}_vk.json", name)),
            verification_key_bin: base.join(format!("{}_vk.bin", name)),
            proof: base.join(format!("{}_proof.json", name)),
            public_inputs: base.join(format!("{}_public.json", name)),
        }
    }
}

/// Track proving key setup status
pub struct SetupManager {
    pub config: TestConfig,
    pub circuit_paths: HashMap<CircuitType, CircuitPaths>,
    pub setup_complete: HashMap<CircuitType, bool>,
}

impl SetupManager {
    pub fn new(config: TestConfig) -> Self {
        let mut circuit_paths = HashMap::new();
        let mut setup_complete = HashMap::new();

        for ct in CircuitType::all() {
            circuit_paths.insert(ct, CircuitPaths::new(&config, ct));
            setup_complete.insert(ct, false);
        }

        Self {
            config,
            circuit_paths,
            setup_complete,
        }
    }

    pub fn get_paths(&self, circuit_type: CircuitType) -> Option<&CircuitPaths> {
        self.circuit_paths.get(&circuit_type)
    }

    pub fn is_setup_complete(&self, circuit_type: CircuitType) -> bool {
        self.setup_complete.get(&circuit_type).copied().unwrap_or(false)
    }

    pub fn mark_setup_complete(&mut self, circuit_type: CircuitType) {
        self.setup_complete.insert(circuit_type, true);
    }
}

/// Result of proof generation
#[derive(Clone, Debug)]
pub struct ProofResult {
    pub circuit_type: CircuitType,
    pub proof_json: String,
    pub public_inputs_json: String,
    pub proving_time_ms: u64,
}

/// Result of batch aggregation
#[derive(Clone, Debug)]
pub struct BatchResult {
    pub batch_id: u64,
    pub proof_count: u32,
    pub old_roots_hash: [u8; 32],
    pub new_roots_hash: [u8; 32],
    pub execution_cycles: u64,
    pub execution_time_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let config = TestConfig::new();
        assert!(config.ptau_power >= 17);
        println!("Output dir: {:?}", config.output_dir);
        println!("Prover binary: {:?}", config.prover_binary);
    }

    #[test]
    fn test_circuit_paths() {
        let config = TestConfig::new();
        let paths = CircuitPaths::new(&config, CircuitType::Transfer);

        assert!(paths.r1cs.to_str().unwrap().contains("transfer"));
        assert!(paths.proving_key.to_str().unwrap().contains("transfer"));
    }
}
