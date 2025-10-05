use std::path::{Path, PathBuf};
use std::process::Command;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::errors::{RapidsnarkError, Result};

/// Configuration for the rapidsnark prover
#[derive(Debug, Clone)]
pub struct ProverConfig {
    /// Path to the rapidsnark prover binary
    pub prover_binary: PathBuf,
    /// Path to the proving key (.zkey file)
    pub proving_key_path: PathBuf,
    /// Path to the witness file (.wtns)
    pub witness_path: PathBuf,
    /// Path where the proof will be written
    pub proof_output_path: PathBuf,
    /// Path where the public inputs will be written
    pub public_output_path: PathBuf,
}

impl ProverConfig {
    /// Create a new prover configuration
    pub fn new<P1, P2, P3, P4, P5>(
        prover_binary: P1,
        proving_key_path: P2,
        witness_path: P3,
        proof_output_path: P4,
        public_output_path: P5,
    ) -> Self
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
        P5: AsRef<Path>,
    {
        Self {
            prover_binary: prover_binary.as_ref().to_path_buf(),
            proving_key_path: proving_key_path.as_ref().to_path_buf(),
            witness_path: witness_path.as_ref().to_path_buf(),
            proof_output_path: proof_output_path.as_ref().to_path_buf(),
            public_output_path: public_output_path.as_ref().to_path_buf(),
        }
    }

    /// Use default rapidsnark prover path from the repository
    pub fn with_default_prover<P2, P3, P4, P5>(
        proving_key_path: P2,
        witness_path: P3,
        proof_output_path: P4,
        public_output_path: P5,
    ) -> Self
    where
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
        P5: AsRef<Path>,
    {
        // Default to the prover in the repository's rapidsnark installation
        let prover_binary = PathBuf::from("rapidsnark/package_macos_arm64/bin/prover");
        Self::new(
            prover_binary,
            proving_key_path,
            witness_path,
            proof_output_path,
            public_output_path,
        )
    }
}

/// Rapidsnark prover wrapper
pub struct RapidsnarkProver {
    config: ProverConfig,
}

impl RapidsnarkProver {
    /// Create a new rapidsnark prover with the given configuration
    pub fn new(config: ProverConfig) -> Self {
        Self { config }
    }

    /// Generate a proof using rapidsnark
    ///
    /// This function calls the rapidsnark prover binary with the configured paths.
    /// The prover will read the proving key and witness, then generate a proof.
    ///
    /// # Returns
    /// * `Result<ProofOutput>` - The generated proof and public inputs
    pub fn prove(&self) -> Result<ProofOutput> {
        // Verify input files exist
        if !self.config.proving_key_path.exists() {
            return Err(RapidsnarkError::Prover(format!(
                "Proving key not found: {}",
                self.config.proving_key_path.display()
            )));
        }

        if !self.config.witness_path.exists() {
            return Err(RapidsnarkError::Prover(format!(
                "Witness file not found: {}",
                self.config.witness_path.display()
            )));
        }

        if !self.config.prover_binary.exists() {
            return Err(RapidsnarkError::Prover(format!(
                "Prover binary not found: {}. Please ensure rapidsnark is installed.",
                self.config.prover_binary.display()
            )));
        }

        println!("Generating proof with rapidsnark...");
        println!("  Prover binary: {}", self.config.prover_binary.display());
        println!("  Proving key:   {}", self.config.proving_key_path.display());
        println!("  Witness:       {}", self.config.witness_path.display());

        // Call rapidsnark prover
        // Usage: prover <zkey_file> <witness_file> <proof_file> <public_file>
        let output = Command::new(&self.config.prover_binary)
            .arg(&self.config.proving_key_path)
            .arg(&self.config.witness_path)
            .arg(&self.config.proof_output_path)
            .arg(&self.config.public_output_path)
            .output()
            .map_err(|e| RapidsnarkError::Prover(format!("Failed to execute prover: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RapidsnarkError::Prover(format!(
                "Prover failed with status {}: {}",
                output.status, stderr
            )));
        }

        println!("✓ Proof generated successfully");
        println!("  Proof:  {}", self.config.proof_output_path.display());
        println!("  Public: {}", self.config.public_output_path.display());

        // Read and parse the generated proof and public inputs
        let proof_json = std::fs::read_to_string(&self.config.proof_output_path)?;
        let public_json = std::fs::read_to_string(&self.config.public_output_path)?;

        let proof: Value = serde_json::from_str(&proof_json)?;
        let public: Vec<String> = serde_json::from_str(&public_json)?;

        Ok(ProofOutput {
            proof,
            public_inputs: public,
            proof_path: self.config.proof_output_path.clone(),
            public_path: self.config.public_output_path.clone(),
        })
    }
}

/// Output from the rapidsnark prover
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOutput {
    /// The proof as a JSON value (Groth16 format)
    pub proof: Value,
    /// Public inputs as hex strings
    pub public_inputs: Vec<String>,
    /// Path to the proof file
    #[serde(skip)]
    pub proof_path: PathBuf,
    /// Path to the public inputs file
    #[serde(skip)]
    pub public_path: PathBuf,
}

impl ProofOutput {
    /// Get the proof as a formatted JSON string
    pub fn proof_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.proof)
            .map_err(|e| RapidsnarkError::Json(e))
    }

    /// Get the public inputs as a formatted JSON string
    pub fn public_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.public_inputs)
            .map_err(|e| RapidsnarkError::Json(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_config_creation() {
        let config = ProverConfig::new(
            "prover",
            "test.zkey",
            "witness.wtns",
            "proof.json",
            "public.json",
        );

        assert_eq!(config.prover_binary, PathBuf::from("prover"));
        assert_eq!(config.proving_key_path, PathBuf::from("test.zkey"));
    }

    #[test]
    fn test_default_prover_path() {
        let config = ProverConfig::with_default_prover(
            "test.zkey",
            "witness.wtns",
            "proof.json",
            "public.json",
        );

        assert!(config.prover_binary.to_str().unwrap().contains("rapidsnark"));
    }
}
