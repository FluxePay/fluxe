use std::path::{Path, PathBuf};
use std::process::Command;
use serde_json::Value;
use crate::errors::{RapidsnarkError, Result};

/// Configuration for the rapidsnark verifier
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Path to the rapidsnark verifier binary
    pub verifier_binary: PathBuf,
    /// Path to the verification key JSON file
    pub verification_key_path: PathBuf,
    /// Path to the public inputs JSON file
    pub public_inputs_path: PathBuf,
    /// Path to the proof JSON file
    pub proof_path: PathBuf,
}

impl VerifierConfig {
    /// Create a new verifier configuration
    pub fn new<P1, P2, P3, P4>(
        verifier_binary: P1,
        verification_key_path: P2,
        public_inputs_path: P3,
        proof_path: P4,
    ) -> Self
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
    {
        Self {
            verifier_binary: verifier_binary.as_ref().to_path_buf(),
            verification_key_path: verification_key_path.as_ref().to_path_buf(),
            public_inputs_path: public_inputs_path.as_ref().to_path_buf(),
            proof_path: proof_path.as_ref().to_path_buf(),
        }
    }

    /// Use default rapidsnark verifier path from the repository
    pub fn with_default_verifier<P2, P3, P4>(
        verification_key_path: P2,
        public_inputs_path: P3,
        proof_path: P4,
    ) -> Self
    where
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
    {
        // Default to the verifier in the repository's rapidsnark installation
        let verifier_binary = PathBuf::from("rapidsnark/package_macos_arm64/bin/verifier");
        Self::new(
            verifier_binary,
            verification_key_path,
            public_inputs_path,
            proof_path,
        )
    }
}

/// Rapidsnark verifier wrapper
pub struct RapidsnarkVerifier {
    config: VerifierConfig,
}

impl RapidsnarkVerifier {
    /// Create a new rapidsnark verifier with the given configuration
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Verify a proof using rapidsnark
    ///
    /// This function calls the rapidsnark verifier binary with the configured paths.
    /// The verifier will read the verification key, public inputs, and proof,
    /// then verify the proof's validity.
    ///
    /// # Returns
    /// * `Result<bool>` - True if the proof is valid, false otherwise
    pub fn verify(&self) -> Result<bool> {
        // Verify input files exist
        if !self.config.verification_key_path.exists() {
            return Err(RapidsnarkError::Verifier(format!(
                "Verification key not found: {}",
                self.config.verification_key_path.display()
            )));
        }

        if !self.config.public_inputs_path.exists() {
            return Err(RapidsnarkError::Verifier(format!(
                "Public inputs not found: {}",
                self.config.public_inputs_path.display()
            )));
        }

        if !self.config.proof_path.exists() {
            return Err(RapidsnarkError::Verifier(format!(
                "Proof not found: {}",
                self.config.proof_path.display()
            )));
        }

        if !self.config.verifier_binary.exists() {
            return Err(RapidsnarkError::Verifier(format!(
                "Verifier binary not found: {}. Please ensure rapidsnark is installed.",
                self.config.verifier_binary.display()
            )));
        }

        println!("Verifying proof with rapidsnark...");
        println!("  Verifier binary: {}", self.config.verifier_binary.display());
        println!("  Verification key: {}", self.config.verification_key_path.display());
        println!("  Public inputs:    {}", self.config.public_inputs_path.display());
        println!("  Proof:            {}", self.config.proof_path.display());

        // Call rapidsnark verifier
        // Usage: verifier <verification_key> <public.json> <proof.json>
        let output = Command::new(&self.config.verifier_binary)
            .arg(&self.config.verification_key_path)
            .arg(&self.config.public_inputs_path)
            .arg(&self.config.proof_path)
            .output()
            .map_err(|e| RapidsnarkError::Verifier(format!("Failed to execute verifier: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Rapidsnark verifier returns success status if proof is valid
        let is_valid = output.status.success();

        if is_valid {
            println!("✓ Proof is VALID");
        } else {
            println!("✗ Proof is INVALID");
            if !stderr.is_empty() {
                println!("  Error: {}", stderr);
            }
        }

        if !stdout.is_empty() {
            println!("  Output: {}", stdout.trim());
        }

        Ok(is_valid)
    }

    /// Verify using snarkjs as an alternative (for cross-validation)
    ///
    /// This requires snarkjs to be installed and available in PATH.
    pub fn verify_with_snarkjs(&self) -> Result<bool> {
        println!("Cross-verifying with snarkjs...");

        let output = Command::new("npx")
            .args(&[
                "snarkjs",
                "groth16",
                "verify",
                self.config.verification_key_path.to_str().unwrap(),
                self.config.public_inputs_path.to_str().unwrap(),
                self.config.proof_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| RapidsnarkError::Verifier(format!("Failed to execute snarkjs: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let is_valid = stdout.contains("OK!");

        if is_valid {
            println!("✓ snarkjs verification: VALID");
        } else {
            println!("✗ snarkjs verification: INVALID");
        }

        Ok(is_valid)
    }
}

/// Helper function to export verification key from a zkey file
///
/// Calls snarkjs to export the verification key from a .zkey file to JSON format.
/// This is required before verification can be performed.
pub fn export_verification_key<P1, P2>(zkey_path: P1, vkey_output_path: P2) -> Result<()>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    println!("Exporting verification key...");
    println!("  From: {}", zkey_path.as_ref().display());
    println!("  To:   {}", vkey_output_path.as_ref().display());

    let output = Command::new("npx")
        .args(&[
            "snarkjs",
            "zkey",
            "export",
            "verificationkey",
            zkey_path.as_ref().to_str().unwrap(),
            vkey_output_path.as_ref().to_str().unwrap(),
        ])
        .output()
        .map_err(|e| RapidsnarkError::Other(format!("Failed to execute snarkjs: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(RapidsnarkError::Other(format!(
            "Failed to export verification key: {}",
            stderr
        )));
    }

    println!("✓ Verification key exported");
    Ok(())
}

/// Parse a verification key JSON file
pub fn parse_verification_key<P: AsRef<Path>>(path: P) -> Result<Value> {
    let content = std::fs::read_to_string(path.as_ref())?;
    let vkey: Value = serde_json::from_str(&content)?;
    Ok(vkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verifier_config_creation() {
        let config = VerifierConfig::new(
            "verifier",
            "vkey.json",
            "public.json",
            "proof.json",
        );

        assert_eq!(config.verifier_binary, PathBuf::from("verifier"));
        assert_eq!(config.verification_key_path, PathBuf::from("vkey.json"));
    }

    #[test]
    fn test_default_verifier_path() {
        let config = VerifierConfig::with_default_verifier(
            "vkey.json",
            "public.json",
            "proof.json",
        );

        assert!(config.verifier_binary.to_str().unwrap().contains("rapidsnark"));
    }
}
