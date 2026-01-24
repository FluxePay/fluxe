//! SP1 ZK Proof Verification for FLUXE Batch Proofs
//!
//! This module handles verification of SP1 batch proofs on Solana.
//! The SP1 proof aggregates multiple individual Groth16 proofs (Mint/Burn/Transfer/ObjectUpdate)
//! and produces a single proof that can be verified on-chain.
//!
//! ## Architecture
//!
//! 1. Individual transaction proofs (Groth16) are verified inside SP1 zkVM
//! 2. SP1 produces a Groth16 proof that the verification program executed correctly
//! 3. This module verifies the SP1 batch proof on Solana
//!
//! ## Proof Format
//!
//! The SP1 proof bytes are structured as:
//! - First 4 bytes: SHA256(groth16_vk)[0:4] - verifies proof was generated with correct SP1 version
//! - Remaining 256 bytes: Groth16 proof (pi_a=64 || pi_b=128 || pi_c=64)
//! - Total: 260 bytes
//!
//! ## Public Values Format
//!
//! The SP1 program commits these public values (serialized as bytes):
//! - old_roots_hash: [u8; 32] - SHA256 of previous state tree roots
//! - new_roots_hash: [u8; 32] - SHA256 of new state tree roots
//! - batch_id: u64 - Sequential batch identifier
//! - chain_id: u32 - FLUXE L2 chain identifier (0xF1C5E)
//! - proof_count: u32 - Number of individual proofs verified

use anchor_lang::prelude::*;

/// FLUXE L2 network identifier
/// This is verified in the batch proof to ensure it's for the correct L2.
/// All settlement chains (Ethereum, Solana) verify the same L2 chain ID.
/// Value: 0xF1C5E = 989278 (derived from "FLUXE")
pub const FLUXE_L2_CHAIN_ID: u32 = 0xF1C5E;

/// FLUXE batch aggregation program verification key hash
/// Generated from SP1 program ELF using extract_vk tool:
/// `cargo run --release --bin extract_vk -p fluxe-aggregation-script`
pub const FLUXE_BATCH_VKEY: &str = "0x00331d2a466af052f5758e7029f9980698a09eb91384bac07237461fe1d81645";

/// Expected length of FLUXE SP1 public values (80 bytes)
/// Format: old_roots_hash(32) + new_roots_hash(32) + batch_id(8) + chain_id(4) + proof_count(4)
pub const FLUXE_PUBLIC_VALUES_LEN: usize = 80;

/// Decoded SP1 batch public values
#[derive(Debug, Clone)]
pub struct BatchPublicValues {
    /// SHA256 hash of old state tree roots
    pub old_roots_hash: [u8; 32],
    /// SHA256 hash of new state tree roots
    pub new_roots_hash: [u8; 32],
    /// Batch identifier
    pub batch_id: u64,
    /// FLUXE L2 chain ID (should be FLUXE_L2_CHAIN_ID)
    pub chain_id: u32,
    /// Number of individual proofs verified in this batch
    pub proof_count: u32,
}

impl BatchPublicValues {
    /// Decode public values from SP1 serialized bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FLUXE_PUBLIC_VALUES_LEN {
            msg!("Invalid public values length: expected {}, got {}", FLUXE_PUBLIC_VALUES_LEN, bytes.len());
            return Err(error!(SP1Error::InvalidPublicValuesLength));
        }

        let mut old_roots_hash = [0u8; 32];
        let mut new_roots_hash = [0u8; 32];

        old_roots_hash.copy_from_slice(&bytes[0..32]);
        new_roots_hash.copy_from_slice(&bytes[32..64]);

        // batch_id is u64 big-endian at offset 64
        let batch_id = u64::from_be_bytes(bytes[64..72].try_into().unwrap());

        // chain_id is u32 big-endian at offset 72
        let chain_id = u32::from_be_bytes(bytes[72..76].try_into().unwrap());

        // proof_count is u32 big-endian at offset 76
        let proof_count = u32::from_be_bytes(bytes[76..80].try_into().unwrap());

        Ok(Self {
            old_roots_hash,
            new_roots_hash,
            batch_id,
            chain_id,
            proof_count,
        })
    }

    /// Validate the public values against expected batch parameters
    pub fn validate(
        &self,
        expected_batch_id: u64,
        expected_old_roots_hash: &[u8; 32],
        expected_new_roots_hash: &[u8; 32],
    ) -> Result<()> {
        // Validate FLUXE L2 chain ID
        if self.chain_id != FLUXE_L2_CHAIN_ID {
            msg!("Invalid chain ID: expected {}, got {}", FLUXE_L2_CHAIN_ID, self.chain_id);
            return Err(error!(SP1Error::InvalidChainId));
        }

        // Validate batch ID
        if self.batch_id != expected_batch_id {
            msg!("Invalid batch ID: expected {}, got {}", expected_batch_id, self.batch_id);
            return Err(error!(SP1Error::InvalidBatchId));
        }

        // Validate old roots hash
        if &self.old_roots_hash != expected_old_roots_hash {
            msg!("Old roots hash mismatch");
            return Err(error!(SP1Error::RootsHashMismatch));
        }

        // Validate new roots hash
        if &self.new_roots_hash != expected_new_roots_hash {
            msg!("New roots hash mismatch");
            return Err(error!(SP1Error::RootsHashMismatch));
        }

        Ok(())
    }
}

/// Verify an SP1 batch proof using sp1-solana
///
/// This function verifies that the SP1 program with FLUXE_BATCH_VKEY produced
/// the given public_values. The sp1-solana crate handles:
/// - Validating the 4-byte vk hash prefix in the proof
/// - Hashing the public_values to create the commitment
/// - Verifying the Groth16 proof using Solana's BN254 precompiles
///
/// # Arguments
/// * `proof` - The SP1 Groth16 proof bytes (~260 bytes: 4-byte vk hash + 256-byte proof)
/// * `public_values` - The SP1 public values (variable length, 80 bytes for FLUXE batch)
///
/// # Returns
/// * `Ok(())` - If proof verification succeeds
/// * `Err` - If verification fails
pub fn verify_sp1_batch_proof(
    proof: &[u8],
    public_values: &[u8],
) -> Result<()> {
    // Get the SP1 Groth16 verification key for SP1 v4.0.0
    // Note: Update this constant when upgrading SP1 version
    let groth16_vk = sp1_solana::GROTH16_VK_4_0_0_RC3_BYTES;

    // Verify the SP1 proof using sp1-solana crate
    // - proof: contains 4-byte vk hash prefix + Groth16 proof (A || B || C)
    // - public_values: SP1 program's public outputs (hashed internally)
    // - FLUXE_BATCH_VKEY: the SP1 program's verification key hash
    // - groth16_vk: the SP1 version's Groth16 verification key
    sp1_solana::verify_proof(
        proof,
        public_values,
        FLUXE_BATCH_VKEY,
        groth16_vk,
    ).map_err(|e| {
        msg!("SP1 proof verification failed: {:?}", e);
        error!(SP1Error::ProofVerificationFailed)
    })?;

    Ok(())
}

/// SP1 verification errors
#[error_code]
pub enum SP1Error {
    #[msg("Invalid public values length")]
    InvalidPublicValuesLength,
    #[msg("Invalid FLUXE L2 chain ID")]
    InvalidChainId,
    #[msg("Invalid batch ID")]
    InvalidBatchId,
    #[msg("State roots hash mismatch")]
    RootsHashMismatch,
    #[msg("SP1 proof verification failed")]
    ProofVerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_values_decode() {
        // Create test public values
        let mut bytes = [0u8; FLUXE_PUBLIC_VALUES_LEN];

        // old_roots_hash
        bytes[0..32].copy_from_slice(&[1u8; 32]);
        // new_roots_hash
        bytes[32..64].copy_from_slice(&[2u8; 32]);
        // batch_id = 42
        bytes[64..72].copy_from_slice(&42u64.to_be_bytes());
        // chain_id = FLUXE_L2_CHAIN_ID
        bytes[72..76].copy_from_slice(&FLUXE_L2_CHAIN_ID.to_be_bytes());
        // proof_count = 10
        bytes[76..80].copy_from_slice(&10u32.to_be_bytes());

        let values = BatchPublicValues::from_bytes(&bytes).unwrap();

        assert_eq!(values.old_roots_hash, [1u8; 32]);
        assert_eq!(values.new_roots_hash, [2u8; 32]);
        assert_eq!(values.batch_id, 42);
        assert_eq!(values.chain_id, FLUXE_L2_CHAIN_ID);
        assert_eq!(values.proof_count, 10);
    }

    #[test]
    fn test_public_values_validation() {
        let values = BatchPublicValues {
            old_roots_hash: [1u8; 32],
            new_roots_hash: [2u8; 32],
            batch_id: 42,
            chain_id: FLUXE_L2_CHAIN_ID,
            proof_count: 10,
        };

        // Should succeed with matching parameters
        assert!(values.validate(42, &[1u8; 32], &[2u8; 32]).is_ok());
    }
}
