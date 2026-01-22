//! FLUXE Aggregation Library
//!
//! Shared types for proof aggregation between host and SP1 guest program.
//! This crate is no_std compatible for use in SP1 zkVM.
//!
//! ## Key Components
//!
//! - **groth16**: BN254 Groth16 verification using pairing precompiles
//! - **BatchInput/BatchOutput**: Types for SP1 program I/O
//! - **StateRoots**: FLUXE state tree roots

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod groth16;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

pub use groth16::{Groth16Proof, Groth16VerifyingKey, Groth16Error, verify as verify_groth16};

/// Transaction type identifier
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TxType {
    Mint = 0,
    Burn = 1,
    Transfer = 2,
    ObjectUpdate = 3,
}

impl From<u8> for TxType {
    fn from(v: u8) -> Self {
        match v {
            0 => TxType::Mint,
            1 => TxType::Burn,
            2 => TxType::Transfer,
            3 => TxType::ObjectUpdate,
            _ => panic!("Invalid tx type"),
        }
    }
}

/// A single Groth16 proof to be verified
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofEntry {
    /// Transaction type (determines which VK to use)
    pub tx_type: TxType,

    /// Groth16 proof bytes (gnark format: 256 bytes uncompressed)
    /// Format: A (64 bytes G1) || B (128 bytes G2) || C (64 bytes G1)
    pub proof_bytes: Vec<u8>,

    /// Public inputs as 32-byte big-endian field elements
    pub public_inputs: Vec<[u8; 32]>,
}

/// State roots (8 Merkle roots)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StateRoots {
    /// Commitment tree root
    pub cmt_root: [u8; 32],
    /// Nullifier tree root
    pub nft_root: [u8; 32],
    /// Object tree root
    pub obj_root: [u8; 32],
    /// Callback tree root
    pub cb_root: [u8; 32],
    /// Ingress tree root
    pub ingress_root: [u8; 32],
    /// Exit tree root
    pub exit_root: [u8; 32],
    /// Sanctions root (reference)
    pub sanctions_root: [u8; 32],
    /// Pool rules root (reference)
    pub pool_rules_root: [u8; 32],
}

impl StateRoots {
    /// Compute SHA256 hash of all roots
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.cmt_root);
        hasher.update(&self.nft_root);
        hasher.update(&self.obj_root);
        hasher.update(&self.cb_root);
        hasher.update(&self.ingress_root);
        hasher.update(&self.exit_root);
        hasher.update(&self.sanctions_root);
        hasher.update(&self.pool_rules_root);
        hasher.finalize().into()
    }

    /// Convert all roots to a flat byte array (256 bytes)
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        bytes[0..32].copy_from_slice(&self.cmt_root);
        bytes[32..64].copy_from_slice(&self.nft_root);
        bytes[64..96].copy_from_slice(&self.obj_root);
        bytes[96..128].copy_from_slice(&self.cb_root);
        bytes[128..160].copy_from_slice(&self.ingress_root);
        bytes[160..192].copy_from_slice(&self.exit_root);
        bytes[192..224].copy_from_slice(&self.sanctions_root);
        bytes[224..256].copy_from_slice(&self.pool_rules_root);
        bytes
    }

    /// Create from flat byte array
    pub fn from_bytes(bytes: &[u8; 256]) -> Self {
        let mut roots = Self::default();
        roots.cmt_root.copy_from_slice(&bytes[0..32]);
        roots.nft_root.copy_from_slice(&bytes[32..64]);
        roots.obj_root.copy_from_slice(&bytes[64..96]);
        roots.cb_root.copy_from_slice(&bytes[96..128]);
        roots.ingress_root.copy_from_slice(&bytes[128..160]);
        roots.exit_root.copy_from_slice(&bytes[160..192]);
        roots.sanctions_root.copy_from_slice(&bytes[192..224]);
        roots.pool_rules_root.copy_from_slice(&bytes[224..256]);
        roots
    }
}

/// Batch input for the SP1 aggregation program
///
/// Note: Verifying keys are NOT included in the batch input.
/// They are embedded at compile time in the SP1 program via `include_bytes!`.
/// This provides stronger security guarantees - VKs cannot be tampered with
/// without changing the SP1 program's ELF hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchInput {
    /// Batch identifier
    pub batch_id: u64,

    /// Chain identifier
    pub chain_id: u32,

    /// Timestamp
    pub timestamp: u64,

    /// State roots before this batch
    pub old_roots: StateRoots,

    /// State roots after this batch
    pub new_roots: StateRoots,

    /// Proofs to verify in this batch
    pub proofs: Vec<ProofEntry>,
}

/// Public outputs committed by the SP1 program
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchOutput {
    /// Hash of old state roots
    pub old_roots_hash: [u8; 32],

    /// Hash of new state roots
    pub new_roots_hash: [u8; 32],

    /// Batch ID
    pub batch_id: u64,

    /// Chain ID
    pub chain_id: u32,

    /// Number of proofs verified
    pub proof_count: u32,
}

impl BatchOutput {
    /// Compute commitment hash for on-chain verification
    pub fn commitment(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.old_roots_hash);
        hasher.update(&self.new_roots_hash);
        hasher.update(&self.batch_id.to_le_bytes());
        hasher.update(&self.chain_id.to_le_bytes());
        hasher.update(&self.proof_count.to_le_bytes());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_roots_hash() {
        let roots = StateRoots {
            cmt_root: [1u8; 32],
            nft_root: [2u8; 32],
            obj_root: [3u8; 32],
            cb_root: [4u8; 32],
            ingress_root: [5u8; 32],
            exit_root: [6u8; 32],
            sanctions_root: [7u8; 32],
            pool_rules_root: [8u8; 32],
        };

        let hash = roots.hash();
        assert_ne!(hash, [0u8; 32]);

        // Same roots should produce same hash
        let hash2 = roots.hash();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_state_roots_roundtrip() {
        let roots = StateRoots {
            cmt_root: [1u8; 32],
            nft_root: [2u8; 32],
            obj_root: [3u8; 32],
            cb_root: [4u8; 32],
            ingress_root: [5u8; 32],
            exit_root: [6u8; 32],
            sanctions_root: [7u8; 32],
            pool_rules_root: [8u8; 32],
        };

        let bytes = roots.to_bytes();
        let recovered = StateRoots::from_bytes(&bytes);

        assert_eq!(roots.cmt_root, recovered.cmt_root);
        assert_eq!(roots.nft_root, recovered.nft_root);
        assert_eq!(roots.sanctions_root, recovered.sanctions_root);
    }

    #[test]
    fn test_tx_type_conversion() {
        assert_eq!(TxType::from(0), TxType::Mint);
        assert_eq!(TxType::from(1), TxType::Burn);
        assert_eq!(TxType::from(2), TxType::Transfer);
        assert_eq!(TxType::from(3), TxType::ObjectUpdate);
    }
}
