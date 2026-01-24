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

/// FLUXE L2 network identifier
/// This is the L2 chain ID used in all batch proofs.
/// All settlement chains (Ethereum, Solana, etc.) verify the same L2 chain ID.
/// Value: 0xF1C5E = 989278 (derived from "FLUXE")
pub const FLUXE_L2_CHAIN_ID: u32 = 0xF1C5E;

/// Size of the historical roots circular buffer
pub const HISTORICAL_ROOTS_SIZE: usize = 64;

/// Empty tree root (Poseidon hash of empty tree)
/// This is the root of an empty sparse Merkle tree
pub const EMPTY_TREE_ROOT: [u8; 32] = [0u8; 32];

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
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Check if all mutable roots are empty (for genesis validation)
    /// Note: sanctions_root and pool_rules_root can be pre-configured
    pub fn mutable_roots_are_empty(&self) -> bool {
        self.cmt_root == EMPTY_TREE_ROOT
            && self.nft_root == EMPTY_TREE_ROOT
            && self.obj_root == EMPTY_TREE_ROOT
            && self.cb_root == EMPTY_TREE_ROOT
            && self.ingress_root == EMPTY_TREE_ROOT
            && self.exit_root == EMPTY_TREE_ROOT
    }
}

/// Circular buffer of recent state root hashes
///
/// Used for UTXO spending proofs that need to reference historical state.
/// A transaction can prove membership against any root in this buffer,
/// not just the latest root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoricalRoots {
    /// Vector of root hashes (always HISTORICAL_ROOTS_SIZE elements)
    pub roots: Vec<[u8; 32]>,
    /// Next write index (wraps around)
    pub next_index: u8,
}

impl Default for HistoricalRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoricalRoots {
    /// Create a new empty historical roots buffer
    pub fn new() -> Self {
        Self {
            roots: alloc::vec![[0u8; 32]; HISTORICAL_ROOTS_SIZE],
            next_index: 0,
        }
    }

    /// Add a new root, overwriting oldest if full
    pub fn push(&mut self, root_hash: [u8; 32]) {
        debug_assert_eq!(self.roots.len(), HISTORICAL_ROOTS_SIZE);
        self.roots[self.next_index as usize] = root_hash;
        self.next_index = (self.next_index + 1) % (HISTORICAL_ROOTS_SIZE as u8);
    }

    /// Check if a root exists in the buffer
    /// Zero hash is always valid (for padding/empty slots)
    pub fn contains(&self, root_hash: &[u8; 32]) -> bool {
        if root_hash == &[0u8; 32] {
            return true;
        }
        self.roots.iter().any(|r| r == root_hash)
    }

    /// Get the most recent root
    pub fn current(&self) -> [u8; 32] {
        debug_assert_eq!(self.roots.len(), HISTORICAL_ROOTS_SIZE);
        let idx = if self.next_index == 0 {
            HISTORICAL_ROOTS_SIZE - 1
        } else {
            (self.next_index - 1) as usize
        };
        self.roots[idx]
    }

    /// Check if the buffer is empty (all zeros)
    pub fn is_empty(&self) -> bool {
        self.roots.iter().all(|r| r == &[0u8; 32])
    }
}

/// Batch/Block input for the SP1 aggregation program (IVC-enabled)
///
/// This unified structure handles both genesis (batch_id=0) and regular blocks.
/// For genesis: prev_public_values is None, proofs is empty.
/// For block N>0: prev_public_values contains the previous block's output.
///
/// Note: Verifying keys are NOT included in the batch input.
/// They are embedded at compile time in the SP1 program via `include_bytes!`.
/// This provides stronger security guarantees - VKs cannot be tampered with
/// without changing the SP1 program's ELF hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchInput {
    /// Batch/block identifier (0 = genesis)
    pub batch_id: u64,

    /// Chain identifier
    pub chain_id: u32,

    /// Timestamp
    pub timestamp: u64,

    /// Previous block's public values for IVC verification
    /// None for genesis block (batch_id = 0)
    /// Some for all subsequent blocks
    pub prev_public_values: Option<BatchOutput>,

    /// Historical roots buffer for UTXO spending proofs
    /// Empty for genesis, populated for subsequent blocks
    pub historical_roots: HistoricalRoots,

    /// State roots before this batch
    pub old_roots: StateRoots,

    /// State roots after this batch
    pub new_roots: StateRoots,

    /// Proofs to verify in this batch
    /// Empty for genesis block
    pub proofs: Vec<ProofEntry>,
}

/// Public outputs committed by the SP1 program
///
/// This is the data that gets committed as public values and verified on-chain.
/// For IVC, the previous block's BatchOutput is verified inside the current proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Length of BatchOutput when serialized to bytes
pub const BATCH_OUTPUT_BYTES_LEN: usize = 80;

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

    /// Serialize to bytes (80 bytes total)
    /// Format: old_roots_hash (32) | new_roots_hash (32) | batch_id (8) | chain_id (4) | proof_count (4)
    pub fn to_bytes(&self) -> [u8; BATCH_OUTPUT_BYTES_LEN] {
        let mut bytes = [0u8; BATCH_OUTPUT_BYTES_LEN];
        bytes[0..32].copy_from_slice(&self.old_roots_hash);
        bytes[32..64].copy_from_slice(&self.new_roots_hash);
        bytes[64..72].copy_from_slice(&self.batch_id.to_be_bytes());
        bytes[72..76].copy_from_slice(&self.chain_id.to_be_bytes());
        bytes[76..80].copy_from_slice(&self.proof_count.to_be_bytes());
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BATCH_OUTPUT_BYTES_LEN {
            return None;
        }
        Some(Self {
            old_roots_hash: bytes[0..32].try_into().ok()?,
            new_roots_hash: bytes[32..64].try_into().ok()?,
            batch_id: u64::from_be_bytes(bytes[64..72].try_into().ok()?),
            chain_id: u32::from_be_bytes(bytes[72..76].try_into().ok()?),
            proof_count: u32::from_be_bytes(bytes[76..80].try_into().ok()?),
        })
    }

    /// Compute public values digest for SP1 recursive verification
    /// This is the hash that verify_sp1_proof expects
    pub fn to_public_values_digest(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
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

    #[test]
    fn test_historical_roots_push_and_contains() {
        let mut hr = HistoricalRoots::new();
        assert!(hr.is_empty());

        let root1 = [1u8; 32];
        let root2 = [2u8; 32];

        hr.push(root1);
        assert!(!hr.is_empty());
        assert!(hr.contains(&root1));
        assert!(!hr.contains(&root2));
        assert_eq!(hr.current(), root1);

        hr.push(root2);
        assert!(hr.contains(&root1));
        assert!(hr.contains(&root2));
        assert_eq!(hr.current(), root2);
    }

    #[test]
    fn test_historical_roots_circular() {
        let mut hr = HistoricalRoots::new();

        // Fill buffer with non-zero values (1..65)
        for i in 1..=64 {
            hr.push([i as u8; 32]);
        }

        // All should be present
        for i in 1..=64 {
            assert!(hr.contains(&[i as u8; 32]));
        }

        // Push one more - should overwrite first (value 1)
        hr.push([100u8; 32]);
        assert!(!hr.contains(&[1u8; 32])); // First one overwritten
        assert!(hr.contains(&[2u8; 32]));  // Second still there
        assert!(hr.contains(&[100u8; 32])); // New one present
    }

    #[test]
    fn test_historical_roots_zero_always_valid() {
        let hr = HistoricalRoots::new();
        assert!(hr.contains(&[0u8; 32]));
    }

    #[test]
    fn test_batch_output_roundtrip() {
        let output = BatchOutput {
            old_roots_hash: [1u8; 32],
            new_roots_hash: [2u8; 32],
            batch_id: 42,
            chain_id: FLUXE_L2_CHAIN_ID,
            proof_count: 10,
        };

        let bytes = output.to_bytes();
        let recovered = BatchOutput::from_bytes(&bytes).unwrap();

        assert_eq!(output, recovered);
    }

    #[test]
    fn test_state_roots_mutable_empty_check() {
        let mut roots = StateRoots::default();
        assert!(roots.mutable_roots_are_empty());

        // Setting a mutable root should make it non-empty
        roots.cmt_root = [1u8; 32];
        assert!(!roots.mutable_roots_are_empty());

        // Setting reference roots should not affect the check
        let mut roots2 = StateRoots::default();
        roots2.sanctions_root = [1u8; 32];
        roots2.pool_rules_root = [2u8; 32];
        assert!(roots2.mutable_roots_are_empty());
    }
}
