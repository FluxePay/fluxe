//! Bridge types for cross-chain withdrawal processing
//!
//! This module defines the shared types used by the withdrawal processing system
//! to track and manage cross-chain withdrawals from the FLUXE protocol to external chains.

use crate::data_structures::ExitReceipt;
use crate::merkle::MerklePath;
use crate::types::{ChainId, Time};
use ark_bn254::Fr as F;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};

/// Status of a withdrawal in the processing pipeline
///
/// A withdrawal goes through several states:
/// 1. Pending - Exit receipt created but batch not yet finalized
/// 2. Ready - Batch finalized, Merkle proof available, can be claimed on L1
/// 3. Claimed - User has claimed the withdrawal on the target chain
/// 4. Failed - Withdrawal failed (e.g., insufficient liquidity, expired)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Exit receipt created, waiting for batch finalization
    Pending,
    /// Batch finalized, Merkle proof available for claiming on L1
    Ready,
    /// Successfully claimed on target chain
    Claimed,
    /// Withdrawal failed (with reason code)
    Failed(WithdrawalFailureReason),
}

impl Default for WithdrawalStatus {
    fn default() -> Self {
        WithdrawalStatus::Pending
    }
}

/// Reason for withdrawal failure
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WithdrawalFailureReason {
    /// Insufficient liquidity on target chain
    InsufficientLiquidity,
    /// Withdrawal expired before being claimed
    Expired,
    /// Invalid Merkle proof
    InvalidProof,
    /// Chain temporarily unavailable
    ChainUnavailable,
    /// Unknown failure
    Unknown,
}

/// A pending withdrawal tracked by the withdrawal processor
///
/// This structure tracks all information needed to generate withdrawal proofs
/// and allow users to claim their assets on the target chain.
#[derive(Clone, Debug)]
pub struct PendingWithdrawal {
    /// The exit receipt proving the burn occurred
    pub exit_receipt: ExitReceipt,

    /// Hash of the exit receipt (cached for quick lookup)
    pub exit_hash: F,

    /// Target chain for this withdrawal
    pub destination_chain: ChainId,

    /// Merkle proof for the exit receipt in the exit tree
    /// Only available after batch finalization (when status is Ready)
    pub merkle_proof: Option<MerklePath>,

    /// Batch ID where this exit was included
    pub batch_id: u64,

    /// Current status of the withdrawal
    pub status: WithdrawalStatus,

    /// Timestamp when the exit receipt was created
    pub created_at: Time,

    /// Timestamp when the batch was finalized (if finalized)
    pub finalized_at: Option<Time>,

    /// Timestamp when claimed on L1 (if claimed)
    pub claimed_at: Option<Time>,

    /// L1 transaction hash of the claim (if claimed)
    pub claim_tx_hash: Option<[u8; 32]>,
}

impl PendingWithdrawal {
    /// Create a new pending withdrawal from an exit receipt
    ///
    /// # Arguments
    /// * `exit_receipt` - The exit receipt from the burn transaction
    /// * `batch_id` - The batch ID where this exit is included
    /// * `created_at` - Timestamp of creation
    pub fn new(exit_receipt: ExitReceipt, batch_id: u64, created_at: Time) -> Self {
        let exit_hash = exit_receipt.hash();
        let destination_chain = exit_receipt.destination_chain;

        Self {
            exit_receipt,
            exit_hash,
            destination_chain,
            merkle_proof: None,
            batch_id,
            status: WithdrawalStatus::Pending,
            created_at,
            finalized_at: None,
            claimed_at: None,
            claim_tx_hash: None,
        }
    }

    /// Mark the withdrawal as ready with a Merkle proof
    ///
    /// Called when the batch is finalized and proof is generated.
    ///
    /// # Arguments
    /// * `proof` - Merkle proof for the exit receipt
    /// * `finalized_at` - Timestamp of finalization
    pub fn mark_ready(&mut self, proof: MerklePath, finalized_at: Time) {
        self.merkle_proof = Some(proof);
        self.status = WithdrawalStatus::Ready;
        self.finalized_at = Some(finalized_at);
    }

    /// Mark the withdrawal as claimed
    ///
    /// Called when the user successfully claims on the target chain.
    ///
    /// # Arguments
    /// * `claimed_at` - Timestamp of claim
    /// * `tx_hash` - L1 transaction hash of the claim
    pub fn mark_claimed(&mut self, claimed_at: Time, tx_hash: [u8; 32]) {
        self.status = WithdrawalStatus::Claimed;
        self.claimed_at = Some(claimed_at);
        self.claim_tx_hash = Some(tx_hash);
    }

    /// Mark the withdrawal as failed
    ///
    /// # Arguments
    /// * `reason` - Reason for failure
    pub fn mark_failed(&mut self, reason: WithdrawalFailureReason) {
        self.status = WithdrawalStatus::Failed(reason);
    }

    /// Check if the withdrawal is ready to be claimed
    pub fn is_ready(&self) -> bool {
        matches!(self.status, WithdrawalStatus::Ready)
    }

    /// Check if the withdrawal has been claimed
    pub fn is_claimed(&self) -> bool {
        matches!(self.status, WithdrawalStatus::Claimed)
    }

    /// Check if the withdrawal is still pending
    pub fn is_pending(&self) -> bool {
        matches!(self.status, WithdrawalStatus::Pending)
    }

    /// Check if the withdrawal has failed
    pub fn is_failed(&self) -> bool {
        matches!(self.status, WithdrawalStatus::Failed(_))
    }
}

/// Proof needed to claim a withdrawal on the target chain
///
/// This structure contains all the information needed for a user to call
/// the withdraw() function on the bridge contract.
#[derive(Clone, Debug)]
pub struct WithdrawalProof {
    /// The exit receipt proving the burn
    pub exit_receipt: ExitReceipt,

    /// Hash of the exit receipt
    pub exit_hash: F,

    /// Merkle proof that exit_hash is in the finalized exit tree
    pub merkle_proof: MerklePath,

    /// The batch ID where this exit was finalized
    pub batch_id: u64,

    /// Root of the exit tree at finalization time
    pub exit_root: F,
}

impl WithdrawalProof {
    /// Create a new withdrawal proof
    ///
    /// # Arguments
    /// * `exit_receipt` - The exit receipt
    /// * `merkle_proof` - Proof of inclusion in exit tree
    /// * `batch_id` - Batch ID where exit was finalized
    /// * `exit_root` - Exit tree root at finalization
    pub fn new(
        exit_receipt: ExitReceipt,
        merkle_proof: MerklePath,
        batch_id: u64,
        exit_root: F,
    ) -> Self {
        let exit_hash = exit_receipt.hash();
        Self {
            exit_receipt,
            exit_hash,
            merkle_proof,
            batch_id,
            exit_root,
        }
    }

    /// Verify that the Merkle proof is valid for the given exit root
    ///
    /// # Arguments
    /// * `params` - Tree parameters for verification
    pub fn verify(&self, params: &crate::merkle::TreeParams) -> bool {
        self.merkle_proof.verify(&self.exit_root, params)
    }

    /// Serialize the proof to bytes for L1 submission
    ///
    /// Returns the proof in a format suitable for the bridge contract.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serialize exit_hash (32 bytes as field element)
        let mut hash_bytes = Vec::new();
        self.exit_hash.serialize_compressed(&mut hash_bytes).unwrap_or_default();
        bytes.extend(&hash_bytes);

        // Serialize batch_id (8 bytes)
        bytes.extend(&self.batch_id.to_be_bytes());

        // Serialize exit_root (32 bytes)
        let mut root_bytes = Vec::new();
        self.exit_root.serialize_compressed(&mut root_bytes).unwrap_or_default();
        bytes.extend(&root_bytes);

        // Serialize Merkle proof
        // First the leaf index (8 bytes)
        bytes.extend(&(self.merkle_proof.leaf_index as u64).to_be_bytes());

        // Then the number of siblings (4 bytes)
        bytes.extend(&(self.merkle_proof.siblings.len() as u32).to_be_bytes());

        // Then each sibling (32 bytes each)
        for sibling in &self.merkle_proof.siblings {
            let mut sibling_bytes = Vec::new();
            sibling.serialize_compressed(&mut sibling_bytes).unwrap_or_default();
            bytes.extend(&sibling_bytes);
        }

        bytes
    }
}

/// Summary of withdrawals for a specific chain
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ChainWithdrawalSummary {
    /// Chain ID
    pub chain_id: ChainId,

    /// Number of pending withdrawals
    pub pending_count: usize,

    /// Number of ready (claimable) withdrawals
    pub ready_count: usize,

    /// Number of claimed withdrawals
    pub claimed_count: usize,

    /// Number of failed withdrawals
    pub failed_count: usize,

    /// Total amount pending withdrawal (in base units)
    pub pending_amount: u128,

    /// Total amount ready for claiming
    pub ready_amount: u128,
}

/// Event emitted when a withdrawal status changes
#[derive(Clone, Debug)]
pub enum WithdrawalEvent {
    /// New withdrawal created
    Created {
        exit_hash: F,
        chain_id: ChainId,
        batch_id: u64,
        amount: u128,
        timestamp: Time,
    },

    /// Withdrawal became ready (batch finalized)
    Ready {
        exit_hash: F,
        chain_id: ChainId,
        batch_id: u64,
        timestamp: Time,
    },

    /// Withdrawal was claimed on L1
    Claimed {
        exit_hash: F,
        chain_id: ChainId,
        claim_tx: [u8; 32],
        timestamp: Time,
    },

    /// Withdrawal failed
    Failed {
        exit_hash: F,
        chain_id: ChainId,
        reason: WithdrawalFailureReason,
        timestamp: Time,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    use crate::types::Amount;

    fn create_test_exit_receipt() -> ExitReceipt {
        let mut rng = thread_rng();
        ExitReceipt {
            destination_chain: 1,
            asset_type: 1,
            amount: Amount::from(1000u64),
            burned_nf: F::rand(&mut rng),
            nonce: 123,
            aux: F::from(0),
        }
    }

    #[test]
    fn test_pending_withdrawal_creation() {
        let receipt = create_test_exit_receipt();
        let withdrawal = PendingWithdrawal::new(receipt.clone(), 5, 1000);

        assert_eq!(withdrawal.destination_chain, 1);
        assert_eq!(withdrawal.batch_id, 5);
        assert!(withdrawal.is_pending());
        assert!(!withdrawal.is_ready());
        assert!(withdrawal.merkle_proof.is_none());
    }

    #[test]
    fn test_withdrawal_status_transitions() {
        let receipt = create_test_exit_receipt();
        let mut withdrawal = PendingWithdrawal::new(receipt, 5, 1000);

        // Initially pending
        assert!(withdrawal.is_pending());
        assert_eq!(withdrawal.status, WithdrawalStatus::Pending);

        // Mark as ready
        let mut rng = thread_rng();
        let proof = MerklePath {
            leaf_index: 0,
            siblings: vec![F::rand(&mut rng), F::rand(&mut rng)],
            leaf: F::rand(&mut rng),
        };
        withdrawal.mark_ready(proof, 2000);

        assert!(withdrawal.is_ready());
        assert_eq!(withdrawal.status, WithdrawalStatus::Ready);
        assert!(withdrawal.merkle_proof.is_some());
        assert_eq!(withdrawal.finalized_at, Some(2000));

        // Mark as claimed
        withdrawal.mark_claimed(3000, [1u8; 32]);

        assert!(withdrawal.is_claimed());
        assert_eq!(withdrawal.status, WithdrawalStatus::Claimed);
        assert_eq!(withdrawal.claimed_at, Some(3000));
        assert_eq!(withdrawal.claim_tx_hash, Some([1u8; 32]));
    }

    #[test]
    fn test_withdrawal_proof_creation() {
        let receipt = create_test_exit_receipt();
        let mut rng = thread_rng();

        let proof = MerklePath {
            leaf_index: 5,
            siblings: vec![F::rand(&mut rng), F::rand(&mut rng), F::rand(&mut rng)],
            leaf: receipt.hash(),
        };

        let exit_root = F::rand(&mut rng);
        let withdrawal_proof = WithdrawalProof::new(
            receipt.clone(),
            proof,
            10,
            exit_root,
        );

        assert_eq!(withdrawal_proof.exit_hash, receipt.hash());
        assert_eq!(withdrawal_proof.batch_id, 10);
        assert_eq!(withdrawal_proof.exit_root, exit_root);
    }

    #[test]
    fn test_withdrawal_proof_serialization() {
        let receipt = create_test_exit_receipt();
        let mut rng = thread_rng();

        let proof = MerklePath {
            leaf_index: 5,
            siblings: vec![F::rand(&mut rng), F::rand(&mut rng)],
            leaf: receipt.hash(),
        };

        let exit_root = F::rand(&mut rng);
        let withdrawal_proof = WithdrawalProof::new(
            receipt,
            proof,
            10,
            exit_root,
        );

        let bytes = withdrawal_proof.to_bytes();

        // Should have: hash(32) + batch_id(8) + root(32) + leaf_index(8) + num_siblings(4) + siblings(32*2)
        // = 32 + 8 + 32 + 8 + 4 + 64 = 148 bytes
        assert!(bytes.len() > 0);
    }

    #[test]
    fn test_withdrawal_failure_status() {
        let receipt = create_test_exit_receipt();
        let mut withdrawal = PendingWithdrawal::new(receipt, 5, 1000);

        withdrawal.mark_failed(WithdrawalFailureReason::InsufficientLiquidity);

        assert!(withdrawal.is_failed());
        assert_eq!(
            withdrawal.status,
            WithdrawalStatus::Failed(WithdrawalFailureReason::InsufficientLiquidity)
        );
    }
}
