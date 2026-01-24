use anchor_lang::prelude::*;
use crate::{MAX_ASSET_TYPES, HISTORICAL_ROOTS_SIZE};

/// Bridge state - main program account
///
/// ## IVC Architecture
///
/// This contract supports IVC (Incrementally Verifiable Computation) where each
/// block proof recursively verifies the previous block. The latest proof
/// cryptographically guarantees all history validity.
#[account]
pub struct BridgeState {
    /// Authority who can manage the bridge
    pub authority: Pubkey,

    /// Sequencer who can submit batches
    pub sequencer: Pubkey,

    /// Last finalized batch ID
    pub last_finalized_batch: u64,

    /// Hash of the last finalized state roots (for IVC state continuity)
    pub last_finalized_roots_hash: [u8; 32],

    /// Current deposit nonce
    pub deposit_nonce: u64,

    /// Whether genesis block has been finalized
    pub genesis_finalized: bool,

    /// Whether the bridge is paused
    pub paused: bool,

    /// PDA bump seed
    pub bump: u8,

    /// Historical roots circular buffer for UTXO spending proofs
    /// Stores recent state root hashes; transactions can reference any of these
    pub historical_roots: [[u8; 32]; HISTORICAL_ROOTS_SIZE],

    /// Next write index in historical roots buffer
    pub next_root_index: u8,

    /// Pool balances per asset type
    pub pool_balances: [u64; MAX_ASSET_TYPES],
}

impl BridgeState {
    pub const LEN: usize = 32 + // authority
        32 + // sequencer
        8 +  // last_finalized_batch
        32 + // last_finalized_roots_hash
        8 +  // deposit_nonce
        1 +  // genesis_finalized
        1 +  // paused
        1 +  // bump
        (32 * HISTORICAL_ROOTS_SIZE) + // historical_roots
        1 +  // next_root_index
        (8 * MAX_ASSET_TYPES); // pool_balances

    /// Add a root hash to the historical roots circular buffer
    pub fn add_historical_root(&mut self, root_hash: [u8; 32]) {
        self.historical_roots[self.next_root_index as usize] = root_hash;
        self.next_root_index = (self.next_root_index + 1) % (HISTORICAL_ROOTS_SIZE as u8);
    }

    /// Check if a root hash exists in the historical roots buffer
    /// Zero hash is always valid (used for empty/padding slots)
    pub fn contains_historical_root(&self, root_hash: &[u8; 32]) -> bool {
        if root_hash == &[0u8; 32] {
            return true;
        }
        self.historical_roots.iter().any(|r| r == root_hash)
    }
}

/// Asset configuration
#[account]
pub struct AssetConfig {
    /// Asset type ID
    pub asset_type: u32,

    /// SPL token mint address
    pub mint: Pubkey,

    /// Minimum deposit amount
    pub min_deposit: u64,

    /// Maximum deposit amount
    pub max_deposit: u64,

    /// Whether this asset is enabled
    pub enabled: bool,

    /// PDA bump seed
    pub bump: u8,
}

impl AssetConfig {
    pub const LEN: usize = 4 + // asset_type
        32 + // mint
        8 +  // min_deposit
        8 +  // max_deposit
        1 +  // enabled
        1;   // bump
}

/// State roots structure matching FLUXE core types
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct StateRoots {
    /// Global commitment tree root
    pub cmt_root: [u8; 32],

    /// Global nullifier tree root
    pub nft_root: [u8; 32],

    /// Global object tree root
    pub obj_root: [u8; 32],

    /// Global callback tree root
    pub cb_root: [u8; 32],

    /// Chain-specific ingress tree root
    pub ingress_root: [u8; 32],

    /// Chain-specific exit tree root
    pub exit_root: [u8; 32],

    /// Sanctions list root
    pub sanctions_root: [u8; 32],

    /// Pool rules root
    pub pool_rules_root: [u8; 32],
}

impl StateRoots {
    pub const LEN: usize = 32 * 8; // 8 roots x 32 bytes
}

/// Batch state - one per finalized batch (IVC-enabled)
///
/// Stores both roots_hash (for IVC verification) and full roots (for withdrawal proofs).
/// The roots_hash is committed by the SP1 proof, and full roots are verified to match.
#[account]
pub struct BatchState {
    /// Batch ID
    pub batch_id: u64,

    /// Hash of state roots for this batch (SHA256 of 8 roots)
    /// This is what the SP1 proof commits to
    pub roots_hash: [u8; 32],

    /// Full state roots (needed for withdrawal verification)
    pub roots: StateRoots,

    /// Number of proofs verified in this batch
    pub proof_count: u32,

    /// Unix timestamp when batch was finalized
    pub timestamp: i64,

    /// PDA bump seed
    pub bump: u8,
}

impl BatchState {
    pub const LEN: usize = 8 + // batch_id
        32 + // roots_hash
        StateRoots::LEN + // roots
        4 +  // proof_count
        8 +  // timestamp
        1;   // bump
}

/// Deposit record - created for each deposit
#[account]
pub struct DepositRecord {
    /// Computed ingress receipt hash
    pub ingress_hash: [u8; 32],

    /// Deposit nonce
    pub nonce: u64,

    /// Asset type
    pub asset_type: u32,

    /// Deposit amount
    pub amount: u64,

    /// Beneficiary commitment
    pub beneficiary_cm: [u8; 32],

    /// Depositor's public key
    pub depositor: Pubkey,

    /// Slot when deposit was made
    pub slot: u64,

    /// PDA bump seed
    pub bump: u8,
}

impl DepositRecord {
    pub const LEN: usize = 32 + // ingress_hash
        8 +  // nonce
        4 +  // asset_type
        8 +  // amount
        32 + // beneficiary_cm
        32 + // depositor
        8 +  // slot
        1;   // bump
}

/// Withdrawal record - created for each withdrawal
#[account]
pub struct WithdrawalRecord {
    /// Exit receipt hash
    pub exit_hash: [u8; 32],

    /// Asset type
    pub asset_type: u32,

    /// Withdrawal amount
    pub amount: u64,

    /// Recipient's public key
    pub recipient: Pubkey,

    /// Batch ID this withdrawal was proven against
    pub batch_id: u64,

    /// Slot when withdrawal was processed
    pub slot: u64,

    /// Whether this withdrawal has been processed
    pub processed: bool,

    /// PDA bump seed
    pub bump: u8,
}

impl WithdrawalRecord {
    pub const LEN: usize = 32 + // exit_hash
        4 +  // asset_type
        8 +  // amount
        32 + // recipient
        8 +  // batch_id
        8 +  // slot
        1 +  // processed
        1;   // bump
}
