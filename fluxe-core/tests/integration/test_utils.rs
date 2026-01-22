//! Test utilities for cross-chain integration tests.
//!
//! This module provides common setup and helper functions for testing
//! FLUXE's multi-chain functionality.

use fluxe_core::bridge::events::DepositEvent;
use fluxe_core::bridge::{
    ChainWithdrawalHandler, PendingWithdrawal, WithdrawalProcessor, WithdrawalStatus,
};
use fluxe_core::data_structures::{ExitReceipt, IngressReceipt};
use fluxe_core::fees::{FeeCollector, FeeWithdrawalResult};
use fluxe_core::merkle::{IncrementalTree, TreeParams};
use fluxe_core::state_manager::{ChainState, GlobalStateManager};
use fluxe_core::types::*;
use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use std::collections::HashMap;

/// Standard tree depth for tests
pub const TEST_TREE_DEPTH: usize = 16;

/// Chain IDs for testing
pub const ETHEREUM_CHAIN_ID: ChainId = 1;
pub const SOLANA_CHAIN_ID: ChainId = 501;
pub const BASE_CHAIN_ID: ChainId = 8453;

/// USDC asset type ID
pub const USDC_ASSET_TYPE: AssetType = 1;

/// Test sequencer address
pub fn test_sequencer_address() -> [u8; 32] {
    let mut addr = [0u8; 32];
    addr[0..20].copy_from_slice(&[0xAB; 20]);
    addr
}

/// Test environment that sets up all components needed for cross-chain testing.
pub struct TestEnvironment {
    /// Global state manager for protocol state
    pub global_state: GlobalStateManager,
    /// Withdrawal processor for tracking cross-chain withdrawals
    pub withdrawal_processor: WithdrawalProcessor,
    /// Fee collector for fee accounting
    pub fee_collector: FeeCollector,
    /// Exit trees per chain (used for Merkle proof generation)
    pub chain_exit_trees: HashMap<ChainId, IncrementalTree>,
    /// Random number generator
    pub rng: ThreadRng,
    /// Current timestamp
    pub current_time: Time,
    /// Current batch ID
    pub current_batch_id: u64,
    /// Nonce counter for receipts
    pub nonce_counter: u64,
}

impl TestEnvironment {
    /// Create a new test environment with Ethereum and Solana chains registered.
    pub fn new() -> Self {
        let mut global_state = GlobalStateManager::new(TEST_TREE_DEPTH);

        // Register chains
        global_state.register_chain(ETHEREUM_CHAIN_ID, ChainType::EVM)
            .expect("Failed to register Ethereum chain");
        global_state.register_chain(SOLANA_CHAIN_ID, ChainType::SVM)
            .expect("Failed to register Solana chain");

        let mut withdrawal_processor = WithdrawalProcessor::new(TEST_TREE_DEPTH);
        withdrawal_processor.register_chain(ETHEREUM_CHAIN_ID)
            .expect("Failed to register Ethereum for withdrawals");
        withdrawal_processor.register_chain(SOLANA_CHAIN_ID)
            .expect("Failed to register Solana for withdrawals");

        let fee_collector = FeeCollector::new(test_sequencer_address());

        let mut chain_exit_trees = HashMap::new();
        chain_exit_trees.insert(ETHEREUM_CHAIN_ID, IncrementalTree::new(TEST_TREE_DEPTH));
        chain_exit_trees.insert(SOLANA_CHAIN_ID, IncrementalTree::new(TEST_TREE_DEPTH));

        Self {
            global_state,
            withdrawal_processor,
            fee_collector,
            chain_exit_trees,
            rng: thread_rng(),
            current_time: 1000,
            current_batch_id: 1,
            nonce_counter: 1,
        }
    }

    /// Create a test environment with an additional chain.
    pub fn with_chain(mut self, chain_id: ChainId, chain_type: ChainType) -> Self {
        self.global_state.register_chain(chain_id, chain_type)
            .expect("Failed to register additional chain");
        self.withdrawal_processor.register_chain(chain_id)
            .expect("Failed to register additional chain for withdrawals");
        self.chain_exit_trees.insert(chain_id, IncrementalTree::new(TEST_TREE_DEPTH));
        self
    }

    /// Advance time by the given amount.
    pub fn advance_time(&mut self, delta: Time) {
        self.current_time += delta;
    }

    /// Advance to next batch.
    pub fn next_batch(&mut self) {
        self.current_batch_id += 1;
    }

    /// Get next nonce.
    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.nonce_counter;
        self.nonce_counter += 1;
        nonce
    }

    /// Create a random field element.
    pub fn random_field(&mut self) -> F {
        F::rand(&mut self.rng)
    }

    /// Create an ingress receipt (deposit).
    pub fn create_ingress_receipt(
        &mut self,
        source_chain: ChainId,
        asset_type: AssetType,
        amount: u128,
    ) -> IngressReceipt {
        let beneficiary_cm = self.random_field();
        let nonce = self.next_nonce();

        IngressReceipt::new(
            source_chain,
            asset_type,
            Amount::from(amount),
            beneficiary_cm,
            nonce,
        )
    }

    /// Create an exit receipt (withdrawal).
    pub fn create_exit_receipt(
        &mut self,
        destination_chain: ChainId,
        asset_type: AssetType,
        amount: u128,
    ) -> ExitReceipt {
        let nullifier = self.random_field();
        let nonce = self.next_nonce();

        ExitReceipt::new(
            destination_chain,
            asset_type,
            Amount::from(amount),
            nullifier,
            nonce,
        )
    }

    /// Create a deposit event from a chain.
    pub fn create_deposit_event(
        &mut self,
        source_chain: ChainId,
        asset_type: AssetType,
        amount: u128,
        block_number: u64,
    ) -> DepositEvent {
        let beneficiary_cm = self.random_field();
        let ingress_hash = self.random_field();
        let mut tx_hash = [0u8; 32];
        for i in 0..32 {
            tx_hash[i] = (self.nonce_counter as u8).wrapping_add(i as u8);
        }

        DepositEvent::new(
            source_chain,
            asset_type,
            Amount::from(amount),
            beneficiary_cm,
            ingress_hash,
            block_number,
        )
        .with_tx_hash(tx_hash)
        .with_log_index(self.next_nonce())
        .with_timestamp(self.current_time)
    }

    /// Process a deposit (mint) on a chain.
    ///
    /// Returns the commitment of the newly created note.
    pub fn process_deposit(
        &mut self,
        source_chain: ChainId,
        asset_type: AssetType,
        amount: u128,
    ) -> Result<(IngressReceipt, Commitment), String> {
        let ingress_receipt = self.create_ingress_receipt(source_chain, asset_type, amount);
        let output_commitment = self.random_field();

        self.global_state
            .process_mint(source_chain, &ingress_receipt, &[output_commitment])
            .map_err(|e| format!("Mint failed: {:?}", e))?;

        Ok((ingress_receipt, output_commitment))
    }

    /// Process a withdrawal (burn) targeting a chain.
    ///
    /// Note: For a withdrawal to succeed, the destination chain must have sufficient
    /// liquidity (deposits). This is the liquidity pool model where each chain
    /// maintains its own supply. To withdraw to a chain, ensure that chain has
    /// been funded with deposits first, or use `process_withdrawal_from_source`
    /// to withdraw back to the source chain.
    ///
    /// Returns the exit receipt and nullifier used.
    pub fn process_withdrawal(
        &mut self,
        destination_chain: ChainId,
        asset_type: AssetType,
        amount: u128,
    ) -> Result<(ExitReceipt, Nullifier), String> {
        let exit_receipt = self.create_exit_receipt(destination_chain, asset_type, amount);
        let nullifier = exit_receipt.burned_nf;

        self.global_state
            .process_burn(destination_chain, &exit_receipt, nullifier)
            .map_err(|e| format!("Burn failed: {:?}", e))?;

        // Add exit receipt to the chain's exit tree
        if let Some(exit_tree) = self.chain_exit_trees.get_mut(&destination_chain) {
            exit_tree.append(exit_receipt.hash());
        }

        // Track withdrawal in processor
        let _exit_hash = self.withdrawal_processor
            .add_withdrawal(
                destination_chain,
                exit_receipt.clone(),
                self.current_batch_id,
                self.current_time,
            )
            .map_err(|e| format!("Failed to add withdrawal: {:?}", e))?;

        Ok((exit_receipt, nullifier))
    }

    /// Seed liquidity on a chain by depositing funds.
    ///
    /// This is a helper for setting up cross-chain withdrawal tests.
    /// In production, liquidity providers would deposit on each chain.
    pub fn seed_liquidity(
        &mut self,
        chain_id: ChainId,
        asset_type: AssetType,
        amount: u128,
    ) -> Result<(), String> {
        let (_receipt, _commitment) = self.process_deposit(chain_id, asset_type, amount)?;
        Ok(())
    }

    /// Finalize the current batch and generate proofs for all pending withdrawals.
    pub fn finalize_batch(&mut self) -> Result<HashMap<ChainId, Vec<[u8; 32]>>, String> {
        let header = BlockHeader {
            prev_roots: StateRoots::default(),
            new_roots: StateRoots::default(),
            batch_id: self.current_batch_id,
            agg_proof: vec![],
            timestamp: self.current_time,
            total_fees: Amount::zero(),
        };

        let result = self.withdrawal_processor
            .process_finalized_batch(
                self.current_batch_id,
                &header,
                &self.chain_exit_trees,
                self.current_time,
            )
            .map_err(|e| format!("Batch finalization failed: {:?}", e))?;

        self.next_batch();
        self.advance_time(100);

        Ok(result)
    }

    /// Collect a fee for a transaction.
    pub fn collect_fee(&mut self, chain_id: ChainId, asset_type: AssetType, amount: u128) {
        self.fee_collector.collect_fee(chain_id, asset_type, Amount::new(amount));
    }

    /// Create fee withdrawal receipts for a chain.
    pub fn create_fee_withdrawal(&mut self, chain_id: ChainId) -> Option<FeeWithdrawalResult> {
        self.fee_collector.create_fee_withdrawal(chain_id)
    }

    /// Get the current global supply for an asset.
    pub fn get_global_supply(&self, asset_type: AssetType) -> Amount {
        self.global_state.get_supply(asset_type)
    }

    /// Get deposited amount on a chain for an asset.
    pub fn get_chain_deposited(&self, chain_id: ChainId, asset_type: AssetType) -> Amount {
        self.global_state
            .get_chain_state(chain_id)
            .map(|cs| cs.get_deposited(asset_type))
            .unwrap_or(Amount::zero())
    }

    /// Get withdrawn amount on a chain for an asset.
    pub fn get_chain_withdrawn(&self, chain_id: ChainId, asset_type: AssetType) -> Amount {
        self.global_state
            .get_chain_state(chain_id)
            .map(|cs| cs.get_withdrawn(asset_type))
            .unwrap_or(Amount::zero())
    }

    /// Check if supply invariant holds.
    pub fn check_supply_invariant(&self, asset_type: AssetType) -> bool {
        self.global_state.check_supply_invariant(asset_type).is_ok()
    }

    /// Get withdrawal status.
    pub fn get_withdrawal_status(
        &self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
    ) -> Option<WithdrawalStatus> {
        self.withdrawal_processor.get_status(chain_id, exit_hash)
    }

    /// Mark a withdrawal as claimed.
    pub fn claim_withdrawal(
        &mut self,
        chain_id: ChainId,
        exit_hash: &[u8; 32],
    ) -> Result<(), String> {
        let claim_tx = [0xCCu8; 32];
        self.withdrawal_processor
            .mark_claimed(chain_id, exit_hash, claim_tx, self.current_time)
            .map_err(|e| format!("Failed to claim: {:?}", e))
    }

    /// Get exit tree root for a chain.
    pub fn get_exit_tree_root(&self, chain_id: ChainId) -> Option<F> {
        self.chain_exit_trees.get(&chain_id).map(|t| t.root())
    }

    /// Verify supply tracking is consistent across all chains.
    pub fn verify_global_consistency(&self) -> Result<(), String> {
        self.global_state
            .check_all_supply_invariants()
            .map_err(|e| format!("Supply invariant violated: {:?}", e))
    }
}

impl Default for TestEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct for tracking multiple deposits in parallel tests.
pub struct ParallelDepositTracker {
    pub deposits: Vec<(ChainId, IngressReceipt, Commitment)>,
}

impl ParallelDepositTracker {
    pub fn new() -> Self {
        Self {
            deposits: Vec::new(),
        }
    }

    pub fn add(&mut self, chain_id: ChainId, receipt: IngressReceipt, commitment: Commitment) {
        self.deposits.push((chain_id, receipt, commitment));
    }

    pub fn total_amount(&self, asset_type: AssetType) -> Amount {
        self.deposits
            .iter()
            .filter(|(_, r, _)| r.asset_type == asset_type)
            .map(|(_, r, _)| r.amount)
            .fold(Amount::zero(), |acc, a| acc.saturating_add(a))
    }

    pub fn count_by_chain(&self, chain_id: ChainId) -> usize {
        self.deposits.iter().filter(|(c, _, _)| *c == chain_id).count()
    }
}

impl Default for ParallelDepositTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper struct for tracking withdrawals.
pub struct WithdrawalTracker {
    pub withdrawals: Vec<(ChainId, ExitReceipt, [u8; 32])>,
}

impl WithdrawalTracker {
    pub fn new() -> Self {
        Self {
            withdrawals: Vec::new(),
        }
    }

    pub fn add(&mut self, chain_id: ChainId, receipt: ExitReceipt, exit_hash: [u8; 32]) {
        self.withdrawals.push((chain_id, receipt, exit_hash));
    }

    pub fn total_amount(&self, asset_type: AssetType) -> Amount {
        self.withdrawals
            .iter()
            .filter(|(_, r, _)| r.asset_type == asset_type)
            .map(|(_, r, _)| r.amount)
            .fold(Amount::zero(), |acc, a| acc.saturating_add(a))
    }
}

impl Default for WithdrawalTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_environment_creation() {
        let env = TestEnvironment::new();

        // Verify chains are registered
        let chains = env.global_state.get_registered_chains();
        assert!(chains.contains(&ETHEREUM_CHAIN_ID));
        assert!(chains.contains(&SOLANA_CHAIN_ID));

        // Verify initial supply is zero
        assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::zero());
    }

    #[test]
    fn test_basic_deposit() {
        let mut env = TestEnvironment::new();

        let (receipt, commitment) = env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1000)
            .expect("Deposit should succeed");

        assert_eq!(receipt.amount, Amount::from(1000u128));
        assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(1000u128));
    }

    #[test]
    fn test_basic_withdrawal() {
        let mut env = TestEnvironment::new();

        // First deposit on Ethereum
        env.process_deposit(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 1000)
            .expect("Deposit should succeed");

        // Seed liquidity on Solana to enable withdrawals there
        // (In production, liquidity providers would do this)
        env.seed_liquidity(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 1000)
            .expect("Seeding liquidity should succeed");

        // Now withdraw to Solana (which has liquidity)
        let (exit_receipt, _nullifier) = env.process_withdrawal(SOLANA_CHAIN_ID, USDC_ASSET_TYPE, 400)
            .expect("Withdrawal should succeed");

        assert_eq!(exit_receipt.amount, Amount::from(400u128));
        // Total supply: 1000 (ETH) + 1000 (SOL) - 400 (withdrawal) = 1600
        assert_eq!(env.get_global_supply(USDC_ASSET_TYPE), Amount::from(1600u128));
    }

    #[test]
    fn test_fee_collection() {
        let mut env = TestEnvironment::new();

        env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 100);
        env.collect_fee(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE, 50);

        let fees = env.fee_collector.get_fees(ETHEREUM_CHAIN_ID, USDC_ASSET_TYPE);
        assert_eq!(fees, Amount::new(150));
    }
}
