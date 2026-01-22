//! FLUXE Bridge V2 - Enhanced with zkSync-style three-phase batch lifecycle
//!
//! This module implements a three-phase commit-prove-execute lifecycle for batch processing:
//! 1. **Commit**: Sequencer submits batch commitment (hash only, no proof yet)
//! 2. **Prove**: Verifier submits proof for the committed batch
//! 3. **Execute**: Finalize batch, process priority operations
//!
//! This design allows for:
//! - Separation of concerns between sequencer and prover
//! - Batch reverts before proof submission
//! - Priority queue for L1->L2 operations
//! - Optimistic or ZK verification modes

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

use crate::error::FluxeError;
use crate::state::*;
use crate::utils::verify_merkle_proof;
use crate::MAX_ASSET_TYPES;

/// Chain ID for Solana mainnet
pub const CHAIN_ID: u32 = 501;

/// Maximum priority operations per batch
pub const MAX_PRIORITY_OPS_PER_BATCH: usize = 100;

/// Verification mode for batch proofs
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationMode {
    /// ZK proof verification via Groth16 verifier CPI
    #[default]
    ZkProof,
    /// Optimistic verification with challenge period
    Optimistic,
}

/// Batch phase in the three-phase lifecycle
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Default)]
pub enum BatchPhase {
    /// Batch has been committed but not yet proven
    #[default]
    Committed,
    /// Batch has been proven but not yet executed
    Proved,
    /// Batch has been fully executed and finalized
    Executed,
}

/// Priority operation type
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq)]
pub enum PriorityOpType {
    /// Deposit from L1 to L2
    Deposit,
    /// Forced withdrawal request
    ForcedWithdrawal,
    /// Forced transaction execution
    ForcedTransaction,
}

// ============ V2 State Structures ============

/// Enhanced bridge state with three-phase tracking
#[account]
pub struct BridgeStateV2 {
    /// Authority who can manage the bridge
    pub authority: Pubkey,

    /// Sequencer who can commit batches
    pub sequencer: Pubkey,

    /// Verifier who can prove batches (can be same as sequencer)
    pub verifier: Pubkey,

    /// Total batches committed (phase 1 complete)
    pub total_batches_committed: u64,

    /// Total batches proved (phase 2 complete)
    pub total_batches_proved: u64,

    /// Total batches executed (phase 3 complete)
    pub total_batches_executed: u64,

    /// Current deposit nonce
    pub deposit_nonce: u64,

    /// Priority queue head index
    pub priority_queue_head: u64,

    /// Priority queue tail index
    pub priority_queue_tail: u64,

    /// Verification mode (ZK or Optimistic)
    pub verification_mode: VerificationMode,

    /// Challenge period in seconds (for optimistic mode)
    pub challenge_period: i64,

    /// Whether the bridge is paused
    pub paused: bool,

    /// PDA bump seed
    pub bump: u8,

    /// Pool balances per asset type
    pub pool_balances: [u64; MAX_ASSET_TYPES],
}

impl BridgeStateV2 {
    pub const LEN: usize = 32 +  // authority
        32 +  // sequencer
        32 +  // verifier
        8 +   // total_batches_committed
        8 +   // total_batches_proved
        8 +   // total_batches_executed
        8 +   // deposit_nonce
        8 +   // priority_queue_head
        8 +   // priority_queue_tail
        1 +   // verification_mode
        8 +   // challenge_period
        1 +   // paused
        1 +   // bump
        (8 * MAX_ASSET_TYPES); // pool_balances
}

/// Batch commitment - stores committed but unproven batch data
#[account]
pub struct BatchCommitment {
    /// Batch ID
    pub batch_id: u64,

    /// Hash of all state roots for this batch
    pub state_roots_hash: [u8; 32],

    /// Number of transactions in this batch
    pub tx_count: u32,

    /// Root hash of L2 logs
    pub l2_logs_root: [u8; 32],

    /// Hash of priority operations to be processed
    pub priority_ops_hash: [u8; 32],

    /// Number of priority operations in this batch
    pub priority_ops_count: u32,

    /// Index of first priority op in this batch
    pub priority_ops_start_index: u64,

    /// Timestamp when batch was committed
    pub committed_at: i64,

    /// Current phase of this batch
    pub phase: BatchPhase,

    /// PDA bump seed
    pub bump: u8,
}

impl BatchCommitment {
    pub const LEN: usize = 8 +   // batch_id
        32 +  // state_roots_hash
        4 +   // tx_count
        32 +  // l2_logs_root
        32 +  // priority_ops_hash
        4 +   // priority_ops_count
        8 +   // priority_ops_start_index
        8 +   // committed_at
        1 +   // phase
        1;    // bump
}

/// Batch proof - stores proof data for verification
#[account]
pub struct BatchProof {
    /// Batch ID this proof is for
    pub batch_id: u64,

    /// Full state roots after batch execution
    pub state_roots: StateRoots,

    /// Groth16 proof data (serialized)
    pub proof_a: [u8; 64],  // G1 point
    pub proof_b: [u8; 128], // G2 point
    pub proof_c: [u8; 64],  // G1 point

    /// Public inputs hash for verification
    pub public_inputs_hash: [u8; 32],

    /// Timestamp when proof was submitted
    pub proved_at: i64,

    /// Address that submitted the proof
    pub prover: Pubkey,

    /// PDA bump seed
    pub bump: u8,
}

impl BatchProof {
    pub const LEN: usize = 8 +   // batch_id
        StateRoots::LEN +         // state_roots
        64 +  // proof_a
        128 + // proof_b
        64 +  // proof_c
        32 +  // public_inputs_hash
        8 +   // proved_at
        32 +  // prover
        1;    // bump
}

/// Enhanced batch state with phase tracking
#[account]
pub struct BatchStateV2 {
    /// Batch ID
    pub batch_id: u64,

    /// State roots for this batch (populated after proof)
    pub roots: StateRoots,

    /// Current phase
    pub phase: BatchPhase,

    /// Timestamp when batch was committed
    pub committed_at: i64,

    /// Timestamp when batch was proved (0 if not proved)
    pub proved_at: i64,

    /// Timestamp when batch was executed (0 if not executed)
    pub executed_at: i64,

    /// Number of priority ops processed in this batch
    pub priority_ops_processed: u32,

    /// PDA bump seed
    pub bump: u8,
}

impl BatchStateV2 {
    pub const LEN: usize = 8 +   // batch_id
        StateRoots::LEN +         // roots
        1 +   // phase
        8 +   // committed_at
        8 +   // proved_at
        8 +   // executed_at
        4 +   // priority_ops_processed
        1;    // bump
}

/// Priority operation for L1->L2 queue
#[account]
pub struct PriorityOperation {
    /// Index in the priority queue
    pub index: u64,

    /// Operation type
    pub op_type: PriorityOpType,

    /// Depositor/requester address
    pub sender: Pubkey,

    /// Asset type for the operation
    pub asset_type: u32,

    /// Amount involved
    pub amount: u64,

    /// Beneficiary commitment (for deposits)
    pub beneficiary_cm: [u8; 32],

    /// Operation hash
    pub op_hash: [u8; 32],

    /// Timestamp when operation was created
    pub created_at: i64,

    /// Expiration timestamp (for forced operations)
    pub expires_at: i64,

    /// Whether this operation has been processed
    pub processed: bool,

    /// Batch ID that processed this operation (0 if not processed)
    pub processed_in_batch: u64,

    /// PDA bump seed
    pub bump: u8,
}

impl PriorityOperation {
    pub const LEN: usize = 8 +   // index
        1 +   // op_type
        32 +  // sender
        4 +   // asset_type
        8 +   // amount
        32 +  // beneficiary_cm
        32 +  // op_hash
        8 +   // created_at
        8 +   // expires_at
        1 +   // processed
        8 +   // processed_in_batch
        1;    // bump
}

// ============ V2 Instructions Module ============

#[program]
pub mod fluxe_bridge_v2 {
    use super::*;

    /// Initialize the V2 bridge with three-phase support
    pub fn initialize_v2(
        ctx: Context<InitializeV2>,
        sequencer: Pubkey,
        verifier: Pubkey,
        verification_mode: VerificationMode,
        challenge_period: i64,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        bridge.authority = ctx.accounts.authority.key();
        bridge.sequencer = sequencer;
        bridge.verifier = verifier;
        bridge.total_batches_committed = 0;
        bridge.total_batches_proved = 0;
        bridge.total_batches_executed = 0;
        bridge.deposit_nonce = 0;
        bridge.priority_queue_head = 0;
        bridge.priority_queue_tail = 0;
        bridge.verification_mode = verification_mode;
        bridge.challenge_period = challenge_period;
        bridge.paused = false;
        bridge.bump = ctx.bumps.bridge;
        bridge.pool_balances = [0u64; MAX_ASSET_TYPES];

        emit!(BridgeInitializedV2 {
            authority: bridge.authority,
            sequencer: bridge.sequencer,
            verifier: bridge.verifier,
            verification_mode,
            challenge_period,
        });

        Ok(())
    }

    /// Register a new asset type with mint address
    pub fn register_asset_v2(
        ctx: Context<RegisterAssetV2>,
        asset_type: u32,
        min_deposit: u64,
        max_deposit: u64,
    ) -> Result<()> {
        require!(asset_type < MAX_ASSET_TYPES as u32, FluxeError::InvalidAssetType);

        let asset_config = &mut ctx.accounts.asset_config;
        asset_config.asset_type = asset_type;
        asset_config.mint = ctx.accounts.mint.key();
        asset_config.min_deposit = min_deposit;
        asset_config.max_deposit = max_deposit;
        asset_config.enabled = true;
        asset_config.bump = ctx.bumps.asset_config;

        emit!(AssetRegisteredV2 {
            asset_type,
            mint: ctx.accounts.mint.key(),
            min_deposit,
            max_deposit,
        });

        Ok(())
    }

    /// Deposit tokens into FLUXE L2 (adds to priority queue)
    pub fn deposit_v2(
        ctx: Context<DepositV2>,
        asset_type: u32,
        amount: u64,
        beneficiary_cm: [u8; 32],
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let asset_config = &ctx.accounts.asset_config;

        // Validate state
        require!(!bridge.paused, FluxeError::BridgePaused);
        require!(asset_config.enabled, FluxeError::AssetDisabled);
        require!(amount > 0, FluxeError::ZeroAmount);
        require!(amount >= asset_config.min_deposit, FluxeError::AmountBelowMinimum);
        require!(amount <= asset_config.max_deposit, FluxeError::AmountAboveMaximum);
        require!(beneficiary_cm != [0u8; 32], FluxeError::InvalidBeneficiary);

        let nonce = bridge.deposit_nonce;
        let priority_index = bridge.priority_queue_tail;

        // Compute operation hash
        let op_hash = compute_priority_op_hash(
            PriorityOpType::Deposit,
            ctx.accounts.user.key(),
            asset_type,
            amount,
            &beneficiary_cm,
            priority_index,
        );

        // Increment counters
        bridge.deposit_nonce = bridge.deposit_nonce.checked_add(1)
            .ok_or(FluxeError::NonceOverflow)?;
        bridge.priority_queue_tail = bridge.priority_queue_tail.checked_add(1)
            .ok_or(FluxeError::NonceOverflow)?;

        // Transfer tokens from user to bridge vault
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.bridge_vault.to_account_info(),
            authority: ctx.accounts.user.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        // Update pool balance
        bridge.pool_balances[asset_type as usize] = bridge.pool_balances[asset_type as usize]
            .checked_add(amount)
            .ok_or(FluxeError::PoolOverflow)?;

        // Initialize priority operation
        let priority_op = &mut ctx.accounts.priority_operation;
        let clock = Clock::get()?;
        priority_op.index = priority_index;
        priority_op.op_type = PriorityOpType::Deposit;
        priority_op.sender = ctx.accounts.user.key();
        priority_op.asset_type = asset_type;
        priority_op.amount = amount;
        priority_op.beneficiary_cm = beneficiary_cm;
        priority_op.op_hash = op_hash;
        priority_op.created_at = clock.unix_timestamp;
        priority_op.expires_at = 0; // Deposits don't expire
        priority_op.processed = false;
        priority_op.processed_in_batch = 0;
        priority_op.bump = ctx.bumps.priority_operation;

        emit!(DepositEventV2 {
            asset_type,
            amount,
            beneficiary_cm,
            op_hash,
            priority_index,
            nonce,
            depositor: ctx.accounts.user.key(),
        });

        Ok(())
    }

    // ============ Three-Phase Batch Lifecycle ============

    /// Phase 1: Commit a batch (sequencer only)
    /// Stores batch commitment without proof
    pub fn commit_batch(
        ctx: Context<CommitBatch>,
        batch_id: u64,
        state_roots_hash: [u8; 32],
        tx_count: u32,
        l2_logs_root: [u8; 32],
        priority_ops_hash: [u8; 32],
        priority_ops_count: u32,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;

        // Validate sequencer
        require!(
            ctx.accounts.sequencer.key() == bridge.sequencer,
            FluxeError::InvalidSequencer
        );

        // Validate batch ID is sequential
        require!(
            batch_id == bridge.total_batches_committed + 1,
            FluxeError::InvalidBatchId
        );

        require!(!bridge.paused, FluxeError::BridgePaused);

        // Validate priority ops count doesn't exceed maximum
        require!(
            priority_ops_count <= MAX_PRIORITY_OPS_PER_BATCH as u32,
            FluxeError::TooManyPriorityOps
        );

        let clock = Clock::get()?;
        let priority_ops_start = bridge.priority_queue_head;

        // Initialize batch commitment
        let commitment = &mut ctx.accounts.batch_commitment;
        commitment.batch_id = batch_id;
        commitment.state_roots_hash = state_roots_hash;
        commitment.tx_count = tx_count;
        commitment.l2_logs_root = l2_logs_root;
        commitment.priority_ops_hash = priority_ops_hash;
        commitment.priority_ops_count = priority_ops_count;
        commitment.priority_ops_start_index = priority_ops_start;
        commitment.committed_at = clock.unix_timestamp;
        commitment.phase = BatchPhase::Committed;
        commitment.bump = ctx.bumps.batch_commitment;

        // Update bridge state
        bridge.total_batches_committed = batch_id;

        emit!(BatchCommittedEvent {
            batch_id,
            state_roots_hash,
            tx_count,
            l2_logs_root,
            priority_ops_hash,
            priority_ops_count,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Phase 2: Prove a batch (verifier submits proof)
    pub fn prove_batch(
        ctx: Context<ProveBatch>,
        batch_id: u64,
        state_roots: StateRoots,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs_hash: [u8; 32],
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let commitment = &mut ctx.accounts.batch_commitment;

        // Validate verifier
        require!(
            ctx.accounts.verifier.key() == bridge.verifier,
            FluxeError::InvalidVerifier
        );

        // Validate batch exists and is in committed phase
        require!(
            commitment.batch_id == batch_id,
            FluxeError::InvalidBatchId
        );
        require!(
            commitment.phase == BatchPhase::Committed,
            FluxeError::InvalidBatchPhase
        );

        // Validate batch ID is next to be proved (must prove in order)
        require!(
            batch_id == bridge.total_batches_proved + 1,
            FluxeError::BatchNotReadyForProof
        );

        require!(!bridge.paused, FluxeError::BridgePaused);

        // Verify state roots hash matches commitment
        let computed_roots_hash = compute_state_roots_hash(&state_roots);
        require!(
            computed_roots_hash == commitment.state_roots_hash,
            FluxeError::StateRootsMismatch
        );

        // In ZK mode, we would verify the proof here via CPI to Groth16 verifier
        // For now, we accept the proof if verification mode is Optimistic
        // In production, this would invoke the verifier program
        if bridge.verification_mode == VerificationMode::ZkProof {
            // TODO: CPI to Groth16 verifier program
            // verify_groth16_proof(proof_a, proof_b, proof_c, public_inputs)?;
            msg!("ZK proof verification would be performed here via CPI");
        }

        let clock = Clock::get()?;

        // Initialize batch proof
        let batch_proof = &mut ctx.accounts.batch_proof;
        batch_proof.batch_id = batch_id;
        batch_proof.state_roots = state_roots;
        batch_proof.proof_a = proof_a;
        batch_proof.proof_b = proof_b;
        batch_proof.proof_c = proof_c;
        batch_proof.public_inputs_hash = public_inputs_hash;
        batch_proof.proved_at = clock.unix_timestamp;
        batch_proof.prover = ctx.accounts.verifier.key();
        batch_proof.bump = ctx.bumps.batch_proof;

        // Update commitment phase
        commitment.phase = BatchPhase::Proved;

        // Update bridge state
        bridge.total_batches_proved = batch_id;

        emit!(BatchProvedEvent {
            batch_id,
            state_roots_hash: computed_roots_hash,
            prover: ctx.accounts.verifier.key(),
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Phase 3: Execute a batch (finalize and process priority ops)
    pub fn execute_batch(
        ctx: Context<ExecuteBatch>,
        batch_id: u64,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let commitment = &ctx.accounts.batch_commitment;
        let batch_proof = &ctx.accounts.batch_proof;

        // Validate batch exists and is in proved phase
        require!(
            commitment.batch_id == batch_id,
            FluxeError::InvalidBatchId
        );
        require!(
            commitment.phase == BatchPhase::Proved,
            FluxeError::InvalidBatchPhase
        );

        // Validate batch ID is next to be executed (must execute in order)
        require!(
            batch_id == bridge.total_batches_executed + 1,
            FluxeError::BatchNotReadyForExecution
        );

        require!(!bridge.paused, FluxeError::BridgePaused);

        // In optimistic mode, check challenge period has passed
        if bridge.verification_mode == VerificationMode::Optimistic {
            let clock = Clock::get()?;
            let time_since_proof = clock.unix_timestamp - batch_proof.proved_at;
            require!(
                time_since_proof >= bridge.challenge_period,
                FluxeError::ChallengePeriodNotPassed
            );
        }

        let clock = Clock::get()?;

        // Initialize batch state
        let batch_state = &mut ctx.accounts.batch_state;
        batch_state.batch_id = batch_id;
        batch_state.roots = batch_proof.state_roots;
        batch_state.phase = BatchPhase::Executed;
        batch_state.committed_at = commitment.committed_at;
        batch_state.proved_at = batch_proof.proved_at;
        batch_state.executed_at = clock.unix_timestamp;
        batch_state.priority_ops_processed = commitment.priority_ops_count;
        batch_state.bump = ctx.bumps.batch_state;

        // Update priority queue head
        bridge.priority_queue_head = bridge.priority_queue_head
            .checked_add(commitment.priority_ops_count as u64)
            .ok_or(FluxeError::NonceOverflow)?;

        // Update bridge state
        bridge.total_batches_executed = batch_id;

        emit!(BatchExecutedEvent {
            batch_id,
            cmt_root: batch_proof.state_roots.cmt_root,
            nft_root: batch_proof.state_roots.nft_root,
            exit_root: batch_proof.state_roots.exit_root,
            priority_ops_processed: commitment.priority_ops_count,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    /// Revert uncommitted batches (admin function for emergency)
    /// Reverts all batches after new_last_batch that haven't been executed
    pub fn revert_batches(
        ctx: Context<RevertBatches>,
        new_last_batch: u64,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;

        // Can only revert to a batch that has been executed
        require!(
            new_last_batch >= bridge.total_batches_executed,
            FluxeError::CannotRevertExecutedBatch
        );

        // Can only revert if there are uncommitted/unproved batches
        require!(
            new_last_batch < bridge.total_batches_committed,
            FluxeError::NothingToRevert
        );

        let old_committed = bridge.total_batches_committed;
        let old_proved = bridge.total_batches_proved;

        // Revert committed and proved counters
        bridge.total_batches_committed = new_last_batch;
        if bridge.total_batches_proved > new_last_batch {
            bridge.total_batches_proved = new_last_batch;
        }

        emit!(BatchRevertedEvent {
            new_last_batch,
            old_committed,
            old_proved,
            reverted_by: ctx.accounts.authority.key(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Withdraw tokens using exit receipt proof (same as V1 but uses V2 state)
    pub fn withdraw_v2(
        ctx: Context<WithdrawV2>,
        exit_receipt_hash: [u8; 32],
        asset_type: u32,
        amount: u64,
        batch_id: u64,
        merkle_proof: Vec<[u8; 32]>,
    ) -> Result<()> {
        // Validate batch_id matches the batch state
        require!(
            ctx.accounts.batch_state.batch_id == batch_id,
            FluxeError::InvalidBatchId
        );

        // Batch must be executed
        require!(
            ctx.accounts.batch_state.phase == BatchPhase::Executed,
            FluxeError::BatchNotExecuted
        );

        let batch_state = &ctx.accounts.batch_state;
        let withdrawal_record = &mut ctx.accounts.withdrawal_record;

        // Validate state
        require!(!ctx.accounts.bridge.paused, FluxeError::BridgePaused);
        require!(!withdrawal_record.processed, FluxeError::AlreadyWithdrawn);

        // Verify exit receipt is in the finalized batch's exit tree
        require!(
            verify_merkle_proof(&merkle_proof, batch_state.roots.exit_root, exit_receipt_hash),
            FluxeError::InvalidExitProof
        );

        // Check pool has sufficient liquidity
        require!(
            ctx.accounts.bridge.pool_balances[asset_type as usize] >= amount,
            FluxeError::InsufficientLiquidity
        );

        // Get bump for signer seeds before mutable borrow
        let bump = ctx.accounts.bridge.bump;

        // Transfer tokens from vault to user
        let seeds = &[
            b"bridge_v2".as_ref(),
            &[bump],
        ];
        let signer_seeds = &[&seeds[..]];

        let cpi_accounts = Transfer {
            from: ctx.accounts.bridge_vault.to_account_info(),
            to: ctx.accounts.user_token_account.to_account_info(),
            authority: ctx.accounts.bridge.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let cpi_ctx = CpiContext::new_with_signer(cpi_program, cpi_accounts, signer_seeds);
        token::transfer(cpi_ctx, amount)?;

        // Now take mutable borrow for state updates
        let bridge = &mut ctx.accounts.bridge;

        // Update pool balance
        bridge.pool_balances[asset_type as usize] = bridge.pool_balances[asset_type as usize]
            .checked_sub(amount)
            .ok_or(FluxeError::PoolUnderflow)?;

        // Mark withdrawal as processed
        withdrawal_record.processed = true;
        withdrawal_record.exit_hash = exit_receipt_hash;
        withdrawal_record.asset_type = asset_type;
        withdrawal_record.amount = amount;
        withdrawal_record.recipient = ctx.accounts.user.key();
        withdrawal_record.batch_id = batch_state.batch_id;
        withdrawal_record.slot = Clock::get()?.slot;
        withdrawal_record.bump = ctx.bumps.withdrawal_record;

        emit!(WithdrawalEventV2 {
            asset_type,
            amount,
            recipient: ctx.accounts.user.key(),
            exit_hash: exit_receipt_hash,
            batch_id: batch_state.batch_id,
        });

        Ok(())
    }

    /// Mark a priority operation as processed (called during batch execution)
    pub fn process_priority_op(
        ctx: Context<ProcessPriorityOp>,
        priority_index: u64,
        batch_id: u64,
    ) -> Result<()> {
        let priority_op = &mut ctx.accounts.priority_operation;

        // Validate operation exists and isn't processed
        require!(
            priority_op.index == priority_index,
            FluxeError::InvalidPriorityOp
        );
        require!(
            !priority_op.processed,
            FluxeError::PriorityOpAlreadyProcessed
        );

        // Mark as processed
        priority_op.processed = true;
        priority_op.processed_in_batch = batch_id;

        Ok(())
    }

    // ============ Admin Functions ============

    /// Pause the bridge (emergency)
    pub fn pause_v2(ctx: Context<AdminActionV2>) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        require!(!bridge.paused, FluxeError::AlreadyPaused);
        bridge.paused = true;

        emit!(BridgePausedV2 {
            authority: ctx.accounts.authority.key(),
        });

        Ok(())
    }

    /// Unpause the bridge
    pub fn unpause_v2(ctx: Context<AdminActionV2>) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        require!(bridge.paused, FluxeError::NotPaused);
        bridge.paused = false;

        emit!(BridgeUnpausedV2 {
            authority: ctx.accounts.authority.key(),
        });

        Ok(())
    }

    /// Update sequencer address
    pub fn update_sequencer_v2(ctx: Context<AdminActionV2>, new_sequencer: Pubkey) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let old_sequencer = bridge.sequencer;
        bridge.sequencer = new_sequencer;

        emit!(SequencerUpdatedV2 {
            old_sequencer,
            new_sequencer,
        });

        Ok(())
    }

    /// Update verifier address
    pub fn update_verifier(ctx: Context<AdminActionV2>, new_verifier: Pubkey) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let old_verifier = bridge.verifier;
        bridge.verifier = new_verifier;

        emit!(VerifierUpdated {
            old_verifier,
            new_verifier,
        });

        Ok(())
    }

    /// Update verification mode
    pub fn update_verification_mode(
        ctx: Context<AdminActionV2>,
        new_mode: VerificationMode,
        new_challenge_period: i64,
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        bridge.verification_mode = new_mode;
        bridge.challenge_period = new_challenge_period;

        emit!(VerificationModeUpdated {
            new_mode,
            new_challenge_period,
        });

        Ok(())
    }

    /// Update asset configuration
    pub fn update_asset_v2(
        ctx: Context<UpdateAssetV2>,
        enabled: bool,
        min_deposit: u64,
        max_deposit: u64,
    ) -> Result<()> {
        let asset_config = &mut ctx.accounts.asset_config;
        asset_config.enabled = enabled;
        asset_config.min_deposit = min_deposit;
        asset_config.max_deposit = max_deposit;

        emit!(AssetUpdatedV2 {
            asset_type: asset_config.asset_type,
            enabled,
            min_deposit,
            max_deposit,
        });

        Ok(())
    }
}

// ============ Account Contexts ============

#[derive(Accounts)]
pub struct InitializeV2<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + BridgeStateV2::LEN,
        seeds = [b"bridge_v2"],
        bump
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(asset_type: u32)]
pub struct RegisterAssetV2<'info> {
    #[account(
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        init,
        payer = authority,
        space = 8 + AssetConfig::LEN,
        seeds = [b"asset_v2", asset_type.to_le_bytes().as_ref()],
        bump
    )]
    pub asset_config: Account<'info, AssetConfig>,

    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(asset_type: u32, amount: u64, beneficiary_cm: [u8; 32])]
pub struct DepositV2<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        seeds = [b"asset_v2", asset_type.to_le_bytes().as_ref()],
        bump = asset_config.bump,
        constraint = asset_config.asset_type == asset_type @ FluxeError::InvalidAssetType,
    )]
    pub asset_config: Account<'info, AssetConfig>,

    #[account(
        init,
        payer = user,
        space = 8 + PriorityOperation::LEN,
        seeds = [b"priority_op", bridge.priority_queue_tail.to_le_bytes().as_ref()],
        bump
    )]
    pub priority_operation: Account<'info, PriorityOperation>,

    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ FluxeError::InvalidTokenAccount,
        constraint = user_token_account.mint == asset_config.mint @ FluxeError::MintMismatch,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"vault_v2", asset_type.to_le_bytes().as_ref()],
        bump,
        constraint = bridge_vault.mint == asset_config.mint @ FluxeError::MintMismatch,
    )]
    pub bridge_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_id: u64)]
pub struct CommitBatch<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        init,
        payer = sequencer,
        space = 8 + BatchCommitment::LEN,
        seeds = [b"batch_commitment", batch_id.to_le_bytes().as_ref()],
        bump
    )]
    pub batch_commitment: Account<'info, BatchCommitment>,

    #[account(mut)]
    pub sequencer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_id: u64)]
pub struct ProveBatch<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        mut,
        seeds = [b"batch_commitment", batch_id.to_le_bytes().as_ref()],
        bump = batch_commitment.bump,
    )]
    pub batch_commitment: Account<'info, BatchCommitment>,

    #[account(
        init,
        payer = verifier,
        space = 8 + BatchProof::LEN,
        seeds = [b"batch_proof", batch_id.to_le_bytes().as_ref()],
        bump
    )]
    pub batch_proof: Account<'info, BatchProof>,

    #[account(mut)]
    pub verifier: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(batch_id: u64)]
pub struct ExecuteBatch<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        seeds = [b"batch_commitment", batch_id.to_le_bytes().as_ref()],
        bump = batch_commitment.bump,
    )]
    pub batch_commitment: Account<'info, BatchCommitment>,

    #[account(
        seeds = [b"batch_proof", batch_id.to_le_bytes().as_ref()],
        bump = batch_proof.bump,
    )]
    pub batch_proof: Account<'info, BatchProof>,

    #[account(
        init,
        payer = executor,
        space = 8 + BatchStateV2::LEN,
        seeds = [b"batch_state_v2", batch_id.to_le_bytes().as_ref()],
        bump
    )]
    pub batch_state: Account<'info, BatchStateV2>,

    #[account(mut)]
    pub executor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RevertBatches<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(exit_receipt_hash: [u8; 32], asset_type: u32, amount: u64, batch_id: u64)]
pub struct WithdrawV2<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        seeds = [b"batch_state_v2", batch_id.to_le_bytes().as_ref()],
        bump = batch_state.bump,
    )]
    pub batch_state: Account<'info, BatchStateV2>,

    #[account(
        init,
        payer = user,
        space = 8 + WithdrawalRecord::LEN,
        seeds = [b"withdrawal_v2", exit_receipt_hash.as_ref()],
        bump
    )]
    pub withdrawal_record: Account<'info, WithdrawalRecord>,

    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ FluxeError::InvalidTokenAccount,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"vault_v2", asset_type.to_le_bytes().as_ref()],
        bump,
    )]
    pub bridge_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(priority_index: u64)]
pub struct ProcessPriorityOp<'info> {
    #[account(
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(
        mut,
        seeds = [b"priority_op", priority_index.to_le_bytes().as_ref()],
        bump = priority_operation.bump,
    )]
    pub priority_operation: Account<'info, PriorityOperation>,

    /// Must be sequencer or verifier
    #[account(
        constraint = operator.key() == bridge.sequencer || operator.key() == bridge.verifier @ FluxeError::InvalidSequencer
    )]
    pub operator: Signer<'info>,
}

#[derive(Accounts)]
pub struct AdminActionV2<'info> {
    #[account(
        mut,
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateAssetV2<'info> {
    #[account(
        seeds = [b"bridge_v2"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeStateV2>,

    #[account(mut)]
    pub asset_config: Account<'info, AssetConfig>,

    pub authority: Signer<'info>,
}

// ============ Helper Functions ============

/// Compute priority operation hash
fn compute_priority_op_hash(
    op_type: PriorityOpType,
    sender: Pubkey,
    asset_type: u32,
    amount: u64,
    beneficiary_cm: &[u8; 32],
    index: u64,
) -> [u8; 32] {
    use solana_program::keccak::hashv;

    let op_type_byte = match op_type {
        PriorityOpType::Deposit => 0u8,
        PriorityOpType::ForcedWithdrawal => 1u8,
        PriorityOpType::ForcedTransaction => 2u8,
    };

    let hash = hashv(&[
        &[op_type_byte],
        sender.as_ref(),
        &asset_type.to_le_bytes(),
        &amount.to_le_bytes(),
        beneficiary_cm,
        &index.to_le_bytes(),
    ]);

    hash.0
}

/// Compute state roots hash for commitment verification
fn compute_state_roots_hash(roots: &StateRoots) -> [u8; 32] {
    use solana_program::keccak::hashv;

    let hash = hashv(&[
        &roots.cmt_root,
        &roots.nft_root,
        &roots.obj_root,
        &roots.cb_root,
        &roots.ingress_root,
        &roots.exit_root,
        &roots.sanctions_root,
        &roots.pool_rules_root,
    ]);

    hash.0
}

// ============ V2 Events ============

#[event]
pub struct BridgeInitializedV2 {
    pub authority: Pubkey,
    pub sequencer: Pubkey,
    pub verifier: Pubkey,
    pub verification_mode: VerificationMode,
    pub challenge_period: i64,
}

#[event]
pub struct AssetRegisteredV2 {
    pub asset_type: u32,
    pub mint: Pubkey,
    pub min_deposit: u64,
    pub max_deposit: u64,
}

#[event]
pub struct AssetUpdatedV2 {
    pub asset_type: u32,
    pub enabled: bool,
    pub min_deposit: u64,
    pub max_deposit: u64,
}

#[event]
pub struct DepositEventV2 {
    pub asset_type: u32,
    pub amount: u64,
    pub beneficiary_cm: [u8; 32],
    pub op_hash: [u8; 32],
    pub priority_index: u64,
    pub nonce: u64,
    pub depositor: Pubkey,
}

#[event]
pub struct BatchCommittedEvent {
    pub batch_id: u64,
    pub state_roots_hash: [u8; 32],
    pub tx_count: u32,
    pub l2_logs_root: [u8; 32],
    pub priority_ops_hash: [u8; 32],
    pub priority_ops_count: u32,
    pub timestamp: i64,
}

#[event]
pub struct BatchProvedEvent {
    pub batch_id: u64,
    pub state_roots_hash: [u8; 32],
    pub prover: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct BatchExecutedEvent {
    pub batch_id: u64,
    pub cmt_root: [u8; 32],
    pub nft_root: [u8; 32],
    pub exit_root: [u8; 32],
    pub priority_ops_processed: u32,
    pub timestamp: i64,
}

#[event]
pub struct BatchRevertedEvent {
    pub new_last_batch: u64,
    pub old_committed: u64,
    pub old_proved: u64,
    pub reverted_by: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawalEventV2 {
    pub asset_type: u32,
    pub amount: u64,
    pub recipient: Pubkey,
    pub exit_hash: [u8; 32],
    pub batch_id: u64,
}

#[event]
pub struct BridgePausedV2 {
    pub authority: Pubkey,
}

#[event]
pub struct BridgeUnpausedV2 {
    pub authority: Pubkey,
}

#[event]
pub struct SequencerUpdatedV2 {
    pub old_sequencer: Pubkey,
    pub new_sequencer: Pubkey,
}

#[event]
pub struct VerifierUpdated {
    pub old_verifier: Pubkey,
    pub new_verifier: Pubkey,
}

#[event]
pub struct VerificationModeUpdated {
    pub new_mode: VerificationMode,
    pub new_challenge_period: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_state_roots_hash() {
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

        let hash = compute_state_roots_hash(&roots);
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);

        // Same input should produce same hash
        let hash2 = compute_state_roots_hash(&roots);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_compute_priority_op_hash() {
        let sender = Pubkey::new_unique();
        let beneficiary_cm = [42u8; 32];

        let hash = compute_priority_op_hash(
            PriorityOpType::Deposit,
            sender,
            1,
            1000,
            &beneficiary_cm,
            0,
        );

        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);

        // Different op type should produce different hash
        let hash2 = compute_priority_op_hash(
            PriorityOpType::ForcedWithdrawal,
            sender,
            1,
            1000,
            &beneficiary_cm,
            0,
        );
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_batch_phase_transitions() {
        // Test that phase values are distinct
        assert_ne!(BatchPhase::Committed, BatchPhase::Proved);
        assert_ne!(BatchPhase::Proved, BatchPhase::Executed);
        assert_ne!(BatchPhase::Committed, BatchPhase::Executed);
    }

    #[test]
    fn test_verification_mode() {
        assert_ne!(VerificationMode::ZkProof, VerificationMode::Optimistic);
        assert_eq!(VerificationMode::default(), VerificationMode::ZkProof);
    }

    #[test]
    fn test_bridge_state_v2_size() {
        // Ensure the size calculation is reasonable
        let expected_size = 32 + 32 + 32 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 8 + 1 + 1 + (8 * MAX_ASSET_TYPES);
        assert_eq!(BridgeStateV2::LEN, expected_size);
    }

    #[test]
    fn test_batch_commitment_size() {
        let expected_size = 8 + 32 + 4 + 32 + 32 + 4 + 8 + 8 + 1 + 1;
        assert_eq!(BatchCommitment::LEN, expected_size);
    }

    #[test]
    fn test_batch_proof_size() {
        let expected_size = 8 + StateRoots::LEN + 64 + 128 + 64 + 32 + 8 + 32 + 1;
        assert_eq!(BatchProof::LEN, expected_size);
    }

    #[test]
    fn test_priority_operation_size() {
        let expected_size = 8 + 1 + 32 + 4 + 8 + 32 + 32 + 8 + 8 + 1 + 8 + 1;
        assert_eq!(PriorityOperation::LEN, expected_size);
    }
}
