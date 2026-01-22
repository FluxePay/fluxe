use anchor_lang::prelude::*;

/// Custom error codes for the FLUXE Bridge program
#[error_code]
pub enum FluxeError {
    /// Caller is not authorized for this action
    #[msg("Unauthorized: caller is not the authority")]
    Unauthorized,

    /// Bridge is currently paused
    #[msg("Bridge is paused")]
    BridgePaused,

    /// Bridge is already paused
    #[msg("Bridge is already paused")]
    AlreadyPaused,

    /// Bridge is not paused
    #[msg("Bridge is not paused")]
    NotPaused,

    /// Invalid asset type
    #[msg("Invalid asset type")]
    InvalidAssetType,

    /// Asset is disabled for deposits
    #[msg("Asset is disabled")]
    AssetDisabled,

    /// Amount is zero
    #[msg("Amount cannot be zero")]
    ZeroAmount,

    /// Amount is below minimum deposit
    #[msg("Amount is below minimum deposit")]
    AmountBelowMinimum,

    /// Amount is above maximum deposit
    #[msg("Amount is above maximum deposit")]
    AmountAboveMaximum,

    /// Invalid beneficiary commitment
    #[msg("Invalid beneficiary commitment")]
    InvalidBeneficiary,

    /// Deposit nonce overflow
    #[msg("Deposit nonce overflow")]
    NonceOverflow,

    /// Pool balance overflow
    #[msg("Pool balance overflow")]
    PoolOverflow,

    /// Pool balance underflow
    #[msg("Pool balance underflow")]
    PoolUnderflow,

    /// Invalid sequencer
    #[msg("Invalid sequencer")]
    InvalidSequencer,

    /// Invalid batch ID (not sequential)
    #[msg("Invalid batch ID: must be sequential")]
    InvalidBatchId,

    /// Withdrawal already processed
    #[msg("Withdrawal already processed")]
    AlreadyWithdrawn,

    /// Invalid exit proof (Merkle proof verification failed)
    #[msg("Invalid exit proof")]
    InvalidExitProof,

    /// Insufficient liquidity in pool
    #[msg("Insufficient liquidity in pool")]
    InsufficientLiquidity,

    /// Invalid token account owner
    #[msg("Invalid token account owner")]
    InvalidTokenAccount,

    /// Token mint mismatch
    #[msg("Token mint mismatch")]
    MintMismatch,

    // ============ V2 Errors (Three-Phase Lifecycle) ============

    /// Invalid verifier
    #[msg("Invalid verifier")]
    InvalidVerifier,

    /// Invalid batch phase for the requested operation
    #[msg("Invalid batch phase for this operation")]
    InvalidBatchPhase,

    /// Batch is not ready for proof submission
    #[msg("Batch is not ready for proof (must prove in order)")]
    BatchNotReadyForProof,

    /// Batch is not ready for execution
    #[msg("Batch is not ready for execution (must execute in order)")]
    BatchNotReadyForExecution,

    /// State roots hash doesn't match commitment
    #[msg("State roots hash doesn't match commitment")]
    StateRootsMismatch,

    /// Challenge period has not passed (optimistic verification)
    #[msg("Challenge period has not passed")]
    ChallengePeriodNotPassed,

    /// Cannot revert an executed batch
    #[msg("Cannot revert an executed batch")]
    CannotRevertExecutedBatch,

    /// Nothing to revert (no uncommitted batches)
    #[msg("Nothing to revert")]
    NothingToRevert,

    /// Batch has not been executed yet
    #[msg("Batch has not been executed")]
    BatchNotExecuted,

    /// Too many priority operations in batch
    #[msg("Too many priority operations in batch")]
    TooManyPriorityOps,

    /// Invalid priority operation
    #[msg("Invalid priority operation")]
    InvalidPriorityOp,

    /// Priority operation already processed
    #[msg("Priority operation already processed")]
    PriorityOpAlreadyProcessed,
}
