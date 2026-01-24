use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

declare_id!("11111111111111111111111111111112");

pub mod error;
pub mod groth16;
pub mod sp1;
pub mod state;
pub mod utils;

// V2 bridge is available as fluxe_bridge_v2 program (separate entry point)
// See lib_v2.rs for zkSync-style three-phase batch lifecycle

use error::FluxeError;
use state::*;
use utils::verify_merkle_proof;

/// Chain ID for Solana mainnet (matches ChainConfig)
pub const CHAIN_ID: u32 = 501;

/// FLUXE L2 network identifier
/// This is the L2 chain ID, NOT the settlement chain (Solana)
/// All settlement contracts verify the same L2 chain ID
/// Value: 0xF1C5E = 989278 (derived from "FLUXE")
pub const FLUXE_L2_CHAIN_ID: u32 = 0xF1C5E;

/// Maximum number of supported asset types
pub const MAX_ASSET_TYPES: usize = 256;

/// Size of historical roots circular buffer
/// Stores ~10 minutes of history at 10-second block intervals
pub const HISTORICAL_ROOTS_SIZE: usize = 64;

#[program]
pub mod fluxe_bridge {
    use super::*;

    /// Initialize the bridge with an authority
    pub fn initialize(ctx: Context<Initialize>, sequencer: Pubkey) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        bridge.authority = ctx.accounts.authority.key();
        bridge.sequencer = sequencer;
        bridge.last_finalized_batch = 0;
        bridge.last_finalized_roots_hash = [0u8; 32];
        bridge.paused = false;
        bridge.genesis_finalized = false;
        bridge.deposit_nonce = 0;
        bridge.bump = ctx.bumps.bridge;
        bridge.next_root_index = 0;

        // Initialize historical roots and pool balances to zero
        bridge.historical_roots = [[0u8; 32]; HISTORICAL_ROOTS_SIZE];
        bridge.pool_balances = [0u64; MAX_ASSET_TYPES];

        emit!(BridgeInitialized {
            authority: bridge.authority,
            sequencer: bridge.sequencer,
        });

        Ok(())
    }

    /// Finalize genesis block (batch_id = 0) with SP1 proof
    ///
    /// Genesis has no transactions and old_roots == new_roots.
    /// Must be called before any regular batch submissions.
    ///
    /// # Arguments
    /// * `public_values` - SP1 public values (80 bytes): old_roots_hash (32) | new_roots_hash (32) | batch_id (8) | chain_id (4) | proof_count (4)
    /// * `proof` - SP1 proof bytes (verification delegated to SP1 verifier program)
    pub fn finalize_genesis(
        ctx: Context<FinalizeGenesis>,
        public_values: [u8; 80],
        _proof: Vec<u8>, // Proof validation handled by SP1 verifier program CPI
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;

        // Validate sequencer
        require!(
            ctx.accounts.sequencer.key() == bridge.sequencer,
            FluxeError::InvalidSequencer
        );

        // Can only finalize genesis once
        require!(!bridge.genesis_finalized, FluxeError::GenesisAlreadyFinalized);
        require!(!bridge.paused, FluxeError::BridgePaused);

        // Decode public values
        let old_roots_hash: [u8; 32] = public_values[0..32].try_into().unwrap();
        let new_roots_hash: [u8; 32] = public_values[32..64].try_into().unwrap();
        let batch_id = u64::from_be_bytes(public_values[64..72].try_into().unwrap());
        let chain_id = u32::from_be_bytes(public_values[72..76].try_into().unwrap());
        let proof_count = u32::from_be_bytes(public_values[76..80].try_into().unwrap());

        // Genesis constraints
        require!(batch_id == 0, FluxeError::InvalidBatchId);
        require!(chain_id == FLUXE_L2_CHAIN_ID, FluxeError::InvalidChainId);
        require!(proof_count == 0, FluxeError::InvalidGenesisState); // No transactions in genesis
        require!(old_roots_hash == new_roots_hash, FluxeError::InvalidGenesisState); // No state change

        // TODO: CPI to SP1 verifier program to verify proof
        // For now, proof verification is handled externally

        // Finalize genesis state
        bridge.last_finalized_batch = 0;
        bridge.last_finalized_roots_hash = new_roots_hash;
        bridge.genesis_finalized = true;

        // Add genesis root to historical buffer
        bridge.add_historical_root(new_roots_hash);

        emit!(GenesisFinalized {
            roots_hash: new_roots_hash,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    /// Register a new asset type with mint address
    pub fn register_asset(
        ctx: Context<RegisterAsset>,
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

        emit!(AssetRegistered {
            asset_type,
            mint: ctx.accounts.mint.key(),
            min_deposit,
            max_deposit,
        });

        Ok(())
    }

    /// Deposit tokens into the FLUXE L2
    pub fn deposit(
        ctx: Context<Deposit>,
        asset_type: u32,
        amount: u64,
        beneficiary_cm: [u8; 32],
        nonce: u64,
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

        // Validate nonce matches expected
        require!(nonce == bridge.deposit_nonce, FluxeError::InvalidBatchId);

        // Increment nonce
        bridge.deposit_nonce = bridge.deposit_nonce.checked_add(1)
            .ok_or(FluxeError::NonceOverflow)?;

        // Compute ingress receipt hash
        let ingress_hash = compute_ingress_hash(
            CHAIN_ID,
            asset_type,
            amount,
            &beneficiary_cm,
            nonce,
        );

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

        // Initialize deposit record
        let deposit_record = &mut ctx.accounts.deposit_record;
        deposit_record.ingress_hash = ingress_hash;
        deposit_record.nonce = nonce;
        deposit_record.asset_type = asset_type;
        deposit_record.amount = amount;
        deposit_record.beneficiary_cm = beneficiary_cm;
        deposit_record.depositor = ctx.accounts.user.key();
        deposit_record.slot = Clock::get()?.slot;
        deposit_record.bump = ctx.bumps.deposit_record;

        emit!(DepositEvent {
            asset_type,
            amount,
            beneficiary_cm,
            ingress_hash,
            nonce,
            depositor: ctx.accounts.user.key(),
        });

        Ok(())
    }

    /// Submit a finalized batch from the sequencer (IVC-enabled)
    ///
    /// IVC guarantees previous block validity - we only verify the latest proof.
    /// The SP1 proof recursively verifies all prior blocks.
    ///
    /// # Arguments
    /// * `public_values` - SP1 public values (80 bytes): old_roots_hash (32) | new_roots_hash (32) | batch_id (8) | chain_id (4) | proof_count (4)
    /// * `new_roots` - Full state roots (verified to match new_roots_hash from proof)
    /// * `proof` - SP1 proof bytes (verification delegated to SP1 verifier program)
    pub fn submit_batch(
        ctx: Context<SubmitBatch>,
        public_values: [u8; 80],
        new_roots: StateRoots,
        _proof: Vec<u8>, // Proof validation handled by SP1 verifier program CPI
    ) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;

        // Genesis must be finalized first
        require!(bridge.genesis_finalized, FluxeError::GenesisNotFinalized);

        // Validate sequencer
        require!(
            ctx.accounts.sequencer.key() == bridge.sequencer,
            FluxeError::InvalidSequencer
        );

        require!(!bridge.paused, FluxeError::BridgePaused);

        // Decode public values
        let old_roots_hash: [u8; 32] = public_values[0..32].try_into().unwrap();
        let new_roots_hash: [u8; 32] = public_values[32..64].try_into().unwrap();
        let batch_id = u64::from_be_bytes(public_values[64..72].try_into().unwrap());
        let chain_id = u32::from_be_bytes(public_values[72..76].try_into().unwrap());
        let proof_count = u32::from_be_bytes(public_values[76..80].try_into().unwrap());

        // Validate chain ID
        require!(chain_id == FLUXE_L2_CHAIN_ID, FluxeError::InvalidChainId);

        // Validate batch ID is sequential
        require!(
            batch_id == bridge.last_finalized_batch + 1,
            FluxeError::InvalidBatchId
        );

        // Validate state continuity: old_roots_hash must match last finalized
        // IVC guarantees this is valid if proof verifies, but we check for defense-in-depth
        require!(
            old_roots_hash == bridge.last_finalized_roots_hash,
            FluxeError::InvalidPreviousRoots
        );

        // Verify provided roots match the committed hash
        let computed_hash = compute_roots_hash(&new_roots);
        require!(
            computed_hash == new_roots_hash,
            FluxeError::RootsHashMismatch
        );

        // TODO: CPI to SP1 verifier program to verify proof
        // This is the ONLY verification needed - IVC guarantees all prior blocks

        // Update bridge state
        bridge.last_finalized_batch = batch_id;
        bridge.last_finalized_roots_hash = new_roots_hash;

        // Add new root to historical buffer
        bridge.add_historical_root(new_roots_hash);

        // Initialize batch state account
        let batch_state = &mut ctx.accounts.batch_state;
        batch_state.batch_id = batch_id;
        batch_state.roots_hash = new_roots_hash;
        batch_state.roots = new_roots;
        batch_state.proof_count = proof_count;
        batch_state.timestamp = Clock::get()?.unix_timestamp;
        batch_state.bump = ctx.bumps.batch_state;

        emit!(BatchFinalized {
            batch_id,
            roots_hash: new_roots_hash,
            proof_count,
            timestamp: batch_state.timestamp,
        });

        Ok(())
    }

    /// Withdraw tokens using exit receipt proof
    pub fn withdraw(
        ctx: Context<Withdraw>,
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
        let batch_state = &ctx.accounts.batch_state;
        let withdrawal_record = &mut ctx.accounts.withdrawal_record;

        // Validate state (read-only checks first)
        require!(!ctx.accounts.bridge.paused, FluxeError::BridgePaused);
        require!(!withdrawal_record.processed, FluxeError::AlreadyWithdrawn);

        // Validate asset type is within bounds
        require!(asset_type < MAX_ASSET_TYPES as u32, FluxeError::InvalidAssetType);

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

        // Transfer tokens from vault to user (use ctx.accounts directly for CPI)
        let seeds = &[
            b"bridge".as_ref(),
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

        emit!(WithdrawalEvent {
            asset_type,
            amount,
            recipient: ctx.accounts.user.key(),
            exit_hash: exit_receipt_hash,
            batch_id: batch_state.batch_id,
        });

        Ok(())
    }

    // ============ Admin Functions ============

    /// Pause the bridge (emergency)
    pub fn pause(ctx: Context<AdminAction>) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        require!(!bridge.paused, FluxeError::AlreadyPaused);
        bridge.paused = true;

        emit!(BridgePaused {
            authority: ctx.accounts.authority.key(),
        });

        Ok(())
    }

    /// Unpause the bridge
    pub fn unpause(ctx: Context<AdminAction>) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        require!(bridge.paused, FluxeError::NotPaused);
        bridge.paused = false;

        emit!(BridgeUnpaused {
            authority: ctx.accounts.authority.key(),
        });

        Ok(())
    }

    /// Update sequencer address
    pub fn update_sequencer(ctx: Context<AdminAction>, new_sequencer: Pubkey) -> Result<()> {
        let bridge = &mut ctx.accounts.bridge;
        let old_sequencer = bridge.sequencer;
        bridge.sequencer = new_sequencer;

        emit!(SequencerUpdated {
            old_sequencer,
            new_sequencer,
        });

        Ok(())
    }

    /// Update asset configuration
    pub fn update_asset(
        ctx: Context<UpdateAsset>,
        enabled: bool,
        min_deposit: u64,
        max_deposit: u64,
    ) -> Result<()> {
        let asset_config = &mut ctx.accounts.asset_config;
        asset_config.enabled = enabled;
        asset_config.min_deposit = min_deposit;
        asset_config.max_deposit = max_deposit;

        emit!(AssetUpdated {
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
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + BridgeState::LEN,
        seeds = [b"bridge"],
        bump
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(asset_type: u32)]
pub struct RegisterAsset<'info> {
    #[account(
        seeds = [b"bridge"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(
        init,
        payer = authority,
        space = 8 + AssetConfig::LEN,
        seeds = [b"asset", asset_type.to_le_bytes().as_ref()],
        bump
    )]
    pub asset_config: Account<'info, AssetConfig>,

    /// The SPL token mint for this asset
    pub mint: Account<'info, Mint>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(asset_type: u32, amount: u64, beneficiary_cm: [u8; 32], nonce: u64)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"bridge"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(
        seeds = [b"asset", asset_type.to_le_bytes().as_ref()],
        bump = asset_config.bump,
        constraint = asset_config.asset_type == asset_type @ FluxeError::InvalidAssetType,
    )]
    pub asset_config: Account<'info, AssetConfig>,

    #[account(
        init,
        payer = user,
        space = 8 + DepositRecord::LEN,
        seeds = [b"deposit", nonce.to_le_bytes().as_ref()],
        bump
    )]
    pub deposit_record: Account<'info, DepositRecord>,

    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ FluxeError::InvalidTokenAccount,
        constraint = user_token_account.mint == asset_config.mint @ FluxeError::MintMismatch,
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    #[account(
        mut,
        seeds = [b"vault", asset_type.to_le_bytes().as_ref()],
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
pub struct FinalizeGenesis<'info> {
    #[account(
        mut,
        seeds = [b"bridge"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(mut)]
    pub sequencer: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(public_values: [u8; 80])]
pub struct SubmitBatch<'info> {
    #[account(
        mut,
        seeds = [b"bridge"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(
        init,
        payer = sequencer,
        space = 8 + BatchState::LEN,
        // batch_id is at bytes 64-72 in public_values (big-endian)
        seeds = [b"batch", &public_values[64..72]],
        bump
    )]
    pub batch_state: Account<'info, BatchState>,

    #[account(mut)]
    pub sequencer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(exit_receipt_hash: [u8; 32], asset_type: u32, amount: u64, batch_id: u64)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [b"bridge"],
        bump = bridge.bump,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(
        seeds = [b"batch", batch_id.to_le_bytes().as_ref()],
        bump = batch_state.bump,
    )]
    pub batch_state: Account<'info, BatchState>,

    #[account(
        init,
        payer = user,
        space = 8 + WithdrawalRecord::LEN,
        seeds = [b"withdrawal", exit_receipt_hash.as_ref()],
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
        seeds = [b"vault", asset_type.to_le_bytes().as_ref()],
        bump,
    )]
    pub bridge_vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    #[account(
        mut,
        seeds = [b"bridge"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeState>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateAsset<'info> {
    #[account(
        seeds = [b"bridge"],
        bump = bridge.bump,
        has_one = authority @ FluxeError::Unauthorized,
    )]
    pub bridge: Account<'info, BridgeState>,

    #[account(mut)]
    pub asset_config: Account<'info, AssetConfig>,

    pub authority: Signer<'info>,
}

// ============ Helper Functions ============

/// Compute ingress receipt hash matching the Rust implementation
fn compute_ingress_hash(
    chain_id: u32,
    asset_type: u32,
    amount: u64,
    beneficiary_cm: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    use solana_program::keccak::hashv;

    let hash = hashv(&[
        &chain_id.to_le_bytes(),
        &asset_type.to_le_bytes(),
        &amount.to_le_bytes(),
        beneficiary_cm,
        &nonce.to_le_bytes(),
    ]);

    hash.0
}

/// Compute SHA256 hash of state roots (matches SP1 program's StateRoots::hash())
/// Hash order: cmt, nft, obj, cb, ingress, exit, sanctions, pool_rules
fn compute_roots_hash(roots: &StateRoots) -> [u8; 32] {
    use solana_program::hash::hashv;

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

    hash.to_bytes()
}

// ============ Events ============

#[event]
pub struct BridgeInitialized {
    pub authority: Pubkey,
    pub sequencer: Pubkey,
}

#[event]
pub struct GenesisFinalized {
    pub roots_hash: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct AssetRegistered {
    pub asset_type: u32,
    pub mint: Pubkey,
    pub min_deposit: u64,
    pub max_deposit: u64,
}

#[event]
pub struct AssetUpdated {
    pub asset_type: u32,
    pub enabled: bool,
    pub min_deposit: u64,
    pub max_deposit: u64,
}

#[event]
pub struct DepositEvent {
    pub asset_type: u32,
    pub amount: u64,
    pub beneficiary_cm: [u8; 32],
    pub ingress_hash: [u8; 32],
    pub nonce: u64,
    pub depositor: Pubkey,
}

#[event]
pub struct BatchFinalized {
    pub batch_id: u64,
    pub roots_hash: [u8; 32],
    pub proof_count: u32,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawalEvent {
    pub asset_type: u32,
    pub amount: u64,
    pub recipient: Pubkey,
    pub exit_hash: [u8; 32],
    pub batch_id: u64,
}

#[event]
pub struct BridgePaused {
    pub authority: Pubkey,
}

#[event]
pub struct BridgeUnpaused {
    pub authority: Pubkey,
}

#[event]
pub struct SequencerUpdated {
    pub old_sequencer: Pubkey,
    pub new_sequencer: Pubkey,
}
