//! FLUXE Unified Keeper
//!
//! Monitors pool balances across Ethereum and Solana, triggering
//! permissionless rebalancing via Circle CCTP (USDC) and LayerZero USDT0 (USDT).
//!
//! Usage:
//!   fluxe-keeper [--dry-run]
//!
//! Environment Variables:
//!   ETH_RPC_URL          - Ethereum RPC endpoint
//!   ETH_BRIDGE_ADDRESS   - FluxeBridge contract address
//!   ETH_PRIVATE_KEY      - Private key for transactions
//!   SOLANA_RPC_URL       - Solana RPC endpoint
//!   SOLANA_PROGRAM_ID    - FLUXE Bridge program ID
//!   SOLANA_KEYPAIR_PATH  - Path to Solana keypair
//!   MIN_REBALANCE_AMOUNT - Minimum USDC/USDT to rebalance (default: 100000000 = 100)
//!   KEEPER_DRY_RUN       - Set to "true" for dry run mode
//!   LAYERZERO_API_URL    - LayerZero OFT API URL (for USDT0)

mod cctp;
mod config;
mod keeper;
mod layerzero;

use config::KeeperConfig;
use keeper::UnifiedKeeper;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load environment
    dotenvy::dotenv().ok();

    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let dry_run = args.iter().any(|a| a == "--dry-run");

    // Load config
    let mut config = KeeperConfig::from_env();
    if dry_run {
        config.dry_run = true;
    }

    info!("=== FLUXE Unified Keeper ===");
    info!("CCTP API: {}", config.cctp_api_url);
    info!("Min rebalance: {} USDC", config.min_rebalance_amount / 1_000_000);
    info!("Dry run: {}", config.dry_run);

    // Create and run keeper
    let mut keeper = UnifiedKeeper::new(config);
    keeper.run().await?;

    Ok(())
}
