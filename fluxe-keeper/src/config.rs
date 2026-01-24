//! Keeper configuration

use serde::{Deserialize, Serialize};

/// Keeper configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperConfig {
    /// Ethereum RPC URL
    pub eth_rpc_url: String,
    /// Ethereum bridge contract address
    pub eth_bridge_address: String,
    /// Ethereum private key for transactions
    pub eth_private_key: String,

    /// Solana RPC URL
    pub solana_rpc_url: String,
    /// Solana program ID
    pub solana_program_id: String,
    /// Solana pool token account address
    pub solana_pool_address: String,
    /// Solana keypair path
    pub solana_keypair_path: String,

    /// CCTP attestation API URL
    pub cctp_api_url: String,

    /// LayerZero OFT API URL
    pub layerzero_api_url: String,

    /// Minimum amount to rebalance (in USDC/USDT with 6 decimals)
    pub min_rebalance_amount: u64,
    /// Polling interval in seconds
    pub poll_interval_secs: u64,

    /// Enable dry run mode (no actual transactions)
    pub dry_run: bool,
}

impl Default for KeeperConfig {
    fn default() -> Self {
        Self {
            eth_rpc_url: "https://eth-sepolia.g.alchemy.com/v2/demo".to_string(),
            eth_bridge_address: String::new(),
            eth_private_key: String::new(),
            solana_rpc_url: "https://api.devnet.solana.com".to_string(),
            solana_program_id: String::new(),
            solana_pool_address: String::new(),
            solana_keypair_path: "~/.config/solana/id.json".to_string(),
            cctp_api_url: "https://iris-api.circle.com/v1".to_string(),
            layerzero_api_url: "https://sdk-api.layerzero-api.com/v1/oft".to_string(),
            min_rebalance_amount: 100_000_000, // 100 USDC/USDT
            poll_interval_secs: 30,
            dry_run: false,
        }
    }
}

impl KeeperConfig {
    /// Load from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(v) = std::env::var("ETH_RPC_URL") {
            config.eth_rpc_url = v;
        }
        if let Ok(v) = std::env::var("ETH_BRIDGE_ADDRESS") {
            config.eth_bridge_address = v;
        }
        if let Ok(v) = std::env::var("ETH_PRIVATE_KEY") {
            config.eth_private_key = v;
        }
        if let Ok(v) = std::env::var("SOLANA_RPC_URL") {
            config.solana_rpc_url = v;
        }
        if let Ok(v) = std::env::var("SOLANA_PROGRAM_ID") {
            config.solana_program_id = v;
        }
        if let Ok(v) = std::env::var("SOLANA_POOL_ADDRESS") {
            config.solana_pool_address = v;
        }
        if let Ok(v) = std::env::var("SOLANA_KEYPAIR_PATH") {
            config.solana_keypair_path = v;
        }
        if let Ok(v) = std::env::var("CCTP_API_URL") {
            config.cctp_api_url = v;
        }
        if let Ok(v) = std::env::var("LAYERZERO_API_URL") {
            config.layerzero_api_url = v;
        }
        if let Ok(v) = std::env::var("MIN_REBALANCE_AMOUNT") {
            if let Ok(amount) = v.parse() {
                config.min_rebalance_amount = amount;
            }
        }
        if let Ok(v) = std::env::var("POLL_INTERVAL_SECS") {
            if let Ok(secs) = v.parse() {
                config.poll_interval_secs = secs;
            }
        }
        if let Ok(v) = std::env::var("KEEPER_DRY_RUN") {
            config.dry_run = v == "true" || v == "1";
        }

        config
    }
}

/// CCTP domain IDs
pub mod cctp_domains {
    pub const ETHEREUM: u32 = 0;
    pub const SOLANA: u32 = 5;
}

/// USDC addresses
pub mod usdc {
    pub const ETHEREUM_SEPOLIA: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
    pub const SOLANA_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
}

/// CCTP contract addresses
pub mod cctp {
    /// Ethereum Sepolia
    pub mod ethereum_sepolia {
        pub const TOKEN_MESSENGER: &str = "0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5";
        pub const MESSAGE_TRANSMITTER: &str = "0x7865fAfC2db2093669d92c0F33AeEF291086BEFD";
    }

    /// Solana Devnet
    pub mod solana_devnet {
        pub const TOKEN_MESSENGER: &str = "CCTPmbSD7gX1bxKPAmg77w8oFzNFpaQiQUWD43TKaecd";
    }
}
