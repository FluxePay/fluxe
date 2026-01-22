/// Multi-chain configuration for FLUXE cross-chain L2
use crate::errors::{FluxeError, FluxeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Chain type enumeration for multi-chain support
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChainType {
    /// Ethereum Virtual Machine chains (Ethereum, Arbitrum, Base, etc.)
    EVM,
    /// Solana Virtual Machine (Solana)
    SVM,
}

impl ChainType {
    /// Returns the string representation of the chain type
    pub fn as_str(&self) -> &'static str {
        match self {
            ChainType::EVM => "EVM",
            ChainType::SVM => "SVM",
        }
    }

    /// Parse chain type from string
    pub fn from_str(s: &str) -> FluxeResult<Self> {
        match s.to_uppercase().as_str() {
            "EVM" => Ok(ChainType::EVM),
            "SVM" => Ok(ChainType::SVM),
            _ => Err(FluxeError::Configuration(format!(
                "Invalid chain type: {}. Must be 'EVM' or 'SVM'",
                s
            ))),
        }
    }
}

/// Configuration for a single asset on a chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetConfig {
    /// Asset type identifier (matches circuit asset_type)
    pub asset_type: u32,

    /// Human-readable asset name (e.g., "USDC", "USDT")
    pub name: String,

    /// Token contract address (ERC20 for EVM, SPL mint for SVM)
    pub token_address: String,

    /// Number of decimals for the token
    pub decimals: u8,

    /// Minimum deposit amount (in smallest unit)
    pub min_deposit: u64,

    /// Maximum deposit amount (in smallest unit)
    pub max_deposit: u64,

    /// Whether this asset is enabled for deposits/withdrawals
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl AssetConfig {
    /// Validate the asset configuration
    pub fn validate(&self) -> FluxeResult<()> {
        if self.name.is_empty() {
            return Err(FluxeError::Configuration(
                "Asset name cannot be empty".to_string(),
            ));
        }

        if self.token_address.is_empty() {
            return Err(FluxeError::Configuration(
                "Token address cannot be empty".to_string(),
            ));
        }

        if self.min_deposit == 0 {
            return Err(FluxeError::Configuration(
                "Minimum deposit must be greater than 0".to_string(),
            ));
        }

        if self.max_deposit <= self.min_deposit {
            return Err(FluxeError::Configuration(format!(
                "Maximum deposit ({}) must be greater than minimum deposit ({})",
                self.max_deposit, self.min_deposit
            )));
        }

        if self.decimals > 18 {
            return Err(FluxeError::Configuration(format!(
                "Decimals ({}) exceeds maximum of 18",
                self.decimals
            )));
        }

        Ok(())
    }

    /// Check if an amount is within the valid deposit range
    pub fn is_valid_amount(&self, amount: u64) -> bool {
        self.enabled && amount >= self.min_deposit && amount <= self.max_deposit
    }
}

/// Configuration for a single chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Unique chain identifier (e.g., 1 for Ethereum mainnet, 501 for Solana)
    pub chain_id: u32,

    /// Chain type (EVM or SVM)
    pub chain_type: ChainType,

    /// Human-readable chain name
    pub name: String,

    /// RPC endpoint URL
    pub rpc_endpoint: String,

    /// Optional WebSocket endpoint URL (mainly for event monitoring)
    pub ws_endpoint: Option<String>,

    /// Bridge contract address (EVM) or program ID (SVM)
    pub bridge_address: String,

    /// Optional verifier contract address (EVM only, for proof verification)
    pub verifier_address: Option<String>,

    /// Supported assets on this chain
    pub assets: Vec<AssetConfig>,

    /// Average block time in milliseconds
    pub block_time_ms: u64,

    /// Number of blocks required for finality/confirmations
    pub finality_blocks: u64,

    /// Maximum batch size for transactions on this chain
    pub max_batch_size: usize,

    /// Base fee for transactions on this chain (in smallest unit)
    pub base_fee: u64,

    /// Optional gas oracle endpoint for fee estimation (EVM chains)
    pub gas_oracle: Option<String>,

    /// Whether this chain is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl ChainConfig {
    /// Validate the chain configuration
    pub fn validate(&self) -> FluxeResult<()> {
        // Validate chain name
        if self.name.is_empty() {
            return Err(FluxeError::Configuration(
                "Chain name cannot be empty".to_string(),
            ));
        }

        // Validate RPC endpoint
        if self.rpc_endpoint.is_empty() {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: RPC endpoint cannot be empty",
                self.name
            )));
        }

        // Basic URL validation
        if !self.rpc_endpoint.starts_with("http://")
            && !self.rpc_endpoint.starts_with("https://")
            && !self.rpc_endpoint.starts_with("ws://")
            && !self.rpc_endpoint.starts_with("wss://") {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: RPC endpoint must start with http://, https://, ws://, or wss://",
                self.name
            )));
        }

        // Validate WebSocket endpoint if provided
        if let Some(ws) = &self.ws_endpoint {
            if !ws.starts_with("ws://") && !ws.starts_with("wss://") {
                return Err(FluxeError::Configuration(format!(
                    "Chain {}: WebSocket endpoint must start with ws:// or wss://",
                    self.name
                )));
            }
        }

        // Validate bridge address
        if self.bridge_address.is_empty() {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: Bridge address cannot be empty",
                self.name
            )));
        }

        // Validate bridge address format based on chain type
        match self.chain_type {
            ChainType::EVM => {
                // EVM addresses should start with 0x and be 42 characters (0x + 40 hex chars)
                if !self.bridge_address.starts_with("0x") || self.bridge_address.len() != 42 {
                    return Err(FluxeError::Configuration(format!(
                        "Chain {}: EVM bridge address must start with '0x' and be 42 characters",
                        self.name
                    )));
                }

                // Validate verifier address if provided
                if let Some(verifier) = &self.verifier_address {
                    if !verifier.starts_with("0x") || verifier.len() != 42 {
                        return Err(FluxeError::Configuration(format!(
                            "Chain {}: EVM verifier address must start with '0x' and be 42 characters",
                            self.name
                        )));
                    }
                }
            }
            ChainType::SVM => {
                // Solana addresses are base58 encoded, typically 32-44 characters
                if self.bridge_address.len() < 32 || self.bridge_address.len() > 44 {
                    return Err(FluxeError::Configuration(format!(
                        "Chain {}: SVM bridge address length should be between 32-44 characters",
                        self.name
                    )));
                }
            }
        }

        // Validate timing parameters
        if self.block_time_ms == 0 {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: Block time must be greater than 0",
                self.name
            )));
        }

        if self.finality_blocks == 0 {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: Finality blocks must be greater than 0",
                self.name
            )));
        }

        if self.max_batch_size == 0 {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: Max batch size must be greater than 0",
                self.name
            )));
        }

        // Validate assets
        if self.assets.is_empty() {
            return Err(FluxeError::Configuration(format!(
                "Chain {}: At least one asset must be configured",
                self.name
            )));
        }

        // Validate each asset and check for duplicates
        let mut seen_asset_types = std::collections::HashSet::new();
        for asset in &self.assets {
            asset.validate()?;

            if !seen_asset_types.insert(asset.asset_type) {
                return Err(FluxeError::Configuration(format!(
                    "Chain {}: Duplicate asset_type {} found",
                    self.name, asset.asset_type
                )));
            }

            // Validate token address format based on chain type
            match self.chain_type {
                ChainType::EVM => {
                    if !asset.token_address.starts_with("0x") || asset.token_address.len() != 42 {
                        return Err(FluxeError::Configuration(format!(
                            "Chain {}, Asset {}: EVM token address must start with '0x' and be 42 characters",
                            self.name, asset.name
                        )));
                    }
                }
                ChainType::SVM => {
                    if asset.token_address.len() < 32 || asset.token_address.len() > 44 {
                        return Err(FluxeError::Configuration(format!(
                            "Chain {}, Asset {}: SVM token address length should be between 32-44 characters",
                            self.name, asset.name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Get asset configuration by asset type
    pub fn get_asset(&self, asset_type: u32) -> Option<&AssetConfig> {
        self.assets.iter().find(|a| a.asset_type == asset_type)
    }

    /// Check if an asset is supported and enabled on this chain
    pub fn is_asset_supported(&self, asset_type: u32) -> bool {
        self.enabled && self.get_asset(asset_type).map_or(false, |a| a.enabled)
    }

    /// Get finality time in milliseconds
    pub fn finality_time_ms(&self) -> u64 {
        self.block_time_ms * self.finality_blocks
    }
}

/// Multi-chain configuration manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiChainConfig {
    /// Map of chain_id to chain configuration
    #[serde(rename = "chains")]
    chains_map: HashMap<String, ChainConfig>,

    /// Default chain ID for operations that don't specify a chain
    pub default_chain: Option<u32>,
}

impl MultiChainConfig {
    /// Create a new empty multi-chain configuration
    pub fn new() -> Self {
        Self {
            chains_map: HashMap::new(),
            default_chain: None,
        }
    }

    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> FluxeResult<Self> {
        let contents = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            FluxeError::Configuration(format!(
                "Failed to read config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Self::from_toml(&contents)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(toml_str: &str) -> FluxeResult<Self> {
        let config: Self = toml::from_str(toml_str).map_err(|e| {
            FluxeError::Configuration(format!("Failed to parse TOML config: {}", e))
        })?;

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> FluxeResult<()> {
        let toml_str = toml::to_string_pretty(self).map_err(|e| {
            FluxeError::Configuration(format!("Failed to serialize config: {}", e))
        })?;

        std::fs::write(path.as_ref(), toml_str).map_err(|e| {
            FluxeError::Configuration(format!(
                "Failed to write config file '{}': {}",
                path.as_ref().display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Apply environment variable overrides to the configuration
    pub fn apply_env_overrides(&mut self) -> FluxeResult<()> {
        // Override RPC endpoints from environment variables
        // Format: FLUXE_CHAIN_{CHAIN_ID}_RPC_ENDPOINT
        for (_, chain) in self.chains_map.iter_mut() {
            let rpc_var = format!("FLUXE_CHAIN_{}_RPC_ENDPOINT", chain.chain_id);
            if let Ok(rpc_endpoint) = std::env::var(&rpc_var) {
                tracing::info!(
                    "Overriding RPC endpoint for chain {} from env var {}",
                    chain.chain_id,
                    rpc_var
                );
                chain.rpc_endpoint = rpc_endpoint;
            }

            let ws_var = format!("FLUXE_CHAIN_{}_WS_ENDPOINT", chain.chain_id);
            if let Ok(ws_endpoint) = std::env::var(&ws_var) {
                tracing::info!(
                    "Overriding WS endpoint for chain {} from env var {}",
                    chain.chain_id,
                    ws_var
                );
                chain.ws_endpoint = Some(ws_endpoint);
            }

            let bridge_var = format!("FLUXE_CHAIN_{}_BRIDGE_ADDRESS", chain.chain_id);
            if let Ok(bridge_address) = std::env::var(&bridge_var) {
                tracing::info!(
                    "Overriding bridge address for chain {} from env var {}",
                    chain.chain_id,
                    bridge_var
                );
                chain.bridge_address = bridge_address;
            }
        }

        // Re-validate after applying overrides
        self.validate()?;
        Ok(())
    }

    /// Validate the entire multi-chain configuration
    pub fn validate(&self) -> FluxeResult<()> {
        if self.chains_map.is_empty() {
            return Err(FluxeError::Configuration(
                "At least one chain must be configured".to_string(),
            ));
        }

        // Validate each chain
        for (_key, chain) in &self.chains_map {
            // Note: We allow flexible map keys (chain ID or name) for TOML convenience
            chain.validate()?;
        }

        // Check for duplicate chain IDs
        let mut seen_ids = std::collections::HashSet::new();
        for chain in self.chains_map.values() {
            if !seen_ids.insert(chain.chain_id) {
                return Err(FluxeError::Configuration(format!(
                    "Duplicate chain_id {} found",
                    chain.chain_id
                )));
            }
        }

        // Validate default chain if specified
        if let Some(default_id) = self.default_chain {
            if !self.chains_map.values().any(|c| c.chain_id == default_id) {
                return Err(FluxeError::Configuration(format!(
                    "Default chain ID {} not found in configured chains",
                    default_id
                )));
            }
        }

        Ok(())
    }

    /// Get chain configuration by chain ID
    pub fn get_chain(&self, chain_id: u32) -> Option<&ChainConfig> {
        self.chains_map.values().find(|c| c.chain_id == chain_id)
    }

    /// Get mutable chain configuration by chain ID
    pub fn get_chain_mut(&mut self, chain_id: u32) -> Option<&mut ChainConfig> {
        self.chains_map.values_mut().find(|c| c.chain_id == chain_id)
    }

    /// Get all configured chains
    pub fn chains(&self) -> impl Iterator<Item = &ChainConfig> {
        self.chains_map.values()
    }

    /// Get all enabled chains
    pub fn enabled_chains(&self) -> impl Iterator<Item = &ChainConfig> {
        self.chains_map.values().filter(|c| c.enabled)
    }

    /// Get the default chain configuration
    pub fn default_chain_config(&self) -> Option<&ChainConfig> {
        self.default_chain.and_then(|id| self.get_chain(id))
    }

    /// Add a new chain configuration
    pub fn add_chain(&mut self, chain: ChainConfig) -> FluxeResult<()> {
        chain.validate()?;

        // Check for duplicate chain ID
        if self.get_chain(chain.chain_id).is_some() {
            return Err(FluxeError::Configuration(format!(
                "Chain with ID {} already exists",
                chain.chain_id
            )));
        }

        let key = chain.chain_id.to_string();
        self.chains_map.insert(key, chain);
        Ok(())
    }

    /// Remove a chain configuration by chain ID
    pub fn remove_chain(&mut self, chain_id: u32) -> Option<ChainConfig> {
        let key = chain_id.to_string();
        self.chains_map.remove(&key)
    }

    /// Get the number of configured chains
    pub fn chain_count(&self) -> usize {
        self.chains_map.len()
    }

    /// Check if a chain is configured
    pub fn has_chain(&self, chain_id: u32) -> bool {
        self.get_chain(chain_id).is_some()
    }

    /// Get all chain IDs
    pub fn chain_ids(&self) -> Vec<u32> {
        self.chains_map.values().map(|c| c.chain_id).collect()
    }

    /// Validate RPC endpoint reachability (optional, can be slow)
    #[cfg(feature = "validate-rpc")]
    pub async fn validate_rpc_endpoints(&self) -> FluxeResult<()> {
        use std::time::Duration;

        for chain in self.chains_map.values() {
            if !chain.enabled {
                continue;
            }

            // Attempt to connect to RPC endpoint with timeout
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| {
                    FluxeError::Configuration(format!("Failed to create HTTP client: {}", e))
                })?;

            // Try a basic health check request
            match client.get(&chain.rpc_endpoint).send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        tracing::warn!(
                            "Chain {} RPC endpoint {} returned status: {}",
                            chain.name,
                            chain.rpc_endpoint,
                            response.status()
                        );
                    } else {
                        tracing::info!("Chain {} RPC endpoint is reachable", chain.name);
                    }
                }
                Err(e) => {
                    return Err(FluxeError::Configuration(format!(
                        "Chain {} RPC endpoint {} is not reachable: {}",
                        chain.name, chain.rpc_endpoint, e
                    )));
                }
            }
        }

        Ok(())
    }
}

impl Default for MultiChainConfig {
    fn default() -> Self {
        Self::new()
    }
}

// Include comprehensive tests
#[cfg(test)]
#[path = "chains_tests.rs"]
mod chains_tests;
