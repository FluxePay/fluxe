use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8545,
            max_connections: 1000,
            request_timeout_secs: 30,
        }
    }
}

/// Sequencer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerConfig {
    /// Maximum transactions per batch
    pub max_batch_size: usize,
    /// Minimum transactions to trigger batch (with time)
    pub min_batch_size: usize,
    /// Time interval to trigger batch (seconds)
    pub batch_interval_secs: u64,
    /// Maximum delay before forcing batch (seconds)
    pub max_batch_delay_secs: u64,
    /// Maximum pending transactions globally
    pub max_pending_txs: usize,
    /// Chain ID for this sequencer
    pub chain_id: u32,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 100,
            min_batch_size: 10,
            batch_interval_secs: 10,
            max_batch_delay_secs: 60,
            max_pending_txs: 10_000,
            chain_id: 1, // Default to Ethereum
        }
    }
}

impl SequencerConfig {
    pub fn batch_interval(&self) -> Duration {
        Duration::from_secs(self.batch_interval_secs)
    }

    pub fn max_batch_delay(&self) -> Duration {
        Duration::from_secs(self.max_batch_delay_secs)
    }
}

/// Full application config
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub sequencer: SequencerConfig,
    /// Path to verifying keys directory
    pub vk_path: Option<String>,
    /// Enable metrics endpoint
    pub metrics_enabled: bool,
    /// Metrics port
    pub metrics_port: u16,
}

impl AppConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(port) = std::env::var("FLUXE_PORT") {
            if let Ok(p) = port.parse() {
                config.server.port = p;
            }
        }

        if let Ok(host) = std::env::var("FLUXE_HOST") {
            config.server.host = host;
        }

        if let Ok(chain_id) = std::env::var("FLUXE_CHAIN_ID") {
            if let Ok(id) = chain_id.parse() {
                config.sequencer.chain_id = id;
            }
        }

        if let Ok(vk_path) = std::env::var("FLUXE_VK_PATH") {
            config.vk_path = Some(vk_path);
        }

        if let Ok(metrics) = std::env::var("FLUXE_METRICS") {
            config.metrics_enabled = metrics == "true" || metrics == "1";
        }

        config
    }
}
