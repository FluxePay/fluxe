/// Configuration for Fluxe protocol
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FluxeConfig {
    pub logging: LogConfig,
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub circuits: CircuitConfig,
    pub compliance: ComplianceConfig,
    pub performance: PerformanceConfig,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,

    /// Enable JSON output format
    pub json_output: bool,

    /// Enable file output
    pub file_output: bool,

    /// Log file path
    pub log_file: PathBuf,

    /// Maximum log file size in MB
    pub max_file_size: u64,

    /// Number of rotated log files to keep
    pub max_files: usize,

    /// Enable performance metrics logging
    pub metrics: bool,

    /// Performance threshold in ms (log slow operations)
    pub slow_op_threshold_ms: u64,

    /// Module-specific log levels
    pub module_levels: Vec<ModuleLogLevel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleLogLevel {
    pub module: String,
    pub level: String,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// API server address
    pub api_address: String,

    /// API server port
    pub api_port: u16,

    /// RPC endpoint for external chain
    pub rpc_endpoint: String,

    /// Request timeout in seconds
    pub request_timeout_secs: u64,

    /// Maximum connections
    pub max_connections: usize,

    /// Enable TLS
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<PathBuf>,

    /// TLS key path
    pub tls_key_path: Option<PathBuf>,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database path
    pub db_path: PathBuf,

    /// Cache size in MB
    pub cache_size_mb: u64,

    /// Enable compression
    pub compression: bool,

    /// Checkpoint interval (blocks)
    pub checkpoint_interval: u64,

    /// Prune old data after N blocks
    pub prune_after_blocks: Option<u64>,
}

/// Circuit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitConfig {
    /// Setup parameters directory
    pub setup_dir: PathBuf,

    /// Proof cache directory
    pub proof_cache_dir: PathBuf,

    /// Enable proof caching
    pub proof_caching: bool,

    /// Maximum proof cache size in MB
    pub proof_cache_size_mb: u64,

    /// Number of parallel proof verification threads
    pub verification_threads: usize,

    /// Maximum batch size for verification
    pub max_batch_size: usize,
}

/// Compliance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    /// Enable sanctions screening
    pub sanctions_screening: bool,

    /// Sanctions list update interval (hours)
    pub sanctions_update_hours: u64,

    /// Default daily limit
    pub default_daily_limit: u128,

    /// Default monthly limit
    pub default_monthly_limit: u128,

    /// Default yearly limit
    pub default_yearly_limit: u128,

    /// Callback timeout (seconds)
    pub callback_timeout_secs: u64,

    /// Risk score threshold for automatic freeze
    pub auto_freeze_risk_threshold: u32,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable parallel processing
    pub parallel_processing: bool,

    /// Number of worker threads
    pub worker_threads: usize,

    /// Queue size for pending transactions
    pub tx_queue_size: usize,

    /// Memory limit in GB
    pub memory_limit_gb: u64,

    /// Enable performance profiling
    pub profiling: bool,

    /// Profiling output directory
    pub profiling_dir: Option<PathBuf>,
}

impl Default for FluxeConfig {
    fn default() -> Self {
        Self {
            logging: LogConfig::default(),
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            circuits: CircuitConfig::default(),
            compliance: ComplianceConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_output: false,
            file_output: true,
            log_file: PathBuf::from("fluxe.log"),
            max_file_size: 100,
            max_files: 10,
            metrics: true,
            slow_op_threshold_ms: 1000,
            module_levels: vec![
                ModuleLogLevel {
                    module: "fluxe_core".to_string(),
                    level: "debug".to_string(),
                },
                ModuleLogLevel {
                    module: "fluxe_circuits".to_string(),
                    level: "debug".to_string(),
                },
                ModuleLogLevel {
                    module: "fluxe_api".to_string(),
                    level: "info".to_string(),
                },
            ],
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            api_address: "127.0.0.1".to_string(),
            api_port: 8080,
            rpc_endpoint: "http://localhost:8545".to_string(),
            request_timeout_secs: 30,
            max_connections: 1000,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("./data/fluxe.db"),
            cache_size_mb: 512,
            compression: true,
            checkpoint_interval: 1000,
            prune_after_blocks: None,
        }
    }
}

impl Default for CircuitConfig {
    fn default() -> Self {
        Self {
            setup_dir: PathBuf::from("./setup"),
            proof_cache_dir: PathBuf::from("./proof_cache"),
            proof_caching: true,
            proof_cache_size_mb: 1024,
            verification_threads: 4,
            max_batch_size: 100,
        }
    }
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            sanctions_screening: true,
            sanctions_update_hours: 24,
            default_daily_limit: 100_000_000_000_000_000_000u128, // 100 units
            default_monthly_limit: 1_000_000_000_000_000_000_000u128, // 1000 units
            default_yearly_limit: 10_000_000_000_000_000_000_000u128, // 10000 units
            callback_timeout_secs: 86400, // 24 hours
            auto_freeze_risk_threshold: 90,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            parallel_processing: true,
            worker_threads: num_cpus::get(),
            tx_queue_size: 10000,
            memory_limit_gb: 8,
            profiling: false,
            profiling_dir: None,
        }
    }
}

impl FluxeConfig {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(level) = std::env::var("FLUXE_LOG_LEVEL") {
            config.logging.level = level;
        }

        if let Ok(addr) = std::env::var("FLUXE_API_ADDRESS") {
            config.network.api_address = addr;
        }

        if let Ok(port) = std::env::var("FLUXE_API_PORT") {
            if let Ok(p) = port.parse() {
                config.network.api_port = p;
            }
        }

        if let Ok(db_path) = std::env::var("FLUXE_DB_PATH") {
            config.storage.db_path = PathBuf::from(db_path);
        }

        config
    }

    /// Initialize logging based on configuration
    pub fn init_logging(&self) {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

        let mut filter = EnvFilter::new(&self.logging.level);

        // Add module-specific levels
        for module_level in &self.logging.module_levels {
            filter = filter.add_directive(
                format!("{}={}", module_level.module, module_level.level)
                    .parse()
                    .unwrap(),
            );
        }

        // Override with environment variable if set
        if let Ok(env_filter) = std::env::var("RUST_LOG") {
            filter = EnvFilter::new(env_filter);
        }

        let subscriber = tracing_subscriber::registry().with(filter);

        if self.logging.json_output {
            subscriber
                .with(fmt::layer().json().with_target(true).with_thread_ids(true))
                .init();
        } else {
            subscriber
                .with(fmt::layer().with_target(true).with_thread_ids(true))
                .init();
        }
    }
}

/// Global configuration instance
static CONFIG: std::sync::OnceLock<FluxeConfig> = std::sync::OnceLock::new();

/// Get the global configuration
pub fn config() -> &'static FluxeConfig {
    CONFIG.get_or_init(|| {
        // Try to load from file, fall back to environment, then defaults
        if let Ok(config) = FluxeConfig::from_file("fluxe.toml") {
            config
        } else {
            FluxeConfig::from_env()
        }
    })
}

/// Set the global configuration (only works once)
pub fn set_config(cfg: FluxeConfig) -> Result<(), FluxeConfig> {
    CONFIG.set(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FluxeConfig::default();
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.network.api_port, 8080);
    }

    #[test]
    fn test_config_serialization() {
        let config = FluxeConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("level = \"info\""));
    }
}