/// Configuration module for FLUXE protocol
pub mod base;
pub mod chains;

pub use base::*;
pub use chains::{AssetConfig, ChainConfig, ChainType, MultiChainConfig};

/// Load both main config and chain config
pub fn load_full_config(
    config_path: Option<&str>,
    chains_config_path: Option<&str>,
) -> Result<(FluxeConfig, MultiChainConfig), Box<dyn std::error::Error>> {
    // Load main config
    let main_config = if let Some(path) = config_path {
        FluxeConfig::from_file(path)?
    } else {
        FluxeConfig::from_env()
    };

    // Load chains config
    let chains_config = if let Some(path) = chains_config_path {
        MultiChainConfig::from_file(path)?
    } else if std::path::Path::new("config/chains.toml").exists() {
        MultiChainConfig::from_file("config/chains.toml")?
    } else {
        // Return error if no chains config found
        return Err("No chains configuration file found. Please create config/chains.toml".into());
    };

    Ok((main_config, chains_config))
}
