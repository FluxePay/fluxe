use super::{AssetConfig, ChainConfig, ChainType, MultiChainConfig};

// Helper function to create a valid EVM chain config for testing
fn create_test_evm_chain() -> ChainConfig {
    ChainConfig {
        chain_id: 1,
        chain_type: ChainType::EVM,
        name: "Ethereum Mainnet".to_string(),
        rpc_endpoint: "https://eth-mainnet.alchemyapi.io/v2/KEY".to_string(),
        ws_endpoint: Some("wss://eth-mainnet.alchemyapi.io/v2/KEY".to_string()),
        bridge_address: "0x1234567890123456789012345678901234567890".to_string(),
        verifier_address: Some("0x0987654321098765432109876543210987654321".to_string()),
        assets: vec![create_test_asset(1, "USDC")],
        block_time_ms: 12000,
        finality_blocks: 32,
        max_batch_size: 100,
        base_fee: 1_000_000,
        gas_oracle: None,
        enabled: true,
    }
}

// Helper function to create a valid SVM chain config for testing
fn create_test_svm_chain() -> ChainConfig {
    ChainConfig {
        chain_id: 501,
        chain_type: ChainType::SVM,
        name: "Solana Mainnet".to_string(),
        rpc_endpoint: "https://api.mainnet-beta.solana.com".to_string(),
        ws_endpoint: Some("wss://api.mainnet-beta.solana.com".to_string()),
        bridge_address: "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
        verifier_address: None,
        assets: vec![create_test_asset_svm(1, "USDC")],
        block_time_ms: 400,
        finality_blocks: 32,
        max_batch_size: 100,
        base_fee: 5_000,
        gas_oracle: None,
        enabled: true,
    }
}

// Helper function to create a test asset for EVM
fn create_test_asset(asset_type: u32, name: &str) -> AssetConfig {
    AssetConfig {
        asset_type,
        name: name.to_string(),
        token_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        decimals: 6,
        min_deposit: 1_000_000,
        max_deposit: 1_000_000_000_000,
        enabled: true,
    }
}

// Helper function to create a test asset for SVM
fn create_test_asset_svm(asset_type: u32, name: &str) -> AssetConfig {
    AssetConfig {
        asset_type,
        name: name.to_string(),
        token_address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
        decimals: 6,
        min_deposit: 1_000_000,
        max_deposit: 1_000_000_000_000,
        enabled: true,
    }
}

#[test]
fn test_chain_type_from_str() {
    assert_eq!(ChainType::from_str("EVM").unwrap(), ChainType::EVM);
    assert_eq!(ChainType::from_str("evm").unwrap(), ChainType::EVM);
    assert_eq!(ChainType::from_str("Evm").unwrap(), ChainType::EVM);
    assert_eq!(ChainType::from_str("SVM").unwrap(), ChainType::SVM);
    assert_eq!(ChainType::from_str("svm").unwrap(), ChainType::SVM);
    assert_eq!(ChainType::from_str("Svm").unwrap(), ChainType::SVM);

    assert!(ChainType::from_str("invalid").is_err());
    assert!(ChainType::from_str("").is_err());
    assert!(ChainType::from_str("ETHEREUM").is_err());
}

#[test]
fn test_chain_type_as_str() {
    assert_eq!(ChainType::EVM.as_str(), "EVM");
    assert_eq!(ChainType::SVM.as_str(), "SVM");
}

#[test]
fn test_asset_config_validation_success() {
    let asset = create_test_asset(1, "USDC");
    assert!(asset.validate().is_ok());
}

#[test]
fn test_asset_config_validation_empty_name() {
    let mut asset = create_test_asset(1, "USDC");
    asset.name = "".to_string();
    assert!(asset.validate().is_err());
}

#[test]
fn test_asset_config_validation_empty_token_address() {
    let mut asset = create_test_asset(1, "USDC");
    asset.token_address = "".to_string();
    assert!(asset.validate().is_err());
}

#[test]
fn test_asset_config_validation_zero_min_deposit() {
    let mut asset = create_test_asset(1, "USDC");
    asset.min_deposit = 0;
    assert!(asset.validate().is_err());
}

#[test]
fn test_asset_config_validation_max_less_than_min() {
    let mut asset = create_test_asset(1, "USDC");
    asset.max_deposit = asset.min_deposit;
    assert!(asset.validate().is_err());

    asset.max_deposit = asset.min_deposit - 1;
    assert!(asset.validate().is_err());
}

#[test]
fn test_asset_config_validation_decimals_too_high() {
    let mut asset = create_test_asset(1, "USDC");
    asset.decimals = 19;
    assert!(asset.validate().is_err());

    asset.decimals = 18;
    assert!(asset.validate().is_ok());
}

#[test]
fn test_asset_is_valid_amount() {
    let asset = create_test_asset(1, "USDC");

    // Valid amounts
    assert!(asset.is_valid_amount(1_000_000));
    assert!(asset.is_valid_amount(5_000_000));
    assert!(asset.is_valid_amount(1_000_000_000_000));

    // Invalid amounts
    assert!(!asset.is_valid_amount(999_999));
    assert!(!asset.is_valid_amount(1_000_000_000_001));
    assert!(!asset.is_valid_amount(0));
}

#[test]
fn test_asset_is_valid_amount_disabled() {
    let mut asset = create_test_asset(1, "USDC");
    asset.enabled = false;

    // Even valid amounts should return false when disabled
    assert!(!asset.is_valid_amount(1_000_000));
}

#[test]
fn test_chain_config_validation_evm_success() {
    let chain = create_test_evm_chain();
    assert!(chain.validate().is_ok());
}

#[test]
fn test_chain_config_validation_svm_success() {
    let chain = create_test_svm_chain();
    assert!(chain.validate().is_ok());
}

#[test]
fn test_chain_config_validation_empty_name() {
    let mut chain = create_test_evm_chain();
    chain.name = "".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_empty_rpc() {
    let mut chain = create_test_evm_chain();
    chain.rpc_endpoint = "".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_rpc_protocol() {
    let mut chain = create_test_evm_chain();
    chain.rpc_endpoint = "ftp://invalid.com".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_ws_protocol() {
    let mut chain = create_test_evm_chain();
    chain.ws_endpoint = Some("http://invalid.com".to_string());
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_empty_bridge_address() {
    let mut chain = create_test_evm_chain();
    chain.bridge_address = "".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_evm_bridge_address() {
    let mut chain = create_test_evm_chain();

    // Too short
    chain.bridge_address = "0x123".to_string();
    assert!(chain.validate().is_err());

    // No 0x prefix
    chain.bridge_address = "1234567890123456789012345678901234567890".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_evm_verifier_address() {
    let mut chain = create_test_evm_chain();
    chain.verifier_address = Some("0x123".to_string());
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_svm_bridge_address() {
    let mut chain = create_test_svm_chain();

    // Too short
    chain.bridge_address = "ABC".to_string();
    assert!(chain.validate().is_err());

    // Too long
    chain.bridge_address = "A".repeat(50);
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_zero_block_time() {
    let mut chain = create_test_evm_chain();
    chain.block_time_ms = 0;
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_zero_finality_blocks() {
    let mut chain = create_test_evm_chain();
    chain.finality_blocks = 0;
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_zero_max_batch_size() {
    let mut chain = create_test_evm_chain();
    chain.max_batch_size = 0;
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_no_assets() {
    let mut chain = create_test_evm_chain();
    chain.assets = vec![];
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_duplicate_asset_types() {
    let mut chain = create_test_evm_chain();
    chain.assets.push(create_test_asset(1, "USDC2")); // Duplicate asset_type
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_validation_invalid_evm_token_address() {
    let mut chain = create_test_evm_chain();
    chain.assets[0].token_address = "invalid".to_string();
    assert!(chain.validate().is_err());
}

#[test]
fn test_chain_config_get_asset() {
    let chain = create_test_evm_chain();

    let asset = chain.get_asset(1);
    assert!(asset.is_some());
    assert_eq!(asset.unwrap().name, "USDC");

    let not_found = chain.get_asset(999);
    assert!(not_found.is_none());
}

#[test]
fn test_chain_config_is_asset_supported() {
    let chain = create_test_evm_chain();

    assert!(chain.is_asset_supported(1));
    assert!(!chain.is_asset_supported(999));
}

#[test]
fn test_chain_config_is_asset_supported_disabled_chain() {
    let mut chain = create_test_evm_chain();
    chain.enabled = false;

    assert!(!chain.is_asset_supported(1));
}

#[test]
fn test_chain_config_is_asset_supported_disabled_asset() {
    let mut chain = create_test_evm_chain();
    chain.assets[0].enabled = false;

    assert!(!chain.is_asset_supported(1));
}

#[test]
fn test_chain_config_finality_time() {
    let chain = create_test_evm_chain();
    assert_eq!(chain.finality_time_ms(), 12000 * 32);

    let sol_chain = create_test_svm_chain();
    assert_eq!(sol_chain.finality_time_ms(), 400 * 32);
}

#[test]
fn test_multi_chain_config_new() {
    let config = MultiChainConfig::new();
    assert_eq!(config.chain_count(), 0);
    assert!(config.default_chain.is_none());
}

#[test]
fn test_multi_chain_config_add_chain() {
    let mut config = MultiChainConfig::new();
    let chain = create_test_evm_chain();

    assert!(config.add_chain(chain.clone()).is_ok());
    assert_eq!(config.chain_count(), 1);
    assert!(config.has_chain(1));

    // Test duplicate prevention
    assert!(config.add_chain(chain).is_err());
}

#[test]
fn test_multi_chain_config_get_chain() {
    let mut config = MultiChainConfig::new();
    let chain = create_test_evm_chain();
    config.add_chain(chain).unwrap();

    let retrieved = config.get_chain(1);
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().name, "Ethereum Mainnet");

    let not_found = config.get_chain(999);
    assert!(not_found.is_none());
}

#[test]
fn test_multi_chain_config_remove_chain() {
    let mut config = MultiChainConfig::new();
    let chain = create_test_evm_chain();
    config.add_chain(chain).unwrap();

    let removed = config.remove_chain(1);
    assert!(removed.is_some());
    assert_eq!(config.chain_count(), 0);

    let not_found = config.remove_chain(1);
    assert!(not_found.is_none());
}

#[test]
fn test_multi_chain_config_chain_ids() {
    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();
    config.add_chain(create_test_svm_chain()).unwrap();

    let ids = config.chain_ids();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&1));
    assert!(ids.contains(&501));
}

#[test]
fn test_multi_chain_config_validation_empty() {
    let config = MultiChainConfig::new();
    assert!(config.validate().is_err());
}

#[test]
fn test_multi_chain_config_validation_invalid_default_chain() {
    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();
    config.default_chain = Some(999); // Non-existent chain

    assert!(config.validate().is_err());
}

#[test]
fn test_multi_chain_config_default_chain_config() {
    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();
    config.default_chain = Some(1);

    let default = config.default_chain_config();
    assert!(default.is_some());
    assert_eq!(default.unwrap().chain_id, 1);
}

#[test]
fn test_multi_chain_config_enabled_chains() {
    let mut config = MultiChainConfig::new();

    let mut eth = create_test_evm_chain();
    eth.enabled = true;
    config.add_chain(eth).unwrap();

    let mut sol = create_test_svm_chain();
    sol.enabled = false;
    config.add_chain(sol).unwrap();

    let enabled: Vec<_> = config.enabled_chains().collect();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0].chain_id, 1);
}

#[test]
fn test_multi_chain_config_from_toml() {
    let toml_str = r#"
        default_chain = 1

        [chains.ethereum]
        chain_id = 1
        chain_type = "EVM"
        name = "Ethereum Mainnet"
        rpc_endpoint = "https://eth-mainnet.alchemyapi.io/v2/KEY"
        bridge_address = "0x1234567890123456789012345678901234567890"
        block_time_ms = 12000
        finality_blocks = 32
        max_batch_size = 100
        base_fee = 1000000
        enabled = true

        [[chains.ethereum.assets]]
        asset_type = 1
        name = "USDC"
        token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        decimals = 6
        min_deposit = 1000000
        max_deposit = 1000000000000
        enabled = true
    "#;

    let config = MultiChainConfig::from_toml(toml_str);
    if let Err(ref e) = config {
        eprintln!("Config error: {}", e);
    }
    assert!(config.is_ok());

    let config = config.unwrap();
    assert_eq!(config.chain_count(), 1);
    assert_eq!(config.default_chain, Some(1));

    let chain = config.get_chain(1).unwrap();
    assert_eq!(chain.name, "Ethereum Mainnet");
    assert_eq!(chain.assets.len(), 1);
    assert_eq!(chain.assets[0].name, "USDC");
}

#[test]
fn test_multi_chain_config_to_toml() {
    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();
    config.default_chain = Some(1);

    let toml_str = toml::to_string(&config);
    assert!(toml_str.is_ok());

    let toml_str = toml_str.unwrap();
    assert!(toml_str.contains("chain_id = 1"));
    assert!(toml_str.contains("Ethereum Mainnet"));
    assert!(toml_str.contains("USDC"));
}

#[test]
fn test_multi_chain_config_multiple_chains() {
    let toml_str = r#"
        default_chain = 1

        [chains.ethereum]
        chain_id = 1
        chain_type = "EVM"
        name = "Ethereum"
        rpc_endpoint = "https://eth.example.com"
        bridge_address = "0x1234567890123456789012345678901234567890"
        block_time_ms = 12000
        finality_blocks = 32
        max_batch_size = 100
        base_fee = 1000000
        enabled = true

        [[chains.ethereum.assets]]
        asset_type = 1
        name = "USDC"
        token_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        decimals = 6
        min_deposit = 1000000
        max_deposit = 1000000000000
        enabled = true

        [chains.solana]
        chain_id = 501
        chain_type = "SVM"
        name = "Solana"
        rpc_endpoint = "https://solana.example.com"
        bridge_address = "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXX"
        block_time_ms = 400
        finality_blocks = 32
        max_batch_size = 100
        base_fee = 5000
        enabled = true

        [[chains.solana.assets]]
        asset_type = 1
        name = "USDC"
        token_address = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        decimals = 6
        min_deposit = 1000000
        max_deposit = 1000000000000
        enabled = true
    "#;

    let config = MultiChainConfig::from_toml(toml_str);
    assert!(config.is_ok());

    let config = config.unwrap();
    assert_eq!(config.chain_count(), 2);
    assert!(config.has_chain(1));
    assert!(config.has_chain(501));

    let eth = config.get_chain(1).unwrap();
    assert_eq!(eth.chain_type, ChainType::EVM);

    let sol = config.get_chain(501).unwrap();
    assert_eq!(sol.chain_type, ChainType::SVM);
}

#[test]
fn test_multi_chain_config_apply_env_overrides() {
    std::env::set_var("FLUXE_CHAIN_1_RPC_ENDPOINT", "https://override-rpc.com");
    std::env::set_var("FLUXE_CHAIN_1_WS_ENDPOINT", "wss://override-ws.com");
    std::env::set_var(
        "FLUXE_CHAIN_1_BRIDGE_ADDRESS",
        "0x9999999999999999999999999999999999999999",
    );

    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();

    assert!(config.apply_env_overrides().is_ok());

    let chain = config.get_chain(1).unwrap();
    assert_eq!(chain.rpc_endpoint, "https://override-rpc.com");
    assert_eq!(chain.ws_endpoint.as_ref().unwrap(), "wss://override-ws.com");
    assert_eq!(
        chain.bridge_address,
        "0x9999999999999999999999999999999999999999"
    );

    // Clean up
    std::env::remove_var("FLUXE_CHAIN_1_RPC_ENDPOINT");
    std::env::remove_var("FLUXE_CHAIN_1_WS_ENDPOINT");
    std::env::remove_var("FLUXE_CHAIN_1_BRIDGE_ADDRESS");
}

#[test]
fn test_multi_chain_config_apply_env_overrides_invalid() {
    std::env::set_var("FLUXE_CHAIN_1_BRIDGE_ADDRESS", "invalid-address");

    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();

    // Should fail validation after applying invalid override
    assert!(config.apply_env_overrides().is_err());

    // Clean up
    std::env::remove_var("FLUXE_CHAIN_1_BRIDGE_ADDRESS");
}

#[test]
fn test_config_file_round_trip() {
    use std::fs;

    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join("test_chains_config.toml");

    let mut config = MultiChainConfig::new();
    config.add_chain(create_test_evm_chain()).unwrap();
    config.add_chain(create_test_svm_chain()).unwrap();
    config.default_chain = Some(1);

    // Save to file
    assert!(config.to_file(&config_path).is_ok());

    // Load from file
    let loaded = MultiChainConfig::from_file(&config_path);
    assert!(loaded.is_ok());

    let loaded = loaded.unwrap();
    assert_eq!(loaded.chain_count(), 2);
    assert_eq!(loaded.default_chain, Some(1));

    // Clean up
    fs::remove_file(config_path).ok();
}
