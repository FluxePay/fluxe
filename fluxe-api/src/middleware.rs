/// Middleware for multi-chain API request handling
use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::api::FluxeApi;

/// Middleware to validate chain_id exists in configuration
///
/// This middleware extracts the chain_id from the URL path and verifies
/// it exists in the MultiChainConfig before allowing the request to proceed.
///
/// # Arguments
/// * `state` - Application state containing MultiChainConfig
/// * `chain_id` - Chain ID extracted from path
/// * `request` - Incoming HTTP request
/// * `next` - Next middleware/handler in the chain
///
/// # Returns
/// * `Ok(Response)` - If chain_id is valid, proceeds to next handler
/// * `Err(StatusCode)` - Returns 400 BAD_REQUEST for invalid chain_id
pub async fn validate_chain_id(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if chain exists in configuration
    if !api.config.has_chain(chain_id) {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if chain is enabled
    match api.config.get_chain(chain_id) {
        Some(chain_config) if chain_config.enabled => {
            // Chain exists and is enabled, proceed
            Ok(next.run(request).await)
        }
        Some(_) => {
            // Chain exists but is disabled
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
        None => {
            // Should not happen due to has_chain check above
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Extract and validate chain_id from request state
///
/// Helper function to get chain_id from request extensions if stored by previous middleware
pub fn get_validated_chain_id(request: &Request) -> Option<u32> {
    request.extensions().get::<u32>().copied()
}

// Middleware tests - tests work with MultiChainConfig only (no ServerVerifier needed for chain validation)
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ApiResponse;
    use fluxe_core::config::{AssetConfig, ChainConfig, ChainType, MultiChainConfig};

    /// Create a test MultiChainConfig with two chains
    fn create_test_config() -> MultiChainConfig {
        let mut config = MultiChainConfig::new();

        // Add Ethereum chain (chain_id = 1)
        let eth_chain = ChainConfig {
            chain_id: 1,
            chain_type: ChainType::EVM,
            name: "Ethereum Testnet".to_string(),
            rpc_endpoint: "https://eth-sepolia.example.com".to_string(),
            ws_endpoint: None,
            bridge_address: "0x1234567890123456789012345678901234567890".to_string(),
            verifier_address: Some("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string()),
            assets: vec![AssetConfig {
                asset_type: 1,
                name: "USDC".to_string(),
                token_address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
                decimals: 6,
                min_deposit: 1_000_000,
                max_deposit: 1_000_000_000_000,
                enabled: true,
            }],
            block_time_ms: 12_000,
            finality_blocks: 32,
            max_batch_size: 100,
            base_fee: 1000,
            gas_oracle: None,
            enabled: true,
        };

        // Add Solana chain (chain_id = 501)
        let sol_chain = ChainConfig {
            chain_id: 501,
            chain_type: ChainType::SVM,
            name: "Solana Devnet".to_string(),
            rpc_endpoint: "https://api.devnet.solana.com".to_string(),
            ws_endpoint: Some("wss://api.devnet.solana.com".to_string()),
            bridge_address: "FLUXEBridgeXXXXXXXXXXXXXXXXXXXXXXXXXXX".to_string(),
            verifier_address: None,
            assets: vec![AssetConfig {
                asset_type: 1,
                name: "USDC".to_string(),
                token_address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                decimals: 6,
                min_deposit: 1_000_000,
                max_deposit: 1_000_000_000_000,
                enabled: true,
            }],
            block_time_ms: 400,
            finality_blocks: 32,
            max_batch_size: 100,
            base_fee: 5000,
            gas_oracle: None,
            enabled: true,
        };

        config.add_chain(eth_chain).unwrap();
        config.add_chain(sol_chain).unwrap();

        config
    }

    #[test]
    fn test_config_has_chain() {
        let config = create_test_config();

        // Chain 1 (Ethereum) should exist
        assert!(config.has_chain(1));

        // Chain 501 (Solana) should exist
        assert!(config.has_chain(501));

        // Chain 999 should not exist
        assert!(!config.has_chain(999));
    }

    #[test]
    fn test_config_chain_enabled() {
        let config = create_test_config();

        // Chain 1 should be enabled
        let eth = config.get_chain(1).unwrap();
        assert!(eth.enabled);

        // Chain 501 should be enabled
        let sol = config.get_chain(501).unwrap();
        assert!(sol.enabled);
    }

    #[test]
    fn test_config_chain_disabled() {
        let mut config = create_test_config();

        // Disable chain 501 (Solana)
        if let Some(chain) = config.get_chain_mut(501) {
            chain.enabled = false;
        }

        // Chain 501 should now be disabled
        let sol = config.get_chain(501).unwrap();
        assert!(!sol.enabled);

        // Chain 1 should still be enabled
        let eth = config.get_chain(1).unwrap();
        assert!(eth.enabled);
    }

    #[test]
    fn test_config_asset_support() {
        let config = create_test_config();

        // USDC (asset_type=1) should be supported on Ethereum
        let eth = config.get_chain(1).unwrap();
        assert!(eth.is_asset_supported(1));

        // Unknown asset (asset_type=99) should not be supported
        assert!(!eth.is_asset_supported(99));
    }
}
