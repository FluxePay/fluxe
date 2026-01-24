use fluxe_sequencer_server::{
    AppConfig, FluxeRpcImpl, FluxeRpcServer, SequencerState, SharedState,
};
use jsonrpsee::server::Server;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tower_http::cors::{Any, CorsLayer};
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

    // Load config from environment
    dotenvy::dotenv().ok();
    let config = AppConfig::from_env();

    info!("Starting FLUXE Sequencer Server");
    info!("Chain ID: {}", config.sequencer.chain_id);
    info!("Listening on {}:{}", config.server.host, config.server.port);

    // Create shared state
    let state: SharedState = Arc::new(SequencerState::new(config.sequencer.clone()));

    // Build JSON-RPC server
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;

    // CORS configuration for browser access
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let middleware = tower::ServiceBuilder::new().layer(cors);

    let server = Server::builder()
        .set_http_middleware(middleware)
        .max_connections(config.server.max_connections)
        .build(addr)
        .await?;

    // Create RPC implementation
    let rpc_impl = FluxeRpcImpl::new(state.clone());

    // Start server
    let handle = server.start(rpc_impl.into_rpc());

    info!("FLUXE JSON-RPC server running at http://{}", addr);
    info!("Endpoints:");
    info!("  - fluxe_submitTransaction");
    info!("  - fluxe_getTransactionStatus");
    info!("  - fluxe_getLatestBlock");
    info!("  - fluxe_getBlock");
    info!("  - fluxe_getStateRoots");
    info!("  - fluxe_getHistoricalRoots");
    info!("  - fluxe_chainInfo");
    info!("  - fluxe_health");
    info!("  - eth_chainId (wallet compatible)");
    info!("  - eth_blockNumber (wallet compatible)");

    // Spawn batch production task
    let batch_state = state.clone();
    tokio::spawn(async move {
        batch_production_loop(batch_state).await;
    });

    // Wait for shutdown signal
    shutdown_signal().await;
    info!("Shutting down...");

    // Stop the server
    handle.stop()?;

    Ok(())
}

/// Background task for batch production
async fn batch_production_loop(state: SharedState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));

    loop {
        interval.tick().await;

        if state.should_create_batch() {
            if let Some(batch_txs) = state.create_batch() {
                let tx_count = batch_txs.len();
                info!("Creating batch with {} transactions", tx_count);

                // TODO: In production, this would:
                // 1. Verify all transaction proofs
                // 2. Apply state transitions
                // 3. Generate SP1 batch proof
                // 4. Submit to L1 settlement contracts
                //
                // For now, we just log the batch creation
                // The actual proof generation will be integrated with fluxe-aggregation

                let tx_hashes: Vec<String> = batch_txs.iter().map(|tx| tx.tx_hash.clone()).collect();

                info!(
                    "Batch ready for proof generation: {} txs, hashes: {:?}",
                    tx_count,
                    &tx_hashes[..std::cmp::min(3, tx_hashes.len())]
                );
            }
        }
    }
}

/// Wait for CTRL+C or termination signal
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
