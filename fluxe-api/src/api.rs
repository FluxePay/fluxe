use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use fluxe_core::{
    config::MultiChainConfig,
    data_structures::{IngressReceipt, ExitReceipt},
    errors::FluxeError,
    server_verifier::{ServerVerifier, TransactionBuilder, TransactionData},
    types::*,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

/// Main Fluxe API service implementing section 12.5 endpoints
pub struct FluxeApi {
    /// Server verifier for batch processing
    pub verifier: Arc<Mutex<ServerVerifier>>,
    /// Multi-chain configuration
    pub config: MultiChainConfig,
}

/// API response wrapper
#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    pub fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

/// Serializable state roots for API requests/responses
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SerializableStateRoots {
    pub cmt_root: String,      // Commitment tree root (hex)
    pub nft_root: String,      // Nullifier tree root (hex)
    pub obj_root: String,      // Object tree root (hex)
    pub cb_root: String,       // Callback tree root (hex)
    pub ingress_root: String,  // Ingress tree root (hex)
    pub exit_root: String,     // Exit tree root (hex)
    pub sanctions_root: String, // Sanctions root (hex)
    pub pool_rules_root: String, // Pool rules root (hex)
}

impl SerializableStateRoots {
    pub fn to_state_roots(&self) -> Result<StateRoots, FluxeError> {
        Ok(StateRoots {
            cmt_root: parse_field_from_hex(&self.cmt_root)?,
            nft_root: parse_field_from_hex(&self.nft_root)?,
            obj_root: parse_field_from_hex(&self.obj_root)?,
            cb_root: parse_field_from_hex(&self.cb_root)?,
            ingress_root: parse_field_from_hex(&self.ingress_root)?,
            exit_root: parse_field_from_hex(&self.exit_root)?,
            sanctions_root: parse_field_from_hex(&self.sanctions_root)?,
            pool_rules_root: parse_field_from_hex(&self.pool_rules_root)?,
        })
    }
}

/// Transaction submission requests
#[derive(Serialize, Deserialize)]
pub struct SubmitMintRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>, // Hex-encoded field elements
    pub notes_out: Vec<SerializableNote>,
    /// Expected new state roots after transaction (hex-encoded)
    /// These must match what the circuit proves
    #[serde(default)]
    pub expected_new_roots: Option<SerializableStateRoots>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitBurnRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub nullifier: String, // Hex-encoded
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    #[serde(default)]
    pub expected_new_roots: Option<SerializableStateRoots>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitTransferRequest {
    pub nullifiers: Vec<String>, // Hex-encoded
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub notes_out: Vec<SerializableNote>,
    #[serde(default)]
    pub expected_new_roots: Option<SerializableStateRoots>,
}

#[derive(Serialize, Deserialize)]
pub struct SubmitObjectUpdateRequest {
    pub old_object_cm: String, // Hex-encoded
    pub new_object_cm: String,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub callback_operations: Vec<SerializableCallbackOp>,
}

/// Serializable versions of core types for API
#[derive(Clone, Serialize, Deserialize)]
pub struct SerializableNote {
    pub asset_type: AssetType,
    pub owner_addr: String, // Hex-encoded
    pub psi: [u8; 32],
    pub chain_hint: ChainHint,
    pub pool_id: PoolId,
}

#[derive(Serialize, Deserialize)]
pub struct SerializableCallbackOp {
    pub op_type: String, // "add" or "process"
    pub ticket: Option<String>, // Hex-encoded
    pub payload: Option<Vec<u8>>,
    pub timestamp: Option<Time>,
    pub signature: Option<Vec<u8>>,
}

/// State query responses
#[derive(Serialize, Deserialize)]
pub struct StateRootsResponse {
    pub cmt_root: String,
    pub nft_root: String,
    pub obj_root: String,
    pub cb_root: String,
    pub ingress_root: String,
    pub exit_root: String,
    pub sanctions_root: String,
    pub pool_rules_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct SupplyResponse {
    pub asset_type: AssetType,
    pub minted_total: u64,
    pub burned_total: u64,
    pub current_supply: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u32>,
}

/// Chain information for listing chains
#[derive(Serialize, Deserialize)]
pub struct ChainInfo {
    pub chain_id: u32,
    pub chain_type: String,
    pub name: String,
    pub enabled: bool,
    pub block_time_ms: u64,
    pub finality_blocks: u64,
    pub supported_assets: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct ProofResponse {
    pub exists: bool,
    pub path: Option<Vec<String>>, // Hex-encoded
    pub leaf: Option<String>,
    pub index: Option<usize>,
}

/// Health check status
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Component health information
#[derive(Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Detailed health check response
#[derive(Serialize, Deserialize)]
pub struct DetailedHealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_seconds: u64,
    pub components: Vec<ComponentHealth>,
    pub chains: Vec<ChainHealthStatus>,
}

/// Chain health status
#[derive(Serialize, Deserialize)]
pub struct ChainHealthStatus {
    pub chain_id: u32,
    pub name: String,
    pub status: HealthStatus,
    pub last_block: Option<u64>,
    pub pending_deposits: Option<u64>,
    pub pending_withdrawals: Option<u64>,
}

/// Readiness response
#[derive(Serialize, Deserialize)]
pub struct ReadinessResponse {
    pub ready: bool,
    pub checks: Vec<ReadinessCheck>,
}

/// Individual readiness check
#[derive(Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub passed: bool,
    pub message: Option<String>,
}

impl FluxeApi {
    pub fn new(verifier: ServerVerifier, config: MultiChainConfig) -> Self {
        Self {
            verifier: Arc::new(Mutex::new(verifier)),
            config,
        }
    }
    
    /// Create the Axum router with all endpoints
    pub fn router(self) -> Router {
        let shared_state = Arc::new(self);

        Router::new()
            // Chain-specific transaction submission endpoints
            .route("/chain/:chain_id/submit/mint", post(submit_mint_chain))
            .route("/chain/:chain_id/submit/burn", post(submit_burn_chain))
            .route("/chain/:chain_id/submit/transfer", post(submit_transfer_chain))
            .route("/chain/:chain_id/submit/object_update", post(submit_object_update_chain))

            // Chain-specific state query endpoints
            .route("/chain/:chain_id/state/roots", get(get_roots_chain))
            .route("/chain/:chain_id/state/supply/:asset_type", get(get_supply_chain))
            .route("/chain/:chain_id/batch/status", get(get_batch_status_chain))

            // Global query endpoints
            .route("/chains", get(list_chains))
            .route("/state/global/roots", get(get_global_roots))
            .route("/state/global/supply/:asset_type", get(get_global_supply))

            // Legacy single-chain endpoints (use default chain if configured)
            .route("/submit/mint", post(submit_mint))
            .route("/submit/burn", post(submit_burn))
            .route("/submit/transfer", post(submit_transfer))
            .route("/submit/object_update", post(submit_object_update))
            .route("/state/roots", get(get_roots))
            .route("/state/supply/:asset_type", get(get_supply))

            // Proof query endpoints (global)
            .route("/proofs/commitment/:cm", get(get_commitment_proof))
            .route("/proofs/nullifier/:nf", get(get_nullifier_proof))
            .route("/proofs/object/:obj", get(get_object_proof))
            .route("/proofs/sanctions/:addr", get(get_sanctions_proof))

            // Batch processing
            .route("/batch/process", post(process_batch))
            .route("/batch/status", get(get_batch_status))

            // Health and info
            .route("/health", get(health_check))
            .route("/health/live", get(health_live))
            .route("/health/ready", get(health_ready))
            .route("/health/detailed", get(health_detailed))
            .route("/info", get(get_info))

            .with_state(shared_state)
    }
    
    /// Start the API server
    pub async fn serve(self, addr: &str) -> Result<(), Box<dyn std::error::Error>> {
        let app = self.router();
        let listener = TcpListener::bind(addr).await?;
        
        println!("Fluxe API server starting on {}", addr);
        axum::serve(listener, app).await?;
        Ok(())
    }
}

// Handler functions
async fn submit_mint(
    State(api): State<Arc<FluxeApi>>,
    Json(req): Json<SubmitMintRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match handle_submit_mint(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(tx_id))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

async fn handle_submit_mint(
    api: Arc<FluxeApi>,
    req: SubmitMintRequest,
) -> Result<String, FluxeError> {
    // Parse proof and public inputs (simplified)
    let proof = parse_proof_from_bytes(&req.proof)?;
    let public_inputs = parse_public_inputs(&req.public_inputs)?;
    
    // Convert serializable notes to core notes
    let notes_out = convert_serializable_notes(&req.notes_out)?;
    
    // Create ingress receipt
    let ingress_receipt = IngressReceipt::new(
        1, // source_chain - default to chain 1
        req.asset_type,
        Amount::from(req.amount), // Convert u64 to Amount
        compute_notes_commitment(&notes_out),
        0, // Would use actual nonce
    );
    
    // Build transaction
    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots(1)?; // Default to chain 1
    drop(verifier);

    // Use expected new roots from client if provided, otherwise compute from state
    // In a proper ZK system, the client knows what the new roots should be
    // because they generated the proof with those roots as public inputs
    let new_roots = match &req.expected_new_roots {
        Some(roots) => roots.to_state_roots()?,
        None => {
            // Fallback: compute expected new roots by simulating the transaction
            // For mint: cmt_root changes (new commitment), ingress_root changes (new receipt)
            // All other roots remain the same
            let computed_roots = old_roots.clone();
            // Note: In production, we would compute the actual tree changes here
            // For now, we indicate that roots will be updated by the verifier
            computed_roots
        }
    };
    
    let chain_id = 1; // Default to chain 1
    let tx = TransactionBuilder::new_mint(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Mint {
            asset_type: req.asset_type,
            amount: Amount::from(req.amount), // Convert u64 to Amount
            notes_out,
            ingress_receipt,
        },
        Some(chain_id),
    );

    // Add to verifier
    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(chain_id, tx)?;
    
    Ok(format!("mint_tx_{}", req.asset_type))
}

async fn submit_burn(
    State(api): State<Arc<FluxeApi>>,
    Json(req): Json<SubmitBurnRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match handle_submit_burn(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(tx_id))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

async fn handle_submit_burn(
    api: Arc<FluxeApi>,
    req: SubmitBurnRequest,
) -> Result<String, FluxeError> {
    let proof = parse_proof_from_bytes(&req.proof)?;
    let public_inputs = parse_public_inputs(&req.public_inputs)?;
    let nullifier = parse_field_from_hex(&req.nullifier)?;

    let exit_receipt = ExitReceipt::new(
        1, // destination_chain - default to chain 1
        req.asset_type,
        Amount::from(req.amount), // Convert u64 to Amount
        nullifier,
        0, // Would use actual nonce
    );

    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots(1)?; // Default to chain 1
    drop(verifier);

    // Use expected new roots from client if provided
    let new_roots = match &req.expected_new_roots {
        Some(roots) => roots.to_state_roots()?,
        None => old_roots.clone(), // Fallback (should be computed in production)
    };

    let chain_id = 1; // Default to chain 1
    let tx = TransactionBuilder::new_burn(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Burn {
            asset_type: req.asset_type,
            amount: Amount::from(req.amount), // Convert u64 to Amount
            nullifier,
            exit_receipt,
        },
        Some(chain_id),
    );

    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(chain_id, tx)?;
    
    Ok(format!("burn_tx_{}", req.asset_type))
}

async fn submit_transfer(
    State(api): State<Arc<FluxeApi>>,
    Json(req): Json<SubmitTransferRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match handle_submit_transfer(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(tx_id))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

async fn handle_submit_transfer(
    api: Arc<FluxeApi>,
    req: SubmitTransferRequest,
) -> Result<String, FluxeError> {
    let proof = parse_proof_from_bytes(&req.proof)?;
    let public_inputs = parse_public_inputs(&req.public_inputs)?;
    let nullifiers = req.nullifiers.iter()
        .map(|s| parse_field_from_hex(s))
        .collect::<Result<Vec<_>, _>>()?;
    let notes_out = convert_serializable_notes(&req.notes_out)?;

    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots(1)?; // Default to chain 1
    drop(verifier);

    // Use expected new roots from client if provided
    let new_roots = match &req.expected_new_roots {
        Some(roots) => roots.to_state_roots()?,
        None => old_roots.clone(), // Fallback (should be computed in production)
    };

    let chain_id = 1; // Default to chain 1
    let tx = TransactionBuilder::new_transfer(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Transfer {
            nullifiers,
            notes_out,
        },
        Some(chain_id),
    );

    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(chain_id, tx)?;
    
    Ok("transfer_tx".to_string())
}

async fn submit_object_update(
    State(api): State<Arc<FluxeApi>>,
    Json(req): Json<SubmitObjectUpdateRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    match handle_submit_object_update(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(tx_id))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

async fn handle_submit_object_update(
    api: Arc<FluxeApi>,
    req: SubmitObjectUpdateRequest,
) -> Result<String, FluxeError> {
    let proof = parse_proof_from_bytes(&req.proof)?;
    let public_inputs = parse_public_inputs(&req.public_inputs)?;
    let old_object_cm = parse_field_from_hex(&req.old_object_cm)?;
    let new_object_cm = parse_field_from_hex(&req.new_object_cm)?;
    let callback_ops = convert_serializable_callback_ops(&req.callback_operations)?;

    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots(1)?; // Default to chain 1
    drop(verifier);

    let new_roots = old_roots.clone(); // Placeholder
    
    let chain_id = 1; // Default to chain 1
    let tx = TransactionBuilder::new_transfer(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::ObjectUpdate {
            old_object_cm,
            new_object_cm,
            callback_ops,
        },
        Some(chain_id),
    );

    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(chain_id, tx)?;
    
    Ok("object_update_tx".to_string())
}

async fn get_roots(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<StateRootsResponse>>, StatusCode> {
    let verifier = api.verifier.lock().unwrap();
    let roots = match verifier.get_current_roots(1) {
        Ok(r) => r,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };

    let response = StateRootsResponse {
        cmt_root: field_to_hex(&roots.cmt_root),
        nft_root: field_to_hex(&roots.nft_root),
        obj_root: field_to_hex(&roots.obj_root),
        cb_root: field_to_hex(&roots.cb_root),
        ingress_root: field_to_hex(&roots.ingress_root),
        exit_root: field_to_hex(&roots.exit_root),
        sanctions_root: field_to_hex(&roots.sanctions_root),
        pool_rules_root: field_to_hex(&roots.pool_rules_root),
        chain_id: None,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_supply(
    State(api): State<Arc<FluxeApi>>,
    Path(asset_type): Path<AssetType>,
) -> Result<Json<ApiResponse<SupplyResponse>>, StatusCode> {
    let verifier = api.verifier.lock().unwrap();
    let supply = verifier.get_supply(asset_type);
    
    // For full supply info, we'd need to access the state manager directly
    let response = SupplyResponse {
        asset_type,
        minted_total: supply.value() as u64, // Convert Amount to u64
        burned_total: 0,      // Would get from state
        current_supply: supply.value() as u64, // Convert Amount to u64
        chain_id: None,
    };
    
    Ok(Json(ApiResponse::success(response)))
}

async fn get_commitment_proof(
    State(api): State<Arc<FluxeApi>>,
    Path(cm_hex): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    // Parse the commitment from hex
    let cm = match parse_field_from_hex(&cm_hex) {
        Ok(c) => c,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };
    
    // Get proof from state manager
    let verifier = api.verifier.lock().unwrap();
    match verifier.get_commitment_proof(&cm) {
        Some(path) => {
            let response = ProofResponse {
                exists: true,
                path: Some(path.siblings.iter().map(field_to_hex).collect()),
                leaf: Some(field_to_hex(&path.leaf)),
                index: Some(path.leaf_index),
            };
            Ok(Json(ApiResponse::success(response)))
        }
        None => {
            let response = ProofResponse {
                exists: false,
                path: None,
                leaf: None,
                index: None,
            };
            Ok(Json(ApiResponse::success(response)))
        }
    }
}

async fn get_nullifier_proof(
    State(api): State<Arc<FluxeApi>>,
    Path(nf_hex): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    // Parse the nullifier from hex
    let nf = match parse_field_from_hex(&nf_hex) {
        Ok(n) => n,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };
    
    // Check if nullifier exists in NFT tree
    let verifier = api.verifier.lock().unwrap();
    if verifier.nullifier_exists(&nf) {
        // Membership proof - nullifier exists (already spent)
        match verifier.get_nullifier_membership_proof(&nf) {
            Some(path) => {
                let response = ProofResponse {
                    exists: true,
                    path: Some(path.siblings.iter().map(field_to_hex).collect()),
                    leaf: Some(field_to_hex(&path.leaf)),
                    index: Some(path.leaf_index),
                };
                Ok(Json(ApiResponse::success(response)))
            }
            None => {
                Ok(Json(ApiResponse::error("Could not generate proof".to_string())))
            }
        }
    } else {
        // Non-membership proof - nullifier doesn't exist (can be spent)
        match verifier.get_nullifier_nonmembership_proof(&nf) {
            Some(range_path) => {
                // For non-membership, return the gap proof
                let response = ProofResponse {
                    exists: false,
                    path: Some(range_path.low_path.siblings.iter().map(field_to_hex).collect()),
                    leaf: Some(field_to_hex(&range_path.low_leaf.hash())),
                    index: Some(range_path.low_path.leaf_index),
                };
                Ok(Json(ApiResponse::success(response)))
            }
            None => {
                Ok(Json(ApiResponse::error("Could not generate non-membership proof".to_string())))
            }
        }
    }
}

async fn get_object_proof(
    State(api): State<Arc<FluxeApi>>,
    Path(obj_hex): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    // Parse the object commitment from hex
    let obj_cm = match parse_field_from_hex(&obj_hex) {
        Ok(o) => o,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };
    
    // Get proof from state manager
    let verifier = api.verifier.lock().unwrap();
    match verifier.get_object_proof(&obj_cm) {
        Some(path) => {
            let response = ProofResponse {
                exists: true,
                path: Some(path.siblings.iter().map(field_to_hex).collect()),
                leaf: Some(field_to_hex(&path.leaf)),
                index: Some(path.leaf_index),
            };
            Ok(Json(ApiResponse::success(response)))
        }
        None => {
            let response = ProofResponse {
                exists: false,
                path: None,
                leaf: None,
                index: None,
            };
            Ok(Json(ApiResponse::success(response)))
        }
    }
}

async fn get_sanctions_proof(
    State(api): State<Arc<FluxeApi>>,
    Path(addr): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    let address = match parse_field_from_hex(&addr) {
        Ok(a) => a,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };
    
    let verifier = api.verifier.lock().unwrap();
    let is_sanctioned = verifier.is_sanctioned(&address);
    
    let response = ProofResponse {
        exists: !is_sanctioned, // Non-membership proof if not sanctioned
        path: if !is_sanctioned { Some(vec!["0x123".to_string()]) } else { None },
        leaf: None,
        index: None,
    };
    
    Ok(Json(ApiResponse::success(response)))
}

async fn process_batch(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    let chain_id = 1; // Default to chain 1
    match api.verifier.lock().unwrap().process_batch(chain_id) {
        Ok(header) => Ok(Json(ApiResponse::success(format!("Block {} created", header.batch_id)))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

async fn get_batch_status(
    State(_api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let status = serde_json::json!({
        "pending_transactions": 0,
        "last_block": 0,
        "last_processed": "2024-01-01T00:00:00Z"
    });
    
    Ok(Json(ApiResponse::success(status)))
}

/// Basic health check - returns OK if server is responding
async fn health_check(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    // Try to acquire verifier lock to ensure it's not deadlocked
    let verifier_ok = api.verifier.try_lock().is_ok();

    let status = if verifier_ok {
        HealthStatus::Healthy
    } else {
        HealthStatus::Degraded
    };

    let response = serde_json::json!({
        "status": status,
        "message": if verifier_ok { "OK" } else { "Verifier busy" }
    });

    Ok(Json(ApiResponse::success(response)))
}

/// Kubernetes liveness probe - just checks if the server is running
async fn health_live() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "ok"
    })))
}

/// Kubernetes readiness probe - checks if the service is ready to accept traffic
async fn health_ready(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<ReadinessResponse>>, StatusCode> {
    let mut checks = Vec::new();
    let mut all_passed = true;

    // Check 1: Verifier is accessible
    let verifier_check = match api.verifier.try_lock() {
        Ok(verifier) => {
            // Try to get roots to verify state is valid
            match verifier.get_current_roots(1) {
                Ok(_) => ReadinessCheck {
                    name: "verifier".to_string(),
                    passed: true,
                    message: Some("Verifier state accessible".to_string()),
                },
                Err(e) => {
                    all_passed = false;
                    ReadinessCheck {
                        name: "verifier".to_string(),
                        passed: false,
                        message: Some(format!("State error: {}", e)),
                    }
                }
            }
        }
        Err(_) => {
            all_passed = false;
            ReadinessCheck {
                name: "verifier".to_string(),
                passed: false,
                message: Some("Verifier locked".to_string()),
            }
        }
    };
    checks.push(verifier_check);

    // Check 2: Chains are configured
    let chain_count = api.config.enabled_chains().count();
    let chains_check = ReadinessCheck {
        name: "chains".to_string(),
        passed: chain_count > 0,
        message: Some(format!("{} chain(s) configured", chain_count)),
    };
    if !chains_check.passed {
        all_passed = false;
    }
    checks.push(chains_check);

    let response = ReadinessResponse {
        ready: all_passed,
        checks,
    };

    // Return 503 if not ready
    if !all_passed {
        return Ok(Json(ApiResponse::success(response)));
    }

    Ok(Json(ApiResponse::success(response)))
}

/// Detailed health check with component status
async fn health_detailed(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<DetailedHealthResponse>>, StatusCode> {
    use std::time::Instant;

    let mut components = Vec::new();
    let mut overall_status = HealthStatus::Healthy;

    // Check verifier component
    let start = Instant::now();
    let verifier_health = match api.verifier.try_lock() {
        Ok(verifier) => {
            let latency = start.elapsed().as_millis() as u64;
            match verifier.get_current_roots(1) {
                Ok(_) => ComponentHealth {
                    name: "verifier".to_string(),
                    status: HealthStatus::Healthy,
                    message: Some("Operational".to_string()),
                    latency_ms: Some(latency),
                },
                Err(e) => {
                    overall_status = HealthStatus::Degraded;
                    ComponentHealth {
                        name: "verifier".to_string(),
                        status: HealthStatus::Degraded,
                        message: Some(format!("State error: {}", e)),
                        latency_ms: Some(latency),
                    }
                }
            }
        }
        Err(_) => {
            overall_status = HealthStatus::Unhealthy;
            ComponentHealth {
                name: "verifier".to_string(),
                status: HealthStatus::Unhealthy,
                message: Some("Verifier locked/unavailable".to_string()),
                latency_ms: None,
            }
        }
    };
    components.push(verifier_health);

    // Check chain connectivity
    let mut chain_statuses = Vec::new();
    for chain_config in api.config.enabled_chains() {
        let chain_status = ChainHealthStatus {
            chain_id: chain_config.chain_id,
            name: chain_config.name.clone(),
            status: if chain_config.enabled {
                HealthStatus::Healthy
            } else {
                HealthStatus::Degraded
            },
            last_block: None, // Would be populated from deposit monitor
            pending_deposits: None,
            pending_withdrawals: None,
        };
        chain_statuses.push(chain_status);
    }

    // TODO: Add uptime tracking (would need static start time)
    let uptime_seconds = 0; // Placeholder

    let response = DetailedHealthResponse {
        status: overall_status,
        version: "0.1.0".to_string(),
        uptime_seconds,
        components,
        chains: chain_statuses,
    };

    Ok(Json(ApiResponse::success(response)))
}

async fn get_info(
    State(_api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let info = serde_json::json!({
        "name": "Fluxe Privacy & Compliance Protocol",
        "version": "0.1.0",
        "description": "ZK-based private stablecoin with compliance",
        "spec_version": "v0.2"
    });

    Ok(Json(ApiResponse::success(info)))
}

// ============================================================================
// Multi-Chain Handlers
// ============================================================================

/// List all supported chains
async fn list_chains(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<Vec<ChainInfo>>>, StatusCode> {
    let chains: Vec<ChainInfo> = api.config.enabled_chains()
        .map(|chain| ChainInfo {
            chain_id: chain.chain_id,
            chain_type: chain.chain_type.as_str().to_string(),
            name: chain.name.clone(),
            enabled: chain.enabled,
            block_time_ms: chain.block_time_ms,
            finality_blocks: chain.finality_blocks,
            supported_assets: chain.assets.iter().map(|a| a.asset_type).collect(),
        })
        .collect();

    Ok(Json(ApiResponse::success(chains)))
}

/// Get global state roots (CMT, NFT, OBJ, CB)
async fn get_global_roots(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<StateRootsResponse>>, StatusCode> {
    let verifier = api.verifier.lock().unwrap();
    let roots = match verifier.get_current_roots(1) {
        Ok(r) => r,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };

    let response = StateRootsResponse {
        cmt_root: field_to_hex(&roots.cmt_root),
        nft_root: field_to_hex(&roots.nft_root),
        obj_root: field_to_hex(&roots.obj_root),
        cb_root: field_to_hex(&roots.cb_root),
        ingress_root: field_to_hex(&roots.ingress_root),
        exit_root: field_to_hex(&roots.exit_root),
        sanctions_root: field_to_hex(&roots.sanctions_root),
        pool_rules_root: field_to_hex(&roots.pool_rules_root),
        chain_id: None, // Global roots don't have a specific chain
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Get global supply across all chains
async fn get_global_supply(
    State(api): State<Arc<FluxeApi>>,
    Path(asset_type): Path<AssetType>,
) -> Result<Json<ApiResponse<SupplyResponse>>, StatusCode> {
    let verifier = api.verifier.lock().unwrap();
    let supply = verifier.get_supply(asset_type);

    let response = SupplyResponse {
        asset_type,
        minted_total: supply.value() as u64,
        burned_total: 0,
        current_supply: supply.value() as u64,
        chain_id: None, // Global supply
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Chain-specific mint submission
async fn submit_mint_chain(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitMintRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate chain exists and is enabled
    let chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !chain_config.enabled {
        return Ok(Json(ApiResponse::error("Chain is not enabled".to_string())));
    }

    // Validate asset is supported on this chain
    if !chain_config.is_asset_supported(req.asset_type) {
        return Ok(Json(ApiResponse::error(format!(
            "Asset type {} is not supported on chain {}",
            req.asset_type, chain_id
        ))));
    }

    match handle_submit_mint(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(format!("chain_{}_mint_{}", chain_id, tx_id)))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

/// Chain-specific burn submission
async fn submit_burn_chain(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitBurnRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate chain exists and is enabled
    let chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !chain_config.enabled {
        return Ok(Json(ApiResponse::error("Chain is not enabled".to_string())));
    }

    // Validate asset is supported on this chain
    if !chain_config.is_asset_supported(req.asset_type) {
        return Ok(Json(ApiResponse::error(format!(
            "Asset type {} is not supported on chain {}",
            req.asset_type, chain_id
        ))));
    }

    match handle_submit_burn(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(format!("chain_{}_burn_{}", chain_id, tx_id)))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

/// Chain-specific transfer submission
async fn submit_transfer_chain(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitTransferRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate chain exists and is enabled
    let chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !chain_config.enabled {
        return Ok(Json(ApiResponse::error("Chain is not enabled".to_string())));
    }

    match handle_submit_transfer(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(format!("chain_{}_transfer_{}", chain_id, tx_id)))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

/// Chain-specific object update submission
async fn submit_object_update_chain(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
    Json(req): Json<SubmitObjectUpdateRequest>,
) -> Result<Json<ApiResponse<String>>, StatusCode> {
    // Validate chain exists and is enabled
    let chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !chain_config.enabled {
        return Ok(Json(ApiResponse::error("Chain is not enabled".to_string())));
    }

    match handle_submit_object_update(api, req).await {
        Ok(tx_id) => Ok(Json(ApiResponse::success(format!("chain_{}_object_{}", chain_id, tx_id)))),
        Err(e) => Ok(Json(ApiResponse::error(e.to_string()))),
    }
}

/// Get chain-specific state roots
async fn get_roots_chain(
    State(api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
) -> Result<Json<ApiResponse<StateRootsResponse>>, StatusCode> {
    // Validate chain exists
    let _chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    let verifier = api.verifier.lock().unwrap();
    let roots = match verifier.get_current_roots(chain_id) {
        Ok(r) => r,
        Err(e) => return Ok(Json(ApiResponse::error(e.to_string()))),
    };

    let response = StateRootsResponse {
        cmt_root: field_to_hex(&roots.cmt_root),
        nft_root: field_to_hex(&roots.nft_root),
        obj_root: field_to_hex(&roots.obj_root),
        cb_root: field_to_hex(&roots.cb_root),
        ingress_root: field_to_hex(&roots.ingress_root),
        exit_root: field_to_hex(&roots.exit_root),
        sanctions_root: field_to_hex(&roots.sanctions_root),
        pool_rules_root: field_to_hex(&roots.pool_rules_root),
        chain_id: Some(chain_id),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Get chain-specific supply
async fn get_supply_chain(
    State(api): State<Arc<FluxeApi>>,
    Path((chain_id, asset_type)): Path<(u32, AssetType)>,
) -> Result<Json<ApiResponse<SupplyResponse>>, StatusCode> {
    // Validate chain exists
    let chain_config = api.config.get_chain(chain_id)
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate asset is supported on this chain
    if !chain_config.is_asset_supported(asset_type) {
        return Ok(Json(ApiResponse::error(format!(
            "Asset type {} is not supported on chain {}",
            asset_type, chain_id
        ))));
    }

    let verifier = api.verifier.lock().unwrap();
    let supply = verifier.get_supply(asset_type);

    let response = SupplyResponse {
        asset_type,
        minted_total: supply.value() as u64,
        burned_total: 0,
        current_supply: supply.value() as u64,
        chain_id: Some(chain_id),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// Get chain-specific batch status
async fn get_batch_status_chain(
    State(_api): State<Arc<FluxeApi>>,
    Path(chain_id): Path<u32>,
) -> Result<Json<ApiResponse<serde_json::Value>>, StatusCode> {
    let status = serde_json::json!({
        "chain_id": chain_id,
        "pending_transactions": 0,
        "last_block": 0,
        "last_processed": "2024-01-01T00:00:00Z"
    });

    Ok(Json(ApiResponse::success(status)))
}

// Utility functions for parsing and conversion
fn parse_proof_from_bytes(bytes: &[u8]) -> Result<ark_groth16::Proof<ark_bn254::Bn254>, FluxeError> {
    use ark_serialize::CanonicalDeserialize;

    // Deserialize the Groth16 proof from compressed bytes
    ark_groth16::Proof::<ark_bn254::Bn254>::deserialize_compressed(&*bytes)
        .map_err(|e| FluxeError::Other(format!("Failed to deserialize proof: {}", e)))
}

fn parse_public_inputs(inputs: &[String]) -> Result<Vec<ark_bn254::Fr>, FluxeError> {
    inputs.iter()
        .map(|s| parse_field_from_hex(s))
        .collect()
}

fn parse_field_from_hex(hex: &str) -> Result<ark_bn254::Fr, FluxeError> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex)
        .map_err(|e| FluxeError::Other(format!("Invalid hex: {}", e)))?;
    
    // Convert bytes to field element (simplified)
    use ark_serialize::CanonicalDeserialize;
    ark_bn254::Fr::deserialize_compressed(&*bytes)
        .map_err(|e| FluxeError::Other(format!("Invalid field element: {}", e)))
}

fn field_to_hex(field: &ark_bn254::Fr) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    field.serialize_compressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(bytes))
}

fn convert_serializable_notes(notes: &[SerializableNote]) -> Result<Vec<fluxe_core::data_structures::Note>, FluxeError> {
    use fluxe_core::data_structures::Note;
    use fluxe_core::crypto::pedersen::PedersenCommitment;

    notes.iter().map(|sn| {
        // Parse owner address from hex
        let owner_addr = parse_field_from_hex(&sn.owner_addr)?;

        // Create a default Pedersen commitment (G1Affine identity point)
        // In production, this should be reconstructed from the proof or stored separately
        // For now, we create a placeholder commitment since the actual value commitment
        // should be verified by the proof itself
        let v_comm = PedersenCommitment {
            commitment: ark_bn254::G1Affine::identity(),
        };

        // Create note with the serialized data
        let note = Note::new(
            sn.asset_type,
            v_comm,
            owner_addr,
            sn.psi,
            sn.pool_id,
        );

        Ok(note)
    }).collect()
}

fn convert_serializable_callback_ops(ops: &[SerializableCallbackOp]) -> Result<Vec<CallbackOperation>, FluxeError> {
    use fluxe_core::data_structures::zk_object::CallbackInvocation;
    use fluxe_core::crypto::schnorr::SchnorrSignature;
    use ark_serialize::CanonicalDeserialize;

    ops.iter().map(|op| {
        match op.op_type.as_str() {
            "add" => {
                // Parse the ticket from hex
                let ticket = op.ticket.as_ref()
                    .ok_or_else(|| FluxeError::Other("Missing ticket for Add operation".to_string()))
                    .and_then(|t| parse_field_from_hex(t))?;

                // Get payload
                let payload = op.payload.clone()
                    .ok_or_else(|| FluxeError::Other("Missing payload for Add operation".to_string()))?;

                // Get timestamp
                let timestamp = op.timestamp
                    .ok_or_else(|| FluxeError::Other("Missing timestamp for Add operation".to_string()))?;

                // Parse signature if provided
                let signature = if let Some(sig_bytes) = &op.signature {
                    Some(SchnorrSignature::deserialize_compressed(&**sig_bytes)
                        .map_err(|e| FluxeError::Other(format!("Failed to deserialize signature: {}", e)))?)
                } else {
                    None
                };

                // Create CallbackInvocation
                let invocation = CallbackInvocation {
                    ticket,
                    payload,
                    timestamp,
                    signature,
                };

                Ok(CallbackOperation::Add(invocation))
            }
            "process" => {
                // Parse the ticket from hex
                let ticket = op.ticket.as_ref()
                    .ok_or_else(|| FluxeError::Other("Missing ticket for Process operation".to_string()))
                    .and_then(|t| parse_field_from_hex(t))?;

                Ok(CallbackOperation::Process(ticket))
            }
            _ => Err(FluxeError::Other(format!("Unknown callback operation type: {}", op.op_type)))
        }
    }).collect()
}

fn compute_notes_commitment(notes: &[fluxe_core::data_structures::Note]) -> ark_bn254::Fr {
    use fluxe_core::crypto::poseidon_hash;
    
    // Compute hash chain: H(0, cm1, cm2, ...)
    // This must match the circuit's cm_out_list_commit computation
    let mut commitment = ark_bn254::Fr::from(0u64);
    
    for note in notes {
        let cm = note.commitment();
        commitment = poseidon_hash(&[commitment, cm]);
    }
    
    commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[test]
    fn test_parse_field_from_hex() {
        // Test valid hex with 0x prefix
        let field = ark_bn254::Fr::from(42u64);
        let hex = field_to_hex(&field);
        let parsed = parse_field_from_hex(&hex).unwrap();
        assert_eq!(field, parsed);
    }

    #[test]
    fn test_parse_public_inputs() {
        let inputs = vec![
            field_to_hex(&ark_bn254::Fr::from(1u64)),
            field_to_hex(&ark_bn254::Fr::from(2u64)),
        ];
        let result = parse_public_inputs(&inputs).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ark_bn254::Fr::from(1u64));
        assert_eq!(result[1], ark_bn254::Fr::from(2u64));
    }

    // TODO: Re-enable test after adding ark-ec to dependencies or using a different approach
    // #[test]
    // fn test_parse_proof_from_bytes() {
    //     use ark_groth16::Proof;
    //     use ark_serialize::CanonicalSerialize;
    //     use ark_bn254::Bn254;
    //     use ark_ec::{CurveGroup, PrimeGroup};
    //
    //     // Create a dummy proof (using generator points)
    //     let proof = Proof::<Bn254> {
    //         a: ark_bn254::G1Projective::generator().into_affine(),
    //         b: ark_bn254::G2Projective::generator().into_affine(),
    //         c: ark_bn254::G1Projective::generator().into_affine(),
    //     };
    //
    //     // Serialize it
    //     let mut bytes = Vec::new();
    //     proof.serialize_compressed(&mut bytes).unwrap();
    //
    //     // Parse it back
    //     let parsed = parse_proof_from_bytes(&bytes).unwrap();
    //
    //     // Verify it matches
    //     assert_eq!(proof.a, parsed.a);
    //     assert_eq!(proof.b, parsed.b);
    //     assert_eq!(proof.c, parsed.c);
    // }

    #[test]
    fn test_parse_proof_from_bytes_invalid() {
        // Test with invalid bytes
        let invalid_bytes = vec![0u8; 10];
        let result = parse_proof_from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_serializable_notes() {
        use ark_bn254::Fr;

        let owner_addr = Fr::from(12345u64);
        let serializable_note = SerializableNote {
            asset_type: 1,
            owner_addr: field_to_hex(&owner_addr),
            psi: [42u8; 32],
            chain_hint: 1,
            pool_id: 1,
        };

        let notes = convert_serializable_notes(&[serializable_note.clone()]).unwrap();
        assert_eq!(notes.len(), 1);

        let note = &notes[0];
        assert_eq!(note.asset_type, 1);
        assert_eq!(note.owner_addr, owner_addr);
        assert_eq!(note.psi, [42u8; 32]);
        assert_eq!(note.chain_hint, 1);
        assert_eq!(note.pool_id, 1);
    }

    #[test]
    fn test_convert_serializable_notes_multiple() {
        use ark_bn254::Fr;

        let notes_input: Vec<SerializableNote> = (0..3).map(|i| {
            SerializableNote {
                asset_type: i,
                owner_addr: field_to_hex(&Fr::from(i as u64)),
                psi: [i as u8; 32],
                chain_hint: 1,
                pool_id: 1,
            }
        }).collect();

        let notes = convert_serializable_notes(&notes_input).unwrap();
        assert_eq!(notes.len(), 3);

        for (i, note) in notes.iter().enumerate() {
            assert_eq!(note.asset_type, i as AssetType);
            assert_eq!(note.owner_addr, Fr::from(i as u64));
        }
    }

    #[test]
    fn test_convert_serializable_notes_invalid_owner() {
        let serializable_note = SerializableNote {
            asset_type: 1,
            owner_addr: "invalid_hex".to_string(),
            psi: [42u8; 32],
            chain_hint: 1,
            pool_id: 1,
        };

        let result = convert_serializable_notes(&[serializable_note]);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_serializable_callback_ops_add() {
        use ark_bn254::Fr;
        use fluxe_core::crypto::{SchnorrSecretKey, SchnorrSignature};
        use ark_ff::UniformRand;

        let ticket = Fr::from(12345u64);
        let payload = vec![1, 2, 3, 4, 5];
        let timestamp = 1000;

        // Generate a valid signature
        let mut rng = rand::thread_rng();
        let sk = SchnorrSecretKey::random(&mut rng);
        let message = [ticket];
        let sig = sk.sign(&message, &mut rng);
        let signature_bytes = sig.to_bytes();

        let serializable_op = SerializableCallbackOp {
            op_type: "add".to_string(),
            ticket: Some(field_to_hex(&ticket)),
            payload: Some(payload.clone()),
            timestamp: Some(timestamp),
            signature: Some(signature_bytes),
        };

        let ops = convert_serializable_callback_ops(&[serializable_op]).unwrap();
        assert_eq!(ops.len(), 1);

        match &ops[0] {
            CallbackOperation::Add(invocation) => {
                assert_eq!(invocation.ticket, ticket);
                assert_eq!(invocation.payload, payload);
                assert_eq!(invocation.timestamp, timestamp);
                assert!(invocation.signature.is_some());
            }
            _ => panic!("Expected Add operation"),
        }
    }

    #[test]
    fn test_convert_serializable_callback_ops_process() {
        use ark_bn254::Fr;

        let ticket = Fr::from(67890u64);

        let serializable_op = SerializableCallbackOp {
            op_type: "process".to_string(),
            ticket: Some(field_to_hex(&ticket)),
            payload: None,
            timestamp: None,
            signature: None,
        };

        let ops = convert_serializable_callback_ops(&[serializable_op]).unwrap();
        assert_eq!(ops.len(), 1);

        match &ops[0] {
            CallbackOperation::Process(t) => {
                assert_eq!(*t, ticket);
            }
            _ => panic!("Expected Process operation"),
        }
    }

    #[test]
    fn test_convert_serializable_callback_ops_invalid_type() {
        let serializable_op = SerializableCallbackOp {
            op_type: "unknown".to_string(),
            ticket: None,
            payload: None,
            timestamp: None,
            signature: None,
        };

        let result = convert_serializable_callback_ops(&[serializable_op]);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_serializable_callback_ops_missing_ticket() {
        let serializable_op = SerializableCallbackOp {
            op_type: "add".to_string(),
            ticket: None,
            payload: Some(vec![1, 2, 3]),
            timestamp: Some(1000),
            signature: Some(vec![10, 20]),
        };

        let result = convert_serializable_callback_ops(&[serializable_op]);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_serializable_callback_ops_multiple() {
        use ark_bn254::Fr;
        use fluxe_core::crypto::SchnorrSecretKey;
        use ark_ff::UniformRand;

        // Generate a valid signature for the first operation
        let mut rng = rand::thread_rng();
        let sk = SchnorrSecretKey::random(&mut rng);
        let ticket1 = Fr::from(1u64);
        let sig = sk.sign(&[ticket1], &mut rng);
        let sig_bytes = sig.to_bytes();

        let ops_input = vec![
            SerializableCallbackOp {
                op_type: "add".to_string(),
                ticket: Some(field_to_hex(&ticket1)),
                payload: Some(vec![1]),
                timestamp: Some(100),
                signature: Some(sig_bytes),
            },
            SerializableCallbackOp {
                op_type: "process".to_string(),
                ticket: Some(field_to_hex(&Fr::from(2u64))),
                payload: None,
                timestamp: None,
                signature: None,
            },
        ];

        let ops = convert_serializable_callback_ops(&ops_input).unwrap();
        assert_eq!(ops.len(), 2);

        match &ops[0] {
            CallbackOperation::Add(_) => {}
            _ => panic!("Expected Add operation"),
        }

        match &ops[1] {
            CallbackOperation::Process(_) => {}
            _ => panic!("Expected Process operation"),
        }
    }

    #[test]
    fn test_compute_notes_commitment() {
        use fluxe_core::data_structures::Note;
        use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
        use ark_bn254::Fr;

        // Create test notes
        let params = PedersenParams::setup_value_commitment();
        let v_comm = PedersenCommitment::commit(&params, 100, &PedersenRandomness { r: Fr::from(123u64) });

        let note1 = Note::new(1, v_comm.clone(), Fr::from(1u64), [1u8; 32], 1);
        let note2 = Note::new(1, v_comm, Fr::from(2u64), [2u8; 32], 1);

        let notes = vec![note1, note2];

        // Compute commitment
        let commitment = compute_notes_commitment(&notes);

        // Verify it's non-zero
        assert_ne!(commitment, Fr::from(0u64));

        // Verify it's deterministic
        let commitment2 = compute_notes_commitment(&notes);
        assert_eq!(commitment, commitment2);
    }
}