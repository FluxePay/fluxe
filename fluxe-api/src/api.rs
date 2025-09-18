use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use fluxe_core::{
    data_structures::{IngressReceipt, ExitReceipt},
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
}

/// API response wrapper
#[derive(Serialize)]
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

/// Transaction submission requests
#[derive(Deserialize)]
pub struct SubmitMintRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>, // Hex-encoded field elements
    pub notes_out: Vec<SerializableNote>,
}

#[derive(Deserialize)]
pub struct SubmitBurnRequest {
    pub asset_type: AssetType,
    pub amount: u64,
    pub nullifier: String, // Hex-encoded
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
}

#[derive(Deserialize)]
pub struct SubmitTransferRequest {
    pub nullifiers: Vec<String>, // Hex-encoded
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub notes_out: Vec<SerializableNote>,
}

#[derive(Deserialize)]
pub struct SubmitObjectUpdateRequest {
    pub old_object_cm: String, // Hex-encoded
    pub new_object_cm: String,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub callback_operations: Vec<SerializableCallbackOp>,
}

/// Serializable versions of core types for API
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize)]
pub struct StateRootsResponse {
    pub cmt_root: String,
    pub nft_root: String,
    pub obj_root: String,
    pub cb_root: String,
    pub ingress_root: String,
    pub exit_root: String,
    pub sanctions_root: String,
    pub pool_rules_root: String,
}

#[derive(Serialize)]
pub struct SupplyResponse {
    pub asset_type: AssetType,
    pub minted_total: u64,
    pub burned_total: u64,
    pub current_supply: u64,
}

#[derive(Serialize)]
pub struct ProofResponse {
    pub exists: bool,
    pub path: Option<Vec<String>>, // Hex-encoded
    pub leaf: Option<String>,
    pub index: Option<usize>,
}

impl FluxeApi {
    pub fn new(verifier: ServerVerifier) -> Self {
        Self {
            verifier: Arc::new(Mutex::new(verifier)),
        }
    }
    
    /// Create the Axum router with all endpoints
    pub fn router(self) -> Router {
        let shared_state = Arc::new(self);
        
        Router::new()
            // Transaction submission endpoints
            .route("/submit/mint", post(submit_mint))
            .route("/submit/burn", post(submit_burn))
            .route("/submit/transfer", post(submit_transfer))
            .route("/submit/object_update", post(submit_object_update))
            
            // State query endpoints
            .route("/state/roots", get(get_roots))
            .route("/state/supply/:asset_type", get(get_supply))
            
            // Proof query endpoints
            .route("/proofs/commitment/:cm", get(get_commitment_proof))
            .route("/proofs/nullifier/:nf", get(get_nullifier_proof))
            .route("/proofs/object/:obj", get(get_object_proof))
            .route("/proofs/sanctions/:addr", get(get_sanctions_proof))
            
            // Batch processing
            .route("/batch/process", post(process_batch))
            .route("/batch/status", get(get_batch_status))
            
            // Health and info
            .route("/health", get(health_check))
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
        req.asset_type,
        req.amount.into(), // Convert u64 to Amount
        compute_notes_commitment(&notes_out),
        0, // Would use actual nonce
    );
    
    // Build transaction
    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots().clone();
    drop(verifier);
    
    // For new roots, we'd need to compute what they would be after this transaction
    // For now, use old roots as placeholder
    let new_roots = old_roots.clone();
    
    let tx = TransactionBuilder::new_mint(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Mint {
            asset_type: req.asset_type,
            amount: req.amount.into(), // Convert u64 to Amount
            notes_out,
            ingress_receipt,
        },
    );
    
    // Add to verifier
    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(tx)?;
    
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
        req.asset_type,
        req.amount.into(), // Convert u64 to Amount
        nullifier,
        0, // Would use actual nonce
    );
    
    let verifier = api.verifier.lock().unwrap();
    let old_roots = verifier.get_current_roots().clone();
    drop(verifier);
    
    let new_roots = old_roots.clone(); // Placeholder
    
    let tx = TransactionBuilder::new_burn(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Burn {
            asset_type: req.asset_type,
            amount: req.amount.into(), // Convert u64 to Amount
            nullifier,
            exit_receipt,
        },
    );
    
    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(tx)?;
    
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
    let old_roots = verifier.get_current_roots().clone();
    drop(verifier);
    
    let new_roots = old_roots.clone(); // Placeholder
    
    let tx = TransactionBuilder::new_transfer(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::Transfer {
            nullifiers,
            notes_out,
        },
    );
    
    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(tx)?;
    
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
    let old_roots = verifier.get_current_roots().clone();
    drop(verifier);
    
    let new_roots = old_roots.clone(); // Placeholder
    
    let tx = TransactionBuilder::new_transfer(old_roots, new_roots).build(
        proof,
        public_inputs,
        TransactionData::ObjectUpdate {
            old_object_cm,
            new_object_cm,
            callback_ops,
        },
    );
    
    let mut verifier = api.verifier.lock().unwrap();
    verifier.add_transaction(tx)?;
    
    Ok("object_update_tx".to_string())
}

async fn get_roots(
    State(api): State<Arc<FluxeApi>>,
) -> Result<Json<ApiResponse<StateRootsResponse>>, StatusCode> {
    let verifier = api.verifier.lock().unwrap();
    let roots = verifier.get_current_roots();
    
    let response = StateRootsResponse {
        cmt_root: field_to_hex(&roots.cmt_root),
        nft_root: field_to_hex(&roots.nft_root),
        obj_root: field_to_hex(&roots.obj_root),
        cb_root: field_to_hex(&roots.cb_root),
        ingress_root: field_to_hex(&roots.ingress_root),
        exit_root: field_to_hex(&roots.exit_root),
        sanctions_root: field_to_hex(&roots.sanctions_root),
        pool_rules_root: field_to_hex(&roots.pool_rules_root),
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
    };
    
    Ok(Json(ApiResponse::success(response)))
}

async fn get_commitment_proof(
    State(_api): State<Arc<FluxeApi>>,
    Path(_cm): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    // Placeholder - would implement actual proof generation
    let response = ProofResponse {
        exists: true,
        path: Some(vec!["0x123".to_string(), "0x456".to_string()]),
        leaf: Some("0x789".to_string()),
        index: Some(0),
    };
    
    Ok(Json(ApiResponse::success(response)))
}

async fn get_nullifier_proof(
    State(_api): State<Arc<FluxeApi>>,
    Path(_nf): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    let response = ProofResponse {
        exists: false,
        path: None,
        leaf: None,
        index: None,
    };
    
    Ok(Json(ApiResponse::success(response)))
}

async fn get_object_proof(
    State(_api): State<Arc<FluxeApi>>,
    Path(_obj): Path<String>,
) -> Result<Json<ApiResponse<ProofResponse>>, StatusCode> {
    let response = ProofResponse {
        exists: true,
        path: Some(vec!["0xabc".to_string()]),
        leaf: Some("0xdef".to_string()),
        index: Some(5),
    };
    
    Ok(Json(ApiResponse::success(response)))
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
    match api.verifier.lock().unwrap().process_batch() {
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

async fn health_check() -> Result<Json<ApiResponse<String>>, StatusCode> {
    Ok(Json(ApiResponse::success("OK".to_string())))
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

// Utility functions for parsing and conversion
fn parse_proof_from_bytes(_bytes: &[u8]) -> Result<ark_groth16::Proof<ark_bls12_381::Bls12_381>, FluxeError> {
    // Placeholder - would deserialize actual Groth16 proof
    Err(FluxeError::Other("Proof parsing not implemented".to_string()))
}

fn parse_public_inputs(inputs: &[String]) -> Result<Vec<ark_bls12_381::Fr>, FluxeError> {
    inputs.iter()
        .map(|s| parse_field_from_hex(s))
        .collect()
}

fn parse_field_from_hex(hex: &str) -> Result<ark_bls12_381::Fr, FluxeError> {
    let hex = hex.trim_start_matches("0x");
    let bytes = hex::decode(hex)
        .map_err(|e| FluxeError::Other(format!("Invalid hex: {}", e)))?;
    
    // Convert bytes to field element (simplified)
    use ark_serialize::CanonicalDeserialize;
    ark_bls12_381::Fr::deserialize_compressed(&*bytes)
        .map_err(|e| FluxeError::Other(format!("Invalid field element: {}", e)))
}

fn field_to_hex(field: &ark_bls12_381::Fr) -> String {
    use ark_serialize::CanonicalSerialize;
    let mut bytes = Vec::new();
    field.serialize_compressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(bytes))
}

fn convert_serializable_notes(_notes: &[SerializableNote]) -> Result<Vec<fluxe_core::data_structures::Note>, FluxeError> {
    // Placeholder - would convert from API format to core format
    Ok(Vec::new())
}

fn convert_serializable_callback_ops(_ops: &[SerializableCallbackOp]) -> Result<Vec<CallbackOperation>, FluxeError> {
    // Placeholder - would convert callback operations
    Ok(Vec::new())
}

fn compute_notes_commitment(_notes: &[fluxe_core::data_structures::Note]) -> ark_bls12_381::Fr {
    // Placeholder - would compute Merkle commitment of notes
    ark_bls12_381::Fr::from(0)
}