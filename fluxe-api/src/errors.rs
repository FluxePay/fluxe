/// API-specific error handling for Fluxe API
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Main error type for API operations
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Authentication required")]
    Unauthorized,

    #[error("Access forbidden")]
    Forbidden,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Request timeout")]
    Timeout,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    #[error("State synchronization error: {0}")]
    StateSyncError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Circuit error: {0}")]
    CircuitError(String),

    #[error("Merkle tree error: {0}")]
    MerkleError(String),

    #[error("Compliance check failed: {0}")]
    ComplianceError(String),

    #[error("Insufficient balance")]
    InsufficientBalance,

    #[error("Double spend detected")]
    DoubleSpend,

    #[error("Invalid asset type: {0}")]
    InvalidAssetType(u32),

    #[error("Invalid pool: {0}")]
    InvalidPool(u32),

    #[error("Service unavailable")]
    ServiceUnavailable,

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("{0}")]
    Other(String),
}

/// Result type alias for API operations
pub type ApiResult<T> = Result<T, ApiError>;

/// Client-specific errors
#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Response parsing failed: {0}")]
    ParseError(String),

    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Note encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Note decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Witness computation failed: {0}")]
    WitnessComputationFailed(String),

    #[error("State not synchronized")]
    StateNotSynced,

    #[error("Transaction building failed: {0}")]
    TransactionBuildFailed(String),
}

/// Server-specific errors
#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Batch processing failed: {0}")]
    BatchProcessingFailed(String),

    #[error("State update failed: {0}")]
    StateUpdateFailed(String),

    #[error("Block production failed: {0}")]
    BlockProductionFailed(String),

    #[error("Root computation mismatch")]
    RootMismatch,

    #[error("Invalid block header")]
    InvalidBlockHeader,

    #[error("Chain reorganization detected")]
    ChainReorg,

    #[error("Consensus failure: {0}")]
    ConsensusFailure(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Event emission failed: {0}")]
    EventEmissionFailed(String),
}

/// API response with error details
#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub request_id: Option<String>,
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_code) = match &self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            ApiError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            ApiError::Timeout => (StatusCode::REQUEST_TIMEOUT, "TIMEOUT"),
            ApiError::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            ApiError::InvalidTransaction(_) => (StatusCode::UNPROCESSABLE_ENTITY, "INVALID_TX"),
            ApiError::ProofVerificationFailed(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "PROOF_FAILED")
            }
            ApiError::InsufficientBalance => {
                (StatusCode::UNPROCESSABLE_ENTITY, "INSUFFICIENT_BALANCE")
            }
            ApiError::DoubleSpend => (StatusCode::CONFLICT, "DOUBLE_SPEND"),
            ApiError::ServiceUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "UNAVAILABLE"),
            ApiError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN_ERROR"),
        };

        let body = Json(json!({
            "error": error_code,
            "message": self.to_string(),
        }));

        (status, body).into_response()
    }
}

/// Helper trait for converting various errors to ApiError
pub trait IntoApiError {
    fn into_api_error(self) -> ApiError;
}

impl IntoApiError for ClientError {
    fn into_api_error(self) -> ApiError {
        ApiError::Other(format!("Client error: {}", self))
    }
}

impl IntoApiError for ServerError {
    fn into_api_error(self) -> ApiError {
        ApiError::InternalError(format!("Server error: {}", self))
    }
}


impl From<reqwest::Error> for ApiError {
    fn from(err: reqwest::Error) -> Self {
        ApiError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        ApiError::SerializationError(err.to_string())
    }
}

impl From<ClientError> for ApiError {
    fn from(err: ClientError) -> Self {
        err.into_api_error()
    }
}

impl From<ServerError> for ApiError {
    fn from(err: ServerError) -> Self {
        err.into_api_error()
    }
}

/// Middleware helper for request tracking
pub struct RequestContext {
    pub request_id: String,
    pub client_id: Option<String>,
    pub start_time: std::time::Instant,
}

impl RequestContext {
    pub fn new() -> Self {
        use rand::Rng;
        let request_id = format!(
            "{:016x}",
            rand::thread_rng().gen::<u64>()
        );
        Self {
            request_id,
            client_id: None,
            start_time: std::time::Instant::now(),
        }
    }

    pub fn with_client(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_conversion() {
        let client_err = ClientError::ConnectionFailed("test".to_string());
        let api_err: ApiError = client_err.into();
        assert!(api_err.to_string().contains("Client error"));
    }

    #[test]
    fn test_error_response() {
        let err = ApiError::BadRequest("invalid input".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_request_context() {
        let ctx = RequestContext::new().with_client("test_client".to_string());
        assert!(ctx.client_id.is_some());
        assert_eq!(ctx.client_id.unwrap(), "test_client");
    }
}