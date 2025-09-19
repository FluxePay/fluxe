use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Using ark_serialize for cryptographic types

pub mod field_wrapper;
pub use field_wrapper::FieldElement;

pub mod amount_wrapper;
pub use amount_wrapper::Amount;

/// Asset type identifier (e.g., USDC, USDT)
pub type AssetType = u32;

/// Note commitment
pub type Commitment = F;

/// Nullifier for spent notes
pub type Nullifier = F;

/// Time representation (Unix timestamp)
pub type Time = u64;

/// Pool identifier
pub type PoolId = u32;

/// Merkle tree root
pub type MerkleRoot = F;

/// Authentication address (Poseidon hash of public key or Ethereum address)
pub type AuthAddr = F;

/// Compliance hash
pub type ComplianceHash = F;

/// Lineage hash for tracking note history
pub type LineageHash = F;

/// Callback hash
pub type CallbacksHash = F;

/// Memo hash
pub type MemoHash = F;

/// Object serial number for anti-replay
pub type Serial = u64;

/// Chain hint for cross-chain support
pub type ChainHint = u32;

/// Reputation score
pub type RepScore = u32;

/// Risk score for compliance
pub type RiskScore = u32;

/// Jurisdiction bits for compliance
pub type JurisdictionBits = [u8; 32];

/// Supply counter for each asset
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Supply {
    pub minted_total: Amount,
    pub burned_total: Amount,
}

impl Default for Supply {
    fn default() -> Self {
        Self::new()
    }
}

impl Supply {
    pub fn new() -> Self {
        Self {
            minted_total: Amount::zero(),
            burned_total: Amount::zero(),
        }
    }

    pub fn current_supply(&self) -> Amount {
        self.minted_total.saturating_sub(self.burned_total)
    }

    pub fn mint(&mut self, amount: Amount) {
        self.minted_total = self.minted_total.saturating_add(amount);
    }

    pub fn burn(&mut self, amount: Amount) -> Result<(), &'static str> {
        let _new_supply = self.current_supply().checked_sub(amount)
            .ok_or("Insufficient supply to burn")?;
        self.burned_total = self.burned_total.saturating_add(amount);
        Ok(())
    }
}

/// Block header for state commitment
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct BlockHeader {
    pub prev_roots: StateRoots,
    pub new_roots: StateRoots,
    pub batch_id: u64,
    pub agg_proof: Vec<u8>, // Placeholder for aggregated proof
    pub timestamp: Time,
}

/// Collection of all Merkle roots
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct StateRoots {
    pub cmt_root: MerkleRoot,
    pub nft_root: MerkleRoot,
    pub obj_root: MerkleRoot,
    pub cb_root: MerkleRoot,
    pub ingress_root: MerkleRoot,
    pub exit_root: MerkleRoot,
    pub sanctions_root: MerkleRoot,
    pub pool_rules_root: MerkleRoot,
}

impl Default for StateRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl StateRoots {
    pub fn new() -> Self {
        Self {
            cmt_root: F::from(0),
            nft_root: F::from(0),
            obj_root: F::from(0),
            cb_root: F::from(0),
            ingress_root: F::from(0),
            exit_root: F::from(0),
            sanctions_root: F::from(0),
            pool_rules_root: F::from(0),
        }
    }
    
    /// Compute hash of all roots
    pub fn hash(&self) -> F {
        use crate::crypto::poseidon_hash;
        poseidon_hash(&[
            self.cmt_root,
            self.nft_root,
            self.obj_root,
            self.cb_root,
            self.ingress_root,
            self.exit_root,
            self.sanctions_root,
            self.pool_rules_root,
        ])
    }
}

/// Transaction types
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionType {
    Mint,
    Burn,
    Transfer,
    ObjectUpdate,
}

/// Result type for Fluxe operations
pub type FluxeResult<T> = Result<T, FluxeError>;

/// Error types for Fluxe
#[derive(Debug, thiserror::Error)]
pub enum FluxeError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Double spend detected: nullifier {0:?} already exists")]
    DoubleSpend(Nullifier),
    
    #[error("Insufficient balance")]
    InsufficientBalance,
    
    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),
    
    #[error("Invalid merkle path")]
    InvalidMerklePath,
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Other error: {0}")]
    Other(String),
}

impl From<String> for FluxeError {
    fn from(s: String) -> Self {
        FluxeError::Other(s)
    }
}

impl From<&str> for FluxeError {
    fn from(s: &str) -> Self {
        FluxeError::Other(s.to_string())
    }
}

// CallbackInvocation is defined in data_structures::zk_object - avoiding duplicate definition

/// Operations on callbacks
#[derive(Clone, Debug)]
pub enum CallbackOperation {
    /// Add a new callback invocation
    Add(crate::data_structures::zk_object::CallbackInvocation),
    /// Process/mark as processed a callback by ticket
    Process(F),
}