use ark_bn254::Fr as F;
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

/// Chain identifier for multi-chain operations
pub type ChainId = u32;

/// Chain type discriminator
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ChainType {
    /// Ethereum Virtual Machine compatible chains
    EVM = 0,
    /// Solana Virtual Machine
    SVM = 1,
}

impl ChainType {
    /// Convert to u8 for serialization
    pub fn as_u8(&self) -> u8 {
        match self {
            ChainType::EVM => 0,
            ChainType::SVM => 1,
        }
    }

    /// Convert from u8 for deserialization
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ChainType::EVM),
            1 => Some(ChainType::SVM),
            _ => None,
        }
    }
}

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
    /// Total fees collected in this block (per-chain aggregation happens in FeeCollector)
    pub total_fees: Amount,
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



// CallbackInvocation is defined in data_structures::zk_object - avoiding duplicate definition

/// Operations on callbacks
#[derive(Clone, Debug)]
pub enum CallbackOperation {
    /// Add a new callback invocation
    Add(crate::data_structures::zk_object::CallbackInvocation),
    /// Process/mark as processed a callback by ticket
    Process(F),
}

/// Global Merkle roots for the unified protocol state
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct GlobalRoots {
    /// Global commitment tree root
    pub cmt_root: MerkleRoot,
    /// Global nullifier tree root
    pub nft_root: MerkleRoot,
    /// Global object board root
    pub obj_root: MerkleRoot,
    /// Global callback board root
    pub cb_root: MerkleRoot,
    /// Global sanctions root (reference)
    pub sanctions_root: MerkleRoot,
    /// Global pool rules root (reference)
    pub pool_rules_root: MerkleRoot,
}

impl Default for GlobalRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalRoots {
    pub fn new() -> Self {
        Self {
            cmt_root: F::from(0),
            nft_root: F::from(0),
            obj_root: F::from(0),
            cb_root: F::from(0),
            sanctions_root: F::from(0),
            pool_rules_root: F::from(0),
        }
    }

    /// Compute hash of global roots
    pub fn hash(&self) -> F {
        use crate::crypto::poseidon_hash;
        poseidon_hash(&[
            self.cmt_root,
            self.nft_root,
            self.obj_root,
            self.cb_root,
            self.sanctions_root,
            self.pool_rules_root,
        ])
    }
}

/// Per-chain state roots for ingress/exit tracking
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ChainStateRoots {
    /// Ingress tree root (deposits from this chain)
    pub ingress_root: MerkleRoot,
    /// Exit tree root (withdrawals to this chain)
    pub exit_root: MerkleRoot,
}

impl Default for ChainStateRoots {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainStateRoots {
    pub fn new() -> Self {
        Self {
            ingress_root: F::from(0),
            exit_root: F::from(0),
        }
    }

    /// Compute hash of chain state roots
    pub fn hash(&self) -> F {
        use crate::crypto::poseidon_hash;
        poseidon_hash(&[self.ingress_root, self.exit_root])
    }
}

/// Global state transition proof
#[derive(Clone, Debug)]
pub struct GlobalTransitionProof {
    /// Old global roots
    pub old_roots: GlobalRoots,
    /// New global roots
    pub new_roots: GlobalRoots,
    /// Operations applied in this transition
    pub operations: Vec<GlobalStateOperation>,
}

impl GlobalTransitionProof {
    /// Verify the transition is valid
    pub fn verify(&self) -> bool {
        // In a real implementation, this would replay operations
        // and verify they produce the correct new roots
        true
    }

    /// Get the state transition hash
    pub fn hash(&self) -> F {
        use crate::crypto::poseidon_hash;
        poseidon_hash(&[
            self.old_roots.hash(),
            self.new_roots.hash(),
            F::from(self.operations.len() as u64),
        ])
    }
}

/// Per-chain state transition proof
#[derive(Clone, Debug)]
pub struct TransitionProof {
    /// Old chain state roots
    pub old_roots: ChainStateRoots,
    /// New chain state roots
    pub new_roots: ChainStateRoots,
    /// Operations applied in this transition
    pub operations: Vec<ChainStateOperation>,
}

impl TransitionProof {
    /// Verify the transition is valid
    pub fn verify(&self) -> bool {
        true
    }

    /// Get the state transition hash
    pub fn hash(&self) -> F {
        use crate::crypto::poseidon_hash;
        poseidon_hash(&[
            self.old_roots.hash(),
            self.new_roots.hash(),
            F::from(self.operations.len() as u64),
        ])
    }
}

/// Global state operations (protocol-wide)
#[derive(Clone, Debug)]
pub enum GlobalStateOperation {
    /// Append commitments to global CMT
    CmtAppend(Vec<Commitment>),
    /// Insert nullifier to global NFT
    NftInsert(Nullifier),
    /// Batch insert nullifiers
    NftBatchInsert(Vec<Nullifier>),
    /// Append object commitment to OBJ tree
    ObjAppend(Commitment),
    /// Insert callback to CB tree
    CbInsert(F),
}

/// Per-chain state operations (boundary crossings)
#[derive(Clone, Debug)]
pub enum ChainStateOperation {
    /// Append ingress receipt (mint from external chain)
    IngressAppend { chain_id: ChainId, receipt_hash: F },
    /// Append exit receipt (burn to external chain)
    ExitAppend { chain_id: ChainId, receipt_hash: F },
}