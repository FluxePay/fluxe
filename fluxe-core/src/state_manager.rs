use crate::crypto::poseidon_hash;
use crate::data_structures::{IngressReceipt, ExitReceipt, CallbackInvocation};
use crate::merkle::{IncrementalTree, SortedTree, MerklePath, TreeParams};
use crate::types::{*, StateRoots};
use ark_bls12_381::Fr as F;
use ark_ff::Zero;
use std::collections::HashMap;

/// Global state manager for Fluxe protocol
pub struct StateManager {
    /// Commitment Tree (append-only) for note commitments
    pub cmt_tree: IncrementalTree,
    
    /// Nullifier Tree (sorted) for spent nullifiers
    pub nft_tree: SortedTree,
    
    /// Object Board (append-only) for zk-objects
    pub obj_tree: IncrementalTree,
    
    /// Callback Board (sorted) for callback invocations
    pub cb_tree: SortedTree,
    
    /// Ingress registry (append-only) for mint receipts
    pub ingress_tree: IncrementalTree,
    
    /// Exit registry (append-only) for burn receipts
    pub exit_tree: IncrementalTree,
    
    /// Reference roots (updated out-of-band)
    pub sanctions_root: MerkleRoot,
    pub pool_rules_root: MerkleRoot,
    
    /// Supply accounting per asset type
    pub supply: HashMap<AssetType, Amount>,
    
    /// Tree parameters
    pub params: TreeParams,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(tree_depth: usize) -> Self {
        let params = TreeParams::new(tree_depth);
        
        Self {
            cmt_tree: IncrementalTree::new(tree_depth),
            nft_tree: SortedTree::new(tree_depth),
            obj_tree: IncrementalTree::new(tree_depth),
            cb_tree: SortedTree::new(tree_depth),
            ingress_tree: IncrementalTree::new(tree_depth),
            exit_tree: IncrementalTree::new(tree_depth),
            sanctions_root: F::zero(),
            pool_rules_root: F::zero(),
            supply: HashMap::new(),
            params,
        }
    }
    
    /// Get current state roots
    pub fn get_roots(&self) -> StateRoots {
        StateRoots {
            cmt_root: self.cmt_tree.root(),
            nft_root: self.nft_tree.root(),
            obj_root: self.obj_tree.root(),
            cb_root: self.cb_tree.root(),
            ingress_root: self.ingress_tree.root(),
            exit_root: self.exit_tree.root(),
            sanctions_root: self.sanctions_root,
            pool_rules_root: self.pool_rules_root,
        }
    }
    
    /// Process a mint transaction (boundary-in)
    pub fn process_mint(
        &mut self,
        ingress_receipt: &IngressReceipt,
        output_commitments: &[Commitment],
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();
        
        // Add ingress receipt
        let ingress_hash = ingress_receipt.hash();
        self.ingress_tree.append(ingress_hash);
        
        // Add output commitments to CMT tree
        for &cm in output_commitments {
            self.cmt_tree.append(cm);
        }
        
        // Update supply
        let supply_entry = self.supply.entry(ingress_receipt.asset_type).or_insert(Amount::zero());
        *supply_entry = *supply_entry + ingress_receipt.amount;
        
        let new_roots = self.get_roots();
        
        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                StateOperation::IngressAppend(ingress_hash),
                StateOperation::CmtAppend(output_commitments.to_vec()),
            ],
        })
    }
    
    /// Process a burn transaction (boundary-out)
    pub fn process_burn(
        &mut self,
        exit_receipt: &ExitReceipt,
        nullifier: Nullifier,
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();
        
        // Check nullifier doesn't exist (prevent double spend)
        if self.nft_tree.contains(&nullifier) {
            return Err(StateError::DoubleSpend(nullifier));
        }
        
        // Add nullifier to NFT tree
        self.nft_tree.insert(nullifier)?;
        
        // Add exit receipt
        let exit_hash = exit_receipt.hash();
        self.exit_tree.append(exit_hash);
        
        // Update supply
        let supply_entry = self.supply.get_mut(&exit_receipt.asset_type)
            .ok_or(StateError::InsufficientSupply)?;
        
        if *supply_entry < exit_receipt.amount {
            return Err(StateError::InsufficientSupply);
        }
        
        *supply_entry = *supply_entry - exit_receipt.amount;
        
        let new_roots = self.get_roots();
        
        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                StateOperation::NftInsert(nullifier),
                StateOperation::ExitAppend(exit_hash),
            ],
        })
    }
    
    /// Process a transfer transaction (in-protocol)
    pub fn process_transfer(
        &mut self,
        input_nullifiers: &[Nullifier],
        output_commitments: &[Commitment],
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();
        
        // Check all nullifiers are fresh
        for &nf in input_nullifiers {
            if self.nft_tree.contains(&nf) {
                return Err(StateError::DoubleSpend(nf));
            }
        }
        
        // Add nullifiers to NFT tree
        for &nf in input_nullifiers {
            self.nft_tree.insert(nf)?;
        }
        
        // Add output commitments to CMT tree
        for &cm in output_commitments {
            self.cmt_tree.append(cm);
        }
        
        let new_roots = self.get_roots();
        
        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations: vec![
                StateOperation::NftBatchInsert(input_nullifiers.to_vec()),
                StateOperation::CmtAppend(output_commitments.to_vec()),
            ],
        })
    }
    
    /// Process an object update
    pub fn process_object_update(
        &mut self,
        new_object_commitment: Commitment,
        callback_invocation: Option<&CallbackInvocation>,
    ) -> Result<TransitionProof, StateError> {
        let old_roots = self.get_roots();
        
        // Add new object commitment
        self.obj_tree.append(new_object_commitment);
        
        // If there's a callback invocation, add it to CB tree
        if let Some(invocation) = callback_invocation {
            let cb_hash = invocation.hash();
            self.cb_tree.insert(cb_hash)?;
        }
        
        let new_roots = self.get_roots();
        
        let mut operations = vec![StateOperation::ObjAppend(new_object_commitment)];
        if let Some(invocation) = callback_invocation {
            operations.push(StateOperation::CbInsert(invocation.hash()));
        }
        
        Ok(TransitionProof {
            old_roots,
            new_roots,
            operations,
        })
    }
    
    /// Get Merkle proof for a commitment
    pub fn get_commitment_proof(&self, commitment: Commitment) -> Option<MerklePath> {
        self.cmt_tree.get_proof(commitment)
    }
    
    /// Get non-membership proof for a nullifier
    pub fn get_nullifier_non_membership_proof(&self, nullifier: Nullifier) -> Option<NonMembershipProof> {
        self.nft_tree.get_non_membership_proof(nullifier)
    }
    
    /// Check if a nullifier exists
    pub fn nullifier_exists(&self, nullifier: Nullifier) -> bool {
        self.nft_tree.contains(&nullifier)
    }
    
    /// Get supply for an asset type
    pub fn get_supply(&self, asset_type: AssetType) -> Amount {
        self.supply.get(&asset_type).copied().unwrap_or(Amount::zero())
    }
    
    /// Update sanctions root (admin operation)
    pub fn update_sanctions_root(&mut self, new_root: MerkleRoot) {
        self.sanctions_root = new_root;
    }
    
    /// Update pool rules root (admin operation)
    pub fn update_pool_rules_root(&mut self, new_root: MerkleRoot) {
        self.pool_rules_root = new_root;
    }
}


/// State transition proof
#[derive(Clone, Debug)]
pub struct TransitionProof {
    pub old_roots: StateRoots,
    pub new_roots: StateRoots,
    pub operations: Vec<StateOperation>,
}

impl TransitionProof {
    /// Verify the transition is valid
    pub fn verify(&self) -> bool {
        // In a real implementation, this would replay operations
        // and verify they produce the correct new roots
        true
    }
    
    /// Get the state transition hash
    pub fn hash(&self) -> F {
        poseidon_hash(&[
            self.old_roots.hash(),
            self.new_roots.hash(),
            F::from(self.operations.len() as u64),
        ])
    }
}

/// State operations that can be applied
#[derive(Clone, Debug)]
pub enum StateOperation {
    CmtAppend(Vec<Commitment>),
    NftInsert(Nullifier),
    NftBatchInsert(Vec<Nullifier>),
    ObjAppend(Commitment),
    CbInsert(F),
    IngressAppend(F),
    ExitAppend(F),
}

/// State manager errors
#[derive(Debug, Clone)]
pub enum StateError {
    DoubleSpend(Nullifier),
    InsufficientSupply,
    TreeError(String),
    InvalidProof,
}

impl From<crate::merkle::TreeError> for StateError {
    fn from(e: crate::merkle::TreeError) -> Self {
        StateError::TreeError(format!("{:?}", e))
    }
}

impl From<String> for StateError {
    fn from(e: String) -> Self {
        StateError::TreeError(e)
    }
}

/// Non-membership proof for nullifiers
#[derive(Clone, Debug)]
pub struct NonMembershipProof {
    /// The leaf with key less than target
    pub low_leaf: SortedLeaf,
    /// Merkle path for the low leaf
    pub low_path: MerklePath,
}

/// Sorted tree leaf for non-membership proofs
#[derive(Clone, Debug)]
pub struct SortedLeaf {
    pub key: F,
    pub next_key: F,
    pub next_index: Option<u64>,
}

impl SortedLeaf {
    /// Hash the leaf
    pub fn hash(&self) -> F {
        let mut inputs = vec![self.key, self.next_key];
        if let Some(idx) = self.next_index {
            inputs.push(F::from(idx));
        }
        poseidon_hash(&inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;
    
    #[test]
    fn test_state_manager_mint() {
        let mut manager = StateManager::new(32);
        let mut rng = thread_rng();
        
        let receipt = IngressReceipt {
            asset_type: 1,
            amount: Amount::from(1000u64),
            beneficiary_cm: F::rand(&mut rng),
            nonce: 1,
            aux: F::zero(),
        };
        
        let commitments = vec![F::rand(&mut rng), F::rand(&mut rng)];
        
        let proof = manager.process_mint(&receipt, &commitments).unwrap();
        
        // Check supply updated
        assert_eq!(manager.get_supply(1), Amount::from(1000u64));
        
        // Check roots changed
        assert_ne!(proof.old_roots, proof.new_roots);
        
        println!("✓ State manager mint test passed");
    }
    
    #[test]
    fn test_state_manager_double_spend() {
        let mut manager = StateManager::new(32);
        let mut rng = thread_rng();
        
        let nullifier = F::rand(&mut rng);
        
        // First spend should succeed
        let result = manager.process_transfer(&[nullifier], &[F::rand(&mut rng)]);
        assert!(result.is_ok());
        
        // Second spend should fail
        let result = manager.process_transfer(&[nullifier], &[F::rand(&mut rng)]);
        assert!(matches!(result, Err(StateError::DoubleSpend(_))));
        
        println!("✓ Double spend prevention test passed");
    }
    
    #[test]
    fn test_state_roots_hash() {
        let roots1 = StateRoots {
            cmt_root: F::from(1u64),
            nft_root: F::from(2u64),
            obj_root: F::from(3u64),
            cb_root: F::from(4u64),
            ingress_root: F::from(5u64),
            exit_root: F::from(6u64),
            sanctions_root: F::from(7u64),
            pool_rules_root: F::from(8u64),
        };
        
        let roots2 = roots1.clone();
        
        // Same roots should have same hash
        assert_eq!(roots1.hash(), roots2.hash());
        
        let mut roots3 = roots1.clone();
        roots3.cmt_root = F::from(9u64);
        
        // Different roots should have different hash
        assert_ne!(roots1.hash(), roots3.hash());
        
        println!("✓ State roots hash test passed");
    }
}