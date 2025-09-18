pub mod incremental_tree;
pub mod sorted_tree;
pub mod tree_error;
pub mod tree_params;

pub use incremental_tree::*;
pub use sorted_tree::*;
pub use tree_error::*;
pub use tree_params::*;

/// Witness data for append operation (compatible with circuit gadgets)
#[derive(Clone, Debug)]
pub struct AppendWitness {
    pub leaf: F,
    pub leaf_index: usize,
    pub pre_siblings: Vec<F>,
    pub height: usize,
}

impl AppendWitness {
    pub fn new(leaf: F, leaf_index: usize, pre_siblings: Vec<F>, height: usize) -> Self {
        Self {
            leaf,
            leaf_index,
            pre_siblings,
            height,
        }
    }
    
    /// Compute the root before insertion
    pub fn compute_old_root(&self, params: &TreeParams) -> F {
        if self.leaf_index == 0 {
            return params.empty_root();
        }
        
        let mut current = params.empty_at_level(0);
        let mut index = self.leaf_index;
        
        for sibling in &self.pre_siblings {
            current = if index & 1 == 0 {
                params.hash_pair(&current, sibling)
            } else {
                params.hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        
        current
    }
    
    /// Compute the root after insertion
    pub fn compute_new_root(&self, params: &TreeParams) -> F {
        let mut current = self.leaf;
        let mut index = self.leaf_index;
        
        for sibling in &self.pre_siblings {
            current = if index & 1 == 0 {
                params.hash_pair(&current, sibling)
            } else {
                params.hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        
        current
    }
}

use crate::crypto::poseidon_hash;
use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// use serde::{Deserialize, Serialize};

/// Merkle path for membership proofs
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerklePath {
    /// Leaf index in tree
    pub leaf_index: usize,
    
    /// Sibling hashes from leaf to root
    pub siblings: Vec<F>,
    
    /// Leaf value
    pub leaf: F,
}

impl MerklePath {
    /// Verify membership proof
    pub fn verify(&self, root: &F, params: &TreeParams) -> bool {
        let mut current = self.leaf;
        let mut index = self.leaf_index;
        
        for sibling in &self.siblings {
            current = if index & 1 == 0 {
                // Current is left child
                params.hash_pair(&current, sibling)
            } else {
                // Current is right child
                params.hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        
        &current == root
    }
    
    /// Compute the root from this path
    pub fn compute_root(&self, params: &TreeParams) -> F {
        let mut current = self.leaf;
        let mut index = self.leaf_index;
        
        for sibling in &self.siblings {
            current = if index & 1 == 0 {
                params.hash_pair(&current, sibling)
            } else {
                params.hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        
        current
    }
}

/// Range proof for non-membership in sorted tree
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangePath {
    /// Low leaf (key < target)
    pub low_leaf: SortedLeaf,
    
    /// Path to low leaf
    pub low_path: MerklePath,
    
    /// Target value we're proving non-membership for
    pub target: F,
}

impl RangePath {
    /// Verify non-membership proof
    pub fn verify(&self, root: &F, params: &TreeParams) -> bool {
        // Verify low leaf is in tree
        if !self.low_path.verify(root, params) {
            return false;
        }
        
        // Verify target is in gap
        self.low_leaf.contains_gap(&self.target)
    }
}

/// Leaf in sorted Merkle tree
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct SortedLeaf {
    /// The key value
    pub key: F,
    
    /// Next larger key (0 if none)
    pub next_key: F,
    
    /// Index of next leaf
    pub next_index: usize,
}

impl SortedLeaf {
    pub fn new(key: F) -> Self {
        Self {
            key,
            next_key: F::from(0),
            next_index: 0,
        }
    }
    
    /// Check if value falls in gap after this leaf
    pub fn contains_gap(&self, value: &F) -> bool {
        *value > self.key && (self.next_key == F::from(0) || *value < self.next_key)
    }
    
    /// Hash this leaf for Merkle tree
    pub fn hash(&self) -> F {
        poseidon_hash(&[
            self.key,
            self.next_key,
            F::from(self.next_index as u64),
        ])
    }
}

/// Witness data for sorted insert operation
#[derive(Clone, Debug)]
pub struct SortedInsertWitness {
    /// The value being inserted
    pub target: F,
    /// Non-membership proof (range proof)
    pub range_proof: RangePath,
    /// New leaf being inserted
    pub new_leaf: SortedLeaf,
    /// Updated predecessor leaf
    pub updated_pred_leaf: SortedLeaf,
    /// Path to the new leaf position (post-insert)
    pub new_leaf_path: MerklePath,
    /// Path to the predecessor position (for update)
    pub pred_update_path: MerklePath,
    /// Tree height
    pub height: usize,
}

impl SortedInsertWitness {
    pub fn new(
        target: F,
        range_proof: RangePath,
        new_leaf: SortedLeaf,
        updated_pred_leaf: SortedLeaf,
        new_leaf_path: MerklePath,
        pred_update_path: MerklePath,
        height: usize,
    ) -> Self {
        Self {
            target,
            range_proof,
            new_leaf,
            updated_pred_leaf,
            new_leaf_path,
            pred_update_path,
            height,
        }
    }
    
    /// Compute the root after insertion
    pub fn compute_new_root(&self, params: &TreeParams) -> F {
        // This is a simplified computation
        // In practice, this would properly update the tree structure
        
        // Step 1: Compute intermediate root after updating predecessor
        let updated_pred_hash = self.updated_pred_leaf.hash();
        let intermediate_root = self.compute_root_with_leaf(
            &self.pred_update_path,
            updated_pred_hash,
            params,
        );
        
        // Step 2: For simplicity, just hash the intermediate root with the new leaf
        // In a real implementation, this would properly insert the new leaf
        let new_leaf_hash = self.new_leaf.hash();
        poseidon_hash(&[intermediate_root, new_leaf_hash])
    }
    
    /// Helper to compute root with a specific leaf
    fn compute_root_with_leaf(
        &self,
        path: &MerklePath,
        leaf_hash: F,
        params: &TreeParams,
    ) -> F {
        let mut current = leaf_hash;
        let mut index = path.leaf_index;
        
        for sibling in &path.siblings {
            current = if index & 1 == 0 {
                params.hash_pair(&current, sibling)
            } else {
                params.hash_pair(sibling, &current)
            };
            index >>= 1;
        }
        
        current
    }
}

/// Base trait for Merkle trees
pub trait MerkleTree {
    /// Get the current root
    fn root(&self) -> F;
    
    /// Get tree height
    fn height(&self) -> usize;
    
    /// Get number of leaves
    fn num_leaves(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_merkle_path() {
        let params = TreeParams::new(4);
        let mut rng = thread_rng();
        
        // Create a simple path
        let leaf = F::rand(&mut rng);
        let siblings = vec![
            F::rand(&mut rng),
            F::rand(&mut rng),
            F::rand(&mut rng),
            F::rand(&mut rng),
        ];
        
        let path = MerklePath {
            leaf_index: 5,
            siblings: siblings.clone(),
            leaf,
        };
        
        let root = path.compute_root(&params);
        assert!(path.verify(&root, &params));
        
        // Wrong root should fail
        let wrong_root = F::rand(&mut rng);
        assert!(!path.verify(&wrong_root, &params));
    }

    #[test]
    fn test_sorted_leaf() {
        let leaf = SortedLeaf {
            key: F::from(10),
            next_key: F::from(20),
            next_index: 1,
        };
        
        // Value in gap
        assert!(leaf.contains_gap(&F::from(15)));
        
        // Value not in gap
        assert!(!leaf.contains_gap(&F::from(5)));
        assert!(!leaf.contains_gap(&F::from(25)));
        assert!(!leaf.contains_gap(&F::from(10)));
        assert!(!leaf.contains_gap(&F::from(20)));
    }
}