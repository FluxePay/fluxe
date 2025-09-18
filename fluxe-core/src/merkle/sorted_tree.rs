use super::{MerklePath, MerkleTree, RangePath, SortedLeaf, SortedInsertWitness, TreeParams};
use ark_bls12_381::Fr as F;
use ark_ff::{Zero, BigInteger, PrimeField};
// use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::cmp::Ordering;

/// Wrapper for field elements that orders by field arithmetic
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldKey(F);

impl PartialOrd for FieldKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FieldKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare as field elements (arithmetic comparison)
        // This compares the BigInteger representation which gives us
        // the correct field arithmetic ordering
        let self_bytes = self.0.into_bigint();
        let other_bytes = other.0.into_bigint();
        self_bytes.cmp(&other_bytes)
    }
}

/// Sorted Merkle tree (S-IMT) with range proofs for non-membership
/// Used for NFT_ROOT, CB_ROOT, SANCTIONS_ROOT
#[derive(Clone, Debug)]
pub struct SortedTree {
    /// Tree parameters
    params: TreeParams,
    
    /// Sorted map of keys to leaf indices
    sorted_keys: BTreeMap<FieldKey, usize>,
    
    /// Leaves by index
    leaves: HashMap<usize, SortedLeaf>,
    
    /// Cached nodes (level -> index -> hash)
    nodes: HashMap<(usize, usize), F>,
    
    /// Next available leaf index
    next_index: usize,
    
    /// Current root
    root: F,
}

impl SortedTree {
    /// Create new empty tree
    pub fn new(height: usize) -> Self {
        let params = TreeParams::new(height);
        let root = params.empty_root();
        
        // Insert sentinel leaf at index 0 with minimum value
        let mut tree = Self {
            params,
            sorted_keys: BTreeMap::new(),
            leaves: HashMap::new(),
            nodes: HashMap::new(),
            next_index: 0,
            root,
        };
        
        // Add sentinel to handle edge cases
        let sentinel = SortedLeaf::new(F::zero());
        tree.insert_leaf(sentinel);
        
        tree
    }
    
    /// Insert a new key (returns error if already exists)
    pub fn insert(&mut self, key: F) -> Result<MerklePath, String> {
        if self.sorted_keys.contains_key(&FieldKey(key)) {
            return Err("Key already exists".to_string());
        }
        
        
        let mut new_leaf = SortedLeaf::new(key);
        
        // Find predecessor and successor
        let (_pred_key, pred_idx) = self.find_predecessor(&key);
        let _succ_opt = self.find_successor(&key);
        
        // Get predecessor leaf data and update it
        let pred_leaf_hash = if let Some(pred_leaf) = self.leaves.get(&pred_idx) {
            new_leaf.next_key = pred_leaf.next_key;
            new_leaf.next_index = pred_leaf.next_index;
            
            // Create updated predecessor
            let mut updated_pred = pred_leaf.clone();
            updated_pred.next_key = key;
            updated_pred.next_index = self.next_index;
            let hash = updated_pred.hash();
            
            // Store updated predecessor
            self.leaves.insert(pred_idx, updated_pred);
            
            Some((pred_idx, hash))
        } else {
            None
        };
        
        // Update predecessor in tree
        if let Some((idx, hash)) = pred_leaf_hash {
            self.update_leaf_hash(idx, hash);
        }
        
        // Insert new leaf
        let path = self.insert_leaf(new_leaf);
        
        Ok(path)
    }
    
    /// Insert a new key and return witness for circuit verification
    pub fn insert_with_witness(&mut self, key: F) -> Result<SortedInsertWitness, String> {
        if self.sorted_keys.contains_key(&FieldKey(key)) {
            return Err("Key already exists".to_string());
        }
        
        // First get non-membership proof before any modifications
        let range_proof = self.prove_non_membership(key)?;
        let old_root = self.root;
        
        // Store original predecessor leaf and its path
        let (_pred_key, pred_idx) = self.find_predecessor(&key);
        let original_pred_leaf = self.leaves.get(&pred_idx)
            .ok_or("Predecessor leaf not found")?
            .clone();
        let pred_path_before = self.get_path(pred_idx)
            .ok_or("Could not get predecessor path")?;
        
        // Create new leaf that will be inserted
        let mut new_leaf = SortedLeaf::new(key);
        new_leaf.next_key = original_pred_leaf.next_key;
        new_leaf.next_index = original_pred_leaf.next_index;
        
        // Create updated predecessor leaf
        let mut updated_pred_leaf = original_pred_leaf.clone();
        updated_pred_leaf.next_key = key;
        updated_pred_leaf.next_index = self.next_index;
        
        // Save the index where new leaf will be inserted
        let new_leaf_index = self.next_index;
        
        // Now perform the actual insertion
        let _insertion_path = self.insert(key)?;
        
        // Get the path for the newly inserted leaf from the updated tree
        let new_leaf_path = self.get_path(new_leaf_index)
            .ok_or("Could not get path for new leaf")?;
        
        // Get the updated path for predecessor (after insertion)
        let pred_path_after = self.get_path(pred_idx)
            .ok_or("Could not get updated predecessor path")?;
        
        // The witness should use:
        // - pred_update_path: the path BEFORE insertion (for verifying old root)
        // - new_leaf_path: the path AFTER insertion (which includes updated sibling hashes)
        let witness = SortedInsertWitness::new(
            key,
            range_proof,
            new_leaf,
            updated_pred_leaf,
            new_leaf_path,  // Path from final tree state
            pred_path_before, // Original path before any updates
            self.params.height,
        );
        
        Ok(witness)
    }
    
    
    /// Insert leaf at next available index
    fn insert_leaf(&mut self, leaf: SortedLeaf) -> MerklePath {
        let index = self.next_index;
        
        if index >= self.params.max_leaves() {
            panic!("Tree is full");
        }
        
        // Store in sorted map
        self.sorted_keys.insert(FieldKey(leaf.key), index);
        
        // Store leaf
        self.leaves.insert(index, leaf.clone());
        let leaf_hash = leaf.hash();
        self.nodes.insert((0, index), leaf_hash);
        
        // Update tree up to root
        let path = self.update_path(index, leaf_hash);
        
        self.next_index += 1;
        
        path
    }
    
    /// Update leaf hash and propagate to root
    fn update_leaf_hash(&mut self, index: usize, new_hash: F) {
        self.nodes.insert((0, index), new_hash);
        self.update_path(index, new_hash);
    }
    
    /// Update path from leaf to root
    fn update_path(&mut self, leaf_index: usize, leaf_hash: F) -> MerklePath {
        let mut siblings = Vec::new();
        let mut current_index = leaf_index;
        let mut current_hash = leaf_hash;
        
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            siblings.push(sibling);
            
            // Compute parent
            let parent_index = current_index >> 1;
            let parent_hash = if current_index & 1 == 0 {
                self.params.hash_pair(&current_hash, &sibling)
            } else {
                self.params.hash_pair(&sibling, &current_hash)
            };
            
            self.nodes.insert((level + 1, parent_index), parent_hash);
            
            current_index = parent_index;
            current_hash = parent_hash;
        }
        
        self.root = current_hash;
        
        MerklePath {
            leaf_index,
            siblings,
            leaf: leaf_hash,
        }
    }
    
    /// Find predecessor (largest key < target)
    fn find_predecessor(&self, target: &F) -> (F, usize) {
        let mut pred_key = F::zero();
        let mut pred_idx = 0; // Sentinel
        
        for (key, &idx) in self.sorted_keys.range(..FieldKey(*target)) {
            pred_key = key.0;
            pred_idx = idx;
        }
        
        (pred_key, pred_idx)
    }
    
    /// Find successor (smallest key > target)
    fn find_successor(&self, target: &F) -> Option<(F, usize)> {
        self.sorted_keys
            .range((std::ops::Bound::Excluded(FieldKey(*target)), std::ops::Bound::Unbounded))
            .next()
            .map(|(k, v)| (k.0, *v))
    }
    
    /// Get non-membership proof for a key
    pub fn prove_non_membership(&self, target: F) -> Result<RangePath, String> {
        if self.sorted_keys.contains_key(&FieldKey(target)) {
            return Err("Key exists, cannot prove non-membership".to_string());
        }
        
        let (_pred_key, pred_idx) = self.find_predecessor(&target);
        
        let low_leaf = self.leaves.get(&pred_idx)
            .ok_or("Predecessor leaf not found")?
            .clone();
        
        let low_path = self.get_path(pred_idx)
            .ok_or("Could not get path for predecessor")?;
        
        // Verify the gap contains target
        if !low_leaf.contains_gap(&target) {
            return Err("Target not in gap".to_string());
        }
        
        Ok(RangePath {
            low_leaf,
            low_path,
            target,
        })
    }
    
    /// Get membership proof for existing key
    pub fn prove_membership(&self, key: F) -> Option<MerklePath> {
        let index = *self.sorted_keys.get(&FieldKey(key))?;
        self.get_path(index)
    }
    
    /// Get path for leaf at index
    pub fn get_path(&self, leaf_index: usize) -> Option<MerklePath> {
        let leaf_hash = self.nodes.get(&(0, leaf_index)).copied()?;
        
        let mut siblings = Vec::new();
        let mut current_index = leaf_index;
        
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            siblings.push(sibling);
            current_index >>= 1;
        }
        
        Some(MerklePath {
            leaf_index,
            siblings,
            leaf: leaf_hash,
        })
    }
    
    /// Check if key exists
    pub fn contains(&self, key: &F) -> bool {
        self.sorted_keys.contains_key(&FieldKey(*key))
    }
    
    /// Get the next available index (used for witness generation)
    pub fn next_index(&self) -> usize {
        self.next_index
    }
    
    /// Export witness for inserting a new key (for circuit use)
    /// This captures all the data needed to prove the insert in-circuit
    pub fn export_insert_witness(&self, key: F) -> Result<SortedInsertWitness, String> {
        use crate::merkle::SortedInsertWitness;
        
        if self.sorted_keys.contains_key(&FieldKey(key)) {
            return Err("Key already exists".to_string());
        }
        
        // Get non-membership proof first
        let range_proof = self.prove_non_membership(key)?;
        
        // Find predecessor
        let (_pred_key, pred_idx) = self.find_predecessor(&key);
        
        // Get predecessor leaf
        let pred_leaf = self.leaves.get(&pred_idx)
            .ok_or("Predecessor leaf not found")?
            .clone();
        
        // Create new leaf that will be inserted
        let mut new_leaf = SortedLeaf::new(key);
        new_leaf.next_key = pred_leaf.next_key;
        new_leaf.next_index = pred_leaf.next_index;
        
        // Create updated predecessor leaf
        let mut updated_pred_leaf = pred_leaf.clone();
        updated_pred_leaf.next_key = key;
        updated_pred_leaf.next_index = self.next_index;
        
        // Get current path for predecessor (before update)
        let mut pred_update_path = self.get_path(pred_idx)
            .ok_or("Could not get path for predecessor")?;
        
        // IMPORTANT: Set the leaf field to the predecessor hash
        // The gadget needs this to verify old_root computation
        pred_update_path.leaf = pred_leaf.hash();
        
        // For the new leaf path, we need to simulate the tree state AFTER
        // the predecessor has been updated. This is needed because the gadget
        // verifies the transformation: old_root -> intermediate -> new_root
        
        // Clone the tree to simulate the intermediate state
        let mut temp_tree = self.clone();
        // Update the predecessor leaf in the temp tree
        temp_tree.leaves.insert(pred_idx, updated_pred_leaf.clone());
        let updated_pred_hash = updated_pred_leaf.hash();
        temp_tree.update_tree_nodes(pred_idx, updated_pred_hash);
        
        // Now compute the path for where the new leaf will go in this intermediate state
        let new_leaf_hash = new_leaf.hash();
        let new_leaf_path = temp_tree.compute_future_path(self.next_index, new_leaf_hash);
        
        Ok(SortedInsertWitness {
            target: key,
            range_proof,
            new_leaf,
            updated_pred_leaf,
            new_leaf_path,
            pred_update_path,
            height: self.params.height,
        })
    }
    
    /// Update the merkle tree nodes for a given leaf
    fn update_tree_nodes(&mut self, leaf_index: usize, leaf_hash: F) {
        let mut current_hash = leaf_hash;
        let mut current_index = leaf_index;
        
        for level in 0..self.params.height {
            self.nodes.insert((level, current_index), current_hash);
            
            let sibling_index = current_index ^ 1;
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            current_hash = if current_index & 1 == 0 {
                self.params.hash_pair(&current_hash, &sibling)
            } else {
                self.params.hash_pair(&sibling, &current_hash)
            };
            
            current_index >>= 1;
        }
        
        self.root = current_hash;
    }
    
    /// Compute what the path will be for a future insertion at index
    fn compute_future_path(&self, leaf_index: usize, leaf_hash: F) -> MerklePath {
        let mut siblings = Vec::new();
        let mut current_index = leaf_index;
        
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            // Get sibling - either exists or is empty
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            siblings.push(sibling);
            current_index >>= 1;
        }
        
        MerklePath {
            leaf_index,
            siblings,
            leaf: leaf_hash,
        }
    }
    
    /// Get all keys in sorted order
    pub fn keys(&self) -> Vec<F> {
        self.sorted_keys.keys().map(|k| k.0).collect()
    }
    
    /// Get non-membership proof (wrapper for state manager compatibility)
    pub fn get_non_membership_proof(&self, nullifier: F) -> Option<crate::state_manager::NonMembershipProof> {
        use crate::state_manager::{NonMembershipProof, SortedLeaf as StateSortedLeaf};
        
        let range_path = self.prove_non_membership(nullifier).ok()?;
        
        // Convert to state manager types
        let low_leaf = StateSortedLeaf {
            key: range_path.low_leaf.key,
            next_key: range_path.low_leaf.next_key,
            next_index: Some(range_path.low_leaf.next_index as u64),
        };
        
        Some(NonMembershipProof {
            low_leaf,
            low_path: range_path.low_path,
        })
    }
}

impl SortedTree {
    /// Get the current root
    pub fn root(&self) -> F {
        self.root
    }
}

impl MerkleTree for SortedTree {
    fn root(&self) -> F {
        self.root
    }
    
    fn height(&self) -> usize {
        self.params.height
    }
    
    fn num_leaves(&self) -> usize {
        self.next_index
    }
}

/// Nullifier tree for spent notes
pub type NullifierTree = SortedTree;

/// Callback tree for compliance callbacks
pub type CallbackTree = SortedTree;

/// Sanctions tree for blacklisted entities
pub type SanctionsTree = SortedTree;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_sorted_tree_insert() {
        let mut tree = SortedTree::new(4);
        
        // Insert some keys
        let key1 = F::from(100);
        let key2 = F::from(200);
        let key3 = F::from(150);
        
        // Insert key1 and verify immediately
        let path1 = tree.insert(key1).unwrap();
        assert!(path1.verify(&tree.root(), &tree.params));
        
        // Insert key2 and verify immediately
        let path2 = tree.insert(key2).unwrap();
        assert!(path2.verify(&tree.root(), &tree.params));
        
        // Insert key3 and verify immediately
        let path3 = tree.insert(key3).unwrap();
        assert!(path3.verify(&tree.root(), &tree.params));
        
        // After all insertions, get fresh paths for verification
        // Note: Old paths are invalid after tree modifications
        let current_path1 = tree.prove_membership(key1).unwrap();
        let current_path2 = tree.prove_membership(key2).unwrap();
        let current_path3 = tree.prove_membership(key3).unwrap();
        
        assert!(current_path1.verify(&tree.root(), &tree.params));
        assert!(current_path2.verify(&tree.root(), &tree.params));
        assert!(current_path3.verify(&tree.root(), &tree.params));
        
        // Keys should be sorted internally
        let keys = tree.keys();
        assert_eq!(keys[1], key1); // After sentinel
        assert_eq!(keys[2], key3);
        assert_eq!(keys[3], key2);
    }

    #[test]
    fn test_non_membership_proof() {
        let mut tree = SortedTree::new(4);
        
        // Insert some keys with gaps
        tree.insert(F::from(100)).unwrap();
        tree.insert(F::from(200)).unwrap();
        tree.insert(F::from(300)).unwrap();
        
        // Prove non-membership for value in gap
        let target = F::from(150);
        let proof = tree.prove_non_membership(target).unwrap();
        
        assert!(proof.verify(&tree.root(), &tree.params));
        assert_eq!(proof.target, target);
        assert_eq!(proof.low_leaf.key, F::from(100));
        assert_eq!(proof.low_leaf.next_key, F::from(200));
    }

    #[test]
    fn test_duplicate_insert() {
        let mut tree = SortedTree::new(4);
        
        let key = F::from(100);
        tree.insert(key).unwrap();
        
        // Second insert should fail
        let result = tree.insert(key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Key already exists");
    }

    #[test]
    fn test_membership_proof() {
        let mut tree = SortedTree::new(4);
        
        let key = F::from(100);
        tree.insert(key).unwrap();
        
        // Get membership proof
        let proof = tree.prove_membership(key).unwrap();
        assert!(proof.verify(&tree.root(), &tree.params));
        
        // Non-existent key should return None
        let proof2 = tree.prove_membership(F::from(999));
        assert!(proof2.is_none());
    }

    #[test]
    fn test_range_edge_cases() {
        let mut tree = SortedTree::new(4);
        
        // Insert sparse keys
        tree.insert(F::from(100)).unwrap();
        tree.insert(F::from(1000)).unwrap();
        
        // Test various points
        let proof1 = tree.prove_non_membership(F::from(50)).unwrap();
        assert!(proof1.verify(&tree.root(), &tree.params));
        
        let proof2 = tree.prove_non_membership(F::from(500)).unwrap();
        assert!(proof2.verify(&tree.root(), &tree.params));
        
        let proof3 = tree.prove_non_membership(F::from(2000)).unwrap();
        assert!(proof3.verify(&tree.root(), &tree.params));
    }
}