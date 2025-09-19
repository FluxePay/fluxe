use super::{MerklePath, MerkleTree, TreeParams};
use ark_bls12_381::Fr as F;
// use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Incremental append-only Merkle tree (I-IMT)
/// Used for CMT_ROOT, OBJ_ROOT, INGRESS_ROOT, EXIT_ROOT
#[derive(Clone, Debug)]
pub struct IncrementalTree {
    /// Tree parameters
    params: TreeParams,
    
    /// Current number of leaves
    num_leaves: usize,
    
    /// Cached nodes (level -> index -> hash)
    nodes: HashMap<(usize, usize), F>,
    
    /// Current root
    root: F,
}

impl IncrementalTree {
    /// Create new empty tree
    pub fn new(height: usize) -> Self {
        let params = TreeParams::new(height);
        let root = params.empty_root();
        
        Self {
            params,
            num_leaves: 0,
            nodes: HashMap::new(),
            root,
        }
    }
    
    /// Get the number of leaves in the tree
    pub fn num_leaves(&self) -> usize {
        self.num_leaves
    }
    
    /// Get the height of the tree
    pub fn height(&self) -> usize {
        self.params.height
    }
    
    /// Append a new leaf
    pub fn append(&mut self, leaf: F) -> MerklePath {
        let leaf_index = self.num_leaves;
        
        if leaf_index >= self.params.max_leaves() {
            panic!("Tree is full");
        }
        
        // Store leaf
        self.nodes.insert((0, leaf_index), leaf);
        
        // Collect siblings for path
        let mut siblings = Vec::new();
        let mut current_index = leaf_index;
        let mut current_hash = leaf;
        
        // Update nodes up the tree
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            // Get sibling hash
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            siblings.push(sibling);
            
            // Compute parent hash
            let parent_index = current_index >> 1;
            let parent_hash = if current_index & 1 == 0 {
                self.params.hash_pair(&current_hash, &sibling)
            } else {
                self.params.hash_pair(&sibling, &current_hash)
            };
            
            // Store parent
            self.nodes.insert((level + 1, parent_index), parent_hash);
            
            // Move up
            current_index = parent_index;
            current_hash = parent_hash;
        }
        
        // Update root
        self.root = current_hash;
        self.num_leaves += 1;
        
        MerklePath {
            leaf_index,
            siblings,
            leaf,
        }
    }
    
    /// Batch append multiple leaves
    pub fn append_batch(&mut self, leaves: &[F]) -> Vec<MerklePath> {
        let start_index = self.num_leaves;
        
        // First, append all leaves
        for &leaf in leaves {
            let leaf_index = self.num_leaves;
            
            if leaf_index >= self.params.max_leaves() {
                panic!("Tree is full");
            }
            
            // Store leaf
            self.nodes.insert((0, leaf_index), leaf);
            self.num_leaves += 1;
            
            // Update nodes up the tree
            let mut current_index = leaf_index;
            let mut current_hash = leaf;
            
            for level in 0..self.params.height {
                let sibling_index = current_index ^ 1;
                
                // Get sibling hash
                let sibling = self.nodes
                    .get(&(level, sibling_index))
                    .copied()
                    .unwrap_or_else(|| self.params.empty_at_level(level));
                
                // Compute parent hash
                let parent_index = current_index >> 1;
                let parent_hash = if current_index & 1 == 0 {
                    self.params.hash_pair(&current_hash, &sibling)
                } else {
                    self.params.hash_pair(&sibling, &current_hash)
                };
                
                // Store parent
                self.nodes.insert((level + 1, parent_index), parent_hash);
                
                // Move up
                current_index = parent_index;
                current_hash = parent_hash;
            }
            
            // Update root
            self.root = current_hash;
        }
        
        // Now generate paths for all the leaves we added
        (start_index..self.num_leaves)
            .map(|i| self.get_path(i).expect("Leaf should exist"))
            .collect()
    }
    
    /// Get siblings for a given index (for pre-insertion witnesses)
    pub fn get_siblings_for_index(&self, leaf_index: usize) -> Vec<F> {
        let mut siblings = Vec::new();
        let mut current_index = leaf_index;
        
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            // Get sibling hash (empty if not present)
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            siblings.push(sibling);
            current_index >>= 1;
        }
        
        siblings
    }
    
    /// Get membership proof for existing leaf
    pub fn get_path(&self, leaf_index: usize) -> Option<MerklePath> {
        if leaf_index >= self.num_leaves {
            return None;
        }
        
        let leaf = self.nodes.get(&(0, leaf_index)).copied()?;
        
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
            leaf,
        })
    }
    
    /// Get leaf at index
    pub fn get_leaf(&self, index: usize) -> Option<F> {
        self.nodes.get(&(0, index)).copied()
    }
    
    /// Get proof for a specific leaf value
    pub fn get_proof(&self, leaf: F) -> Option<MerklePath> {
        // Find the leaf index
        for index in 0..self.num_leaves {
            if let Some(stored_leaf) = self.get_leaf(index) {
                if stored_leaf == leaf {
                    return self.get_path(index);
                }
            }
        }
        None
    }
    
    /// Recompute root from scratch (for verification)
    pub fn recompute_root(&mut self) -> F {
        if self.num_leaves == 0 {
            return self.params.empty_root();
        }
        
        // Build tree level by level
        let mut level_size = self.params.max_leaves();
        
        for level in 0..self.params.height {
            level_size >>= 1;
            
            for index in 0..level_size {
                let left_child = self.nodes
                    .get(&(level, index * 2))
                    .copied()
                    .unwrap_or_else(|| self.params.empty_at_level(level));
                    
                let right_child = self.nodes
                    .get(&(level, index * 2 + 1))
                    .copied()
                    .unwrap_or_else(|| self.params.empty_at_level(level));
                
                if left_child != self.params.empty_at_level(level) || 
                   right_child != self.params.empty_at_level(level) {
                    // Only compute if at least one child is non-empty
                    let parent = self.params.hash_pair(&left_child, &right_child);
                    self.nodes.insert((level + 1, index), parent);
                }
            }
        }
        
        self.nodes
            .get(&(self.params.height, 0))
            .copied()
            .unwrap_or_else(|| self.params.empty_root())
    }
}

impl IncrementalTree {
    /// Get the current root
    pub fn root(&self) -> F {
        self.root
    }
    
    /// Get the tree parameters
    pub fn params(&self) -> &TreeParams {
        &self.params
    }
    
    /// Get reference to internal nodes (for witness generation)
    pub fn nodes(&self) -> &HashMap<(usize, usize), F> {
        &self.nodes
    }
    
    /// Generate append witness for a leaf before actually inserting it
    pub fn generate_append_witness(&self, leaf: F) -> super::AppendWitness {
        let leaf_index = self.num_leaves;
        let mut pre_siblings = Vec::new();
        let mut current_index = leaf_index;
        
        for level in 0..self.params.height {
            let sibling_index = current_index ^ 1;
            
            // Get sibling from current tree state (before insertion)
            let sibling = self.nodes
                .get(&(level, sibling_index))
                .copied()
                .unwrap_or_else(|| self.params.empty_at_level(level));
            
            pre_siblings.push(sibling);
            current_index >>= 1;
        }
        
        super::AppendWitness::new(leaf, leaf_index, pre_siblings, self.params.height)
    }
}

impl MerkleTree for IncrementalTree {
    fn root(&self) -> F {
        self.root
    }
    
    fn height(&self) -> usize {
        self.params.height
    }
    
    fn num_leaves(&self) -> usize {
        self.num_leaves
    }
}

/// Commitment tree for note commitments
pub type CommitmentTree = IncrementalTree;

/// Object tree for zk-objects
pub type ObjectTree = IncrementalTree;

/// Ingress tree for deposit receipts
pub type IngressTree = IncrementalTree;

/// Exit tree for withdrawal receipts
pub type ExitTree = IncrementalTree;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_incremental_tree() {
        let mut tree = IncrementalTree::new(4);
        let mut rng = thread_rng();
        
        // Empty tree
        assert_eq!(tree.num_leaves(), 0);
        let empty_root = tree.root();
        
        // Add first leaf
        let leaf1 = F::rand(&mut rng);
        let path1 = tree.append(leaf1);
        assert_eq!(tree.num_leaves(), 1);
        assert!(path1.verify(&tree.root(), &tree.params));
        
        // Add second leaf
        let leaf2 = F::rand(&mut rng);
        let path2 = tree.append(leaf2);
        assert_eq!(tree.num_leaves(), 2);
        assert!(path2.verify(&tree.root(), &tree.params));
        
        // First path should still be valid
        let path1_retrieved = tree.get_path(0).unwrap();
        assert!(path1_retrieved.verify(&tree.root(), &tree.params));
        
        // Root should change after adding leaves
        assert_ne!(tree.root(), empty_root);
    }

    #[test]
    fn test_batch_append() {
        let mut tree = IncrementalTree::new(4);
        let mut rng = thread_rng();
        
        let leaves: Vec<F> = (0..4).map(|_| F::rand(&mut rng)).collect();
        let paths = tree.append_batch(&leaves);
        
        assert_eq!(tree.num_leaves(), 4);
        assert_eq!(paths.len(), 4);
        
        // All paths should be valid
        for path in paths {
            assert!(path.verify(&tree.root(), &tree.params));
        }
    }

    #[test]
    fn test_tree_consistency() {
        let mut tree = IncrementalTree::new(3);
        let rng = thread_rng();
        
        // Add maximum leaves
        for i in 0..8 {
            let leaf = F::from(i as u64);
            tree.append(leaf);
        }
        
        // Verify all paths
        for i in 0..8 {
            let path = tree.get_path(i).unwrap();
            assert!(path.verify(&tree.root(), &tree.params));
            assert_eq!(path.leaf, F::from(i as u64));
        }
    }

    #[test]
    #[should_panic(expected = "Tree is full")]
    fn test_tree_overflow() {
        let mut tree = IncrementalTree::new(2); // Max 4 leaves
        
        for i in 0..5 {
            tree.append(F::from(i as u64));
        }
    }
}