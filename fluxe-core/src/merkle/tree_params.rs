use crate::crypto::poseidon_hash;
use ark_bls12_381::Fr as F;
use ark_ff::Zero;

/// Parameters for Merkle trees
#[derive(Clone, Debug)]
pub struct TreeParams {
    /// Tree height
    pub height: usize,
    
    /// Empty hashes at each level
    pub empty_hashes: Vec<F>,
}

impl TreeParams {
    /// Create new tree parameters
    pub fn new(height: usize) -> Self {
        let mut empty_hashes = Vec::with_capacity(height + 1);
        
        // Leaf level empty value
        empty_hashes.push(F::zero());
        
        // Build empty hashes bottom-up
        for _ in 0..height {
            let prev = empty_hashes.last().unwrap();
            let empty_hash = poseidon_hash(&[*prev, *prev]);
            empty_hashes.push(empty_hash);
        }
        
        Self {
            height,
            empty_hashes,
        }
    }
    
    /// Hash two children nodes
    pub fn hash_pair(&self, left: &F, right: &F) -> F {
        poseidon_hash(&[*left, *right])
    }
    
    /// Get empty hash at level (0 = leaf)
    pub fn empty_at_level(&self, level: usize) -> F {
        self.empty_hashes[level]
    }
    
    /// Get empty root for empty tree
    pub fn empty_root(&self) -> F {
        self.empty_hashes[self.height]
    }
    
    /// Maximum number of leaves
    pub fn max_leaves(&self) -> usize {
        1 << self.height
    }
}

impl Default for TreeParams {
    fn default() -> Self {
        // Default to height 31 (2^31 leaves max)
        Self::new(31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_params() {
        let params = TreeParams::new(4);
        
        assert_eq!(params.height, 4);
        assert_eq!(params.max_leaves(), 16);
        assert_eq!(params.empty_hashes.len(), 5);
        
        // Empty hashes should be different at each level
        for i in 1..params.empty_hashes.len() {
            assert_ne!(params.empty_hashes[i], params.empty_hashes[i-1]);
        }
    }

    #[test]
    fn test_hash_pair() {
        let params = TreeParams::new(4);
        
        let left = F::from(1);
        let right = F::from(2);
        
        let hash1 = params.hash_pair(&left, &right);
        let hash2 = params.hash_pair(&left, &right);
        
        // Should be deterministic
        assert_eq!(hash1, hash2);
        
        // Order matters
        let hash3 = params.hash_pair(&right, &left);
        assert_ne!(hash1, hash3);
    }
}