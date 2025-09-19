use fluxe_core::merkle::{IncrementalTree, MerkleTree, TreeParams};
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

#[test]
fn test_empty_tree() {
    let tree = IncrementalTree::new(4);
    
    assert_eq!(tree.num_leaves(), 0);
    assert_eq!(tree.height(), 4);
    
    // Empty tree root should be deterministic
    let tree2 = IncrementalTree::new(4);
    assert_eq!(tree.root(), tree2.root());
}

#[test]
fn test_single_leaf() {
    let mut tree = IncrementalTree::new(4);
    let mut rng = thread_rng();
    
    let leaf = F::rand(&mut rng);
    let path = tree.append(leaf);
    
    assert_eq!(tree.num_leaves(), 1);
    assert_eq!(path.leaf_index, 0);
    assert_eq!(path.leaf, leaf);
    
    // Verify the path
    let params = TreeParams::new(4);
    assert!(path.verify(&tree.root(), &params));
}

#[test]
fn test_sequential_append() {
    let mut tree = IncrementalTree::new(3); // Max 8 leaves
    let rng = thread_rng();
    let params = TreeParams::new(3);
    
    let mut leaves = Vec::new();
    let mut paths = Vec::new();
    
    // Add leaves one by one
    for i in 0..8 {
        let leaf = F::from(i as u64);
        leaves.push(leaf);
        
        let path = tree.append(leaf);
        assert_eq!(path.leaf_index, i);
        assert_eq!(tree.num_leaves(), i + 1);
        
        // Verify the new path
        assert!(path.verify(&tree.root(), &params));
        
        paths.push(path);
    }
    
    // All old paths should still verify
    for path in &paths {
        let retrieved = tree.get_path(path.leaf_index).unwrap();
        assert!(retrieved.verify(&tree.root(), &params));
    }
}

#[test]
fn test_batch_append() {
    let mut tree = IncrementalTree::new(4);
    let mut rng = thread_rng();
    let params = TreeParams::new(4);
    
    // Generate random leaves
    let leaves: Vec<F> = (0..10).map(|_| F::rand(&mut rng)).collect();
    
    // Batch append
    let paths = tree.append_batch(&leaves);
    
    assert_eq!(tree.num_leaves(), 10);
    assert_eq!(paths.len(), 10);
    
    // Verify all paths
    for (i, path) in paths.iter().enumerate() {
        assert_eq!(path.leaf_index, i);
        assert_eq!(path.leaf, leaves[i]);
        assert!(path.verify(&tree.root(), &params));
    }
}

#[test]
fn test_get_path() {
    let mut tree = IncrementalTree::new(4);
    let mut rng = thread_rng();
    let params = TreeParams::new(4);
    
    // Add some leaves
    let leaves: Vec<F> = (0..5).map(|_| F::rand(&mut rng)).collect();
    tree.append_batch(&leaves);
    
    // Get paths for existing leaves
    for i in 0..5 {
        let path = tree.get_path(i).unwrap();
        assert_eq!(path.leaf_index, i);
        assert_eq!(path.leaf, leaves[i]);
        assert!(path.verify(&tree.root(), &params));
    }
    
    // Non-existent leaf
    assert!(tree.get_path(10).is_none());
}

#[test]
fn test_get_leaf() {
    let mut tree = IncrementalTree::new(4);
    
    let leaves = vec![F::from(1u64), F::from(2u64), F::from(3u64)];
    tree.append_batch(&leaves);
    
    // Get existing leaves
    assert_eq!(tree.get_leaf(0), Some(F::from(1u64)));
    assert_eq!(tree.get_leaf(1), Some(F::from(2u64)));
    assert_eq!(tree.get_leaf(2), Some(F::from(3u64)));
    
    // Non-existent leaf
    assert_eq!(tree.get_leaf(5), None);
}

#[test]
fn test_tree_consistency() {
    let mut tree1 = IncrementalTree::new(4);
    let mut tree2 = IncrementalTree::new(4);
    let mut rng = thread_rng();
    
    // Add same leaves to both trees
    let leaves: Vec<F> = (0..7).map(|_| F::rand(&mut rng)).collect();
    
    // Tree 1: batch append
    tree1.append_batch(&leaves);
    
    // Tree 2: sequential append
    for leaf in &leaves {
        tree2.append(*leaf);
    }
    
    // Roots should be identical
    assert_eq!(tree1.root(), tree2.root());
    assert_eq!(tree1.num_leaves(), tree2.num_leaves());
    
    // Paths should be identical
    for i in 0..7 {
        let path1 = tree1.get_path(i).unwrap();
        let path2 = tree2.get_path(i).unwrap();
        
        assert_eq!(path1.siblings, path2.siblings);
        assert_eq!(path1.leaf, path2.leaf);
    }
}

#[test]
fn test_deterministic_roots() {
    let mut tree = IncrementalTree::new(3);
    
    // Add specific values
    for i in 0..4 {
        tree.append(F::from(i as u64));
    }
    
    let root1 = tree.root();
    
    // Create another tree with same values
    let mut tree2 = IncrementalTree::new(3);
    for i in 0..4 {
        tree2.append(F::from(i as u64));
    }
    
    let root2 = tree2.root();
    
    assert_eq!(root1, root2, "Roots should be deterministic");
}

#[test]
#[should_panic(expected = "Tree is full")]
fn test_tree_overflow() {
    let mut tree = IncrementalTree::new(2); // Max 4 leaves
    
    for i in 0..5 {
        tree.append(F::from(i as u64));
    }
}

#[test]
fn test_proof_verification_failure() {
    let mut tree = IncrementalTree::new(4);
    let params = TreeParams::new(4);
    let mut rng = thread_rng();
    
    // Add some leaves
    let leaf1 = F::rand(&mut rng);
    let path1 = tree.append(leaf1);
    
    let leaf2 = F::rand(&mut rng);
    tree.append(leaf2);
    
    // Tamper with the path
    let mut bad_path = path1.clone();
    bad_path.siblings[0] = F::rand(&mut rng);
    
    // Verification should fail
    assert!(!bad_path.verify(&tree.root(), &params));
}

#[test]
fn test_different_tree_heights() {
    for height in 1..=10 {
        let mut tree = IncrementalTree::new(height);
        let params = TreeParams::new(height);
        let mut rng = thread_rng();
        
        // Add one leaf
        let leaf = F::rand(&mut rng);
        let path = tree.append(leaf);
        
        // Should have correct height
        assert_eq!(tree.height(), height);
        assert_eq!(path.siblings.len(), height);
        
        // Path should verify
        assert!(path.verify(&tree.root(), &params));
    }
}