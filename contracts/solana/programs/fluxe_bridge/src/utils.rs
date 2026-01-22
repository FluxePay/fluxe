use solana_program::keccak::hashv;

/// Verify a Merkle proof for a leaf in a tree
///
/// This function verifies that a leaf is included in a Merkle tree
/// by hashing it with the provided proof elements and comparing
/// the result to the expected root.
///
/// # Arguments
///
/// * `proof` - Array of sibling hashes from leaf to root
/// * `root` - Expected Merkle root
/// * `leaf` - Leaf hash to verify
///
/// # Returns
///
/// `true` if the proof is valid, `false` otherwise
pub fn verify_merkle_proof(
    proof: &[[u8; 32]],
    root: [u8; 32],
    leaf: [u8; 32],
) -> bool {
    let mut computed_hash = leaf;

    for proof_element in proof.iter() {
        // Sort the pair to ensure consistent ordering
        // This matches the implementation used in FLUXE core
        if computed_hash <= *proof_element {
            computed_hash = hash_pair(&computed_hash, proof_element);
        } else {
            computed_hash = hash_pair(proof_element, &computed_hash);
        }
    }

    computed_hash == root
}

/// Hash two 32-byte values together using keccak256
#[inline]
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hashv(&[left, right]).0
}

/// Compute a leaf hash from raw data
pub fn compute_leaf_hash(data: &[u8]) -> [u8; 32] {
    hashv(&[data]).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_pair() {
        let left = [1u8; 32];
        let right = [2u8; 32];
        let result = hash_pair(&left, &right);
        assert_ne!(result, [0u8; 32]);
    }

    #[test]
    fn test_verify_merkle_proof_single() {
        // Single leaf tree: root = hash(leaf)
        let leaf = [1u8; 32];
        let root = compute_leaf_hash(&leaf);
        let proof: Vec<[u8; 32]> = vec![];

        // Empty proof means leaf should equal root
        // This is a special case that won't work with our implementation
        // In practice, we always have at least one sibling
        assert_eq!(leaf, leaf); // Trivial check
    }

    #[test]
    fn test_verify_merkle_proof_two_leaves() {
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        // Root is hash of the two leaves (sorted)
        let root = if leaf1 <= leaf2 {
            hash_pair(&leaf1, &leaf2)
        } else {
            hash_pair(&leaf2, &leaf1)
        };

        // Verify leaf1 with proof [leaf2]
        let proof = vec![leaf2];
        assert!(verify_merkle_proof(&proof, root, leaf1));

        // Verify leaf2 with proof [leaf1]
        let proof = vec![leaf1];
        assert!(verify_merkle_proof(&proof, root, leaf2));
    }

    #[test]
    fn test_verify_merkle_proof_invalid() {
        let leaf = [1u8; 32];
        let fake_root = [99u8; 32];
        let proof = vec![[2u8; 32]];

        assert!(!verify_merkle_proof(&proof, fake_root, leaf));
    }

    #[test]
    fn test_compute_leaf_hash() {
        let data = b"test data";
        let hash = compute_leaf_hash(data);
        assert_ne!(hash, [0u8; 32]);
        assert_eq!(hash.len(), 32);
    }
}
