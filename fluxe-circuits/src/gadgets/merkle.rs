use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::merkle::MerklePath;

use crate::gadgets::poseidon::poseidon_hash_zk;

/// Merkle path variable for membership proofs in circuits
#[derive(Clone)]
pub struct MerklePathVar {
    pub leaf_index: FpVar<F>,
    pub siblings: Vec<FpVar<F>>,
    pub leaf: FpVar<F>,
}

impl MerklePathVar {
    /// Create new path variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        path: impl FnOnce() -> Result<MerklePath, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let path = path()?;
        
        let leaf_index = FpVar::new_witness(cs.clone(), || Ok(F::from(path.leaf_index as u64)))?;
        let leaf = FpVar::new_witness(cs.clone(), || Ok(path.leaf))?;
        
        let siblings = path.siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            leaf_index,
            siblings,
            leaf,
        })
    }
    
    /// Verify membership proof in circuit
    pub fn verify(&self, root: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        let computed_root = self.compute_root()?;
        computed_root.is_eq(root)
    }
    
    /// Compute root from path
    pub fn compute_root(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut current = self.leaf.clone();
        let index_bits = self.leaf_index.to_bits_le()?;
        
        for (i, sibling) in self.siblings.iter().enumerate() {
            // Select based on bit i of index
            let is_left = if i < index_bits.len() {
                index_bits[i].not()
            } else {
                Boolean::FALSE
            };
            
            // If is_left, current goes left; otherwise right
            let left = is_left.select(&current, sibling)?;
            let right = is_left.select(sibling, &current)?;
            
            current = poseidon_hash_zk(&[left, right])?;
        }
        
        Ok(current)
    }
    
    /// Enforce that this path is valid for the given root
    pub fn enforce_valid(&self, root: &FpVar<F>) -> Result<(), SynthesisError> {
        let is_valid = self.verify(root)?;
        is_valid.enforce_equal(&Boolean::TRUE)
    }
    
    /// Compute the root with a specific leaf at this path's position
    pub fn compute_root_with_leaf(&self, leaf: &FpVar<F>) -> Result<FpVar<F>, SynthesisError> {
        let mut current = leaf.clone();
        let index_bits = self.leaf_index.to_bits_le()?;
        
        for (i, sibling) in self.siblings.iter().enumerate() {
            let is_left = if i < index_bits.len() {
                index_bits[i].not()
            } else {
                Boolean::FALSE
            };
            
            let left = is_left.select(&current, sibling)?;
            let right = is_left.select(sibling, &current)?;
            
            current = poseidon_hash_zk(&[left, right])?;
        }
        
        Ok(current)
    }
}

/// Generic Merkle tree gadget utilities
pub struct MerkleTreeGadget;

impl MerkleTreeGadget {
    /// Verify membership of a leaf in a tree
    /// DEPRECATED: This simplified helper assumes left ordering and ignores index bits.
    /// Use MerklePathVar::enforce_valid for proper membership verification.
    #[deprecated(note = "Use MerklePathVar::enforce_valid for proper index-aware verification")]
    pub fn verify_membership(
        _cs: ConstraintSystemRef<F>,
        leaf: &FpVar<F>,
        path: &[FpVar<F>],
        root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // WARNING: This simplified version assumes left ordering
        // and does not use index bits to determine sibling positions.
        // This is UNSAFE for production use.
        let mut current = leaf.clone();
        
        for sibling in path {
            // UNSAFE: Always assumes current is on the left
            current = poseidon_hash_zk(&[current, sibling.clone()])?;
        }
        
        // Enforce computed root equals expected root
        current.enforce_equal(root)
    }
    
    /// Verify non-membership using range proof (simplified)
    pub fn verify_non_membership(
        _cs: ConstraintSystemRef<F>,
        target: &FpVar<F>,
        low_key: &FpVar<F>,
        high_key: &FpVar<F>,
        path: &[FpVar<F>],
        root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        // Verify low_key is in the tree
        Self::verify_membership(_cs.clone(), low_key, path, root)?;
        
        // Verify target is in the gap: low_key < target < high_key
        // Note: FpVar doesn't have direct comparison methods,
        // so we would need to implement bit-wise comparison or use a comparison gadget
        // For now, we just check they're not equal (simplified)
        let not_eq_low = target.is_neq(low_key)?;
        let not_eq_high = target.is_neq(high_key)?;
        let in_gap = not_eq_low.and(&not_eq_high)?;
        
        in_gap.enforce_equal(&Boolean::TRUE)
    }
}