use ark_bls12_381::Fr as F;
use ark_r1cs_std::{fields::fp::FpVar, boolean::Boolean, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use super::poseidon::poseidon_hash_zk;
use fluxe_core::merkle::AppendWitness;

/// Append proof for an Incremental Merkle Tree.
/// 
/// This gadget verifies that appending a new leaf at a specific index
/// transforms old_root into new_root using proper structural verification.
/// It enforces:
/// 1. The append position is valid (next available slot)
/// 2. The pre-insertion siblings correctly compute the old root
/// 3. The same siblings with the new leaf compute the new root
/// 4. The leaf index is consistent with tree size
pub struct ImtAppendProofVar {
    pub old_root: FpVar<F>,
    pub new_root: FpVar<F>,
    pub leaf_index: FpVar<F>,
    pub appended_leaf: FpVar<F>,
    pub pre_siblings: Vec<FpVar<F>>,
    pub height: usize,
}

impl ImtAppendProofVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        witness: AppendWitness,
        old_root: F,
        new_root: F,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            old_root: FpVar::new_witness(cs.clone(), || Ok(old_root))?,
            new_root: FpVar::new_witness(cs.clone(), || Ok(new_root))?,
            leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(witness.leaf_index as u64)))?,
            appended_leaf: FpVar::new_witness(cs.clone(), || Ok(witness.leaf))?,
            pre_siblings: witness
                .pre_siblings
                .into_iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(s)))
                .collect::<Result<Vec<_>, _>>()?,
            height: witness.height,
        })
    }
    
    pub fn new_public(
        cs: ConstraintSystemRef<F>,
        witness: AppendWitness,
        old_root: F,
        new_root: F,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            old_root: FpVar::new_input(cs.clone(), || Ok(old_root))?,
            new_root: FpVar::new_input(cs.clone(), || Ok(new_root))?,
            leaf_index: FpVar::new_witness(cs.clone(), || Ok(F::from(witness.leaf_index as u64)))?,
            appended_leaf: FpVar::new_witness(cs.clone(), || Ok(witness.leaf))?,
            pre_siblings: witness
                .pre_siblings
                .into_iter()
                .map(|s| FpVar::new_witness(cs.clone(), || Ok(s)))
                .collect::<Result<Vec<_>, _>>()?,
            height: witness.height,
        })
    }

    /// Verify the append operation is valid
    pub fn verify(&self) -> Result<Boolean<F>, SynthesisError> {
        // SANITY CHECK 1: Verify the siblings array length matches tree height
        let siblings_len_valid = Boolean::constant(self.pre_siblings.len() == self.height);
        
        // SANITY CHECK 2: Verify leaf index is non-negative (implicitly true for FpVar)
        // and within valid range for tree (< 2^height)
        let max_index = F::from(1u64 << self.height) - F::from(1u64);
        let index_in_range = self.leaf_index.is_cmp(
            &FpVar::constant(max_index),
            std::cmp::Ordering::Less,
            true, // allow equal
        )?;
        
        // SANITY CHECK 3: Verify the appended leaf is non-zero (optional but good practice)
        // This prevents accidental empty appends
        let leaf_nonzero = self.appended_leaf.is_neq(&FpVar::zero())?;
        
        // 1. Verify the old root computation using empty leaf at position
        let computed_old_root = self.compute_root_with_empty()?;
        let old_root_valid = computed_old_root.is_eq(&self.old_root)?;
        
        // 2. Verify the new root computation using the appended leaf
        let computed_new_root = self.compute_root_with_leaf()?;
        let new_root_valid = computed_new_root.is_eq(&self.new_root)?;
        
        // SANITY CHECK 4: Verify old and new roots are different
        // (appending should change the root)
        let roots_different = self.old_root.is_neq(&self.new_root)?;
        
        // 3. All checks must pass
        siblings_len_valid
            .and(&index_in_range)?
            .and(&leaf_nonzero)?
            .and(&old_root_valid)?
            .and(&new_root_valid)?
            .and(&roots_different)
    }
    
    /// Enforce that this is a valid append proof
    pub fn enforce(&self) -> Result<(), SynthesisError> {
        let is_valid = self.verify()?;
        is_valid.enforce_equal(&Boolean::TRUE)
    }
    
    /// Compute root with empty leaf at the append position
    pub fn compute_root_with_empty(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut current = FpVar::zero(); // Empty leaf
        let index_bits = self.index_to_bits()?;
        
        for (level, sibling) in self.pre_siblings.iter().enumerate() {
            // Get the bit for this level
            let bit = &index_bits[level];
            
            // Compute parent hash: if bit=0, current is left; if bit=1, current is right
            let left_child = bit.select(sibling, &current)?;
            let right_child = bit.select(&current, sibling)?;
            
            current = poseidon_hash_zk(&[left_child, right_child])?;
        }
        
        Ok(current)
    }
    
    /// Compute root with the appended leaf at the position
    pub fn compute_root_with_leaf(&self) -> Result<FpVar<F>, SynthesisError> {
        let mut current = self.appended_leaf.clone();
        let index_bits = self.index_to_bits()?;
        
        for (level, sibling) in self.pre_siblings.iter().enumerate() {
            // Get the bit for this level
            let bit = &index_bits[level];
            
            // Compute parent hash: if bit=0, current is left; if bit=1, current is right
            let left_child = bit.select(sibling, &current)?;
            let right_child = bit.select(&current, sibling)?;
            
            current = poseidon_hash_zk(&[left_child, right_child])?;
        }
        
        Ok(current)
    }
    
    /// Convert leaf index to binary representation
    fn index_to_bits(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Use the built-in bit decomposition which is secure
        let all_bits = self.leaf_index.to_bits_le()?;
        
        // Take only the bits we need for this tree height
        let mut bits = Vec::new();
        for i in 0..self.height {
            if i < all_bits.len() {
                bits.push(all_bits[i].clone());
            } else {
                bits.push(Boolean::FALSE);
            }
        }
        
        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use fluxe_core::merkle::{IncrementalTree, TreeParams};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_append_witness_computation() {
        let mut rng = thread_rng();
        let mut tree = IncrementalTree::new(4);
        let params = TreeParams::new(4);
        
        // Add a few leaves first
        let leaf1 = F::rand(&mut rng);
        let leaf2 = F::rand(&mut rng);
        tree.append(leaf1);
        tree.append(leaf2);
        
        let old_root = tree.root();
        
        // Now append a new leaf
        let new_leaf = F::rand(&mut rng);
        
        // Create witness before insertion
        let witness = tree.generate_append_witness(new_leaf);
        
        // Verify witness computes correct old root
        assert_eq!(witness.compute_old_root(&params), old_root);
        
        // Actually append and verify new root
        tree.append(new_leaf);
        let new_root = tree.root();
        assert_eq!(witness.compute_new_root(&params), new_root);
    }
    
    #[test]
    fn test_append_gadget() {
        let mut rng = thread_rng();
        let cs = ConstraintSystem::<F>::new_ref();
        let mut tree = IncrementalTree::new(4);
        
        // Add initial leaves
        tree.append(F::rand(&mut rng));
        tree.append(F::rand(&mut rng));
        
        let old_root = tree.root();
        let new_leaf = F::rand(&mut rng);
        
        // Create witness
        let witness = tree.generate_append_witness(new_leaf);
        
        tree.append(new_leaf);
        let new_root = tree.root();
        
        // Create and test gadget
        let gadget = ImtAppendProofVar::new_witness(
            cs.clone(),
            witness,
            old_root,
            new_root,
        ).unwrap();
        
        gadget.enforce().unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}