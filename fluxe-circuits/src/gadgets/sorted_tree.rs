use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use fluxe_core::merkle::{SortedLeaf, RangePath};

use super::poseidon::poseidon_hash_zk;
use super::merkle::MerklePathVar;
use super::comparison::ComparisonGadget;

/// Variable for sorted tree leaf
#[derive(Clone)]
pub struct SortedLeafVar {
    pub key: FpVar<F>,
    pub next_key: FpVar<F>,
    pub next_index: FpVar<F>,
}

impl SortedLeafVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<SortedLeaf, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let leaf = f()?;
        Ok(Self {
            key: FpVar::new_witness(cs.clone(), || Ok(leaf.key))?,
            next_key: FpVar::new_witness(cs.clone(), || Ok(leaf.next_key))?,
            next_index: FpVar::new_witness(cs.clone(), || Ok(F::from(leaf.next_index as u64)))?,
        })
    }
    
    /// Compute hash of this leaf
    pub fn hash(&self) -> Result<FpVar<F>, SynthesisError> {
        poseidon_hash_zk(&[
            self.key.clone(),
            self.next_key.clone(),
            self.next_index.clone(),
        ])
    }
    
    /// Check if a value falls in the gap after this leaf
    pub fn contains_gap(&self, value: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        // value > key AND (next_key == 0 OR value < next_key)
        let cs = value.cs();
        let value_gt_key = ComparisonGadget::is_greater_than(cs.clone(), value, &self.key)?;
        
        let next_is_zero = self.next_key.is_eq(&FpVar::zero())?;
        let value_lt_next = ComparisonGadget::is_less_than(cs, value, &self.next_key)?;
        let next_check = &next_is_zero | &value_lt_next;
        
        Ok(&value_gt_key & &next_check)
    }
}

/// Variable for range path (non-membership proof)
#[derive(Clone)]
pub struct RangePathVar {
    pub low_leaf: SortedLeafVar,
    pub low_path: MerklePathVar,
    pub target: FpVar<F>,
}

impl RangePathVar {
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        f: impl FnOnce() -> Result<RangePath, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let range_path = f()?;
        Ok(Self {
            low_leaf: SortedLeafVar::new_witness(cs.clone(), || Ok(range_path.low_leaf))?,
            low_path: MerklePathVar::new_witness(cs.clone(), || Ok(range_path.low_path))?,
            target: FpVar::new_witness(cs, || Ok(range_path.target))?,
        })
    }
    
    /// Verify non-membership proof
    pub fn verify(&self, root: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        // 1. Verify low leaf is in tree
        let leaf_hash = self.low_leaf.hash()?;
        self.low_path.leaf.enforce_equal(&leaf_hash)?;
        
        let computed_root = self.low_path.compute_root()?;
        let path_valid = computed_root.is_eq(root)?;
        
        // 2. Verify target is in gap
        let in_gap = self.low_leaf.contains_gap(&self.target)?;
        
        Ok(&path_valid & &in_gap)
    }
    
    /// Enforce that this is a valid non-membership proof
    pub fn enforce_valid(&self, root: &FpVar<F>) -> Result<(), SynthesisError> {
        let is_valid = self.verify(root)?;
        is_valid.enforce_equal(&Boolean::TRUE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use fluxe_core::merkle::{SortedTree, MerkleTree};
    
    #[test]
    fn test_sorted_leaf_gadget() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let leaf = SortedLeaf {
            key: F::from(100),
            next_key: F::from(200),
            next_index: 5,
        };
        
        let leaf_var = SortedLeafVar::new_witness(cs.clone(), || Ok(leaf.clone())).unwrap();
        
        // Test gap checking
        let value_in_gap = FpVar::new_witness(cs.clone(), || Ok(F::from(150))).unwrap();
        let in_gap = leaf_var.contains_gap(&value_in_gap).unwrap();
        assert!(in_gap.value().unwrap());
        
        let value_not_in_gap = FpVar::new_witness(cs.clone(), || Ok(F::from(250))).unwrap();
        let not_in_gap = leaf_var.contains_gap(&value_not_in_gap).unwrap();
        assert!(!not_in_gap.value().unwrap());
        
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_range_path_verification() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Create a sorted tree and insert some values
        let mut tree = SortedTree::new(4);
        tree.insert(F::from(100)).unwrap();
        tree.insert(F::from(200)).unwrap();
        tree.insert(F::from(300)).unwrap();
        
        // Get non-membership proof for value in gap
        let target = F::from(150);
        let range_path = tree.prove_non_membership(target).unwrap();
        
        // Create gadget variables
        let range_path_var = RangePathVar::new_witness(cs.clone(), || Ok(range_path)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(tree.root())).unwrap();
        
        // Verify the proof
        range_path_var.enforce_valid(&root_var).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }
}