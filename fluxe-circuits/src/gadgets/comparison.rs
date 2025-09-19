use ark_bls12_381::Fr as F;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Comparison gadget for field elements
pub struct ComparisonGadget;

impl ComparisonGadget {
    /// Check if a < b for field elements
    /// Uses bit decomposition to perform lexicographic comparison
    pub fn is_less_than(
        _cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Get bit representations (little-endian)
        let a_bits = a.to_bits_le()?;
        let b_bits = b.to_bits_le()?;
        
        // Pad to same length
        let max_len = a_bits.len().max(b_bits.len());
        let a_bits_padded = Self::pad_bits(a_bits, max_len);
        let b_bits_padded = Self::pad_bits(b_bits, max_len);
        
        // Compare from MSB to LSB
        let mut result = Boolean::FALSE;
        let mut determined = Boolean::FALSE;
        
        // Iterate from most significant bit
        for i in (0..max_len).rev() {
            // If not yet determined and a[i] < b[i], then a < b
            let a_bit_is_zero = !&a_bits_padded[i];
            let b_bit_is_one = b_bits_padded[i].clone();
            // a[i] = 0 AND b[i] = 1 means a < b at this position
            let this_pos_less = &a_bit_is_zero & &b_bit_is_one;
            
            // If not yet determined and a[i] > b[i], then a > b (determined but not less)
            let a_bit_is_one = a_bits_padded[i].clone();
            let b_bit_is_zero = !&b_bits_padded[i];
            // a[i] = 1 AND b[i] = 0 means a > b at this position
            let this_pos_greater = &a_bit_is_one & &b_bit_is_zero;
            
            // Update result if not yet determined
            let not_determined = !&determined;
            // Update result to true if not yet determined AND this position shows less
            let update_to_less = &not_determined & &this_pos_less;
            // result = result OR update_to_less
            result = &result | &update_to_less;
            
            // Mark as determined if we found a difference
            // Found a difference if either less or greater at this position
            let found_difference = &this_pos_less | &this_pos_greater;
            // Mark as determined if we found a difference
            determined = &determined | &found_difference;
        }
        
        Ok(result)
    }
    
    /// Check if a > b for field elements
    pub fn is_greater_than(
        cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // a > b iff b < a
        Self::is_less_than(cs, b, a)
    }
    
    /// Check if a <= b for field elements
    pub fn is_less_than_or_equal(
        cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // a <= b iff !(a > b)
        let gt = Self::is_greater_than(cs, a, b)?;
        Ok(!&gt)
    }
    
    /// Check if a >= b for field elements
    pub fn is_greater_than_or_equal(
        cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // a >= b iff !(a < b)
        let lt = Self::is_less_than(cs, a, b)?;
        Ok(!&lt)
    }
    
    /// Check if value is in range [min, max]
    pub fn is_in_range(
        cs: ConstraintSystemRef<F>,
        value: &FpVar<F>,
        min: &FpVar<F>,
        max: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let gte_min = Self::is_greater_than_or_equal(cs.clone(), value, min)?;
        let lte_max = Self::is_less_than_or_equal(cs, value, max)?;
        // value >= lower AND value <= upper
        Ok(&gte_min & &lte_max)
    }
    
    /// Pad bits to desired length
    fn pad_bits(mut bits: Vec<Boolean<F>>, target_len: usize) -> Vec<Boolean<F>> {
        while bits.len() < target_len {
            bits.push(Boolean::FALSE);
        }
        bits
    }
    
    /// Optimized comparison for small values (< 2^64)
    /// Assumes both values fit in 64 bits
    pub fn is_less_than_64bit(
        _cs: ConstraintSystemRef<F>,
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Get 64-bit representations
        let a_bits = a.to_bits_le()?;
        let b_bits = b.to_bits_le()?;
        
        let a_bits_64 = Self::pad_bits(a_bits[..64.min(a_bits.len())].to_vec(), 64);
        let b_bits_64 = Self::pad_bits(b_bits[..64.min(b_bits.len())].to_vec(), 64);
        
        // Compare from MSB
        let mut result = Boolean::FALSE;
        let mut determined = Boolean::FALSE;
        
        for i in (0..64).rev() {
            let a_i = &a_bits_64[i];
            let b_i = &b_bits_64[i];
            
            // a[i] = 0 and b[i] = 1 => a < b at position i
            let a_i_not = !a_i;
            // a[i] = 0 AND b[i] = 1 => a < b at position i
            let less_at_i = &a_i_not & b_i;
            
            // a[i] = 1 and b[i] = 0 => a > b at position i  
            let b_i_not = !b_i;
            // a[i] = 1 AND b[i] = 0 => a > b at position i
            let greater_at_i = a_i & &b_i_not;
            
            // Update result if not determined
            let not_determined = !&determined;
            // Update result if not determined AND less at this position
            let should_set_less = &not_determined & &less_at_i;
            // result = result OR should_set_less
            result = &result | &should_set_less;
            
            // Mark as determined if difference found
            // Mark as determined if difference found
            let found_diff = &less_at_i | &greater_at_i;
            // determined = determined OR found_diff
            determined = &determined | &found_diff;
        }
        
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_field_comparison() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Test basic comparisons
        let a = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap();
        
        let less_than = ComparisonGadget::is_less_than(cs.clone(), &a, &b).unwrap();
        assert!(less_than.value().unwrap());
        
        let greater_than = ComparisonGadget::is_greater_than(cs.clone(), &a, &b).unwrap();
        assert!(!greater_than.value().unwrap());
        
        // Test equality edge case
        let c = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
        let equal_lt = ComparisonGadget::is_less_than(cs.clone(), &a, &c).unwrap();
        assert!(!equal_lt.value().unwrap());
        
        let equal_lte = ComparisonGadget::is_less_than_or_equal(cs.clone(), &a, &c).unwrap();
        assert!(equal_lte.value().unwrap());
        
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_range_check() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(150u64))).unwrap();
        let min = FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap();
        let max = FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap();
        
        let in_range = ComparisonGadget::is_in_range(cs.clone(), &value, &min, &max).unwrap();
        assert!(in_range.value().unwrap());
        
        let out_value = FpVar::new_witness(cs.clone(), || Ok(F::from(250u64))).unwrap();
        let out_range = ComparisonGadget::is_in_range(cs.clone(), &out_value, &min, &max).unwrap();
        assert!(!out_range.value().unwrap());
        
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_64bit_comparison() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let a = FpVar::new_witness(cs.clone(), || Ok(F::from(1000000u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(F::from(2000000u64))).unwrap();
        
        let less_than = ComparisonGadget::is_less_than_64bit(cs.clone(), &a, &b).unwrap();
        assert!(less_than.value().unwrap());
        
        // Test with larger values
        let c = FpVar::new_witness(cs.clone(), || Ok(F::from(u64::MAX / 2))).unwrap();
        let d = FpVar::new_witness(cs.clone(), || Ok(F::from(u64::MAX / 2 + 1))).unwrap();
        
        let large_lt = ComparisonGadget::is_less_than_64bit(cs.clone(), &c, &d).unwrap();
        assert!(large_lt.value().unwrap());
        
        assert!(cs.is_satisfied().unwrap());
    }
}