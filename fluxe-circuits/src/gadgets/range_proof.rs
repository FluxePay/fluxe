use ark_bls12_381::Fr as F;
use ark_ff::{Zero, Field, One};
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Range proof gadget for proving values are within specific bit ranges.
/// 
/// SECURITY: This implementation uses proper bit decomposition from FpVar::to_bits_le()
/// which ensures the decomposition is constrained and cannot be manipulated.
pub struct RangeProofGadget;

impl RangeProofGadget {
    /// Prove that a value fits within the specified number of bits.
    /// Compatibility wrapper that calls prove_range_bits.
    #[deprecated(note = "Use prove_range_bits directly")]
    pub fn prove_range(
        cs: ConstraintSystemRef<F>,
        value: &FpVar<F>,
        bits: usize,
    ) -> Result<(), SynthesisError> {
        Self::prove_range_bits(cs, value, bits)
    }
    
    /// Prove that a value fits within the specified number of bits.
    /// 
    /// This is the ONLY range proof method that should be used.
    /// It properly decomposes the value into bits and verifies upper bits are zero.
    pub fn prove_range_bits(
        _cs: ConstraintSystemRef<F>,
        value: &FpVar<F>,
        bits: usize,
    ) -> Result<(), SynthesisError> {
        // Get the bit decomposition (constrained by ark-r1cs-std)
        let value_bits = value.to_bits_le()?;
        
        // Enforce that all bits beyond 'bits' are zero
        for i in bits..value_bits.len() {
            value_bits[i].enforce_equal(&Boolean::FALSE)?;
        }
        
        // Optional: Reconstruct and verify (for extra safety, though to_bits_le already ensures this)
        // This adds extra constraints but provides defense in depth
        let reconstructed = Self::le_bits_to_fp_var(&value_bits[..bits.min(value_bits.len())])?;
        
        // Create a mask for the valid bits
        let mask = if bits >= 254 {
            // For full field element range
            value.clone()
        } else {
            // Mask to only the lower 'bits' bits
            reconstructed
        };
        
        // For values that should fit in 'bits' bits, verify reconstruction matches
        if bits < 254 {
            value.enforce_equal(&mask)?;
        }
        
        Ok(())
    }
    
    /// Helper function to reconstruct a field element from little-endian bits.
    /// Used internally for verification.
    fn le_bits_to_fp_var(bits: &[Boolean<F>]) -> Result<FpVar<F>, SynthesisError> {
        let mut result = FpVar::<F>::zero();
        let mut power = F::one();
        
        for bit in bits.iter() {
            let bit_value = bit.select(&FpVar::constant(F::one()), &FpVar::zero())?;
            result += &bit_value * power;
            power = power.double();
        }
        
        Ok(result)
    }
    
    /// Prove that a value is within [lower, upper] bounds.
    /// Both bounds are inclusive.
    pub fn prove_range_bounds(
        cs: ConstraintSystemRef<F>,
        value: &FpVar<F>,
        lower: u64,
        upper: u64,
        max_bits: usize,
    ) -> Result<(), SynthesisError> {
        // First ensure value fits in max_bits
        Self::prove_range_bits(cs.clone(), value, max_bits)?;
        
        // For bounds checking, we need comparison gadgets
        // Check: lower <= value <= upper
        let lower_var = FpVar::constant(F::from(lower));
        let upper_var = FpVar::constant(F::from(upper));
        
        // value - lower >= 0 (value >= lower)
        let diff_lower = value.clone() - &lower_var;
        Self::prove_range_bits(cs.clone(), &diff_lower, max_bits)?;
        
        // upper - value >= 0 (value <= upper)
        let diff_upper = upper_var - value;
        Self::prove_range_bits(cs, &diff_upper, max_bits)?;
        
        Ok(())
    }
    
    /// Prove that the sum of values doesn't overflow.
    /// All values must fit in value_bits, and their sum must fit in sum_bits.
    pub fn prove_sum_with_range(
        cs: ConstraintSystemRef<F>,
        values: &[FpVar<F>],
        value_bits: usize,
        sum_bits: usize,
    ) -> Result<FpVar<F>, SynthesisError> {
        // Range check each value
        for value in values {
            Self::prove_range_bits(cs.clone(), value, value_bits)?;
        }
        
        // Compute sum
        let mut sum = FpVar::<F>::zero();
        for value in values {
            sum += value;
        }
        
        // Range check sum
        Self::prove_range_bits(cs, &sum, sum_bits)?;
        
        Ok(sum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::UniformRand;
    use ark_std::rand::thread_rng;
    
    #[test]
    fn test_range_proof_8_bit() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Test valid 8-bit value
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(255u64))).unwrap();
        RangeProofGadget::prove_range_bits(cs.clone(), &value, 8).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        // Test invalid 8-bit value (256)
        let cs = ConstraintSystem::<F>::new_ref();
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(256u64))).unwrap();
        RangeProofGadget::prove_range_bits(cs.clone(), &value, 8).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_range_proof_64_bit() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Test maximum 64-bit value
        let max_64 = (1u64 << 63) - 1;
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(max_64))).unwrap();
        RangeProofGadget::prove_range_bits(cs.clone(), &value, 64).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_range_bounds() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Test value within bounds
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(50u64))).unwrap();
        RangeProofGadget::prove_range_bounds(cs.clone(), &value, 10, 100, 8).unwrap();
        assert!(cs.is_satisfied().unwrap());
        
        // Test value outside bounds
        let cs = ConstraintSystem::<F>::new_ref();
        let value = FpVar::new_witness(cs.clone(), || Ok(F::from(5u64))).unwrap();
        RangeProofGadget::prove_range_bounds(cs.clone(), &value, 10, 100, 8).unwrap();
        // This should fail because 5 < 10, making diff_lower negative
        assert!(!cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_sum_with_range() {
        let cs = ConstraintSystem::<F>::new_ref();
        
        let values = vec![
            FpVar::new_witness(cs.clone(), || Ok(F::from(100u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(200u64))).unwrap(),
            FpVar::new_witness(cs.clone(), || Ok(F::from(50u64))).unwrap(),
        ];
        
        let sum = RangeProofGadget::prove_sum_with_range(cs.clone(), &values, 8, 10).unwrap();
        
        // Verify sum equals 350
        let expected_sum = FpVar::constant(F::from(350u64));
        sum.enforce_equal(&expected_sum).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_range_utils() {
        // Test bit decomposition round-trip
        let cs = ConstraintSystem::<F>::new_ref();
        let mut rng = thread_rng();
        
        for _ in 0..10 {
            let value = F::rand(&mut rng);
            let value_var = FpVar::new_witness(cs.clone(), || Ok(value)).unwrap();
            
            let bits = value_var.to_bits_le().unwrap();
            let reconstructed = RangeProofGadget::le_bits_to_fp_var(&bits).unwrap();
            
            reconstructed.enforce_equal(&value_var).unwrap();
        }
        
        assert!(cs.is_satisfied().unwrap());
    }
}