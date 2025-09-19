use ark_bls12_381::Fr as F;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ed_on_bls12_381::{
    EdwardsProjective as Jubjub,
    Fq as JubjubFq,
};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;

type JubjubVar = AffineVar<ark_ed_on_bls12_381::EdwardsConfig, FpVar<JubjubFq>>;
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::fp::FpVar,
    groups::CurveVar,
    prelude::*,
    R1CSVar,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Pedersen commitment parameters using Jubjub curve
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenParamsEC {
    /// Generator for value (G)
    pub g: Jubjub,
    /// Generator for randomness (H)
    pub h: Jubjub,
}

impl PedersenParamsEC {
    /// Create new parameters with random generators
    pub fn new<R: rand::Rng>(rng: &mut R) -> Self {
        // Generate two random points with no known discrete log relationship
        let g = Jubjub::rand(rng);
        let h = Jubjub::rand(rng);
        
        // Ensure they're different
        assert_ne!(g, h);
        // Note: In production, should also verify they're not identity elements
        
        Self { g, h }
    }
    
    /// Setup with deterministic parameters (for testing/reproducibility)
    pub fn setup() -> Self {
        use ark_std::test_rng;
        use rand::SeedableRng;
        
        // Use a deterministic RNG with fixed seed
        let seed = [1u8; 32]; // Fixed seed for reproducibility
        let mut rng = rand::rngs::StdRng::from_seed(seed);
        
        // Generate G from the standard generator
        let g = Jubjub::generator();
        
        // Generate H by hashing a nothing-up-my-sleeve string
        // In production, this should come from a trusted setup ceremony
        let h_scalar = F::from_be_bytes_mod_order(b"FLUXE_PEDERSEN_H_GENERATOR_2024");
        // Use scalar multiplication via the Group trait
        let g_gen = Jubjub::generator();
        let h = g_gen.mul_bigint(h_scalar.into_bigint());
        
        Self { g, h }
    }
}

/// Pedersen commitment in Jubjub curve
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct PedersenCommitmentEC {
    /// The commitment point C = g^v * h^r
    pub commitment: Jubjub,
}

impl PedersenCommitmentEC {
    /// Create a commitment to value v with randomness r
    /// C = g^v * h^r
    pub fn commit(params: &PedersenParamsEC, value: u64, randomness: &F) -> Self {
        // Convert value to scalar field element
        let value_scalar = F::from(value);
        
        // Perform scalar multiplication
        // In arkworks, curve points implement Mul<ScalarField>
        use ark_std::ops::Mul;
        let g_times_v = params.g.mul(value_scalar);
        let h_times_r = params.h.mul(*randomness);
        
        // Add the two curve points
        let commitment = g_times_v + h_times_r;
        Self { commitment }
    }
    
    /// Verify that a commitment opens to the given value and randomness
    pub fn verify_opening(
        &self,
        params: &PedersenParamsEC,
        value: u64,
        randomness: &F,
    ) -> bool {
        let expected = Self::commit(params, value, randomness);
        self.commitment == expected.commitment
    }
}

/// Pedersen parameters variable for circuits
#[derive(Clone)]
pub struct PedersenParamsVar {
    /// Generator for value (G)
    pub g: JubjubVar,
    /// Generator for randomness (H)
    pub h: JubjubVar,
}

impl PedersenParamsVar {
    /// Create new parameters as constants in circuit
    pub fn new_constant(
        cs: ConstraintSystemRef<F>,
        params: &PedersenParamsEC,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            g: JubjubVar::new_constant(cs.clone(), params.g.into_affine())?,
            h: JubjubVar::new_constant(cs, params.h.into_affine())?,
        })
    }
    
    /// Create new parameters as witnesses in circuit
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        params: impl FnOnce() -> Result<PedersenParamsEC, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let params = params()?;
        Ok(Self {
            g: JubjubVar::new_witness(cs.clone(), || Ok(params.g.into_affine()))?,
            h: JubjubVar::new_witness(cs, || Ok(params.h.into_affine()))?,
        })
    }
}

/// Pedersen commitment variable for circuits
#[derive(Clone)]
pub struct PedersenCommitmentVar {
    /// The commitment point C = g^v * h^r
    pub commitment: JubjubVar,
}

impl PedersenCommitmentVar {
    /// Create commitment variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        commitment: impl FnOnce() -> Result<PedersenCommitmentEC, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let comm = commitment()?;
        Ok(Self {
            commitment: JubjubVar::new_witness(cs, || Ok(comm.commitment.into_affine()))?,
        })
    }
    
    /// Create commitment variable as public input
    pub fn new_input(
        cs: ConstraintSystemRef<F>,
        commitment: impl FnOnce() -> Result<PedersenCommitmentEC, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let comm = commitment()?;
        Ok(Self {
            commitment: JubjubVar::new_input(cs, || Ok(comm.commitment.into_affine()))?,
        })
    }
    
    /// Commit to a value with randomness in circuit
    /// Returns C = g^v * h^r
    pub fn commit(
        params: &PedersenParamsVar,
        value: &FpVar<F>,
        randomness: &FpVar<F>,
    ) -> Result<Self, SynthesisError> {
        // Convert value and randomness to bits for scalar multiplication
        let value_bits = value.to_bits_le()?;
        let randomness_bits = randomness.to_bits_le()?;
        
        // Compute g^v
        let g_v = params.g.scalar_mul_le(value_bits.iter())?;
        
        // Compute h^r
        let h_r = params.h.scalar_mul_le(randomness_bits.iter())?;
        
        // Compute C = g^v * h^r
        let commitment = g_v + h_r;
        
        Ok(Self { commitment })
    }
    
    /// Verify that this commitment opens to the given value and randomness
    /// Returns a Boolean indicating whether the opening is valid
    pub fn verify_opening(
        &self,
        params: &PedersenParamsVar,
        value: &FpVar<F>,
        randomness: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // Recompute the commitment
        let expected = Self::commit(params, value, randomness)?;
        
        // Check if the computed commitment equals this commitment
        self.commitment.is_eq(&expected.commitment)
    }
    
    /// Enforce that this commitment opens to the given value and randomness
    pub fn enforce_opening(
        &self,
        params: &PedersenParamsVar,
        value: &FpVar<F>,
        randomness: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let is_valid = self.verify_opening(params, value, randomness)?;
        is_valid.enforce_equal(&Boolean::TRUE)
    }
    
    /// Convert commitment to field elements for hashing
    pub fn to_field_elements(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        // Get x and y coordinates of the commitment point
        let x = self.commitment.x.clone();
        let y = self.commitment.y.clone();
        
        // Convert from JubjubFq to F (BLS12-381 scalar field)
        // This is safe because JubjubFq fits in F
        Ok(vec![x, y])
    }
}

/// Range proof for Pedersen commitments
pub struct PedersenRangeProof;

impl PedersenRangeProof {
    /// Prove that a committed value is in range [0, 2^bits)
    pub fn prove_range(
        cs: ConstraintSystemRef<F>,
        commitment: &PedersenCommitmentVar,
        params: &PedersenParamsVar,
        value: &FpVar<F>,
        randomness: &FpVar<F>,
        bits: usize,
    ) -> Result<(), SynthesisError> {
        // First verify the commitment opens correctly
        commitment.enforce_opening(params, value, randomness)?;
        
        // Then verify the value is in range
        use crate::gadgets::range_proof::RangeProofGadget;
        RangeProofGadget::prove_range(cs, value, bits)?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;
    
    #[test]
    fn test_pedersen_commitment_native() {
        let mut rng = test_rng();
        
        // Setup parameters
        let params = PedersenParamsEC::setup();
        
        // Create a commitment
        let value = 1000u64;
        let randomness = F::rand(&mut rng);
        let commitment = PedersenCommitmentEC::commit(&params, value, &randomness);
        
        // Verify opening
        assert!(commitment.verify_opening(&params, value, &randomness));
        
        // Wrong value should fail
        assert!(!commitment.verify_opening(&params, value + 1, &randomness));
        
        // Wrong randomness should fail
        let wrong_randomness = F::rand(&mut rng);
        assert!(!commitment.verify_opening(&params, value, &wrong_randomness));
    }
    
    #[test]
    fn test_pedersen_commitment_circuit() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Setup parameters
        let params = PedersenParamsEC::setup();
        let params_var = PedersenParamsVar::new_constant(cs.clone(), &params).unwrap();
        
        // Create commitment natively
        let value = 1000u64;
        let randomness = F::rand(&mut rng);
        let commitment = PedersenCommitmentEC::commit(&params, value, &randomness);
        
        // Witness the commitment
        let commitment_var = PedersenCommitmentVar::new_witness(
            cs.clone(),
            || Ok(commitment.clone()),
        ).unwrap();
        
        // Witness value and randomness
        let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value))).unwrap();
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(randomness)).unwrap();
        
        // Verify opening in circuit
        commitment_var.enforce_opening(&params_var, &value_var, &randomness_var).unwrap();
        
        // Check constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_pedersen_range_proof() {
        let mut rng = test_rng();
        let cs = ConstraintSystem::<F>::new_ref();
        
        // Setup parameters
        let params = PedersenParamsEC::setup();
        let params_var = PedersenParamsVar::new_constant(cs.clone(), &params).unwrap();
        
        // Create commitment to value in range
        let value = 1000u64;
        let randomness = F::rand(&mut rng);
        let commitment = PedersenCommitmentEC::commit(&params, value, &randomness);
        
        // Witness everything
        let commitment_var = PedersenCommitmentVar::new_witness(
            cs.clone(),
            || Ok(commitment),
        ).unwrap();
        let value_var = FpVar::new_witness(cs.clone(), || Ok(F::from(value))).unwrap();
        let randomness_var = FpVar::new_witness(cs.clone(), || Ok(randomness)).unwrap();
        
        // Prove value is in 64-bit range
        PedersenRangeProof::prove_range(
            cs.clone(),
            &commitment_var,
            &params_var,
            &value_var,
            &randomness_var,
            64,
        ).unwrap();
        
        // Check constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_commitment_homomorphism() {
        let mut rng = test_rng();
        
        // Setup parameters
        let params = PedersenParamsEC::setup();
        
        // Create two commitments
        let value1 = 100u64;
        let randomness1 = F::rand(&mut rng);
        let comm1 = PedersenCommitmentEC::commit(&params, value1, &randomness1);
        
        let value2 = 200u64;
        let randomness2 = F::rand(&mut rng);
        let comm2 = PedersenCommitmentEC::commit(&params, value2, &randomness2);
        
        // Add commitments - homomorphic property
        let comm_sum = PedersenCommitmentEC {
            commitment: comm1.commitment + comm2.commitment,
        };
        
        // Verify the sum
        let value_sum = value1 + value2;
        let randomness_sum = randomness1 + randomness2;
        
        // The homomorphic property should hold:
        // C(v1, r1) + C(v2, r2) = C(v1+v2, r1+r2)
        assert!(comm_sum.verify_opening(&params, value_sum, &randomness_sum));
    }
}