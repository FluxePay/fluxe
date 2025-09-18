use ark_bls12_381::Fr as F;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_ff::{BigInteger, PrimeField};
use fluxe_core::crypto::pedersen::{PedersenCommitment, PedersenParams};

/// Pedersen commitment variable for circuits
/// 
/// DEPRECATED: This gadget is insecure and returns TRUE without verification.
/// Use pedersen_ec::PedersenCommitmentVar for secure verification.
#[deprecated(since = "0.1.0", note = "Use pedersen_ec::PedersenCommitmentVar for secure verification")]
#[derive(Clone)]
pub struct PedersenCommitmentVar {
    /// X-coordinate of commitment point (for efficiency)
    pub commitment_x: FpVar<F>,
}

impl PedersenCommitmentVar {
    /// Create new commitment variable as witness
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        value: u64,
        randomness: &F,
    ) -> Result<Self, SynthesisError> {
        // In a real implementation, would compute commitment in-circuit
        // For now, compute outside and witness the result
        let params = PedersenParams::setup_value_commitment();
        let commitment = PedersenCommitment::commit(
            &params,
            value,
            &fluxe_core::crypto::pedersen::PedersenRandomness { r: *randomness },
        );
        
        // Convert Fq to Fr using same method as Note::commitment
        use ark_ff::{BigInteger, PrimeField};
        let x_bytes = commitment.commitment.x.into_bigint().to_bytes_le();
        let x_fr = fluxe_core::utils::bytes_to_field(&x_bytes);
        let commitment_x = FpVar::new_witness(cs, || Ok(x_fr))?;
        
        Ok(Self { commitment_x })
    }
    
    /// Create commitment variable from constant
    pub fn constant(commitment: &PedersenCommitment) -> Self {
        // Convert Fq to Fr using same method as Note::commitment
        use ark_ff::{BigInteger, PrimeField};
        let x_bytes = commitment.commitment.x.into_bigint().to_bytes_le();
        let x_fr = fluxe_core::utils::bytes_to_field(&x_bytes);
        Self {
            commitment_x: FpVar::constant(x_fr),
        }
    }
    
    /// Verify that this commitment correctly commits to the given value and randomness
    /// 
    /// WARNING: This is currently a stub that always returns true!
    /// A proper implementation requires:
    /// 1. In-circuit elliptic curve scalar multiplication
    /// 2. Computing g^value * h^randomness 
    /// 3. Verifying the result matches the commitment point
    /// 
    /// This is a CRITICAL security issue that must be fixed before production use
    #[deprecated(since = "0.1.0", note = "CRITICAL: This always returns TRUE without verification")]
    pub fn verify_commitment(
        &self,
        _value: &FpVar<F>,
        _randomness: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        // SECURITY CRITICAL: This method DOES NOT verify commitments!
        // It always returns TRUE, allowing arbitrary value forgery.
        // DO NOT USE IN PRODUCTION
        // Use pedersen_ec::PedersenCommitmentVar::verify_opening instead
        eprintln!("CRITICAL WARNING: Pedersen commitment verification is not implemented!");
        eprintln!("This allows UNLIMITED MONEY CREATION - DO NOT USE IN PRODUCTION");
        panic!("Insecure Pedersen commitment verification called - aborting for safety");
        
        // Unreachable, but kept for completeness
        #[allow(unreachable_code)]
        Ok(Boolean::TRUE)
    }
}