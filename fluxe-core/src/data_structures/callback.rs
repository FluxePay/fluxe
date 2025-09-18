use crate::crypto::poseidon_hash;
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Callback package sent from user to service provider
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CallbackPackage {
    /// The callback ticket (randomized verification key)
    pub ticket: F,
    
    /// Method to be called
    pub method_id: u32,
    
    /// Expiry time for this callback
    pub expiry: Time,
    
    /// Encryption key for callback parameters
    pub enc_key: F,
    
    /// Commitment randomness
    pub com_rand: F,
}

impl CallbackPackage {
    pub fn new(method_id: u32, expiry: Time) -> Self {
        use ark_ff::UniformRand;
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        Self {
            ticket: F::rand(&mut rng),
            method_id,
            expiry,
            enc_key: F::rand(&mut rng),
            com_rand: F::rand(&mut rng),
        }
    }

    /// Compute commitment to this package
    pub fn commitment(&self) -> F {
        poseidon_hash(&[
            self.ticket,
            F::from(self.method_id as u64),
            F::from(self.expiry),
            self.enc_key,
            self.com_rand,
        ])
    }
}