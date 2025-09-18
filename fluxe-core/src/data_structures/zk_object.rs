use crate::crypto::{poseidon_hash, domain_sep_to_field, DOM_OBJ, SchnorrSignature, SchnorrPublicKey};
use crate::data_structures::ComplianceState;
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Using ark_serialize for ZK object serialization

/// zk-Object representing per-user compliance state machine
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ZkObject {
    /// Commitment to compliance state
    pub state_hash: F,
    
    /// Anti-replay serial number
    pub serial: Serial,
    
    /// Hash-chain head of pending callbacks
    pub cb_head_hash: F,
}

impl ZkObject {
    /// Create a new zk-object
    pub fn new(state: &ComplianceState) -> Self {
        Self {
            state_hash: state.hash(),
            serial: 0,
            cb_head_hash: F::from(0),
        }
    }

    /// Compute commitment to this object
    pub fn commitment<R: rand::Rng>(&self, rng: &mut R) -> F {
        let r_obj = F::rand(rng);
        self.commitment_with_randomness(&r_obj)
    }

    /// Compute commitment with specific randomness
    pub fn commitment_with_randomness(&self, r_obj: &F) -> F {
        let input = vec![
            domain_sep_to_field(DOM_OBJ),
            self.state_hash,
            F::from(self.serial),
            self.cb_head_hash,
            *r_obj,
        ];
        
        poseidon_hash(&input)
    }

    /// Update object for new callback
    pub fn add_callback(&mut self, callback_entry: &CallbackEntry) {
        // Increment serial for anti-replay
        self.serial += 1;
        
        // Update callback hash chain (O(1) append)
        self.cb_head_hash = poseidon_hash(&[self.cb_head_hash, callback_entry.hash()]);
    }

    /// Process a callback and update state
    pub fn process_callback(&mut self, new_state_hash: F, callback_to_remove: &CallbackEntry) {
        self.serial += 1;
        self.state_hash = new_state_hash;
        // In practice, would update cb_head_hash to remove the processed callback
        // For simplicity, we'll just update it
        self.cb_head_hash = poseidon_hash(&[self.cb_head_hash, callback_to_remove.hash()]);
    }

    /// Check if object is valid for spending
    pub fn can_spend(&self, state: &ComplianceState, current_time: Time) -> Result<(), String> {
        // Verify state hash matches
        if self.state_hash != state.hash() {
            return Err("State hash mismatch".to_string());
        }

        // Check if frozen
        if state.frozen {
            return Err("Account is frozen".to_string());
        }

        // Additional checks would verify no expired callbacks remain unprocessed
        // This would require checking the callback chain
        
        Ok(())
    }
}

/// Callback entry in the hash chain
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CallbackEntry {
    /// Method identifier
    pub method_id: u32,
    
    /// Expiry time for this callback
    pub expiry: Time,
    
    /// Provider public key who can invoke this
    pub provider_key: F,
    
    /// User-specific randomness
    pub user_rand: F,
}

impl CallbackEntry {
    pub fn new(method_id: u32, expiry: Time, provider_key: F) -> Self {
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        Self {
            method_id,
            expiry,
            provider_key,
            user_rand: F::rand(&mut rng),
        }
    }

    /// Compute hash of this entry
    pub fn hash(&self) -> F {
        poseidon_hash(&[
            F::from(self.method_id as u64),
            F::from(self.expiry),
            self.provider_key,
            self.user_rand,
        ])
    }

    /// Generate ticket for this callback
    pub fn ticket(&self) -> F {
        poseidon_hash(&[self.provider_key, self.user_rand])
    }

    /// Check if callback has expired
    pub fn is_expired(&self, current_time: Time) -> bool {
        current_time > self.expiry
    }
}

/// Callback invocation posted by compliance provider
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct CallbackInvocation {
    /// Verification key (ticket)
    pub ticket: F,
    
    /// Encrypted payload
    pub payload: Vec<u8>,
    
    /// Timestamp of invocation
    pub timestamp: Time,
    
    /// Signature verifiable under ticket
    pub signature: Option<SchnorrSignature>,
}

impl CallbackInvocation {
    pub fn new(ticket: F, payload: Vec<u8>, timestamp: Time) -> Self {
        Self {
            ticket,
            payload,
            timestamp,
            signature: None,
        }
    }

    /// Sign the invocation with provider's secret key
    pub fn sign(&mut self, provider_sk: &crate::crypto::SchnorrSecretKey) {
        // Create message to sign: H(ticket || payload || timestamp)
        let payload_hash = poseidon_hash(&[
            self.ticket,
            crate::utils::bytes_to_field(&self.payload),
            F::from(self.timestamp),
        ]);
        
        let message = vec![payload_hash];
        // Use thread_rng for better randomness than test_rng
        // In production with high security requirements, consider using OsRng
        use rand::thread_rng;
        let mut rng = thread_rng();
        self.signature = Some(provider_sk.sign(&message, &mut rng));
    }

    /// Verify the invocation signature using the public key derived from ticket
    pub fn verify(&self, provider_pk: &SchnorrPublicKey) -> bool {
        match &self.signature {
            None => false,
            Some(sig) => {
                // Verify that the ticket matches the provider's public key
                if provider_pk.to_field() != self.ticket {
                    return false;
                }
                
                // Create message that was signed
                let payload_hash = poseidon_hash(&[
                    self.ticket,
                    crate::utils::bytes_to_field(&self.payload),
                    F::from(self.timestamp),
                ]);
                
                let message = vec![payload_hash];
                provider_pk.verify(&message, sig)
            }
        }
    }

    /// Convert to field element for Merkle tree
    pub fn to_field(&self) -> F {
        poseidon_hash(&[
            self.ticket,
            F::from(self.timestamp),
            crate::utils::bytes_to_field(&self.payload[..32.min(self.payload.len())]),
        ])
    }
    
    /// Compute hash of the invocation
    pub fn hash(&self) -> F {
        self.to_field()
    }
}

/// Supported callback methods
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallbackMethod {
    /// Freeze user's assets
    FreezeAssets,
    
    /// Unfreeze with new limits
    UnfreezeAssets { 
        daily_limit: Amount,
        monthly_limit: Amount,
        yearly_limit: Amount,
    },
    
    /// Update risk score
    UpdateRiskScore(RiskScore),
    
    /// Update compliance level
    UpdateComplianceLevel(u8),
    
    /// Request additional documentation
    RequestDocuments,
}

impl CallbackMethod {
    /// Get method ID
    pub fn id(&self) -> u32 {
        match self {
            CallbackMethod::FreezeAssets => 1,
            CallbackMethod::UnfreezeAssets { .. } => 2,
            CallbackMethod::UpdateRiskScore(_) => 3,
            CallbackMethod::UpdateComplianceLevel(_) => 4,
            CallbackMethod::RequestDocuments => 5,
        }
    }

    /// Execute method on compliance state
    pub fn execute(&self, state: &mut ComplianceState) -> Result<(), String> {
        match self {
            CallbackMethod::FreezeAssets => {
                state.freeze();
                Ok(())
            }
            CallbackMethod::UnfreezeAssets { daily_limit, monthly_limit, yearly_limit } => {
                state.unfreeze(*daily_limit, *monthly_limit, *yearly_limit);
                Ok(())
            }
            CallbackMethod::UpdateRiskScore(score) => {
                state.risk_score = *score;
                Ok(())
            }
            CallbackMethod::UpdateComplianceLevel(level) => {
                state.level = *level;
                Ok(())
            }
            CallbackMethod::RequestDocuments => {
                // This would trigger off-chain document request
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_zk_object() {
        let state = ComplianceState::new_verified(1);
        let mut obj = ZkObject::new(&state);
        
        assert_eq!(obj.serial, 0);
        assert_eq!(obj.state_hash, state.hash());
        
        // Test callback addition
        let callback = CallbackEntry::new(1, 1000, F::from(123));
        obj.add_callback(&callback);
        assert_eq!(obj.serial, 1);
    }

    #[test]
    fn test_callback_entry() {
        let entry = CallbackEntry::new(1, 1000, F::from(123));
        
        assert!(!entry.is_expired(999));
        assert!(!entry.is_expired(1000));
        assert!(entry.is_expired(1001));
        
        let ticket = entry.ticket();
        let ticket2 = entry.ticket();
        assert_eq!(ticket, ticket2); // Ticket should be deterministic
    }

    #[test]
    fn test_callback_methods() {
        let mut state = ComplianceState::new_verified(1);
        
        // Test freeze
        let freeze = CallbackMethod::FreezeAssets;
        freeze.execute(&mut state).unwrap();
        assert!(state.frozen);
        
        // Test unfreeze
        let unfreeze = CallbackMethod::UnfreezeAssets {
            daily_limit: crate::types::Amount::from(5000u128),
            monthly_limit: crate::types::Amount::from(25000u128),
            yearly_limit: crate::types::Amount::from(100000u128),
        };
        unfreeze.execute(&mut state).unwrap();
        assert!(!state.frozen);
        assert_eq!(state.daily_limit, crate::types::Amount::from(5000u128));
    }

    #[test]
    fn test_callback_invocation_signature() {
        use crate::crypto::SchnorrSecretKey;
        let mut rng = thread_rng();
        
        // Create provider key pair
        let provider_sk = SchnorrSecretKey::random(&mut rng);
        let provider_pk = provider_sk.public_key();
        
        // Create callback invocation
        let ticket = provider_pk.to_field();
        let payload = vec![1, 2, 3, 4];
        let timestamp = 1234567890;
        
        let mut invocation = CallbackInvocation::new(ticket, payload, timestamp);
        
        // Verify unsigned invocation fails
        assert!(!invocation.verify(&provider_pk));
        
        // Sign the invocation
        invocation.sign(&provider_sk);
        
        // Verify signed invocation succeeds
        assert!(invocation.verify(&provider_pk));
        
        // Verify with wrong public key fails
        let wrong_sk = SchnorrSecretKey::random(&mut rng);
        let wrong_pk = wrong_sk.public_key();
        assert!(!invocation.verify(&wrong_pk));
        
        // Verify tampered invocation fails
        invocation.timestamp = 9999999;
        assert!(!invocation.verify(&provider_pk));
    }
}