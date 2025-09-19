use crate::crypto::{poseidon_hash, SchnorrSecretKey, SchnorrPublicKey, SchnorrSignature};
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::collections::HashMap;

/// Attestation provider identity
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct AttestationProvider {
    /// Provider ID
    pub id: u32,
    
    /// Provider name
    pub name: String,
    
    /// Provider public key
    pub public_key: SchnorrPublicKey,
    
    /// Provider jurisdiction
    pub jurisdiction: u32,
    
    /// Provider trust level (0-100)
    pub trust_level: u8,
}

/// Attestation data with provider signature
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAttestation {
    /// User identifier being attested
    pub user_cm: F,
    
    /// Type of attestation
    pub attestation_type: AttestationType,
    
    /// Timestamp
    pub timestamp: Time,
    
    /// Provider ID
    pub provider_id: u32,
    
    /// Optional supporting data
    pub data: Vec<u8>,
    
    /// Provider signature
    pub signature: SchnorrSignature,
}

/// Types of attestations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// Sanctions check cleared
    SanctionsClear { 
        duration: Time,
        jurisdiction: u32,
    },
    
    /// AML check passed
    AMLPass { 
        score: RiskScore,
        methodology: String,
    },
    
    /// KYC verification completed
    KYCComplete { 
        level: u8,
        document_hash: F,
    },
    
    /// Transaction monitoring alert cleared
    AlertCleared { 
        alert_id: u64,
        resolution: String,
    },
    
    /// Custom attestation
    Custom {
        type_id: u32,
        data_hash: F,
    },
}

impl AttestationType {
    /// Get numeric ID for the attestation type
    pub fn type_id(&self) -> u32 {
        match self {
            AttestationType::SanctionsClear { .. } => 1,
            AttestationType::AMLPass { .. } => 2,
            AttestationType::KYCComplete { .. } => 3,
            AttestationType::AlertCleared { .. } => 4,
            AttestationType::Custom { type_id, .. } => 100 + type_id,
        }
    }
    
    /// Compute hash of attestation type
    pub fn hash(&self) -> F {
        match self {
            AttestationType::SanctionsClear { duration, jurisdiction } => {
                poseidon_hash(&[
                    F::from(self.type_id() as u64),
                    F::from(*duration),
                    F::from(*jurisdiction as u64),
                ])
            }
            AttestationType::AMLPass { score, .. } => {
                poseidon_hash(&[
                    F::from(self.type_id() as u64),
                    F::from(*score as u64),
                ])
            }
            AttestationType::KYCComplete { level, document_hash } => {
                poseidon_hash(&[
                    F::from(self.type_id() as u64),
                    F::from(*level as u64),
                    *document_hash,
                ])
            }
            AttestationType::AlertCleared { alert_id, .. } => {
                poseidon_hash(&[
                    F::from(self.type_id() as u64),
                    F::from(*alert_id),
                ])
            }
            AttestationType::Custom { type_id, data_hash } => {
                poseidon_hash(&[
                    F::from((100 + type_id) as u64),
                    *data_hash,
                ])
            }
        }
    }
}

impl SignedAttestation {
    /// Create new attestation
    pub fn new(
        user_cm: F,
        attestation_type: AttestationType,
        timestamp: Time,
        provider_id: u32,
        data: Vec<u8>,
    ) -> Self {
        use rand::thread_rng;
        let mut rng = thread_rng();
        
        // Create with dummy signature for now
        Self {
            user_cm,
            attestation_type,
            timestamp,
            provider_id,
            data,
            signature: SchnorrSignature {
                r_point: ark_bls12_381::G1Projective::rand(&mut rng),
                s: F::rand(&mut rng),
            },
        }
    }
    
    /// Sign the attestation with provider's key
    pub fn sign(&mut self, provider_sk: &SchnorrSecretKey) {
        let message = self.message_to_sign();
        let mut rng = rand::thread_rng();
        self.signature = provider_sk.sign(&message, &mut rng);
    }
    
    /// Verify attestation signature
    pub fn verify(&self, provider_pk: &SchnorrPublicKey) -> bool {
        let message = self.message_to_sign();
        provider_pk.verify(&message, &self.signature)
    }
    
    /// Get message fields for signing
    fn message_to_sign(&self) -> Vec<F> {
        vec![
            self.user_cm,
            self.attestation_type.hash(),
            F::from(self.timestamp),
            F::from(self.provider_id as u64),
            crate::utils::bytes_to_field(&self.data),
        ]
    }
    
    /// Compute commitment to this attestation
    pub fn commitment(&self) -> F {
        let mut fields = self.message_to_sign();
        // Add signature components
        let r_affine: ark_bls12_381::G1Affine = self.signature.r_point.into();
        fields.push(crate::crypto::schnorr::fq_to_fr(r_affine.x));
        fields.push(crate::crypto::schnorr::fq_to_fr(r_affine.y));
        fields.push(self.signature.s);
        
        poseidon_hash(&fields)
    }
}

/// Attestation registry for managing providers
pub struct AttestationRegistry {
    /// Registered providers
    providers: HashMap<u32, AttestationProvider>,
    
    /// Attestation history
    attestations: Vec<SignedAttestation>,
    
    /// Revoked attestations
    revoked: Vec<F>,
}

impl Default for AttestationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            attestations: Vec::new(),
            revoked: Vec::new(),
        }
    }
    
    /// Register a new provider
    pub fn register_provider(&mut self, provider: AttestationProvider) {
        self.providers.insert(provider.id, provider);
    }
    
    /// Get provider by ID
    pub fn get_provider(&self, id: u32) -> Option<&AttestationProvider> {
        self.providers.get(&id)
    }
    
    /// Add attestation
    pub fn add_attestation(&mut self, attestation: SignedAttestation) -> Result<(), String> {
        // Verify provider exists
        let provider = self.providers
            .get(&attestation.provider_id)
            .ok_or("Provider not found")?;
        
        // Verify signature
        if !attestation.verify(&provider.public_key) {
            return Err("Invalid signature".to_string());
        }
        
        self.attestations.push(attestation);
        Ok(())
    }
    
    /// Revoke an attestation
    pub fn revoke_attestation(&mut self, commitment: F) {
        if !self.revoked.contains(&commitment) {
            self.revoked.push(commitment);
        }
    }
    
    /// Check if attestation is revoked
    pub fn is_revoked(&self, commitment: &F) -> bool {
        self.revoked.contains(commitment)
    }
    
    /// Get attestations for a user
    pub fn get_user_attestations(&self, user_cm: F) -> Vec<&SignedAttestation> {
        self.attestations
            .iter()
            .filter(|a| a.user_cm == user_cm && !self.is_revoked(&a.commitment()))
            .collect()
    }
    
    /// Compute aggregate trust score for user
    pub fn compute_trust_score(&self, user_cm: F) -> u32 {
        let attestations = self.get_user_attestations(user_cm);
        
        let mut score = 0u32;
        for attestation in attestations {
            if let Some(provider) = self.providers.get(&attestation.provider_id) {
                // Weight by provider trust level
                let weight = provider.trust_level as u32;
                
                // Add points based on attestation type
                let points = match &attestation.attestation_type {
                    AttestationType::KYCComplete { level, .. } => 50 * (*level as u32),
                    AttestationType::SanctionsClear { .. } => 100,
                    AttestationType::AMLPass { score, .. } => {
                        // Higher AML score means lower risk
                        if *score > 80 { 100 } else if *score > 60 { 50 } else { 25 }
                    }
                    AttestationType::AlertCleared { .. } => 25,
                    AttestationType::Custom { .. } => 10,
                };
                
                score += (points * weight) / 100;
            }
        }
        
        score
    }
}

/// Attestation aggregator for batch verification
pub struct AttestationAggregator {
    attestations: Vec<SignedAttestation>,
}

impl Default for AttestationAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationAggregator {
    pub fn new() -> Self {
        Self {
            attestations: Vec::new(),
        }
    }
    
    /// Add attestation to batch
    pub fn add(&mut self, attestation: SignedAttestation) {
        self.attestations.push(attestation);
    }
    
    /// Verify all attestations in batch
    pub fn verify_batch(&self, registry: &AttestationRegistry) -> Result<(), String> {
        for attestation in &self.attestations {
            let provider = registry
                .get_provider(attestation.provider_id)
                .ok_or("Provider not found")?;
            
            if !attestation.verify(&provider.public_key) {
                return Err(format!("Invalid signature for attestation from provider {}", 
                    attestation.provider_id));
            }
        }
        Ok(())
    }
    
    /// Compute aggregate commitment
    pub fn aggregate_commitment(&self) -> F {
        let mut commitment = F::from(0);
        for attestation in &self.attestations {
            commitment = poseidon_hash(&[commitment, attestation.commitment()]);
        }
        commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    
    #[test]
    fn test_attestation_signing() {
        let mut rng = thread_rng();
        
        // Create provider key pair
        let provider_sk = SchnorrSecretKey::random(&mut rng);
        let provider_pk = provider_sk.public_key();
        
        // Create provider
        let provider = AttestationProvider {
            id: 1,
            name: "Test Provider".to_string(),
            public_key: provider_pk.clone(),
            jurisdiction: 1,
            trust_level: 90,
        };
        
        // Create attestation
        let user_cm = F::rand(&mut rng);
        let mut attestation = SignedAttestation::new(
            user_cm,
            AttestationType::KYCComplete {
                level: 2,
                document_hash: F::rand(&mut rng),
            },
            1000,
            provider.id,
            vec![1, 2, 3],
        );
        
        // Sign attestation
        attestation.sign(&provider_sk);
        
        // Verify signature
        assert!(attestation.verify(&provider_pk));
        
        // Wrong key should fail
        let wrong_sk = SchnorrSecretKey::random(&mut rng);
        let wrong_pk = wrong_sk.public_key();
        assert!(!attestation.verify(&wrong_pk));
    }
    
    #[test]
    fn test_attestation_registry() {
        let mut rng = thread_rng();
        let mut registry = AttestationRegistry::new();
        
        // Create and register provider
        let provider_sk = SchnorrSecretKey::random(&mut rng);
        let provider = AttestationProvider {
            id: 1,
            name: "Provider 1".to_string(),
            public_key: provider_sk.public_key(),
            jurisdiction: 1,
            trust_level: 80,
        };
        registry.register_provider(provider.clone());
        
        // Create and sign attestation
        let user_cm = F::rand(&mut rng);
        let mut attestation = SignedAttestation::new(
            user_cm,
            AttestationType::SanctionsClear {
                duration: 86400,
                jurisdiction: 1,
            },
            1000,
            1,
            vec![],
        );
        attestation.sign(&provider_sk);
        
        // Add attestation
        registry.add_attestation(attestation.clone()).unwrap();
        
        // Check user attestations
        let user_attestations = registry.get_user_attestations(user_cm);
        assert_eq!(user_attestations.len(), 1);
        
        // Revoke attestation
        let commitment = attestation.commitment();
        registry.revoke_attestation(commitment);
        
        // Check revoked
        assert!(registry.is_revoked(&commitment));
        
        // Should not be returned anymore
        let user_attestations = registry.get_user_attestations(user_cm);
        assert_eq!(user_attestations.len(), 0);
    }
    
    #[test]
    fn test_trust_score_computation() {
        let mut rng = thread_rng();
        let mut registry = AttestationRegistry::new();
        
        // Create providers with different trust levels
        let provider1_sk = SchnorrSecretKey::random(&mut rng);
        let provider1 = AttestationProvider {
            id: 1,
            name: "High Trust".to_string(),
            public_key: provider1_sk.public_key(),
            jurisdiction: 1,
            trust_level: 100,
        };
        
        let provider2_sk = SchnorrSecretKey::random(&mut rng);
        let provider2 = AttestationProvider {
            id: 2,
            name: "Medium Trust".to_string(),
            public_key: provider2_sk.public_key(),
            jurisdiction: 2,
            trust_level: 50,
        };
        
        registry.register_provider(provider1);
        registry.register_provider(provider2);
        
        // Add attestations for user
        let user_cm = F::rand(&mut rng);
        
        // KYC from high trust provider
        let mut kyc_attestation = SignedAttestation::new(
            user_cm,
            AttestationType::KYCComplete {
                level: 3,
                document_hash: F::rand(&mut rng),
            },
            1000,
            1,
            vec![],
        );
        kyc_attestation.sign(&provider1_sk);
        registry.add_attestation(kyc_attestation).unwrap();
        
        // AML from medium trust provider
        let mut aml_attestation = SignedAttestation::new(
            user_cm,
            AttestationType::AMLPass {
                score: 85,
                methodology: "ML-based".to_string(),
            },
            1001,
            2,
            vec![],
        );
        aml_attestation.sign(&provider2_sk);
        registry.add_attestation(aml_attestation).unwrap();
        
        // Compute trust score
        let score = registry.compute_trust_score(user_cm);
        
        // KYC level 3: 50 * 3 = 150 points, weighted by 100% = 150
        // AML score 85: 100 points, weighted by 50% = 50
        // Total: 200
        assert_eq!(score, 200);
    }
    
    #[test]
    fn test_attestation_aggregator() {
        let mut rng = thread_rng();
        let registry = AttestationRegistry::new();
        let mut aggregator = AttestationAggregator::new();
        
        // Create multiple attestations
        for i in 0..3 {
            let attestation = SignedAttestation::new(
                F::rand(&mut rng),
                AttestationType::Custom {
                    type_id: i,
                    data_hash: F::rand(&mut rng),
                },
                1000 + i as u64,
                1,
                vec![i as u8],
            );
            aggregator.add(attestation);
        }
        
        // Compute aggregate commitment
        let commitment = aggregator.aggregate_commitment();
        
        // Should be deterministic
        let commitment2 = aggregator.aggregate_commitment();
        assert_eq!(commitment, commitment2);
    }
}