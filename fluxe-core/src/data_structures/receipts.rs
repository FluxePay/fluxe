use crate::crypto::poseidon_hash;
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Using ark_serialize for cryptographic types

/// Ingress receipt for deposits/mints
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IngressReceipt {
    /// Asset type being minted
    pub asset_type: AssetType,
    
    /// Amount being minted
    pub amount: Amount,
    
    /// Commitment(s) to notes minted in response
    pub beneficiary_cm: F,
    
    /// Nonce for uniqueness
    pub nonce: u64,
    
    /// Auxiliary data binding to external deposit reference
    pub aux: F,
}

impl IngressReceipt {
    pub fn new(asset_type: AssetType, amount: Amount, beneficiary_cm: F, nonce: u64) -> Self {
        Self {
            asset_type,
            amount,
            beneficiary_cm,
            nonce,
            aux: F::from(0),
        }
    }

    /// Compute hash of this receipt
    pub fn hash(&self) -> F {
        poseidon_hash(&[
            F::from(self.asset_type as u64),
            self.amount.to_field(),
            self.beneficiary_cm,
            F::from(self.nonce),
            self.aux,
        ])
    }

    /// Set auxiliary data (e.g., external transaction hash)
    pub fn set_aux(&mut self, aux_data: &[u8]) {
        self.aux = crate::utils::bytes_to_field(aux_data);
    }
}

/// Exit receipt for withdrawals/burns
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ExitReceipt {
    /// Asset type being burned
    pub asset_type: AssetType,
    
    /// Amount being burned
    pub amount: Amount,
    
    /// Nullifier proving the burn of an input note
    pub burned_nf: Nullifier,
    
    /// Nonce for uniqueness
    pub nonce: u64,
    
    /// Auxiliary data binding to external withdrawal reference
    pub aux: F,
}

impl ExitReceipt {
    pub fn new(asset_type: AssetType, amount: Amount, burned_nf: Nullifier, nonce: u64) -> Self {
        Self {
            asset_type,
            amount,
            burned_nf,
            nonce,
            aux: F::from(0),
        }
    }

    /// Compute hash of this receipt
    pub fn hash(&self) -> F {
        poseidon_hash(&[
            F::from(self.asset_type as u64),
            self.amount.to_field(),
            self.burned_nf,
            F::from(self.nonce),
            self.aux,
        ])
    }

    /// Set auxiliary data (e.g., destination address)
    pub fn set_aux(&mut self, aux_data: &[u8]) {
        self.aux = crate::utils::bytes_to_field(aux_data);
    }
}

/// Bundle of receipts for a block
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ReceiptBundle {
    /// Ingress receipts (deposits)
    pub ingress: Vec<IngressReceipt>,
    
    /// Exit receipts (withdrawals)
    pub exit: Vec<ExitReceipt>,
    
    /// Block number
    pub block_num: u64,
    
    /// Timestamp
    pub timestamp: Time,
}

impl ReceiptBundle {
    pub fn new(block_num: u64, timestamp: Time) -> Self {
        Self {
            ingress: Vec::new(),
            exit: Vec::new(),
            block_num,
            timestamp,
        }
    }

    /// Add an ingress receipt
    pub fn add_ingress(&mut self, receipt: IngressReceipt) {
        self.ingress.push(receipt);
    }

    /// Add an exit receipt
    pub fn add_exit(&mut self, receipt: ExitReceipt) {
        self.exit.push(receipt);
    }

    /// Calculate net supply change
    pub fn net_supply_change(&self, asset_type: AssetType) -> i128 {
        let minted: i128 = self.ingress
            .iter()
            .filter(|r| r.asset_type == asset_type)
            .map(|r| r.amount.as_i128())
            .sum();
            
        let burned: i128 = self.exit
            .iter()
            .filter(|r| r.asset_type == asset_type)
            .map(|r| r.amount.as_i128())
            .sum();
            
        minted - burned
    }

    /// Compute commitment to all receipts
    pub fn commitment(&self) -> F {
        let mut ingress_hash = F::from(0);
        for receipt in &self.ingress {
            ingress_hash = poseidon_hash(&[ingress_hash, receipt.hash()]);
        }
        
        let mut exit_hash = F::from(0);
        for receipt in &self.exit {
            exit_hash = poseidon_hash(&[exit_hash, receipt.hash()]);
        }
        
        poseidon_hash(&[
            ingress_hash,
            exit_hash,
            F::from(self.block_num),
            F::from(self.timestamp),
        ])
    }
}

/// Receipt for tracking compliance attestations
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationReceipt {
    /// User identifier (commitment to user record)
    pub user_cm: F,
    
    /// Type of attestation
    pub attestation_type: AttestationType,
    
    /// Timestamp of attestation
    pub timestamp: Time,
    
    /// Attestation data hash
    pub data_hash: F,
    
    /// Provider signature
    pub provider_sig: Vec<u8>,
}

/// Types of compliance attestations
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// Sanctions check cleared
    SanctionsClear { duration: Time },
    
    /// AML check passed
    AMLPass { score: RiskScore },
    
    /// KYC verification completed
    KYCComplete { level: u8 },
    
    /// Transaction monitoring alert cleared
    AlertCleared { alert_id: u64 },
}

impl AttestationReceipt {
    pub fn new(user_cm: F, attestation_type: AttestationType, timestamp: Time) -> Self {
        Self {
            user_cm,
            attestation_type,
            timestamp,
            data_hash: F::from(0),
            provider_sig: vec![0u8; 64], // Placeholder
        }
    }

    /// Compute hash for binding into compliance_hash
    pub fn hash(&self) -> F {
        let type_field = match &self.attestation_type {
            AttestationType::SanctionsClear { duration } => {
                poseidon_hash(&[F::from(1), F::from(*duration)])
            }
            AttestationType::AMLPass { score } => {
                poseidon_hash(&[F::from(2), F::from(*score as u64)])
            }
            AttestationType::KYCComplete { level } => {
                poseidon_hash(&[F::from(3), F::from(*level as u64)])
            }
            AttestationType::AlertCleared { alert_id } => {
                poseidon_hash(&[F::from(4), F::from(*alert_id)])
            }
        };
        
        poseidon_hash(&[
            self.user_cm,
            type_field,
            F::from(self.timestamp),
            self.data_hash,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_ingress_receipt() {
        let mut rng = thread_rng();
        let beneficiary = F::rand(&mut rng);
        
        let receipt = IngressReceipt::new(1, Amount::from(1000u128), beneficiary, 123);
        let hash1 = receipt.hash();
        let hash2 = receipt.hash();
        assert_eq!(hash1, hash2); // Hash should be deterministic
    }

    #[test]
    fn test_exit_receipt() {
        let mut rng = thread_rng();
        let nullifier = F::rand(&mut rng);
        
        let receipt = ExitReceipt::new(1, Amount::from(500u128), nullifier, 456);
        let hash1 = receipt.hash();
        let hash2 = receipt.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_receipt_bundle() {
        let mut rng = thread_rng();
        let mut bundle = ReceiptBundle::new(1, 1000);
        
        // Add some receipts
        let ingress = IngressReceipt::new(1, Amount::from(1000u128), F::rand(&mut rng), 1);
        let exit = ExitReceipt::new(1, Amount::from(300u128), F::rand(&mut rng), 2);
        
        bundle.add_ingress(ingress);
        bundle.add_exit(exit);
        
        // Check net supply change
        let net = bundle.net_supply_change(1);
        assert_eq!(net, 700); // 1000 minted - 300 burned
    }

    #[test]
    fn test_attestation_receipt() {
        let mut rng = thread_rng();
        let user_cm = F::rand(&mut rng);
        
        let attestation = AttestationReceipt::new(
            user_cm,
            AttestationType::KYCComplete { level: 2 },
            1000,
        );
        
        let hash = attestation.hash();
        assert_ne!(hash, F::from(0));
    }
}