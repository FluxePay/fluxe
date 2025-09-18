use crate::crypto::{pedersen::PedersenCommitment, poseidon_hash, domain_sep_to_field, DOM_NOTE, DOM_NF};
use crate::types::*;
use ark_bls12_381::Fr as F;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// Using ark_serialize for field element serialization

/// A confidential UTXO note
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Note {
    /// Asset type (e.g., USDC = 1, USDT = 2)
    pub asset_type: AssetType,
    
    /// Pedersen commitment to value with range proof
    pub v_comm: PedersenCommitment,
    
    /// Owner address (Poseidon(pk) or Ethereum address)
    pub owner_addr: AuthAddr,
    
    /// Per-note entropy (32 bytes)
    pub psi: [u8; 32],
    
    /// Target chain or local shard hint
    pub chain_hint: ChainHint,
    
    /// Commitment to compliance metadata
    pub compliance_hash: ComplianceHash,
    
    /// Bounded lineage accumulator (rolling hash)
    pub lineage_hash: LineageHash,
    
    /// Policy pool identifier
    pub pool_id: PoolId,
    
    /// Hash-chain head for pending callbacks embedded in note
    pub callbacks_hash: CallbacksHash,
    
    /// Hash of encrypted memo delivered off-chain
    pub memo_hash: MemoHash,
}

impl Note {
    /// Create a new note
    pub fn new(
        asset_type: AssetType,
        v_comm: PedersenCommitment,
        owner_addr: AuthAddr,
        psi: [u8; 32],
        pool_id: PoolId,
    ) -> Self {
        Self {
            asset_type,
            v_comm,
            owner_addr,
            psi,
            chain_hint: 1, // Default to main chain
            compliance_hash: F::from(0),
            lineage_hash: F::from(0),
            pool_id,
            callbacks_hash: F::from(0),
            memo_hash: F::from(0),
        }
    }

    /// Create a new note with lineage from parent notes
    pub fn new_with_lineage(
        asset_type: AssetType,
        v_comm: PedersenCommitment,
        owner_addr: AuthAddr,
        psi: [u8; 32],
        pool_id: PoolId,
        parent_lineages: &[F],
    ) -> Self {
        // Compute lineage with horizon of 100 transactions
        let lineage_hash = crate::crypto::compute_lineage_hash(parent_lineages, 100, 0);
        
        Self {
            asset_type,
            v_comm,
            owner_addr,
            psi,
            chain_hint: 1,
            compliance_hash: F::from(0),
            lineage_hash,
            pool_id,
            callbacks_hash: F::from(0),
            memo_hash: F::from(0),
        }
    }

    /// Compute the note commitment
    pub fn commitment(&self) -> Commitment {
        let mut input = vec![domain_sep_to_field(DOM_NOTE)];
        input.push(F::from(self.asset_type));
        
        // Serialize Pedersen commitment to field element
        // Convert Fq coordinate to Fr by hashing
        use ark_ff::{BigInteger, PrimeField};
        let v_comm_bytes = self.v_comm.commitment.x.into_bigint().to_bytes_le();
        let v_comm_fr = crate::utils::bytes_to_field(&v_comm_bytes);
        input.push(v_comm_fr);
        
        input.push(self.owner_addr);
        input.push(crate::utils::bytes_to_field(&self.psi));
        input.push(F::from(self.chain_hint));
        input.push(self.compliance_hash);
        input.push(self.lineage_hash);
        input.push(F::from(self.pool_id));
        input.push(self.callbacks_hash);
        input.push(self.memo_hash);
        
        poseidon_hash(&input)
    }

    /// Compute the nullifier for this note
    pub fn nullifier(&self, nk: &F) -> Nullifier {
        let cm = self.commitment();
        let psi_field = crate::utils::bytes_to_field(&self.psi);
        
        let input = vec![
            domain_sep_to_field(DOM_NF),
            *nk,
            psi_field,
            cm,
        ];
        
        poseidon_hash(&input)
    }

    /// Update lineage hash for output notes
    pub fn update_lineage(&mut self, parent_lineages: &[LineageHash], context: &F) {
        let mut input = Vec::new();
        for lineage in parent_lineages {
            input.push(*lineage);
        }
        input.push(*context);
        
        self.lineage_hash = poseidon_hash(&input);
    }
}

/// Nullifier leaf in sorted Merkle tree
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct NullifierLeaf {
    /// The nullifier value
    pub key: Nullifier,
    
    /// Link to next larger key (0 = none)
    pub next_key: Nullifier,
    
    /// Merkle index pointer
    pub next_index: u64,
}

impl NullifierLeaf {
    pub fn new(key: Nullifier) -> Self {
        Self {
            key,
            next_key: F::from(0),
            next_index: 0,
        }
    }

    /// Check if a value is in the gap between this leaf and the next
    pub fn contains_gap(&self, value: &Nullifier) -> bool {
        *value > self.key && (self.next_key == F::from(0) || *value < self.next_key)
    }
}

/// Authentication methods
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// Poseidon address: owner_addr = Poseidon(pk_owner)
    PoseidonKey(F),
    
    /// Ethereum address
    EthereumAddress([u8; 20]),
}

impl AuthMethod {
    /// Convert to field element for use in note
    pub fn to_field(&self) -> AuthAddr {
        match self {
            AuthMethod::PoseidonKey(pk) => poseidon_hash(&[*pk]),
            AuthMethod::EthereumAddress(addr) => {
                let mut bytes = [0u8; 32];
                bytes[..20].copy_from_slice(addr);
                crate::utils::bytes_to_field(&bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::pedersen::{PedersenParams, PedersenRandomness};
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_note_commitment() {
        let mut rng = thread_rng();
        let params = PedersenParams::setup_value_commitment();
        
        let value = 1000u64;
        let randomness = PedersenRandomness::new(&mut rng);
        let v_comm = PedersenCommitment::commit(&params, value, &randomness);
        
        let owner_addr = F::rand(&mut rng);
        let psi = [1u8; 32];
        
        let note = Note::new(1, v_comm, owner_addr, psi, 0);
        let commitment = note.commitment();
        
        // Commitment should be deterministic
        let commitment2 = note.commitment();
        assert_eq!(commitment, commitment2);
    }

    #[test]
    fn test_nullifier() {
        let mut rng = thread_rng();
        let params = PedersenParams::setup_value_commitment();
        
        let value = 1000u64;
        let randomness = PedersenRandomness::new(&mut rng);
        let v_comm = PedersenCommitment::commit(&params, value, &randomness);
        
        let owner_addr = F::rand(&mut rng);
        let nk = F::rand(&mut rng);
        let psi = [1u8; 32];
        
        let note = Note::new(1, v_comm, owner_addr, psi, 0);
        let nullifier = note.nullifier(&nk);
        
        // Different nk should give different nullifier
        let nk2 = F::rand(&mut rng);
        let nullifier2 = note.nullifier(&nk2);
        assert_ne!(nullifier, nullifier2);
    }
}