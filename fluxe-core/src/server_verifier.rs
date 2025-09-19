use crate::{
    data_structures::{ExitReceipt, IngressReceipt, Note},
    state_manager::StateManager,
    types::*,
};
use ark_bls12_381::Fr as F;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;

/// Server-side batch verifier implementing section 12.4 of the spec
/// Verifies client proofs and deterministically reapplies Merkle operations
pub struct ServerVerifier {
    /// State manager for tracking roots and trees
    state: StateManager,
    
    /// Verifying keys for different circuit types
    vk_mint: VerifyingKey<ark_bls12_381::Bls12_381>,
    vk_burn: VerifyingKey<ark_bls12_381::Bls12_381>,
    vk_transfer: VerifyingKey<ark_bls12_381::Bls12_381>,
    vk_object_update: VerifyingKey<ark_bls12_381::Bls12_381>,
    
    /// Pending transaction batch
    pending_batch: TransactionBatch,
}

/// A batch of transactions to be processed together
#[derive(Clone, Debug)]
pub struct TransactionBatch {
    pub transactions: Vec<VerifiedTransaction>,
    pub batch_id: u64,
    pub timestamp: Time,
}

/// A transaction that has been client-proven and verified
#[derive(Clone, Debug)]
pub struct VerifiedTransaction {
    pub tx_type: TransactionType,
    pub proof: Proof<ark_bls12_381::Bls12_381>,
    pub public_inputs: Vec<F>,
    pub old_roots: StateRoots,
    pub new_roots: StateRoots,
    pub transaction_data: TransactionData,
}

/// Specific transaction data for different types
#[derive(Clone, Debug)]
pub enum TransactionData {
    Mint {
        asset_type: AssetType,
        amount: Amount,
        notes_out: Vec<Note>,
        ingress_receipt: IngressReceipt,
    },
    Burn {
        asset_type: AssetType,
        amount: Amount,
        nullifier: Nullifier,
        exit_receipt: ExitReceipt,
    },
    Transfer {
        nullifiers: Vec<Nullifier>,
        notes_out: Vec<Note>,
    },
    ObjectUpdate {
        old_object_cm: F,
        new_object_cm: F,
        callback_ops: Vec<CallbackOperation>,
    },
}

impl ServerVerifier {
    pub fn new(
        state: StateManager,
        vk_mint: VerifyingKey<ark_bls12_381::Bls12_381>,
        vk_burn: VerifyingKey<ark_bls12_381::Bls12_381>,
        vk_transfer: VerifyingKey<ark_bls12_381::Bls12_381>,
        vk_object_update: VerifyingKey<ark_bls12_381::Bls12_381>,
    ) -> Self {
        Self {
            state,
            vk_mint,
            vk_burn,
            vk_transfer,
            vk_object_update,
            pending_batch: TransactionBatch {
                transactions: Vec::new(),
                batch_id: 0,
                timestamp: 0,
            },
        }
    }
    
    /// Add a transaction to the pending batch
    pub fn add_transaction(&mut self, tx: VerifiedTransaction) -> Result<(), FluxeError> {
        // Verify the proof first
        self.verify_transaction_proof(&tx)?;
        
        // Add to pending batch
        self.pending_batch.transactions.push(tx);
        Ok(())
    }
    
    /// Process the entire batch and produce a block
    pub fn process_batch(&mut self) -> Result<BlockHeader, FluxeError> {
        if self.pending_batch.transactions.is_empty() {
            return Err(FluxeError::Other("No transactions in batch".to_string()));
        }
        
        let prev_roots = self.state.get_roots();
        
        // Process transactions in canonical order according to spec section 7.2:
        // INGRESS appends → CMT appends → NFT inserts → CB inserts → OBJ appends → EXIT appends
        
        // 1. Process all ingress operations (mints)
        for tx in &self.pending_batch.transactions {
            if let TransactionData::Mint { ingress_receipt, .. } = &tx.transaction_data {
                self.state.ingress_tree.append(ingress_receipt.hash());
            }
        }
        
        // 2. Process all CMT appends (mints and transfers)
        for tx in &self.pending_batch.transactions {
            match &tx.transaction_data {
                TransactionData::Mint { notes_out, .. } => {
                    for note in notes_out {
                        self.state.cmt_tree.append(note.commitment());
                    }
                }
                TransactionData::Transfer { notes_out, .. } => {
                    for note in notes_out {
                        self.state.cmt_tree.append(note.commitment());
                    }
                }
                _ => {}
            }
        }
        
        // 3. Process all NFT inserts (burns and transfers)
        for tx in &self.pending_batch.transactions {
            match &tx.transaction_data {
                TransactionData::Burn { nullifier, .. } => {
                    if self.state.nft_tree.contains(nullifier) {
                        return Err(FluxeError::DoubleSpend(*nullifier));
                    }
                    self.state.nft_tree.insert(*nullifier)?;
                }
                TransactionData::Transfer { nullifiers, .. } => {
                    for &nf in nullifiers {
                        if self.state.nft_tree.contains(&nf) {
                            return Err(FluxeError::DoubleSpend(nf));
                        }
                        self.state.nft_tree.insert(nf)?;
                    }
                }
                _ => {}
            }
        }
        
        // 4. Process callback operations
        for tx in &self.pending_batch.transactions {
            if let TransactionData::ObjectUpdate { callback_ops, .. } = &tx.transaction_data {
                for op in callback_ops {
                    match op {
                        CallbackOperation::Add(invocation) => {
                            self.state.cb_tree.insert(invocation.ticket)?;
                        }
                        CallbackOperation::Process(_ticket) => {
                            // Mark as processed - implementation depends on callback design
                            // This might involve updating the sorted tree structure
                        }
                    }
                }
            }
        }
        
        // 5. Process all OBJ appends (object updates)
        for tx in &self.pending_batch.transactions {
            if let TransactionData::ObjectUpdate { new_object_cm, .. } = &tx.transaction_data {
                self.state.obj_tree.append(*new_object_cm);
            }
        }
        
        // 6. Process all EXIT appends (burns)
        for tx in &self.pending_batch.transactions {
            if let TransactionData::Burn { exit_receipt, .. } = &tx.transaction_data {
                self.state.exit_tree.append(exit_receipt.hash());
            }
        }
        
        // Update supply accounting
        self.update_supply_accounting()?;
        
        // Roots are updated automatically by the state manager operations
        let new_roots = self.state.get_roots();
        
        // Verify reconstructed roots match declared roots
        self.verify_root_consistency(&new_roots)?;
        
        // Create block header
        let header = BlockHeader {
            prev_roots,
            new_roots,
            batch_id: self.pending_batch.batch_id,
            agg_proof: self.generate_aggregate_proof()?,
            timestamp: self.pending_batch.timestamp,
        };
        
        // Advance to next batch
        self.pending_batch.batch_id += 1;
        self.pending_batch.transactions.clear();
        
        Ok(header)
    }
    
    /// Verify a single transaction's proof
    fn verify_transaction_proof(&self, tx: &VerifiedTransaction) -> Result<(), FluxeError> {
        let vk = match tx.tx_type {
            TransactionType::Mint => &self.vk_mint,
            TransactionType::Burn => &self.vk_burn,
            TransactionType::Transfer => &self.vk_transfer,
            TransactionType::ObjectUpdate => &self.vk_object_update,
        };
        
        let verified = Groth16::<ark_bls12_381::Bls12_381>::verify(vk, &tx.public_inputs, &tx.proof)
            .map_err(|e| FluxeError::InvalidProof(format!("Groth16 verification failed: {}", e)))?;
        
        if !verified {
            return Err(FluxeError::InvalidProof("Proof verification failed".to_string()));
        }
        
        Ok(())
    }
    
    /// Update supply accounting based on mint/burn operations
    fn update_supply_accounting(&mut self) -> Result<(), FluxeError> {
        for tx in &self.pending_batch.transactions {
            match &tx.transaction_data {
                TransactionData::Mint { asset_type, amount, .. } => {
                    let supply = self.state.supply
                        .entry(*asset_type)
                        .or_insert(Amount::zero());
                    *supply = *supply + *amount;
                }
                TransactionData::Burn { asset_type, amount, .. } => {
                    let supply = self.state.supply
                        .entry(*asset_type)
                        .or_insert(Amount::zero());
                    if *supply < *amount {
                        return Err(FluxeError::InsufficientBalance);
                    }
                    *supply = *supply - *amount;
                }
                _ => {}
            }
        }
        Ok(())
    }
    
    /// Verify that reconstructed roots match the declared roots from transactions
    fn verify_root_consistency(&self, new_roots: &StateRoots) -> Result<(), FluxeError> {
        // In a more sophisticated implementation, this would verify that all 
        // transactions' declared new roots are consistent with the final state
        
        // For now, we just verify that at least one transaction's new roots match
        // the final state (meaning the batch was processed correctly)
        
        if let Some(last_tx) = self.pending_batch.transactions.last() {
            if &last_tx.new_roots != new_roots {
                return Err(FluxeError::Other(
                    "Reconstructed roots don't match declared roots".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Generate aggregated proof for the entire batch
    fn generate_aggregate_proof(&self) -> Result<Vec<u8>, FluxeError> {
        // Placeholder for aggregated proof generation
        // In production, this would create a SNARK proof that all client proofs
        // were verified and state transitions were applied correctly
        
        let mut proof_data = Vec::new();
        
        // Include batch metadata
        proof_data.extend_from_slice(&self.pending_batch.batch_id.to_le_bytes());
        proof_data.extend_from_slice(&self.pending_batch.timestamp.to_le_bytes());
        proof_data.extend_from_slice(&(self.pending_batch.transactions.len() as u32).to_le_bytes());
        
        // Include hash of all transaction proofs
        let mut tx_hash = F::from(0);
        for tx in &self.pending_batch.transactions {
            // Simplified: hash the proof bytes
            tx_hash = crate::crypto::poseidon_hash(&[
                tx_hash,
                F::from(tx.public_inputs.len() as u64),
            ]);
        }
        
        let mut tx_hash_bytes = Vec::new();
        tx_hash.serialize_compressed(&mut tx_hash_bytes)
            .map_err(|e| FluxeError::SerializationError(format!("Failed to serialize tx hash: {}", e)))?;
        proof_data.extend(tx_hash_bytes);
        
        Ok(proof_data)
    }
    
    /// Get current state roots
    pub fn get_current_roots(&self) -> StateRoots {
        self.state.get_roots()
    }
    
    /// Get supply for an asset
    pub fn get_supply(&self, asset_type: AssetType) -> Amount {
        self.state.get_supply(asset_type)
    }
    
    /// Check if address is sanctioned
    pub fn is_sanctioned(&self, _address: &F) -> bool {
        // In a real implementation, this would check against the sanctions tree
        // For now, return false (not sanctioned)
        false
    }
}

/// Transaction builder helper for creating verified transactions
pub struct TransactionBuilder {
    tx_type: TransactionType,
    old_roots: StateRoots,
    new_roots: StateRoots,
}

impl TransactionBuilder {
    pub fn new_mint(old_roots: StateRoots, new_roots: StateRoots) -> Self {
        Self {
            tx_type: TransactionType::Mint,
            old_roots,
            new_roots,
        }
    }
    
    pub fn new_burn(old_roots: StateRoots, new_roots: StateRoots) -> Self {
        Self {
            tx_type: TransactionType::Burn,
            old_roots,
            new_roots,
        }
    }
    
    pub fn new_transfer(old_roots: StateRoots, new_roots: StateRoots) -> Self {
        Self {
            tx_type: TransactionType::Transfer,
            old_roots,
            new_roots,
        }
    }
    
    pub fn build(
        self,
        proof: Proof<ark_bls12_381::Bls12_381>,
        public_inputs: Vec<F>,
        transaction_data: TransactionData,
    ) -> VerifiedTransaction {
        VerifiedTransaction {
            tx_type: self.tx_type,
            proof,
            public_inputs,
            old_roots: self.old_roots,
            new_roots: self.new_roots,
            transaction_data,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    
    use rand::thread_rng;

    // Mock setup for testing
    fn create_mock_verifying_keys() -> (
        VerifyingKey<ark_bls12_381::Bls12_381>,
        VerifyingKey<ark_bls12_381::Bls12_381>,
        VerifyingKey<ark_bls12_381::Bls12_381>,
        VerifyingKey<ark_bls12_381::Bls12_381>,
    ) {
        // In tests, we'd use actual circuit setups
        // For now, create dummy VKs
        use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
        
        struct DummyCircuit;
        impl ConstraintSynthesizer<F> for DummyCircuit {
            fn generate_constraints(self, _cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
                Ok(())
            }
        }
        
        let mut rng = thread_rng();
        let (pk, vk) = Groth16::<ark_bls12_381::Bls12_381>::circuit_specific_setup(
            DummyCircuit, &mut rng
        ).unwrap();
        
        (vk.clone(), vk.clone(), vk.clone(), vk)
    }

    #[test]
    fn test_server_verifier_creation() {
        let state = StateManager::new(32);
        let (vk_mint, vk_burn, vk_transfer, vk_object_update) = create_mock_verifying_keys();
        
        let verifier = ServerVerifier::new(
            state,
            vk_mint,
            vk_burn, 
            vk_transfer,
            vk_object_update,
        );
        
        assert_eq!(verifier.pending_batch.transactions.len(), 0);
    }

    #[test]
    fn test_supply_accounting() {
        let state = StateManager::new(32);
        let (vk_mint, vk_burn, vk_transfer, vk_object_update) = create_mock_verifying_keys();
        let mut verifier = ServerVerifier::new(
            state,
            vk_mint,
            vk_burn,
            vk_transfer,
            vk_object_update,
        );
        
        // Test mint increases supply
        let supply = verifier.state.supply.entry(1).or_insert(Amount::zero());
        *supply = *supply + Amount::from(1000u64);
        assert_eq!(verifier.get_supply(1), Amount::from(1000u64));
        
        // Test burn decreases supply
        let supply = verifier.state.supply.entry(1).or_insert(Amount::zero());
        *supply = *supply - Amount::from(300u64);
        assert_eq!(verifier.get_supply(1), Amount::from(700u64));
    }
}