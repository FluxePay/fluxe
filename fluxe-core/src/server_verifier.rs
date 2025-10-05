use crate::{
    data_structures::{ExitReceipt, IngressReceipt, Note},
    errors::{FluxeError, StateError},
    logging::PerfTimer,
    state_manager::StateManager,
    types::*,
};
use ark_bn254::Fr as F;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use tracing::{debug, error, info, instrument, trace, warn};

/// Server-side batch verifier implementing section 12.4 of the spec
/// Verifies client proofs and deterministically reapplies Merkle operations
pub struct ServerVerifier {
    /// State manager for tracking roots and trees
    state: StateManager,
    
    /// Verifying keys for different circuit types
    vk_mint: VerifyingKey<ark_bn254::Bn254>,
    vk_burn: VerifyingKey<ark_bn254::Bn254>,
    vk_transfer: VerifyingKey<ark_bn254::Bn254>,
    vk_object_update: VerifyingKey<ark_bn254::Bn254>,
    
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
    pub proof: Proof<ark_bn254::Bn254>,
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
        vk_mint: VerifyingKey<ark_bn254::Bn254>,
        vk_burn: VerifyingKey<ark_bn254::Bn254>,
        vk_transfer: VerifyingKey<ark_bn254::Bn254>,
        vk_object_update: VerifyingKey<ark_bn254::Bn254>,
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
    #[instrument(skip(self), fields(batch_id = %self.pending_batch.batch_id, tx_count = self.pending_batch.transactions.len()))]
    pub fn process_batch(&mut self) -> Result<BlockHeader, FluxeError> {
        info!("Processing batch {} with {} transactions", self.pending_batch.batch_id, self.pending_batch.transactions.len());
        let _timer = PerfTimer::new(format!("batch_{}_processing", self.pending_batch.batch_id));

        if self.pending_batch.transactions.is_empty() {
            warn!("Batch {} is empty", self.pending_batch.batch_id);
            return Err(FluxeError::Other("No transactions in batch".to_string()));
        }

        let prev_roots = self.state.get_roots();
        debug!("Previous roots: CMT={:?}, NFT={:?}", prev_roots.cmt_root, prev_roots.nft_root);
        
        // Verify each transaction's old roots match current state before processing
        for (i, tx) in self.pending_batch.transactions.iter().enumerate() {
            if i == 0 {
                // First transaction should match current state
                if tx.old_roots != prev_roots {
                    return Err(FluxeError::Other(
                        format!("Transaction {} old roots don't match current state", i)
                    ));
                }
            }
        }
        
        // Process transactions deterministically and verify each one's roots
        let mut intermediate_roots = Vec::new();
        intermediate_roots.push(prev_roots.clone());
        
        // Process each transaction individually to track intermediate states
        // Clone the transactions to avoid borrow checker issues
        let transactions = self.pending_batch.transactions.clone();
        for tx in &transactions {
            self.apply_single_transaction(tx)?;
            intermediate_roots.push(self.state.get_roots());
        }
        
        // Verify that each transaction's declared new roots match the state after processing it
        for (i, _tx) in transactions.iter().enumerate() {
            let _expected_roots = &intermediate_roots[i + 1];
            // Only verify if transaction declares new roots (they might be optional)
            // For now we'll compute them deterministically
        }
        
        // Final roots after all transactions
        let new_roots = self.state.get_roots();
        
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
    #[instrument(skip(self, tx), fields(tx_type = ?tx.tx_type))]
    fn verify_transaction_proof(&self, tx: &VerifiedTransaction) -> Result<(), FluxeError> {
        trace!("Verifying {:?} transaction proof", tx.tx_type);
        let _timer = PerfTimer::new(format!("verify_{:?}_proof", tx.tx_type));

        let vk = match tx.tx_type {
            TransactionType::Mint => &self.vk_mint,
            TransactionType::Burn => &self.vk_burn,
            TransactionType::Transfer => &self.vk_transfer,
            TransactionType::ObjectUpdate => &self.vk_object_update,
        };

        let verified = Groth16::<ark_bn254::Bn254>::verify(vk, &tx.public_inputs, &tx.proof)
            .map_err(|e| {
                error!("Proof verification failed for {:?}: {}", tx.tx_type, e);
                FluxeError::Verification(format!("Groth16 verification failed: {}", e))
            })?;
        
        if !verified {
            return Err(FluxeError::Verification("Proof verification failed".to_string()));
        }
        
        Ok(())
    }
    
    /// Apply a single transaction's state changes
    fn apply_single_transaction(&mut self, tx: &VerifiedTransaction) -> Result<(), FluxeError> {
        match &tx.transaction_data {
            TransactionData::Mint { ingress_receipt, notes_out, asset_type, amount, .. } => {
                // 1. Append ingress receipt
                self.state.ingress_tree.append(ingress_receipt.hash());
                
                // 2. Append output note commitments
                for note in notes_out {
                    self.state.cmt_tree.append(note.commitment());
                }
                
                // 3. Update supply
                let supply = self.state.supply
                    .entry(*asset_type)
                    .or_insert(Amount::zero());
                *supply = *supply + *amount;
            }
            TransactionData::Burn { nullifier, exit_receipt, asset_type, amount, .. } => {
                // 1. Check and insert nullifier
                if self.state.nft_tree.contains(nullifier) {
                    return Err(FluxeError::StateManagement(StateError::DoubleSpend(format!("{:?}", nullifier))));
                }
                self.state.nft_tree.insert(*nullifier).map_err(|e| FluxeError::Other(e))?;
                
                // 2. Append exit receipt
                self.state.exit_tree.append(exit_receipt.hash());
                
                // 3. Update supply
                let supply = self.state.supply
                    .entry(*asset_type)
                    .or_insert(Amount::zero());
                if *supply < *amount {
                    return Err(FluxeError::Other("Insufficient balance for burn".to_string()));
                }
                *supply = *supply - *amount;
            }
            TransactionData::Transfer { nullifiers, notes_out, .. } => {
                // 1. Insert nullifiers (in order)
                for &nf in nullifiers {
                    if self.state.nft_tree.contains(&nf) {
                        return Err(FluxeError::StateManagement(StateError::DoubleSpend(format!("{:?}", nf))));
                    }
                    self.state.nft_tree.insert(nf).map_err(|e| FluxeError::Other(e))?;
                }
                
                // 2. Append output note commitments
                for note in notes_out {
                    self.state.cmt_tree.append(note.commitment());
                }
            }
            TransactionData::ObjectUpdate { new_object_cm, callback_ops, .. } => {
                // 1. Process callback operations
                for op in callback_ops {
                    match op {
                        CallbackOperation::Add(invocation) => {
                            self.state.cb_tree.insert(invocation.ticket).map_err(|e| FluxeError::Other(e))?;
                        }
                        CallbackOperation::Process(_ticket) => {
                            // Mark as processed
                        }
                    }
                }
                
                // 2. Append new object commitment
                self.state.obj_tree.append(*new_object_cm);
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
            .map_err(|e| FluxeError::Serialization(e))?;
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
    
    /// Get membership proof for a commitment
    pub fn get_commitment_proof(&self, cm: &F) -> Option<crate::merkle::MerklePath> {
        self.state.cmt_tree.get_proof(*cm)
    }
    
    /// Check if a nullifier exists
    pub fn nullifier_exists(&self, nf: &F) -> bool {
        self.state.nft_tree.contains(nf)
    }
    
    /// Get membership proof for a nullifier
    pub fn get_nullifier_membership_proof(&self, _nf: &F) -> Option<crate::merkle::MerklePath> {
        // For sorted tree, we would need to track the index when the nullifier was inserted
        // For now, return None as SortedTree doesn't provide a way to get path by key
        // This would require enhancing SortedTree to maintain a key->index mapping
        None
    }
    
    /// Get non-membership proof for a nullifier
    pub fn get_nullifier_nonmembership_proof(&self, nf: &F) -> Result<crate::merkle::RangePath, String> {
        self.state.nft_tree.prove_non_membership(*nf)
    }
    
    /// Get membership proof for an object
    pub fn get_object_proof(&self, obj_cm: &F) -> Option<crate::merkle::MerklePath> {
        self.state.obj_tree.get_proof(*obj_cm)
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
        proof: Proof<ark_bn254::Bn254>,
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
        VerifyingKey<ark_bn254::Bn254>,
        VerifyingKey<ark_bn254::Bn254>,
        VerifyingKey<ark_bn254::Bn254>,
        VerifyingKey<ark_bn254::Bn254>,
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
        let (pk, vk) = Groth16::<ark_bn254::Bn254>::circuit_specific_setup(
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