//! Mock Sequencer for E2E Testing
//!
//! This module provides a simplified sequencer that:
//! 1. Manages global and per-chain state
//! 2. Batches transactions
//! 3. Tracks state transitions
//! 4. Provides witness data for circuits

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::Fr as F;
use ark_ff::UniformRand;
use rand::thread_rng;

use fluxe_core::crypto::poseidon_hash;
use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
use fluxe_core::crypto::ec_auth::compute_ec_public_key;
use fluxe_core::data_structures::{Note, IngressReceipt, ExitReceipt};
use fluxe_core::merkle::{
    IncrementalTree, SortedTree, TreeParams, MerklePath, RangePath, AppendWitness, SortedLeaf,
};
use fluxe_core::types::{Amount, ChainId, AssetType};
use fluxe_core::state_manager::NonMembershipProof;

use crate::{CircuitType, ProofResult};

/// Chain identifier constants
pub const CHAIN_ETHEREUM: ChainId = 1;
pub const CHAIN_SOLANA: ChainId = 501;
pub const CHAIN_BASE: ChainId = 8453;

/// State roots for a batch
#[derive(Clone, Debug)]
pub struct StateRoots {
    pub cmt_root: F,
    pub nft_root: F,
    pub obj_root: F,
    pub cb_root: F,
}

impl StateRoots {
    pub fn to_bytes(&self) -> [u8; 128] {
        [0u8; 128] // Simplified serialization
    }

    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(self.cmt_root.to_string().as_bytes());
        hasher.update(self.nft_root.to_string().as_bytes());
        hasher.update(self.obj_root.to_string().as_bytes());
        hasher.update(self.cb_root.to_string().as_bytes());
        hasher.finalize().into()
    }
}

/// Convert NonMembershipProof to RangePath
fn nm_proof_to_range_path(proof: NonMembershipProof, target: F) -> RangePath {
    RangePath {
        low_leaf: proof.low_leaf,
        low_path: proof.low_path,
        target,
    }
}

/// Per-chain state
#[derive(Clone)]
pub struct ChainState {
    pub chain_id: ChainId,
    /// Deposits on this chain
    pub ingress_tree: IncrementalTree,
    /// Withdrawals to this chain
    pub exit_tree: IncrementalTree,
    /// Per-asset supply tracking
    pub deposited: HashMap<AssetType, Amount>,
    pub withdrawn: HashMap<AssetType, Amount>,
    /// Pending ingress receipts (not yet processed)
    pub pending_ingress: Vec<IngressReceipt>,
}

impl ChainState {
    pub fn new(chain_id: ChainId, tree_height: usize) -> Self {
        Self {
            chain_id,
            ingress_tree: IncrementalTree::new(tree_height),
            exit_tree: IncrementalTree::new(tree_height),
            deposited: HashMap::new(),
            withdrawn: HashMap::new(),
            pending_ingress: Vec::new(),
        }
    }

    pub fn record_deposit(&mut self, asset: AssetType, amount: Amount) {
        let current = self.deposited.entry(asset).or_insert(Amount::from(0u64));
        *current = Amount(current.0 + amount.0);
    }

    pub fn record_withdrawal(&mut self, asset: AssetType, amount: Amount) {
        let current = self.withdrawn.entry(asset).or_insert(Amount::from(0u64));
        *current = Amount(current.0 + amount.0);
    }

    pub fn net_balance(&self, asset: AssetType) -> i128 {
        let deposited = self.deposited.get(&asset).map(|a| a.0).unwrap_or(0) as i128;
        let withdrawn = self.withdrawn.get(&asset).map(|a| a.0).unwrap_or(0) as i128;
        deposited - withdrawn
    }
}

/// Global state manager
pub struct MockSequencer {
    /// Global commitment tree (all notes)
    pub cmt_tree: IncrementalTree,
    /// Global nullifier tree (spent notes)
    pub nft_tree: SortedTree,
    /// Global object tree (compliance objects)
    pub obj_tree: IncrementalTree,
    /// Global callback tree
    pub cb_tree: SortedTree,
    /// Sanctions tree (addresses)
    pub sanctions_tree: SortedTree,
    /// Pool rules tree
    pub pool_rules_tree: IncrementalTree,
    /// Per-chain state
    pub chains: HashMap<ChainId, ChainState>,
    /// Tree parameters
    pub tree_params: TreeParams,
    /// Pedersen parameters
    pub pedersen_params: PedersenParams,
    /// Current batch
    pub current_batch_id: u64,
    /// Transaction history
    pub tx_history: Vec<TransactionRecord>,
    /// Committed notes by hash
    pub notes_by_hash: HashMap<F, NoteRecord>,
}

/// Record of a committed note
#[derive(Clone, Debug)]
pub struct NoteRecord {
    pub note: Note,
    pub value: u64,
    pub randomness: F,
    pub nk: F,
    pub owner_sk: F,
    pub owner_pk: (F, F),
    pub source_chain: ChainId,
}

/// Record of a processed transaction
#[derive(Clone, Debug)]
pub struct TransactionRecord {
    pub batch_id: u64,
    pub circuit_type: CircuitType,
    pub old_roots: StateRoots,
    pub new_roots: StateRoots,
    pub proof: Option<ProofResult>,
    pub timestamp: u64,
}

impl MockSequencer {
    pub fn new(tree_height: usize) -> Self {
        let tree_params = TreeParams::new(tree_height);

        let mut sequencer = Self {
            cmt_tree: IncrementalTree::new(tree_height),
            nft_tree: SortedTree::new(tree_height),
            obj_tree: IncrementalTree::new(tree_height),
            cb_tree: SortedTree::new(tree_height),
            sanctions_tree: SortedTree::new(tree_height),
            pool_rules_tree: IncrementalTree::new(tree_height),
            chains: HashMap::new(),
            tree_params,
            pedersen_params: PedersenParams::setup_value_commitment(),
            current_batch_id: 0,
            tx_history: Vec::new(),
            notes_by_hash: HashMap::new(),
        };

        // Initialize supported chains
        sequencer.chains.insert(CHAIN_ETHEREUM, ChainState::new(CHAIN_ETHEREUM, tree_height));
        sequencer.chains.insert(CHAIN_SOLANA, ChainState::new(CHAIN_SOLANA, tree_height));
        sequencer.chains.insert(CHAIN_BASE, ChainState::new(CHAIN_BASE, tree_height));

        sequencer
    }

    /// Get current state roots
    pub fn get_roots(&self) -> StateRoots {
        StateRoots {
            cmt_root: self.cmt_tree.root(),
            nft_root: self.nft_tree.root(),
            obj_root: self.obj_tree.root(),
            cb_root: self.cb_tree.root(),
        }
    }

    /// Get chain-specific roots
    pub fn get_chain_roots(&self, chain_id: ChainId) -> Option<(F, F)> {
        self.chains.get(&chain_id).map(|chain| {
            (chain.ingress_tree.root(), chain.exit_tree.root())
        })
    }

    /// Create a deposit (simulates L1 deposit event)
    pub fn create_deposit(
        &mut self,
        source_chain: ChainId,
        asset_type: AssetType,
        amount: u64,
        recipient_addr: F,
    ) -> Result<DepositResult, String> {
        let chain = self.chains.get_mut(&source_chain)
            .ok_or("Unknown chain")?;

        let mut rng = thread_rng();

        // Create note for recipient
        let randomness = F::rand(&mut rng);
        let v_comm = PedersenCommitment::commit(
            &self.pedersen_params,
            amount,
            &PedersenRandomness { r: randomness },
        );

        let nk = F::rand(&mut rng);
        let owner_sk = F::rand(&mut rng);
        // Derive public key from secret key using EC scalar multiplication
        let (owner_pk_x, owner_pk_y) = compute_ec_public_key(owner_sk);
        let owner_addr = poseidon_hash(&[owner_pk_x, owner_pk_y]);

        let mut note = Note::new(
            asset_type,
            v_comm.clone(),
            owner_addr,
            [1u8; 32], // psi
            1, // pool_id
        );
        // Set non-zero compliance_hash and callbacks_hash (required by circuit constraints)
        note.compliance_hash = F::from(1u64);
        note.callbacks_hash = F::from(1u64);
        note.lineage_hash = F::from(1u64);

        // Create ingress receipt
        let cm = note.commitment();
        let beneficiary_cm = poseidon_hash(&[F::from(0u64), cm]);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let ingress = IngressReceipt::new(
            source_chain,
            asset_type,
            Amount::from(amount as u128),
            beneficiary_cm,
            nonce,
        );

        // Get old roots
        let cmt_root_old = self.cmt_tree.root();
        let ingress_root_old = chain.ingress_tree.root();

        // Get append witnesses
        let cmt_append = self.cmt_tree.generate_append_witness(cm);
        let ingress_hash = ingress.hash();
        let ingress_append = chain.ingress_tree.generate_append_witness(ingress_hash);

        // Apply state changes
        self.cmt_tree.append(cm);
        chain.ingress_tree.append(ingress_hash);
        chain.record_deposit(asset_type, Amount::from(amount as u128));
        chain.pending_ingress.push(ingress.clone());

        // Get new roots
        let cmt_root_new = self.cmt_tree.root();
        let ingress_root_new = chain.ingress_tree.root();

        // Store note record
        let note_record = NoteRecord {
            note: note.clone(),
            value: amount,
            randomness,
            nk,
            owner_sk,
            owner_pk: (owner_pk_x, owner_pk_y),
            source_chain,
        };
        self.notes_by_hash.insert(cm, note_record.clone());

        Ok(DepositResult {
            note,
            note_record,
            ingress,
            cmt_append,
            ingress_append,
            cmt_root_old,
            cmt_root_new,
            ingress_root_old,
            ingress_root_new,
        })
    }

    /// Create a transfer between notes
    pub fn create_transfer(
        &mut self,
        input_cm: F,
        output_value: u64,
        output_recipient: F,
        fee: u64,
    ) -> Result<TransferResult, String> {
        let note_record = self.notes_by_hash.get(&input_cm)
            .cloned()
            .ok_or("Note not found")?;

        if note_record.value < output_value + fee {
            return Err("Insufficient balance".to_string());
        }

        let mut rng = thread_rng();

        // Get input witness
        let cm_path = self.cmt_tree
            .get_proof(input_cm)
            .ok_or("Input note not in tree")?;

        let nf_in = note_record.note.nullifier(&note_record.nk);

        // Check nullifier not spent
        let nf_nm_proof = self.nft_tree
            .get_non_membership_proof(nf_in)
            .ok_or("Nullifier already spent")?;
        let nf_nm = nm_proof_to_range_path(nf_nm_proof, nf_in);

        // Get NFT insert witness
        let nf_insert = self.nft_tree
            .export_insert_witness(nf_in)
            .map_err(|e| format!("NFT insert failed: {}", e))?;

        // Create output note
        let out_randomness = F::rand(&mut rng);
        let out_v_comm = PedersenCommitment::commit(
            &self.pedersen_params,
            output_value,
            &PedersenRandomness { r: out_randomness },
        );

        let out_nk = F::rand(&mut rng);
        let out_owner_sk = F::rand(&mut rng);
        // Derive public key from secret key using EC scalar multiplication
        let (out_owner_pk_x, out_owner_pk_y) = compute_ec_public_key(out_owner_sk);
        let out_owner_addr = poseidon_hash(&[out_owner_pk_x, out_owner_pk_y]);

        let mut output_note = Note::new(
            note_record.note.asset_type,
            out_v_comm.clone(),
            out_owner_addr,
            [2u8; 32], // new psi
            1, // pool_id
        );
        // Set non-zero compliance_hash and callbacks_hash (required by circuit constraints)
        output_note.compliance_hash = F::from(1u64);
        output_note.callbacks_hash = F::from(1u64);
        // Compute lineage: poseidon_hash([input_lineage, context])
        // Context is the output index (0 for first output)
        let output_lineage = poseidon_hash(&[note_record.note.lineage_hash, F::from(0u64)]);
        output_note.lineage_hash = output_lineage;

        // Get sanctions proofs
        let sanctions_nm_proof_in = self.sanctions_tree
            .get_non_membership_proof(note_record.note.owner_addr)
            .ok_or("Sender is sanctioned")?;
        let sanctions_nm_in = nm_proof_to_range_path(sanctions_nm_proof_in, note_record.note.owner_addr);

        let sanctions_nm_proof_out = self.sanctions_tree
            .get_non_membership_proof(out_owner_addr)
            .ok_or("Recipient is sanctioned")?;
        let sanctions_nm_out = nm_proof_to_range_path(sanctions_nm_proof_out, out_owner_addr);

        // Get old roots
        let cmt_root_old = self.cmt_tree.root();
        let nft_root_old = self.nft_tree.root();
        let sanctions_root = self.sanctions_tree.root();

        // Get CMT append witness
        let output_cm = output_note.commitment();
        let cmt_append = self.cmt_tree.generate_append_witness(output_cm);

        // Apply state changes
        self.cmt_tree.append(output_cm);
        self.nft_tree.insert(nf_in)
            .map_err(|e| e.to_string())?;

        // Get new roots
        let cmt_root_new = self.cmt_tree.root();
        let nft_root_new = self.nft_tree.root();

        // Store output note
        let output_record = NoteRecord {
            note: output_note.clone(),
            value: output_value,
            randomness: out_randomness,
            nk: out_nk,
            owner_sk: out_owner_sk,
            owner_pk: (out_owner_pk_x, out_owner_pk_y),
            source_chain: note_record.source_chain,
        };
        self.notes_by_hash.insert(output_cm, output_record.clone());

        // Convert insert witness
        let nf_insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
            target: nf_insert.target,
            range_proof: nf_insert.range_proof,
            new_leaf: nf_insert.new_leaf,
            updated_pred_leaf: nf_insert.updated_pred_leaf,
            new_leaf_path: nf_insert.new_leaf_path,
            pred_update_path: nf_insert.pred_update_path,
            height: nf_insert.height,
        };

        Ok(TransferResult {
            input_note: note_record.note.clone(),
            input_record: note_record,
            output_note,
            output_record,
            fee: Amount::from(fee as u128),
            cm_path,
            nf_nm,
            nf_insert: nf_insert_witness,
            sanctions_nm_in,
            sanctions_nm_out,
            cmt_append,
            cmt_root_old,
            cmt_root_new,
            nft_root_old,
            nft_root_new,
            sanctions_root,
            pool_rules_root: F::from(0u64),
        })
    }

    /// Create a withdrawal (burn)
    pub fn create_withdrawal(
        &mut self,
        input_cm: F,
        destination_chain: ChainId,
        amount: u64,
    ) -> Result<WithdrawalResult, String> {
        let note_record = self.notes_by_hash.get(&input_cm)
            .cloned()
            .ok_or("Note not found")?;

        if note_record.value < amount {
            return Err("Insufficient balance".to_string());
        }

        let chain = self.chains.get_mut(&destination_chain)
            .ok_or("Unknown destination chain")?;

        // Get input witness
        let cm_path = self.cmt_tree
            .get_proof(input_cm)
            .ok_or("Input note not in tree")?;

        let nf_in = note_record.note.nullifier(&note_record.nk);

        // Check nullifier not spent
        let nf_nm_proof = self.nft_tree
            .get_non_membership_proof(nf_in)
            .ok_or("Nullifier already spent")?;
        let nf_nm = nm_proof_to_range_path(nf_nm_proof, nf_in);

        // Get NFT insert witness
        let nf_insert = self.nft_tree
            .export_insert_witness(nf_in)
            .map_err(|e| format!("NFT insert failed: {}", e))?;

        // Create exit receipt
        let exit_receipt = ExitReceipt {
            destination_chain,
            asset_type: note_record.note.asset_type,
            amount: Amount::from(amount as u128),
            burned_nf: nf_in,
            nonce: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            aux: F::from(0u64),
        };

        // Get old roots
        let cmt_root = self.cmt_tree.root();
        let nft_root_old = self.nft_tree.root();
        let exit_root_old = chain.exit_tree.root();

        // Get exit append witness
        let exit_hash = exit_receipt.hash();
        let exit_append = chain.exit_tree.generate_append_witness(exit_hash);

        // Apply state changes
        self.nft_tree.insert(nf_in)
            .map_err(|e| e.to_string())?;
        chain.exit_tree.append(exit_hash);
        chain.record_withdrawal(note_record.note.asset_type, Amount::from(amount as u128));

        // Get new roots
        let nft_root_new = self.nft_tree.root();
        let exit_root_new = chain.exit_tree.root();

        // Convert insert witness
        let nf_insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
            target: nf_insert.target,
            range_proof: nf_insert.range_proof,
            new_leaf: nf_insert.new_leaf,
            updated_pred_leaf: nf_insert.updated_pred_leaf,
            new_leaf_path: nf_insert.new_leaf_path,
            pred_update_path: nf_insert.pred_update_path,
            height: nf_insert.height,
        };

        Ok(WithdrawalResult {
            input_note: note_record.note.clone(),
            input_record: note_record,
            exit_receipt,
            cm_path,
            nf_nm,
            nf_insert: nf_insert_witness,
            exit_append,
            cmt_root,
            nft_root_old,
            nft_root_new,
            exit_root_old,
            exit_root_new,
        })
    }

    /// Finalize current batch
    pub fn finalize_batch(&mut self) -> u64 {
        self.current_batch_id += 1;
        self.current_batch_id
    }

    /// Get global supply for an asset
    pub fn global_supply(&self, asset: AssetType) -> Amount {
        let mut total: u128 = 0;
        for chain in self.chains.values() {
            if let Some(deposited) = chain.deposited.get(&asset) {
                total = total.saturating_add(deposited.0);
            }
            if let Some(withdrawn) = chain.withdrawn.get(&asset) {
                total = total.saturating_sub(withdrawn.0);
            }
        }
        Amount(total)
    }

    /// Verify supply invariant
    pub fn verify_supply_invariant(&self) -> Result<(), String> {
        for asset in [1u32, 2, 3] {
            let mut global_deposited: u128 = 0;
            let mut global_withdrawn: u128 = 0;

            for chain in self.chains.values() {
                if let Some(d) = chain.deposited.get(&asset) {
                    global_deposited = global_deposited.saturating_add(d.0);
                }
                if let Some(w) = chain.withdrawn.get(&asset) {
                    global_withdrawn = global_withdrawn.saturating_add(w.0);
                }
            }

            if global_withdrawn > global_deposited {
                return Err(format!(
                    "Supply invariant violated for asset {}: withdrawn {} > deposited {}",
                    asset, global_withdrawn, global_deposited
                ));
            }
        }

        Ok(())
    }
}

/// Result of a deposit operation
#[derive(Clone)]
pub struct DepositResult {
    pub note: Note,
    pub note_record: NoteRecord,
    pub ingress: IngressReceipt,
    pub cmt_append: AppendWitness,
    pub ingress_append: AppendWitness,
    pub cmt_root_old: F,
    pub cmt_root_new: F,
    pub ingress_root_old: F,
    pub ingress_root_new: F,
}

/// Result of a transfer operation
#[derive(Clone)]
pub struct TransferResult {
    pub input_note: Note,
    pub input_record: NoteRecord,
    pub output_note: Note,
    pub output_record: NoteRecord,
    pub fee: Amount,
    pub cm_path: MerklePath,
    pub nf_nm: RangePath,
    pub nf_insert: fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness,
    pub sanctions_nm_in: RangePath,
    pub sanctions_nm_out: RangePath,
    pub cmt_append: AppendWitness,
    pub cmt_root_old: F,
    pub cmt_root_new: F,
    pub nft_root_old: F,
    pub nft_root_new: F,
    pub sanctions_root: F,
    pub pool_rules_root: F,
}

/// Result of a withdrawal operation
#[derive(Clone)]
pub struct WithdrawalResult {
    pub input_note: Note,
    pub input_record: NoteRecord,
    pub exit_receipt: ExitReceipt,
    pub cm_path: MerklePath,
    pub nf_nm: RangePath,
    pub nf_insert: fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness,
    pub exit_append: AppendWitness,
    pub cmt_root: F,
    pub nft_root_old: F,
    pub nft_root_new: F,
    pub exit_root_old: F,
    pub exit_root_new: F,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequencer_creation() {
        let seq = MockSequencer::new(16);
        assert!(seq.chains.contains_key(&CHAIN_ETHEREUM));
        assert!(seq.chains.contains_key(&CHAIN_SOLANA));
    }

    #[test]
    fn test_deposit_creates_note() {
        let mut seq = MockSequencer::new(16);
        let recipient = F::from(12345u64);

        let result = seq.create_deposit(
            CHAIN_ETHEREUM,
            1, // USDC
            1000,
            recipient,
        ).unwrap();

        assert!(seq.notes_by_hash.contains_key(&result.note.commitment()));

        let chain = seq.chains.get(&CHAIN_ETHEREUM).unwrap();
        assert_eq!(chain.deposited.get(&1).unwrap().0, 1000);
    }

    #[test]
    fn test_full_flow() {
        let mut seq = MockSequencer::new(16);
        let recipient = F::from(12345u64);

        // Deposit on Ethereum
        let deposit = seq.create_deposit(
            CHAIN_ETHEREUM,
            1,
            1000,
            recipient,
        ).unwrap();

        // Transfer
        let transfer = seq.create_transfer(
            deposit.note.commitment(),
            900,
            F::from(67890u64),
            100,
        ).unwrap();

        // Withdraw to Solana
        let _withdrawal = seq.create_withdrawal(
            transfer.output_note.commitment(),
            CHAIN_SOLANA,
            900,
        ).unwrap();

        // Verify supply
        seq.verify_supply_invariant().unwrap();

        // Ethereum should have +1000 deposited
        let eth = seq.chains.get(&CHAIN_ETHEREUM).unwrap();
        assert_eq!(eth.deposited.get(&1).unwrap().0, 1000);

        // Solana should have -900 (withdrawn)
        let sol = seq.chains.get(&CHAIN_SOLANA).unwrap();
        assert_eq!(sol.withdrawn.get(&1).unwrap().0, 900);
    }
}
