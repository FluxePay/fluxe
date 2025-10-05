use ark_bn254::{Bn254, Fr as F};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;

use crate::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
};

/// Circuit types in the Fluxe system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CircuitType {
    Mint,
    Burn,
    Transfer,  // Default 1-in/2-out
    TransferCustom(usize, usize), // (num_inputs, num_outputs)
    ObjectUpdate,
}

impl CircuitType {
    /// Get a string identifier for file naming
    pub fn identifier(&self) -> String {
        match self {
            CircuitType::Mint => "Mint".to_string(),
            CircuitType::Burn => "Burn".to_string(),
            CircuitType::Transfer => "Transfer_1_2".to_string(), // Default
            CircuitType::TransferCustom(i, o) => format!("Transfer_{}_{}", i, o),
            CircuitType::ObjectUpdate => "ObjectUpdate".to_string(),
        }
    }
}

/// Trusted setup parameters for a circuit
#[derive(Clone)]
pub struct TrustedSetup {
    pub proving_key: ProvingKey<Bn254>,
    pub verifying_key: VerifyingKey<Bn254>,
}

impl TrustedSetup {
    /// Save setup parameters to files
    pub fn save_to_files(&self, dir: &Path, circuit_type: CircuitType) -> Result<(), std::io::Error> {
        fs::create_dir_all(dir)?;
        
        let pk_path = dir.join(format!("{}_pk.bin", circuit_type.identifier()));
        let vk_path = dir.join(format!("{}_vk.bin", circuit_type.identifier()));
        
        // Save proving key
        let pk_file = File::create(pk_path)?;
        let mut pk_writer = BufWriter::new(pk_file);
        self.proving_key.serialize_compressed(&mut pk_writer)
            .map_err(std::io::Error::other)?;
        pk_writer.flush()?;
        
        // Save verifying key
        let vk_file = File::create(vk_path)?;
        let mut vk_writer = BufWriter::new(vk_file);
        self.verifying_key.serialize_compressed(&mut vk_writer)
            .map_err(std::io::Error::other)?;
        vk_writer.flush()?;
        
        Ok(())
    }
    
    /// Load setup parameters from files
    pub fn load_from_files(dir: &Path, circuit_type: CircuitType) -> Result<Self, std::io::Error> {
        let pk_path = dir.join(format!("{}_pk.bin", circuit_type.identifier()));
        let vk_path = dir.join(format!("{}_vk.bin", circuit_type.identifier()));
        
        // Load proving key
        let pk_file = File::open(pk_path)?;
        let mut pk_reader = BufReader::new(pk_file);
        let proving_key = ProvingKey::deserialize_compressed(&mut pk_reader)
            .map_err(std::io::Error::other)?;
        
        // Load verifying key
        let vk_file = File::open(vk_path)?;
        let mut vk_reader = BufReader::new(vk_file);
        let verifying_key = VerifyingKey::deserialize_compressed(&mut vk_reader)
            .map_err(std::io::Error::other)?;
        
        Ok(Self {
            proving_key,
            verifying_key,
        })
    }
}

/// Setup manager for all circuits
pub struct SetupManager {
    setups: std::collections::HashMap<CircuitType, TrustedSetup>,
}

impl Default for SetupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SetupManager {
    /// Create a new setup manager
    pub fn new() -> Self {
        Self {
            setups: std::collections::HashMap::new(),
        }
    }
    
    /// Generate trusted setup for all circuits
    pub fn generate_all_setups<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), Box<dyn std::error::Error>> {
        // Generate setup for MintCircuit
        println!("Generating trusted setup for MintCircuit...");
        let mint_setup = self.generate_mint_setup(rng)?;
        self.setups.insert(CircuitType::Mint, mint_setup);
        
        // Generate setup for BurnCircuit
        println!("Generating trusted setup for BurnCircuit...");
        let burn_setup = self.generate_burn_setup(rng)?;
        self.setups.insert(CircuitType::Burn, burn_setup);
        
        // Generate setup for TransferCircuit
        println!("Generating trusted setup for TransferCircuit...");
        let transfer_setup = self.generate_transfer_setup(rng)?;
        self.setups.insert(CircuitType::Transfer, transfer_setup);
        
        // Generate setup for ObjectUpdateCircuit
        println!("Generating trusted setup for ObjectUpdateCircuit...");
        let object_update_setup = self.generate_object_update_setup(rng)?;
        self.setups.insert(CircuitType::ObjectUpdate, object_update_setup);
        
        Ok(())
    }
    
    /// Generate setup for MintCircuit
    pub fn generate_mint_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        
        use fluxe_core::data_structures::{Note, IngressReceipt};
        use fluxe_core::crypto::pedersen::PedersenCommitment;
        
        
        
        // Create dummy circuit for setup
        use fluxe_core::crypto::pedersen::{PedersenParams, PedersenRandomness};
        let params = PedersenParams::setup_value_commitment();
        let value = 1000u64;
        let randomness = F::from(42u64); // Use deterministic non-zero value
        
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        let dummy_note = Note {
            asset_type: 1,
            v_comm,
            owner_addr: F::from(123u64), // Use deterministic value
            psi: [7u8; 32],
            chain_hint: 0,
            compliance_hash: F::from(1u64),
            lineage_hash: F::from(0u64),
            pool_id: 1,
            callbacks_hash: F::from(0u64),
            memo_hash: F::from(0u64),
        };
        
        let note_cm = dummy_note.commitment();
        
        use fluxe_core::merkle::IncrementalTree;
        let mut cmt_tree = IncrementalTree::new(16);
        let mut ingress_tree = IncrementalTree::new(16);
        
        let dummy_circuit = MintCircuit::new(
            vec![dummy_note],
            vec![value],
            vec![randomness],
            IngressReceipt {
                asset_type: 1,
                amount: value.into(),
                beneficiary_cm: note_cm, // Use actual commitment
                nonce: 1,
                aux: F::from(0u64),
            },
            &mut cmt_tree,
            &mut ingress_tree,
        );
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for BurnCircuit
    pub fn generate_burn_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        use ark_ff::UniformRand;
        use fluxe_core::data_structures::{Note, ExitReceipt};
        use fluxe_core::crypto::pedersen::{PedersenCommitment, PedersenParams, PedersenRandomness};
        use fluxe_core::merkle::{IncrementalTree, SortedTree};
        use crate::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
        
        // Use consistent deterministic values for setup
        let params = PedersenParams::setup_value_commitment();
        let value = 500u64;
        let randomness = F::from(42u64); // Non-zero deterministic value
        
        let v_comm = PedersenCommitment::commit(
            &params,
            value,
            &PedersenRandomness { r: randomness },
        );
        
        // Generate consistent owner key and address using circuit-compatible method
        let owner_sk = F::from(123u64);
        let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
        let (owner_pk_x, owner_pk_y) = get_pk_coords_circuit_compatible(owner_sk);
        
        // Generate nullifier key
        let nk = F::from(456u64);
        
        let dummy_note = Note {
            asset_type: 1,
            v_comm,
            owner_addr,
            psi: [7u8; 32],
            chain_hint: 0,
            compliance_hash: F::from(1u64),
            lineage_hash: F::from(1u64),
            pool_id: 1,
            callbacks_hash: F::from(1u64),
            memo_hash: F::from(0u64),
        };
        
        // Generate nullifier for consistency
        let nk = F::rand(rng);
        let nf_in = dummy_note.nullifier(&nk);
        
        // Build actual trees for proper proofs
        let mut cmt_tree = IncrementalTree::new(16);
        let cm = dummy_note.commitment();
        cmt_tree.append(cm);
        let cm_path = cmt_tree.get_proof(cm).unwrap();
        
        // Build NFT tree with sentinel and get non-membership proof
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64)); // Sentinel
        let nft_root_old = nft_tree.root();
        let nf_nonmembership = nft_tree.prove_non_membership(nf_in).unwrap();
        
        // Get insert witness
        let nf_insert_witness_core = nft_tree.insert_with_witness(nf_in).unwrap();
        let nf_insert_witness = crate::gadgets::sorted_insert::SortedInsertWitness {
            target: nf_insert_witness_core.target,
            range_proof: nf_insert_witness_core.range_proof,
            new_leaf: nf_insert_witness_core.new_leaf,
            updated_pred_leaf: nf_insert_witness_core.updated_pred_leaf,
            new_leaf_path: nf_insert_witness_core.new_leaf_path,
            pred_update_path: nf_insert_witness_core.pred_update_path,
            height: nf_insert_witness_core.height,
        };
        let nft_root_new = nft_tree.root();
        
        // Build exit tree
        let exit_receipt = ExitReceipt::new(1, value.into(), nf_in, 1);
        let mut exit_tree = IncrementalTree::new(16);
        let exit_root_old = exit_tree.root();
        exit_tree.append(exit_receipt.hash());
        let exit_append_witness = exit_tree.generate_append_witness(exit_receipt.hash());
        let exit_root_new = exit_tree.root();
        
        let dummy_circuit = BurnCircuit {
            note_in: dummy_note.clone(),
            value_in: value,
            value_randomness_in: randomness,
            owner_sk,
            owner_pk_x,
            owner_pk_y,
            nk,
            cm_path,
            nf_nonmembership: Some(nf_nonmembership),
            nf_insert_witness: Some(nf_insert_witness),
            exit_receipt,
            exit_append_witness,
            cmt_root: cmt_tree.root(),
            nft_root_old,
            nft_root_new,
            exit_root_old,
            exit_root_new,
            asset_type: 1,
            amount: value.into(),
            nf_in,
        };
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for TransferCircuit
    pub fn generate_transfer_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        
        use fluxe_core::data_structures::Note;
        use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
        use fluxe_core::merkle::{IncrementalTree, SortedTree};
        use fluxe_core::crypto::poseidon_hash;
        use crate::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
        use crate::gadgets::sorted_insert::SortedInsertWitness;
        
        // Setup parameters
        let params = PedersenParams::setup_value_commitment();
        let num_inputs = 1;
        let num_outputs = 2;  // Match common case of payment + change
        
        // Build CMT tree
        let mut cmt_tree = IncrementalTree::new(16);
        
        // Build NFT tree with sentinel
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64)); // Sentinel
        let nft_root_old = nft_tree.root();
        
        // Create input notes with proper owner authentication
        let mut notes_in = Vec::new();
        let mut values_in = Vec::new();
        let mut value_randomness_in = Vec::new();
        let mut owner_sks = Vec::new();
        let mut owner_pks = Vec::new();
        let mut nks = Vec::new();
        let mut cm_paths = Vec::new();
        let mut nf_list = Vec::new();
        let mut nf_nonmembership_proofs = Vec::new();
        let mut nf_insert_witnesses = Vec::new();
        
        for i in 0..num_inputs {
            let value = 500u64;
            let randomness = F::from(42u64 + i as u64);
            let v_comm = PedersenCommitment::commit(
                &params,
                value,
                &PedersenRandomness { r: randomness },
            );
            
            let owner_sk = F::from(123u64);
            let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
            let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
            
            let nk = F::from(456u64);
            let psi_bytes = [7u8 + i as u8; 32];
            
            let mut note = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
            note.compliance_hash = F::from(1u64);
            note.callbacks_hash = F::from(1u64);
            note.lineage_hash = F::from(1u64);
            note.memo_hash = F::from(0u64);
            
            let cm = note.commitment();
            cmt_tree.append(cm);
            let path = cmt_tree.get_path(0).unwrap();
            
            let nf = note.nullifier(&nk);
            
            notes_in.push(note);
            values_in.push(value);
            value_randomness_in.push(randomness);
            owner_sks.push(owner_sk);
            owner_pks.push((pk_x, pk_y));
            nks.push(nk);
            cm_paths.push(path);
            nf_list.push(nf);
        }
        
        // Generate non-membership proofs for nullifiers
        for nf in &nf_list {
            let nm_proof = nft_tree.prove_non_membership(*nf).unwrap();
            nf_nonmembership_proofs.push(Some(nm_proof));
        }
        
        // Generate insert witnesses
        for nf in &nf_list {
            let insert_witness_core = nft_tree.insert_with_witness(*nf).unwrap();
            let insert_witness = SortedInsertWitness {
                target: insert_witness_core.target,
                range_proof: insert_witness_core.range_proof,
                new_leaf: insert_witness_core.new_leaf,
                updated_pred_leaf: insert_witness_core.updated_pred_leaf,
                new_leaf_path: insert_witness_core.new_leaf_path,
                pred_update_path: insert_witness_core.pred_update_path,
                height: insert_witness_core.height,
            };
            nf_insert_witnesses.push(insert_witness);
        }
        
        let cmt_root_old = cmt_tree.root();
        let nft_root_new = nft_tree.root();
        
        // Create output notes
        let mut notes_out = Vec::new();
        let mut values_out = Vec::new();
        let mut value_randomness_out = Vec::new();
        let mut cm_list = Vec::new();
        let mut cmt_appends_out = Vec::new();
        
        let total_value: u64 = values_in.iter().sum();
        let fee = 10u64;
        let value_per_output = (total_value - fee) / num_outputs as u64;
        
        for i in 0..num_outputs {
            let randomness = F::from(1000u64 + i as u64);
            let v_comm = PedersenCommitment::commit(
                &params,
                value_per_output,
                &PedersenRandomness { r: randomness },
            );
            
            let recipient_sk = F::from(2000u64 + i as u64);
            let recipient_addr = compute_owner_address_circuit_compatible(recipient_sk);
            
            // Compute lineage hash for output note
            let parent_lineages: Vec<F> = notes_in.iter()
                .map(|n| n.lineage_hash)
                .collect();
            let mut lineage_input = parent_lineages;
            lineage_input.push(F::from(i as u64));
            let expected_lineage = poseidon_hash(&lineage_input);
            
            let mut note = Note::new(1, v_comm, recipient_addr, [0u8; 32], 1);
            note.compliance_hash = F::from(1u64);
            note.callbacks_hash = F::from(1u64);
            note.lineage_hash = expected_lineage;
            note.memo_hash = F::from(0u64);
            
            let cm = note.commitment();
            let append_witness = cmt_tree.generate_append_witness(cm);
            cmt_appends_out.push(append_witness);
            cmt_tree.append(cm);
            
            notes_out.push(note);
            values_out.push(value_per_output);
            value_randomness_out.push(randomness);
            cm_list.push(cm);
        }
        
        let cmt_root_new = cmt_tree.root();
        
        let dummy_circuit = TransferCircuit {
            notes_in,
            values_in,
            value_randomness_in,
            notes_out,
            values_out,
            value_randomness_out,
            nks,
            owner_sks,
            owner_pks,
            cm_paths,
            nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
            sanctions_nm_proofs_in: vec![None; num_inputs],
            sanctions_nm_proofs_out: vec![None; num_outputs],
            cmt_paths_out: vec![],
            nf_nonmembership: nf_nonmembership_proofs,
            source_pool_policies: vec![],
            dest_pool_policies: vec![],
            pool_policy_paths: vec![],
            cmt_appends_out,
            nf_insert_witnesses,
            cmt_root_old,
            cmt_root_new,
            nft_root_old,
            nft_root_new,
            sanctions_root: F::from(999999u64),
            pool_rules_root: F::from(888888u64),
            nf_list,
            cm_list,
            fee: fee.into(),
        };
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for TransferCircuit with custom input/output counts
    pub fn generate_transfer_setup_custom<R: RngCore + CryptoRng>(&self, rng: &mut R, num_inputs: usize, num_outputs: usize) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        
        use fluxe_core::data_structures::Note;
        use fluxe_core::crypto::pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness};
        use fluxe_core::merkle::{IncrementalTree, SortedTree};
        use fluxe_core::crypto::poseidon_hash;
        use crate::utils::ec_helpers::{compute_owner_address_circuit_compatible, get_pk_coords_circuit_compatible};
        use crate::gadgets::sorted_insert::SortedInsertWitness;
        
        // Setup parameters
        let params = PedersenParams::setup_value_commitment();
        
        // Build CMT tree
        let mut cmt_tree = IncrementalTree::new(16);
        
        // Build NFT tree with sentinel
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64)); // Sentinel
        let nft_root_old = nft_tree.root();
        
        // Create input notes with proper owner authentication
        let mut notes_in = Vec::new();
        let mut values_in = Vec::new();
        let mut value_randomness_in = Vec::new();
        let mut owner_sks = Vec::new();
        let mut owner_pks = Vec::new();
        let mut nks = Vec::new();
        let mut cm_paths = Vec::new();
        let mut nf_list = Vec::new();
        let mut nf_nonmembership_proofs = Vec::new();
        let mut nf_insert_witnesses = Vec::new();
        
        for i in 0..num_inputs {
            let value = 500u64;
            let randomness = F::from(42u64 + i as u64);
            let v_comm = PedersenCommitment::commit(
                &params,
                value,
                &PedersenRandomness { r: randomness },
            );
            
            let owner_sk = F::from(123u64);
            let owner_addr = compute_owner_address_circuit_compatible(owner_sk);
            let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);
            
            let nk = F::from(456u64);
            let psi_bytes = [7u8 + i as u8; 32];
            
            let mut note = Note::new(1, v_comm, owner_addr, psi_bytes, 1);
            note.compliance_hash = F::from(1u64);
            note.callbacks_hash = F::from(1u64);
            note.lineage_hash = F::from(1u64);
            note.memo_hash = F::from(0u64);
            
            let cm = note.commitment();
            cmt_tree.append(cm);
            let path = cmt_tree.get_path(i).unwrap();
            
            let nf = note.nullifier(&nk);
            
            notes_in.push(note);
            values_in.push(value);
            value_randomness_in.push(randomness);
            owner_sks.push(owner_sk);
            owner_pks.push((pk_x, pk_y));
            nks.push(nk);
            cm_paths.push(path);
            nf_list.push(nf);
        }
        
        // Generate non-membership proofs for nullifiers
        for nf in &nf_list {
            let nm_proof = nft_tree.prove_non_membership(*nf).unwrap();
            nf_nonmembership_proofs.push(Some(nm_proof));
        }
        
        // Generate insert witnesses
        for nf in &nf_list {
            let insert_witness_core = nft_tree.insert_with_witness(*nf).unwrap();
            let insert_witness = SortedInsertWitness {
                target: insert_witness_core.target,
                range_proof: insert_witness_core.range_proof,
                new_leaf: insert_witness_core.new_leaf,
                updated_pred_leaf: insert_witness_core.updated_pred_leaf,
                new_leaf_path: insert_witness_core.new_leaf_path,
                pred_update_path: insert_witness_core.pred_update_path,
                height: insert_witness_core.height,
            };
            nf_insert_witnesses.push(insert_witness);
        }
        
        let cmt_root_old = cmt_tree.root();
        let nft_root_new = nft_tree.root();
        
        // Create output notes
        let mut notes_out = Vec::new();
        let mut values_out = Vec::new();
        let mut value_randomness_out = Vec::new();
        let mut cm_list = Vec::new();
        let mut cmt_appends_out = Vec::new();
        
        let total_value: u64 = values_in.iter().sum();
        let fee = 10u64;
        let value_per_output = (total_value - fee) / num_outputs as u64;
        
        for i in 0..num_outputs {
            let randomness = F::from(1000u64 + i as u64);
            let v_comm = PedersenCommitment::commit(
                &params,
                value_per_output,
                &PedersenRandomness { r: randomness },
            );
            
            let recipient_sk = F::from(2000u64 + i as u64);
            let recipient_addr = compute_owner_address_circuit_compatible(recipient_sk);
            
            // Compute lineage hash for output note
            let parent_lineages: Vec<F> = notes_in.iter()
                .map(|n| n.lineage_hash)
                .collect();
            let mut lineage_input = parent_lineages;
            lineage_input.push(F::from(i as u64));
            let expected_lineage = poseidon_hash(&lineage_input);
            
            let mut note = Note::new(1, v_comm, recipient_addr, [0u8; 32], 1);
            note.compliance_hash = F::from(1u64);
            note.callbacks_hash = F::from(1u64);
            note.lineage_hash = expected_lineage;
            note.memo_hash = F::from(0u64);
            
            let cm = note.commitment();
            let append_witness = cmt_tree.generate_append_witness(cm);
            cmt_appends_out.push(append_witness);
            cmt_tree.append(cm);
            
            notes_out.push(note);
            values_out.push(value_per_output);
            value_randomness_out.push(randomness);
            cm_list.push(cm);
        }
        
        let cmt_root_new = cmt_tree.root();
        
        let dummy_circuit = TransferCircuit {
            notes_in,
            values_in,
            value_randomness_in,
            notes_out,
            values_out,
            value_randomness_out,
            nks,
            owner_sks,
            owner_pks,
            cm_paths,
            nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
            sanctions_nm_proofs_in: vec![None; num_inputs],
            sanctions_nm_proofs_out: vec![None; num_outputs],
            cmt_paths_out: vec![],
            nf_nonmembership: nf_nonmembership_proofs,
            source_pool_policies: vec![],
            dest_pool_policies: vec![],
            pool_policy_paths: vec![],
            cmt_appends_out,
            nf_insert_witnesses,
            cmt_root_old,
            cmt_root_new,
            nft_root_old,
            nft_root_new,
            sanctions_root: F::from(999999u64),
            pool_rules_root: F::from(888888u64),
            nf_list,
            cm_list,
            fee: 10u64.into(),
        };
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for ObjectUpdateCircuit
    pub fn generate_object_update_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        
        use fluxe_core::data_structures::{ComplianceState, ZkObject};
        use fluxe_core::merkle::{IncrementalTree, SortedTree};
        
        // Create states
        let state_old = ComplianceState::new_verified(1);
        let mut state_new = state_old.clone();
        state_new.level = 2;
        state_new.risk_score = 50;
        
        // Create objects
        let obj_old = ZkObject {
            state_hash: state_old.hash(),
            serial: 1,
            cb_head_hash: F::from(0u64),
        };
        
        let obj_new = ZkObject {
            state_hash: state_new.hash(),
            serial: 2,
            cb_head_hash: F::from(0u64),
        };
        
        // Build object tree
        let mut obj_tree = IncrementalTree::new(16);
        let obj_old_cm = obj_old.commitment_with_randomness(&F::from(42u64));
        obj_tree.append(obj_old_cm);
        let obj_path_old = obj_tree.get_path(0).unwrap();
        let obj_root_old = obj_tree.root();
        
        // Get append witness for new object
        let obj_new_cm = obj_new.commitment_with_randomness(&F::from(43u64));
        let obj_append_witness = obj_tree.generate_append_witness(obj_new_cm);
        obj_tree.append(obj_new_cm);
        let obj_root_new = obj_tree.root();
        
        // Build callback tree with sentinel
        let mut cb_tree = SortedTree::new(16);
        let _ = cb_tree.insert(F::from(0u64)); // Sentinel
        let cb_root = cb_tree.root();
        
        let dummy_circuit = ObjectUpdateCircuit {
            obj_old,
            state_old,
            obj_new,
            state_new,
            callback_entry: None,
            callback_invocation: None,
            callback_signature: None,
            cb_path: None,
            cb_nonmembership: None,
            obj_path_old,
            obj_append_witness: Some(obj_append_witness),
            obj_old_randomness: F::from(42u64),
            obj_new_randomness: F::from(43u64),
            decrypt_key: None,
            obj_root_old,
            obj_root_new,
            cb_root,
            current_time: 1000,
        };
        
        let (proving_key, verifying_key) = Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Get setup for a specific circuit type
    pub fn get_setup(&self, circuit_type: CircuitType) -> Option<&TrustedSetup> {
        self.setups.get(&circuit_type)
    }
    
    /// Save all setups to directory
    pub fn save_all(&self, dir: &Path) -> Result<(), std::io::Error> {
        for (circuit_type, setup) in &self.setups {
            setup.save_to_files(dir, *circuit_type)?;
        }
        Ok(())
    }
    
    /// Load all setups from directory
    pub fn load_all(&mut self, dir: &Path) -> Result<(), std::io::Error> {
        for circuit_type in &[
            CircuitType::Mint,
            CircuitType::Burn,
            CircuitType::Transfer,
            CircuitType::ObjectUpdate,
        ] {
            let setup = TrustedSetup::load_from_files(dir, *circuit_type)?;
            self.setups.insert(*circuit_type, setup);
        }
        Ok(())
    }
}

/// Generate a deterministic RNG for testing
pub fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(12345)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    #[ignore] // Slow test - generates cryptographic setup for all circuits
    fn test_trusted_setup_generation() {
        let mut rng = test_rng();
        let mut manager = SetupManager::new();
        
        // Generate all setups
        manager.generate_all_setups(&mut rng).unwrap();
        
        // Verify all setups were generated
        assert!(manager.get_setup(CircuitType::Mint).is_some());
        assert!(manager.get_setup(CircuitType::Burn).is_some());
        assert!(manager.get_setup(CircuitType::Transfer).is_some());
        assert!(manager.get_setup(CircuitType::ObjectUpdate).is_some());
        
        println!("✓ Trusted setup generation test passed");
    }
    
    #[test]
    fn test_setup_serialization() {
        let mut rng = test_rng();
        let manager = SetupManager::new();
        
        // Generate mint setup
        let setup = manager.generate_mint_setup(&mut rng).unwrap();
        
        // Save to temp directory
        let temp_dir = PathBuf::from("/tmp/fluxe_test_setup");
        fs::create_dir_all(&temp_dir).unwrap();
        setup.save_to_files(&temp_dir, CircuitType::Mint).unwrap();
        
        // Load back
        let loaded_setup = TrustedSetup::load_from_files(&temp_dir, CircuitType::Mint).unwrap();
        
        // Verify keys match (simplified check)
        assert_eq!(
            setup.verifying_key.alpha_g1,
            loaded_setup.verifying_key.alpha_g1
        );
        
        // Cleanup
        fs::remove_dir_all(temp_dir).ok();
        
        println!("✓ Setup serialization test passed");
    }
}