use ark_bn254::{Bn254, Fr as F};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::collections::HashMap;

use crate::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
    object_update::ObjectUpdateCircuit,
};

/// Type alias for chain identifiers (e.g., 1 for Ethereum, 501 for Solana)
pub type ChainId = u32;

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

    /// Check if this circuit is chain-specific or global
    /// Chain-specific circuits (Mint, Burn) require chain_id
    /// Global circuits (Transfer, ObjectUpdate) work across all chains
    pub fn is_chain_specific(&self) -> bool {
        matches!(self, CircuitType::Mint | CircuitType::Burn)
    }
}

/// Configuration for circuit setup loading
#[derive(Debug, Clone)]
pub struct CircuitSetupConfig {
    /// Base directory for circuit keys
    pub base_dir: String,
    /// Key format version for compatibility tracking
    pub key_version: u32,
    /// Whether to allow loading global circuits when chain-specific expected
    pub allow_global_fallback: bool,
}

impl Default for CircuitSetupConfig {
    fn default() -> Self {
        Self {
            base_dir: "target/keys".to_string(),
            key_version: 1,
            allow_global_fallback: true,
        }
    }
}

/// Trusted setup parameters for a circuit
#[derive(Clone)]
pub struct TrustedSetup {
    /// Chain ID this setup is for (None for global circuits)
    pub chain_id: Option<ChainId>,
    /// Circuit type
    pub circuit_type: CircuitType,
    /// Proving key
    pub proving_key: ProvingKey<Bn254>,
    /// Verifying key
    pub verifying_key: VerifyingKey<Bn254>,
}

impl TrustedSetup {
    /// Create a new TrustedSetup for a specific circuit and optional chain
    pub fn new(
        chain_id: Option<ChainId>,
        circuit_type: CircuitType,
        proving_key: ProvingKey<Bn254>,
        verifying_key: VerifyingKey<Bn254>,
    ) -> Self {
        Self {
            chain_id,
            circuit_type,
            proving_key,
            verifying_key,
        }
    }

    /// Determine the directory path for this setup
    /// Returns: chain_{id}/{circuit}_pk.bin for chain-specific circuits
    ///          global/{circuit}_pk.bin for global circuits
    pub fn get_directory_path(&self, base_dir: &Path) -> std::io::Result<std::path::PathBuf> {
        let dir = if let Some(cid) = self.chain_id {
            base_dir.join(format!("chain_{}", cid))
        } else {
            base_dir.join("global")
        };
        Ok(dir)
    }

    /// Get the proving key filename for this setup
    pub fn get_pk_filename(&self) -> String {
        format!("v1_{}_pk.bin", self.circuit_type.identifier())
    }

    /// Get the verifying key filename for this setup
    pub fn get_vk_filename(&self) -> String {
        format!("v1_{}_vk.bin", self.circuit_type.identifier())
    }

    /// Save setup parameters to files with new directory structure
    /// Creates: base_dir/chain_{id}/{circuit}_pk.bin or base_dir/global/{circuit}_pk.bin
    pub fn save_setup(&self, base_dir: &Path) -> Result<(), std::io::Error> {
        let dir = self.get_directory_path(base_dir)?;
        fs::create_dir_all(&dir)?;

        let pk_path = dir.join(self.get_pk_filename());
        let vk_path = dir.join(self.get_vk_filename());

        // Save proving key
        let pk_file = File::create(&pk_path)?;
        let mut pk_writer = BufWriter::new(pk_file);
        self.proving_key.serialize_compressed(&mut pk_writer)
            .map_err(std::io::Error::other)?;
        pk_writer.flush()?;

        // Save verifying key
        let vk_file = File::create(&vk_path)?;
        let mut vk_writer = BufWriter::new(vk_file);
        self.verifying_key.serialize_compressed(&mut vk_writer)
            .map_err(std::io::Error::other)?;
        vk_writer.flush()?;

        Ok(())
    }

    /// Save setup parameters to files (legacy single-directory format)
    /// This is kept for backward compatibility
    #[deprecated(
        since = "0.2.0",
        note = "use save_setup() with base_dir instead; automatically handles chain-specific paths"
    )]
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

    /// Load setup parameters from files (legacy single-directory format)
    /// This is kept for backward compatibility
    #[deprecated(
        since = "0.2.0",
        note = "use load_setup() with base_dir and chain_id instead"
    )]
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
            chain_id: None,
            circuit_type,
            proving_key,
            verifying_key,
        })
    }

    /// Load setup parameters from files with new directory structure
    pub fn load_setup(
        base_dir: &Path,
        chain_id: Option<ChainId>,
        circuit_type: CircuitType,
    ) -> Result<Self, std::io::Error> {
        let dir = if let Some(cid) = chain_id {
            base_dir.join(format!("chain_{}", cid))
        } else {
            base_dir.join("global")
        };

        let pk_filename = format!("v1_{}_pk.bin", circuit_type.identifier());
        let vk_filename = format!("v1_{}_vk.bin", circuit_type.identifier());

        let pk_path = dir.join(pk_filename);
        let vk_path = dir.join(vk_filename);

        // Load proving key
        let pk_file = File::open(&pk_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to open proving key at {}: {}", pk_path.display(), e),
            )
        })?;
        let mut pk_reader = BufReader::new(pk_file);
        let proving_key = ProvingKey::deserialize_compressed(&mut pk_reader)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize proving key: {}", e),
            ))?;

        // Load verifying key
        let vk_file = File::open(&vk_path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("Failed to open verifying key at {}: {}", vk_path.display(), e),
            )
        })?;
        let mut vk_reader = BufReader::new(vk_file);
        let verifying_key = VerifyingKey::deserialize_compressed(&mut vk_reader)
            .map_err(|e| std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize verifying key: {}", e),
            ))?;

        Ok(Self {
            chain_id,
            circuit_type,
            proving_key,
            verifying_key,
        })
    }
}

/// Circuit setup manager for multi-chain key management
/// Stores and manages trusted setup keys for different chains and circuit types
pub struct CircuitSetupManager {
    /// Map of (ChainId, CircuitType) to TrustedSetup
    /// For global circuits, ChainId is None
    setups: HashMap<(Option<ChainId>, CircuitType), TrustedSetup>,
    /// Configuration for setup loading/saving
    config: CircuitSetupConfig,
}

/// Legacy alias for backward compatibility
pub type SetupManager = CircuitSetupManager;

impl Default for CircuitSetupManager {
    fn default() -> Self {
        Self::new(CircuitSetupConfig::default())
    }
}

impl CircuitSetupManager {
    /// Create a new circuit setup manager with default configuration
    pub fn new(config: CircuitSetupConfig) -> Self {
        Self {
            setups: HashMap::new(),
            config,
        }
    }

    /// Create a new circuit setup manager with default configuration
    pub fn with_default_config() -> Self {
        Self::new(CircuitSetupConfig::default())
    }

    /// Generate all global circuit setups (Transfer, ObjectUpdate)
    pub fn generate_global_circuits<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating global circuits (shared across all chains)");
        println!("--------------------------------------------------");

        // Generate setup for TransferCircuit
        println!("Generating trusted setup for TransferCircuit (global)...");
        let transfer_setup = self.generate_transfer_setup(rng)?;
        let transfer_ts = TrustedSetup::new(None, CircuitType::Transfer, transfer_setup.proving_key, transfer_setup.verifying_key);
        self.setups.insert((None, CircuitType::Transfer), transfer_ts);

        // Generate setup for ObjectUpdateCircuit
        println!("Generating trusted setup for ObjectUpdateCircuit (global)...");
        let object_update_setup = self.generate_object_update_setup(rng)?;
        let object_update_ts = TrustedSetup::new(None, CircuitType::ObjectUpdate, object_update_setup.proving_key, object_update_setup.verifying_key);
        self.setups.insert((None, CircuitType::ObjectUpdate), object_update_ts);

        println!("Global circuits generated successfully");
        Ok(())
    }

    /// Generate chain-specific circuit setups (Mint, Burn) for a specific chain
    pub fn generate_chain_circuits<R: RngCore + CryptoRng>(
        &mut self,
        chain_id: ChainId,
        rng: &mut R,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("Generating chain-specific circuits for chain_id={}", chain_id);
        println!("--------------------------------------------------");

        // Generate setup for MintCircuit
        println!("Generating trusted setup for MintCircuit (chain_{})...", chain_id);
        let mint_setup = self.generate_mint_setup(rng)?;
        let mint_ts = TrustedSetup::new(Some(chain_id), CircuitType::Mint, mint_setup.proving_key, mint_setup.verifying_key);
        self.setups.insert((Some(chain_id), CircuitType::Mint), mint_ts);

        // Generate setup for BurnCircuit
        println!("Generating trusted setup for BurnCircuit (chain_{})...", chain_id);
        let burn_setup = self.generate_burn_setup(rng)?;
        let burn_ts = TrustedSetup::new(Some(chain_id), CircuitType::Burn, burn_setup.proving_key, burn_setup.verifying_key);
        self.setups.insert((Some(chain_id), CircuitType::Burn), burn_ts);

        println!("Chain-specific circuits for chain_id={} generated successfully", chain_id);
        Ok(())
    }

    /// Generate trusted setup for all circuits for a specific chain
    pub fn generate_all_setups_for_chain<R: RngCore + CryptoRng>(
        &mut self,
        chain_id: ChainId,
        rng: &mut R,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.generate_chain_circuits(chain_id, rng)?;
        self.generate_global_circuits(rng)?;
        Ok(())
    }

    /// Generate trusted setup for all circuits (legacy method, generates for all chains)
    /// This is kept for backward compatibility but now generates only global circuits
    pub fn generate_all_setups<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<(), Box<dyn std::error::Error>> {
        self.generate_global_circuits(rng)
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
                source_chain: 1, // Default test chain ID
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
            chain_id: None, // Circuits are chain-agnostic
            circuit_type: CircuitType::Mint,
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
        let exit_receipt = ExitReceipt::new(1, 1, value.into(), nf_in, 1);
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
            chain_id: None, // Circuits are chain-agnostic
            circuit_type: CircuitType::Burn,
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
            chain_id: None, // Circuits are chain-agnostic
            circuit_type: CircuitType::Transfer,
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
            chain_id: None, // Circuits are chain-agnostic
            circuit_type: CircuitType::Transfer,
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
            chain_id: None, // Circuits are chain-agnostic
            circuit_type: CircuitType::ObjectUpdate,
            proving_key,
            verifying_key,
        })
    }

    /// Get setup for a specific circuit and optional chain
    /// Returns the setup if it exists for the (chain_id, circuit_type) pair
    pub fn get(&self, chain_id: Option<ChainId>, circuit_type: CircuitType) -> Option<&TrustedSetup> {
        self.setups.get(&(chain_id, circuit_type))
    }

    /// Get proving key for a specific circuit and optional chain
    /// For chain-specific circuits (Mint, Burn) chain_id must be provided
    /// For global circuits (Transfer, ObjectUpdate) chain_id is ignored
    pub fn get_pk(&self, chain_id: Option<ChainId>, circuit_type: CircuitType) -> Option<&ProvingKey<Bn254>> {
        let cid = if circuit_type.is_chain_specific() {
            chain_id
        } else {
            None
        };
        self.get(cid, circuit_type).map(|setup| &setup.proving_key)
    }

    /// Get verifying key for a specific circuit and optional chain
    /// For chain-specific circuits (Mint, Burn) chain_id must be provided
    /// For global circuits (Transfer, ObjectUpdate) chain_id is ignored
    pub fn get_vk(&self, chain_id: Option<ChainId>, circuit_type: CircuitType) -> Option<&VerifyingKey<Bn254>> {
        let cid = if circuit_type.is_chain_specific() {
            chain_id
        } else {
            None
        };
        self.get(cid, circuit_type).map(|setup| &setup.verifying_key)
    }

    /// Get setup for a specific circuit type (legacy method)
    /// This is kept for backward compatibility and works with global circuits only
    #[deprecated(since = "0.2.0", note = "use get() with explicit chain_id instead")]
    pub fn get_setup(&self, circuit_type: CircuitType) -> Option<&TrustedSetup> {
        self.get(None, circuit_type)
    }

    /// Load all setups for a specific chain from directory
    pub fn load_for_chain(&mut self, chain_id: ChainId) -> Result<(), std::io::Error> {
        let base_dir = Path::new(&self.config.base_dir);

        // Load chain-specific circuits
        for circuit_type in &[CircuitType::Mint, CircuitType::Burn] {
            match TrustedSetup::load_setup(base_dir, Some(chain_id), *circuit_type) {
                Ok(setup) => {
                    self.setups.insert((Some(chain_id), *circuit_type), setup);
                }
                Err(e) => {
                    return Err(std::io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to load {} for chain_{}: {}",
                            circuit_type.identifier(),
                            chain_id,
                            e
                        ),
                    ));
                }
            }
        }

        // Load global circuits (only once per manager instance)
        if !self.setups.contains_key(&(None, CircuitType::Transfer)) {
            for circuit_type in &[CircuitType::Transfer, CircuitType::ObjectUpdate] {
                match TrustedSetup::load_setup(base_dir, None, *circuit_type) {
                    Ok(setup) => {
                        self.setups.insert((None, *circuit_type), setup);
                    }
                    Err(e) => {
                        return Err(std::io::Error::new(
                            e.kind(),
                            format!("Failed to load global {}: {}", circuit_type.identifier(), e),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Load all available setups from directory (all chains and global circuits)
    pub fn load_all(&mut self) -> Result<(), std::io::Error> {
        let base_dir = Path::new(&self.config.base_dir);

        // Load global circuits
        for circuit_type in &[CircuitType::Transfer, CircuitType::ObjectUpdate] {
            match TrustedSetup::load_setup(base_dir, None, *circuit_type) {
                Ok(setup) => {
                    self.setups.insert((None, *circuit_type), setup);
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load global {}: {}", circuit_type.identifier(), e);
                    // Continue loading other setups
                }
            }
        }

        // Discover and load all chain-specific circuits
        let global_dir = base_dir.join("global");
        let chains_dir_pattern = format!("{}chain_*", base_dir.display());

        if let Ok(entries) = fs::read_dir(base_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(name) => name.to_string(),
                        None => continue,
                    };

                    // Parse chain_id from "chain_1", "chain_501", etc.
                    if let Some(chain_id_str) = dir_name.strip_prefix("chain_") {
                        if let Ok(chain_id) = chain_id_str.parse::<ChainId>() {
                            // Try to load chain-specific circuits for this chain
                            let _ = self.load_for_chain(chain_id);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Save all setups to directory with new directory structure
    pub fn save_all(&self) -> Result<(), std::io::Error> {
        let base_dir = Path::new(&self.config.base_dir);

        for ((_chain_id, _circuit_type), setup) in &self.setups {
            setup.save_setup(base_dir)?;
        }
        Ok(())
    }

    /// Save a specific setup
    pub fn save_setup(&self, chain_id: Option<ChainId>, circuit_type: CircuitType) -> Result<(), std::io::Error> {
        let base_dir = Path::new(&self.config.base_dir);

        match self.get(chain_id, circuit_type) {
            Some(setup) => setup.save_setup(base_dir),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "Setup not found for circuit_type={:?}, chain_id={:?}",
                    circuit_type, chain_id
                ),
            )),
        }
    }

    /// Migrate legacy keys from old format (flat directory) to new format (chain-specific)
    /// This is useful when upgrading from the old setup.rs to the new multi-chain version
    pub fn migrate_legacy_keys(old_dir: &Path, new_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Check if old keys exist
        for circuit_type in &[
            CircuitType::Mint,
            CircuitType::Burn,
            CircuitType::Transfer,
            CircuitType::ObjectUpdate,
        ] {
            let old_pk_path = old_dir.join(format!("{}_pk.bin", circuit_type.identifier()));
            let old_vk_path = old_dir.join(format!("{}_vk.bin", circuit_type.identifier()));

            if old_pk_path.exists() && old_vk_path.exists() {
                println!("Migrating {:?}...", circuit_type);

                // Load from old format
                #[allow(deprecated)]
                let setup = TrustedSetup::load_from_files(old_dir, *circuit_type)?;

                // Save to new format as global (no chain_id)
                let global_setup = TrustedSetup::new(
                    None,
                    *circuit_type,
                    setup.proving_key,
                    setup.verifying_key,
                );
                global_setup.save_setup(new_dir)?;
                println!("  Migrated {:?} to global", circuit_type);
            }
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &CircuitSetupConfig {
        &self.config
    }

    /// Get mutable configuration
    pub fn config_mut(&mut self) -> &mut CircuitSetupConfig {
        &mut self.config
    }

    /// Save all setups to directory (legacy method)
    #[deprecated(since = "0.2.0", note = "use save_all() which uses config.base_dir instead")]
    pub fn save_all_to_dir(&self, dir: &Path) -> Result<(), std::io::Error> {
        for ((_chain_id, _circuit_type), setup) in &self.setups {
            setup.save_setup(dir)?;
        }
        Ok(())
    }

    /// Load all setups from directory (legacy method)
    #[deprecated(since = "0.2.0", note = "use load_all() which uses config.base_dir instead")]
    pub fn load_all_from_dir(&mut self, dir: &Path) -> Result<(), std::io::Error> {
        for circuit_type in &[
            CircuitType::Mint,
            CircuitType::Burn,
            CircuitType::Transfer,
            CircuitType::ObjectUpdate,
        ] {
            match TrustedSetup::load_setup(dir, None, *circuit_type) {
                Ok(setup) => {
                    self.setups.insert((None, *circuit_type), setup);
                }
                Err(_e) => {
                    // Try loading from old format for backward compatibility
                    #[allow(deprecated)]
                    match TrustedSetup::load_from_files(dir, *circuit_type) {
                        Ok(setup) => {
                            self.setups.insert((None, *circuit_type), setup);
                        }
                        Err(e) => {
                            return Err(std::io::Error::new(
                                e.kind(),
                                format!("Failed to load {}: {}", circuit_type.identifier(), e),
                            ));
                        }
                    }
                }
            }
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
    fn test_trusted_setup_generation_global() {
        let mut rng = test_rng();
        let mut manager = CircuitSetupManager::with_default_config();

        // Generate global setups
        manager.generate_global_circuits(&mut rng).unwrap();

        // Verify global setups were generated
        assert!(manager.get(None, CircuitType::Transfer).is_some());
        assert!(manager.get(None, CircuitType::ObjectUpdate).is_some());

        println!("✓ Global trusted setup generation test passed");
    }

    #[test]
    #[ignore] // Slow test - generates cryptographic setup for all circuits
    fn test_trusted_setup_generation_chain_specific() {
        let mut rng = test_rng();
        let mut manager = CircuitSetupManager::with_default_config();
        let chain_id = 1u32; // Ethereum

        // Generate chain-specific setups
        manager.generate_chain_circuits(chain_id, &mut rng).unwrap();

        // Verify chain-specific setups were generated
        assert!(manager.get(Some(chain_id), CircuitType::Mint).is_some());
        assert!(manager.get(Some(chain_id), CircuitType::Burn).is_some());

        println!("✓ Chain-specific trusted setup generation test passed");
    }

    #[test]
    fn test_setup_directory_structure() {
        let temp_dir = PathBuf::from("/tmp/fluxe_test_multi_chain");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create setup for chain 1 (Ethereum)
        let setup_eth = TrustedSetup {
            chain_id: Some(1),
            circuit_type: CircuitType::Mint,
            proving_key: dummy_proving_key(),
            verifying_key: dummy_verifying_key(),
        };

        // Create setup for chain 501 (Solana)
        let setup_sol = TrustedSetup {
            chain_id: Some(501),
            circuit_type: CircuitType::Mint,
            proving_key: dummy_proving_key(),
            verifying_key: dummy_verifying_key(),
        };

        // Create global setup
        let setup_global = TrustedSetup {
            chain_id: None,
            circuit_type: CircuitType::Transfer,
            proving_key: dummy_proving_key(),
            verifying_key: dummy_verifying_key(),
        };

        // Verify directory paths
        assert_eq!(
            setup_eth.get_directory_path(&temp_dir).unwrap(),
            temp_dir.join("chain_1")
        );
        assert_eq!(
            setup_sol.get_directory_path(&temp_dir).unwrap(),
            temp_dir.join("chain_501")
        );
        assert_eq!(
            setup_global.get_directory_path(&temp_dir).unwrap(),
            temp_dir.join("global")
        );

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();

        println!("✓ Directory structure test passed");
    }

    #[test]
    fn test_setup_serialization_new_format() {
        let mut rng = test_rng();
        let manager = CircuitSetupManager::with_default_config();

        // Generate mint setup
        let setup = manager.generate_mint_setup(&mut rng).unwrap();

        // Create TrustedSetup with chain_id
        let ts = TrustedSetup {
            chain_id: Some(1),
            circuit_type: CircuitType::Mint,
            proving_key: setup.proving_key,
            verifying_key: setup.verifying_key,
        };

        // Save to temp directory
        let temp_dir = PathBuf::from("/tmp/fluxe_test_setup_new");
        fs::create_dir_all(&temp_dir).unwrap();
        ts.save_setup(&temp_dir).unwrap();

        // Verify directory structure
        assert!(temp_dir.join("chain_1").exists());
        assert!(temp_dir.join("chain_1/v1_Mint_pk.bin").exists());
        assert!(temp_dir.join("chain_1/v1_Mint_vk.bin").exists());

        // Load back
        let loaded_setup = TrustedSetup::load_setup(&temp_dir, Some(1), CircuitType::Mint).unwrap();

        // Verify keys match
        assert_eq!(
            ts.verifying_key.alpha_g1,
            loaded_setup.verifying_key.alpha_g1
        );

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();

        println!("✓ Setup serialization (new format) test passed");
    }

    #[test]
    fn test_circuit_type_chain_specific() {
        // Chain-specific circuits
        assert!(CircuitType::Mint.is_chain_specific());
        assert!(CircuitType::Burn.is_chain_specific());

        // Global circuits
        assert!(!CircuitType::Transfer.is_chain_specific());
        assert!(!CircuitType::ObjectUpdate.is_chain_specific());
        assert!(!CircuitType::TransferCustom(2, 3).is_chain_specific());

        println!("✓ Circuit type chain specificity test passed");
    }

    #[test]
    fn test_manager_get_keys() {
        let mut rng = test_rng();
        let mut manager = CircuitSetupManager::with_default_config();

        // Generate some setups
        let mint_setup = manager.generate_mint_setup(&mut rng).unwrap();
        let ts_mint = TrustedSetup {
            chain_id: Some(1),
            circuit_type: CircuitType::Mint,
            proving_key: mint_setup.proving_key,
            verifying_key: mint_setup.verifying_key,
        };
        manager.setups.insert((Some(1), CircuitType::Mint), ts_mint);

        let transfer_setup = manager.generate_transfer_setup(&mut rng).unwrap();
        let ts_transfer = TrustedSetup {
            chain_id: None,
            circuit_type: CircuitType::Transfer,
            proving_key: transfer_setup.proving_key,
            verifying_key: transfer_setup.verifying_key,
        };
        manager.setups.insert((None, CircuitType::Transfer), ts_transfer);

        // Test getting proving keys
        assert!(manager.get_pk(Some(1), CircuitType::Mint).is_some());
        assert!(manager.get_pk(None, CircuitType::Transfer).is_some());

        // Test getting verifying keys
        assert!(manager.get_vk(Some(1), CircuitType::Mint).is_some());
        assert!(manager.get_vk(None, CircuitType::Transfer).is_some());

        println!("✓ Manager get keys test passed");
    }

    // Helper functions for tests
    fn dummy_proving_key() -> ProvingKey<Bn254> {
        let mut rng = test_rng();
        let manager = CircuitSetupManager::with_default_config();
        manager.generate_mint_setup(&mut rng).unwrap().proving_key
    }

    fn dummy_verifying_key() -> VerifyingKey<Bn254> {
        let mut rng = test_rng();
        let manager = CircuitSetupManager::with_default_config();
        manager.generate_mint_setup(&mut rng).unwrap().verifying_key
    }

    #[test]
    #[ignore] // Slow test - generates cryptographic setup for all circuits
    fn test_trusted_setup_generation() {
        let mut rng = test_rng();
        let mut manager = CircuitSetupManager::with_default_config();

        // Generate all setups (legacy method)
        manager.generate_all_setups(&mut rng).unwrap();

        // Verify all global setups were generated
        assert!(manager.get(None, CircuitType::Transfer).is_some());
        assert!(manager.get(None, CircuitType::ObjectUpdate).is_some());

        println!("✓ Trusted setup generation test (legacy) passed");
    }

    #[test]
    fn test_setup_serialization() {
        let mut rng = test_rng();
        let manager = CircuitSetupManager::with_default_config();

        // Generate mint setup
        let setup = manager.generate_mint_setup(&mut rng).unwrap();

        // Create TrustedSetup
        let ts = TrustedSetup {
            chain_id: Some(1),
            circuit_type: CircuitType::Mint,
            proving_key: setup.proving_key,
            verifying_key: setup.verifying_key,
        };

        // Save to temp directory using legacy method
        let temp_dir = PathBuf::from("/tmp/fluxe_test_setup_legacy");
        fs::create_dir_all(&temp_dir).unwrap();

        #[allow(deprecated)]
        ts.save_to_files(&temp_dir, CircuitType::Mint).unwrap();

        // Load back using legacy method
        #[allow(deprecated)]
        let loaded_setup = TrustedSetup::load_from_files(&temp_dir, CircuitType::Mint).unwrap();

        // Verify keys match (simplified check)
        assert_eq!(
            ts.verifying_key.alpha_g1,
            loaded_setup.verifying_key.alpha_g1
        );

        // Cleanup
        fs::remove_dir_all(temp_dir).ok();

        println!("✓ Setup serialization test (legacy) passed");
    }
}