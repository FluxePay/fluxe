use ark_bls12_381::{Bls12_381, Fr as F};
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
    Transfer,
    ObjectUpdate,
}

/// Trusted setup parameters for a circuit
#[derive(Clone)]
pub struct TrustedSetup {
    pub proving_key: ProvingKey<Bls12_381>,
    pub verifying_key: VerifyingKey<Bls12_381>,
}

impl TrustedSetup {
    /// Save setup parameters to files
    pub fn save_to_files(&self, dir: &Path, circuit_type: CircuitType) -> Result<(), std::io::Error> {
        fs::create_dir_all(dir)?;
        
        let pk_path = dir.join(format!("{:?}_pk.bin", circuit_type));
        let vk_path = dir.join(format!("{:?}_vk.bin", circuit_type));
        
        // Save proving key
        let pk_file = File::create(pk_path)?;
        let mut pk_writer = BufWriter::new(pk_file);
        self.proving_key.serialize_compressed(&mut pk_writer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        pk_writer.flush()?;
        
        // Save verifying key
        let vk_file = File::create(vk_path)?;
        let mut vk_writer = BufWriter::new(vk_file);
        self.verifying_key.serialize_compressed(&mut vk_writer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        vk_writer.flush()?;
        
        Ok(())
    }
    
    /// Load setup parameters from files
    pub fn load_from_files(dir: &Path, circuit_type: CircuitType) -> Result<Self, std::io::Error> {
        let pk_path = dir.join(format!("{:?}_pk.bin", circuit_type));
        let vk_path = dir.join(format!("{:?}_vk.bin", circuit_type));
        
        // Load proving key
        let pk_file = File::open(pk_path)?;
        let mut pk_reader = BufReader::new(pk_file);
        let proving_key = ProvingKey::deserialize_compressed(&mut pk_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
        // Load verifying key
        let vk_file = File::open(vk_path)?;
        let mut vk_reader = BufReader::new(vk_file);
        let verifying_key = VerifyingKey::deserialize_compressed(&mut vk_reader)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        
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
    fn generate_mint_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        use ark_ff::UniformRand;
        use fluxe_core::data_structures::{Note, IngressReceipt};
        use fluxe_core::crypto::pedersen::PedersenCommitment;
        use ark_ec::CurveGroup;
        use ark_bls12_381::G1Projective;
        
        // Create dummy circuit for setup
        let dummy_note = Note {
            asset_type: 1,
            v_comm: PedersenCommitment {
                commitment: G1Projective::rand(rng).into_affine(),
            },
            owner_addr: F::rand(rng),
            psi: [0u8; 32],
            chain_hint: 0,
            compliance_hash: F::rand(rng),
            lineage_hash: F::from(0u64),
            pool_id: 1,
            callbacks_hash: F::from(0u64),
            memo_hash: F::from(0u64),
        };
        
        use fluxe_core::merkle::IncrementalTree;
        let mut cmt_tree = IncrementalTree::new(16);
        let mut ingress_tree = IncrementalTree::new(16);
        
        let dummy_circuit = MintCircuit::new(
            vec![dummy_note],
            vec![1000],
            vec![F::rand(rng)],
            IngressReceipt {
                asset_type: 1,
                amount: 1000u64.into(),
                beneficiary_cm: F::rand(rng),
                nonce: 1,
                aux: F::from(0u64),
            },
            &mut cmt_tree,
            &mut ingress_tree,
        );
        
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for BurnCircuit
    fn generate_burn_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        use ark_ff::UniformRand;
        use fluxe_core::data_structures::{Note, ExitReceipt};
        use fluxe_core::crypto::pedersen::PedersenCommitment;
        use fluxe_core::merkle::{MerklePath, AppendWitness};
        use ark_ec::CurveGroup;
        use ark_bls12_381::G1Projective;
        
        // Generate consistent owner key and address
        let owner_sk = F::rand(rng);
        let owner_addr = {
            use fluxe_core::crypto::poseidon_hash;
            poseidon_hash(&[owner_sk])
        };
        
        let dummy_note = Note {
            asset_type: 1,
            v_comm: PedersenCommitment {
                commitment: G1Projective::rand(rng).into_affine(),
            },
            owner_addr,
            psi: [0u8; 32],
            chain_hint: 0,
            compliance_hash: F::rand(rng),
            lineage_hash: F::rand(rng),
            pool_id: 1,
            callbacks_hash: F::rand(rng),
            memo_hash: F::from(0u64),
        };
        
        // Generate nullifier for consistency
        let nk = F::rand(rng);
        let nf_in = dummy_note.nullifier(&nk);
        
        let dummy_circuit = BurnCircuit {
            note_in: dummy_note.clone(),
            value_in: 1000,
            value_randomness_in: F::rand(rng),
            owner_sk,
            owner_pk_x: F::rand(rng),
            owner_pk_y: F::rand(rng),
            nk,
            cm_path: MerklePath {
                leaf_index: 0,
                siblings: vec![F::from(0u64); 32],
                leaf: F::rand(rng),
            },
            nf_nonmembership: Some({
                use fluxe_core::merkle::{RangePath, SortedLeaf};
                RangePath {
                    target: nf_in,
                    low_leaf: SortedLeaf {
                        key: F::from(0u64),
                        next_key: F::from(u64::MAX),
                        next_index: 1,
                    },
                    low_path: MerklePath {
                        leaf_index: 0,
                        siblings: vec![F::from(0u64); 32],
                        leaf: F::from(0u64),
                    },
                }
            }),
            nf_insert_witness: None, // Dummy circuit doesn't need real witness
            exit_receipt: ExitReceipt {
                asset_type: 1,
                amount: 500u64.into(),
                burned_nf: nf_in,
                nonce: 1,
                aux: F::from(0u64),
            },
            exit_append_witness: AppendWitness {
                leaf_index: 0,
                leaf: ExitReceipt {
                    asset_type: 1,
                    amount: 500u64.into(),
                    burned_nf: nf_in,
                    nonce: 1,
                    aux: F::from(0u64),
                }.hash(),
                pre_siblings: vec![F::from(0u64); 32],
                height: 32,
            },
            cmt_root: F::rand(rng),
            nft_root_old: F::from(0u64),
            nft_root_new: {
                // Compute using simplified method
                use fluxe_core::crypto::poseidon_hash;
                let binding = poseidon_hash(&[F::from(0u64), nf_in, F::from(9999u64)]);
                poseidon_hash(&[binding, nf_in])
            },
            exit_root_old: F::from(0u64),
            exit_root_new: {
                // Compute using simplified method
                use fluxe_core::crypto::poseidon_hash;
                let exit_hash = ExitReceipt {
                    asset_type: 1,
                    amount: 500u64.into(),
                    burned_nf: nf_in,
                    nonce: 1,
                    aux: F::from(0u64),
                }.hash();
                let binding = poseidon_hash(&[F::from(0u64), exit_hash, F::from(0u64)]);
                poseidon_hash(&[binding, exit_hash])
            },
            asset_type: 1,
            amount: 500u64.into(),
            nf_in,
        };
        
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for TransferCircuit
    fn generate_transfer_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        use ark_ff::UniformRand;
        use fluxe_core::data_structures::Note;
        use fluxe_core::crypto::pedersen::PedersenCommitment;
        use fluxe_core::merkle::MerklePath;
        use ark_ec::CurveGroup;
        use ark_bls12_381::G1Projective;
        
        // Create dummy inputs (2 notes)
        let mut notes_in = Vec::new();
        let mut values_in = Vec::new();
        let mut value_randomness_in = Vec::new();
        let mut nks = Vec::new();
        let mut cm_paths = Vec::new();
        let mut nf_list = Vec::new();
        
        for _ in 0..2 {
            notes_in.push(Note {
                asset_type: 1,
                v_comm: PedersenCommitment {
                    commitment: G1Projective::rand(rng).into_affine(),
                },
                owner_addr: F::rand(rng),
                psi: [0u8; 32],
                chain_hint: 0,
                compliance_hash: F::rand(rng),
                lineage_hash: F::rand(rng),
                pool_id: 1,
                callbacks_hash: F::rand(rng),
                memo_hash: F::from(0u64),
            });
            values_in.push(500);
            value_randomness_in.push(F::rand(rng));
            nks.push(F::rand(rng));
            cm_paths.push(MerklePath {
                leaf_index: 0,
                siblings: vec![F::from(0u64); 32],
                leaf: F::rand(rng),
            });
            nf_list.push(F::rand(rng));
        }
        
        // Create dummy outputs (2 notes)
        let mut notes_out = Vec::new();
        let mut values_out = Vec::new();
        let mut value_randomness_out = Vec::new();
        let mut cm_list = Vec::new();
        
        for _ in 0..2 {
            notes_out.push(Note {
                asset_type: 1,
                v_comm: PedersenCommitment {
                    commitment: G1Projective::rand(rng).into_affine(),
                },
                owner_addr: F::rand(rng),
                psi: [0u8; 32],
                chain_hint: 0,
                compliance_hash: F::rand(rng),
                lineage_hash: F::rand(rng),
                pool_id: 1,
                callbacks_hash: F::from(0u64),
                memo_hash: F::from(0u64),
            });
            values_out.push(495);
            value_randomness_out.push(F::rand(rng));
            cm_list.push(F::rand(rng));
        }
        
        // Create dummy non-membership proofs
        use fluxe_core::merkle::{SortedLeaf, RangePath};
        let mut nm_proofs = Vec::new();
        for _ in 0..2 {
            let low_leaf = SortedLeaf {
                key: F::rand(rng),
                next_key: F::rand(rng),
                next_index: 0,
            };
            let low_path = MerklePath {
                leaf_index: 0,
                siblings: vec![F::rand(rng); 16],
                leaf: F::rand(rng),
            };
            nm_proofs.push(Some(RangePath {
                low_leaf,
                low_path,
                target: F::rand(rng),
            }));
        }
        
        let dummy_circuit = TransferCircuit {
            notes_in,
            values_in,
            value_randomness_in,
            notes_out,
            values_out,
            value_randomness_out,
            nks,
            owner_sks: vec![F::rand(rng), F::rand(rng)],
            owner_pks: vec![(F::rand(rng), F::rand(rng)), (F::rand(rng), F::rand(rng))],
            cm_paths,
            nf_nonmembership_proofs: nm_proofs.clone(),
            sanctions_nm_proofs_in: vec![None; 2],
            sanctions_nm_proofs_out: vec![None; 2],
            cmt_paths_out: vec![],
            nf_nonmembership: nm_proofs,
            source_pool_policies: vec![],
            dest_pool_policies: vec![],
            pool_policy_paths: vec![],
            cmt_appends_out: vec![],
            nf_insert_witnesses: vec![],
            cmt_root_old: F::rand(rng),
            cmt_root_new: F::rand(rng),
            nft_root_old: F::rand(rng),
            nft_root_new: F::rand(rng),
            sanctions_root: F::rand(rng),
            pool_rules_root: F::rand(rng),
            nf_list,
            cm_list,
            fee: 10u64.into(),
        };
        
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, rng)?;
        
        Ok(TrustedSetup {
            proving_key,
            verifying_key,
        })
    }
    
    /// Generate setup for ObjectUpdateCircuit
    fn generate_object_update_setup<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Result<TrustedSetup, Box<dyn std::error::Error>> {
        use ark_ff::UniformRand;
        use fluxe_core::data_structures::{ComplianceState, ZkObject};
        use fluxe_core::merkle::MerklePath;
        
        let state_old = ComplianceState::new();
        let state_new = ComplianceState {
            level: 2,
            ..state_old.clone()
        };
        
        let obj_old = ZkObject {
            state_hash: state_old.hash(),
            serial: 100,
            cb_head_hash: F::rand(rng),
        };
        
        let obj_new = ZkObject {
            state_hash: state_new.hash(),
            serial: 101,
            cb_head_hash: obj_old.cb_head_hash,
        };
        
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
            obj_path_old: MerklePath {
                leaf_index: 0,
                siblings: vec![F::from(0u64); 32],
                leaf: F::rand(rng),
            },
            decrypt_key: None,
            obj_root_old: F::rand(rng),
            obj_root_new: F::rand(rng),
            cb_root: F::rand(rng),
            current_time: 2000,
        };
        
        let (proving_key, verifying_key) = Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, rng)?;
        
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