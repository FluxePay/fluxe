/// Fluxe API Client Library
///
/// Provides easy-to-use client methods for interacting with the Fluxe API server

use ark_bn254::Fr as F;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use reqwest;
use std::error::Error;

use fluxe_circuits::{
    mint::MintCircuit,
    burn::BurnCircuit,
    transfer::TransferCircuit,
};

use fluxe_core::{
    data_structures::{Note, IngressReceipt, ExitReceipt},
    crypto::{
        pedersen::{PedersenParams, PedersenCommitment, PedersenRandomness},
        poseidon_hash,
    },
    merkle::{IncrementalTree, SortedTree, MerklePath},
    types::*,
};

use crate::api::{
    ApiResponse, SubmitMintRequest, SubmitBurnRequest, SubmitTransferRequest, SerializableNote,
    StateRootsResponse, SupplyResponse, ProofResponse,
};

/// Client for interacting with Fluxe API
pub struct FluxeClient {
    base_url: String,
    client: reqwest::Client,
}

impl FluxeClient {
    /// Create a new Fluxe client
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    // ============ Transaction Submission ============

    /// Submit a mint transaction
    pub async fn submit_mint(
        &self,
        asset_type: AssetType,
        amount: u64,
        recipient_addr: F,
        proving_key: &ProvingKey<ark_bn254::Bn254>,
    ) -> Result<String, Box<dyn Error>> {
        // Create mint note
        let params = PedersenParams::setup_value_commitment();
        let randomness = F::from(rand::random::<u64>());
        let v_comm = PedersenCommitment::commit(
            &params,
            amount,
            &PedersenRandomness { r: randomness },
        );

        let mut note = Note::new(
            asset_type,
            v_comm,
            recipient_addr,
            rand::random::<[u8; 32]>(),
            1, // chain_hint
        );
        note.compliance_hash = F::from(1u64);
        note.callbacks_hash = F::from(0u64);
        note.lineage_hash = F::from(0u64);
        note.memo_hash = F::from(0u64);

        // Create ingress receipt
        let cm = note.commitment();
        let beneficiary_cm = poseidon_hash(&[F::from(0u64), cm]);
        let ingress = IngressReceipt::new(
            1, // source_chain - default to chain 1
            asset_type,
            Amount::from(amount as u128),
            beneficiary_cm,
            1,
        );

        // Create circuit
        let mut cmt_tree = IncrementalTree::new(16);
        let mut ingress_tree = IncrementalTree::new(16);
        let circuit = MintCircuit::new(
            vec![note.clone()],
            vec![amount],
            vec![randomness],
            ingress,
            &mut cmt_tree,
            &mut ingress_tree,
        );

        // Generate proof
        let mut rng = rand::thread_rng();
        let proof = Groth16::<ark_bn254::Bn254>::prove(proving_key, circuit.clone(), &mut rng)?;
        // Get public inputs from circuit using FluxeCircuit trait
        use fluxe_circuits::circuits::FluxeCircuit;
        let public_inputs = circuit.public_inputs();

        // Prepare request
        let request = SubmitMintRequest {
            asset_type,
            amount,
            proof: serialize_proof(&proof)?,
            public_inputs: public_inputs.iter().map(field_to_hex).collect(),
            notes_out: vec![note_to_serializable(&note)],
        };

        // Send request
        let response = self.client
            .post(format!("{}/submit/mint", self.base_url))
            .json(&request)
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Submit a burn transaction
    pub async fn submit_burn(
        &self,
        note: Note,
        value: u64,
        value_randomness: F,
        owner_sk: F,
        nk: F,
        cm_path: MerklePath,
        proving_key: &ProvingKey<ark_bn254::Bn254>,
        nft_root_old: F,
        exit_root_old: F,
    ) -> Result<String, Box<dyn Error>> {
        use fluxe_circuits::utils::ec_helpers::get_pk_coords_circuit_compatible;

        // Compute nullifier
        let nf = note.nullifier(&nk);

        // Create exit receipt
        let exit_receipt = ExitReceipt::new(
            1, // destination_chain - default to chain 1
            note.asset_type,
            Amount::from(value as u128),
            nf,
            1,
        );

        // Create dummy trees for witness generation
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64));
        let exit_tree = IncrementalTree::new(16);

        // Get witnesses
        let nm_proof = nft_tree.prove_non_membership(nf).ok();
        let insert_witness = nft_tree.insert_with_witness(nf).ok().map(|w| {
            fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
                target: w.target,
                range_proof: w.range_proof,
                new_leaf: w.new_leaf,
                updated_pred_leaf: w.updated_pred_leaf,
                new_leaf_path: w.new_leaf_path,
                pred_update_path: w.pred_update_path,
                height: w.height,
            }
        });
        let exit_append_witness = exit_tree.generate_append_witness(exit_receipt.hash());

        // Get pk coordinates
        let (pk_x, pk_y) = get_pk_coords_circuit_compatible(owner_sk);

        // Create burn circuit
        let circuit = BurnCircuit {
            note_in: note.clone(),
            value_in: value,
            value_randomness_in: value_randomness,
            owner_sk,
            owner_pk_x: pk_x,
            owner_pk_y: pk_y,
            nk,
            cm_path,
            nf_nonmembership: nm_proof,
            nf_insert_witness: insert_witness,
            exit_receipt,
            exit_append_witness,
            cmt_root: F::from(0u64), // Would get from API
            nft_root_old,
            nft_root_new: nft_tree.root(),
            exit_root_old,
            exit_root_new: exit_tree.root(),
            asset_type: note.asset_type,
            amount: Amount::from(value as u128),
            nf_in: nf,
        };

        // Generate proof
        let mut rng = rand::thread_rng();
        let proof = Groth16::<ark_bn254::Bn254>::prove(proving_key, circuit.clone(), &mut rng)?;
        // Get public inputs from circuit using FluxeCircuit trait
        use fluxe_circuits::circuits::FluxeCircuit;
        let public_inputs = circuit.public_inputs();

        // Prepare request
        let request = SubmitBurnRequest {
            asset_type: note.asset_type,
            amount: value,
            nullifier: field_to_hex(&nf),
            proof: serialize_proof(&proof)?,
            public_inputs: public_inputs.iter().map(field_to_hex).collect(),
        };

        // Send request
        let response = self.client
            .post(format!("{}/submit/burn", self.base_url))
            .json(&request)
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Submit a transfer transaction
    pub async fn submit_transfer(
        &self,
        notes_in: Vec<Note>,
        values_in: Vec<u64>,
        value_randomness_in: Vec<F>,
        notes_out: Vec<Note>,
        values_out: Vec<u64>,
        value_randomness_out: Vec<F>,
        nks: Vec<F>,
        owner_sks: Vec<F>,
        cm_paths: Vec<MerklePath>,
        proving_key: &ProvingKey<ark_bn254::Bn254>,
        old_roots: (F, F), // (cmt_root_old, nft_root_old)
    ) -> Result<String, Box<dyn Error>> {
        use fluxe_circuits::utils::ec_helpers::get_pk_coords_circuit_compatible;

        // Compute nullifiers
        let nullifiers: Vec<F> = notes_in.iter().zip(&nks)
            .map(|(note, nk)| note.nullifier(nk))
            .collect();

        // Get owner pks
        let owner_pks: Vec<(F, F)> = owner_sks.iter()
            .map(|sk| get_pk_coords_circuit_compatible(*sk))
            .collect();

        // Create dummy trees for witness generation
        let mut cmt_tree = IncrementalTree::new(16);
        let mut nft_tree = SortedTree::new(16);
        let _ = nft_tree.insert(F::from(0u64));

        // Get non-membership proofs
        let nf_nonmembership_proofs: Vec<_> = nullifiers.iter()
            .map(|nf| nft_tree.prove_non_membership(*nf).ok())
            .collect();

        // Get insert witnesses
        let nf_insert_witnesses: Vec<_> = nullifiers.iter()
            .filter_map(|nf| {
                nft_tree.insert_with_witness(*nf).ok().map(|w| {
                    fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
                target: w.target,
                range_proof: w.range_proof,
                new_leaf: w.new_leaf,
                updated_pred_leaf: w.updated_pred_leaf,
                new_leaf_path: w.new_leaf_path,
                pred_update_path: w.pred_update_path,
                height: w.height,
            }
                })
            })
            .collect();

        // Get append witnesses for outputs
        let cmt_appends_out: Vec<_> = notes_out.iter()
            .map(|note| {
                let cm = note.commitment();
                let witness = cmt_tree.generate_append_witness(cm);
                cmt_tree.append(cm);
                witness
            })
            .collect();

        // Compute output commitments
        let cm_list: Vec<F> = notes_out.iter().map(|n| n.commitment()).collect();

        // Create transfer circuit
        let notes_in_len = notes_in.len();
        let notes_out_len = notes_out.len();

        let circuit = TransferCircuit {
            notes_in,
            values_in,
            value_randomness_in,
            notes_out: notes_out.clone(),
            values_out,
            value_randomness_out,
            nks,
            owner_sks,
            owner_pks,
            cm_paths,
            nf_nonmembership_proofs: nf_nonmembership_proofs.clone(),
            sanctions_nm_proofs_in: vec![None; notes_in_len],
            sanctions_nm_proofs_out: vec![None; notes_out_len],
            cmt_paths_out: vec![],
            nf_nonmembership: nf_nonmembership_proofs,
            source_pool_policies: vec![],
            dest_pool_policies: vec![],
            pool_policy_paths: vec![],
            cmt_appends_out,
            nf_insert_witnesses,
            cmt_root_old: old_roots.0,
            cmt_root_new: cmt_tree.root(),
            nft_root_old: old_roots.1,
            nft_root_new: nft_tree.root(),
            sanctions_root: F::from(0u64),
            pool_rules_root: F::from(0u64),
            nf_list: nullifiers.clone(),
            cm_list,
            fee: Amount::from(10u128),
        };

        // Generate proof
        let mut rng = rand::thread_rng();
        let proof = Groth16::<ark_bn254::Bn254>::prove(proving_key, circuit.clone(), &mut rng)?;
        // Get public inputs from circuit using FluxeCircuit trait
        use fluxe_circuits::circuits::FluxeCircuit;
        let public_inputs = circuit.public_inputs();

        // Prepare request
        let request = SubmitTransferRequest {
            nullifiers: nullifiers.iter().map(field_to_hex).collect(),
            proof: serialize_proof(&proof)?,
            public_inputs: public_inputs.iter().map(field_to_hex).collect(),
            notes_out: notes_out.iter().map(note_to_serializable).collect(),
        };

        // Send request
        let response = self.client
            .post(format!("{}/submit/transfer", self.base_url))
            .json(&request)
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    // ============ State Queries ============

    /// Get current state roots
    pub async fn get_roots(&self) -> Result<StateRootsResponse, Box<dyn Error>> {
        let response = self.client
            .get(format!("{}/state/roots", self.base_url))
            .send()
            .await?;

        let api_response: ApiResponse<StateRootsResponse> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Get supply information for an asset type
    pub async fn get_supply(&self, asset_type: AssetType) -> Result<SupplyResponse, Box<dyn Error>> {
        let response = self.client
            .get(format!("{}/state/supply/{}", self.base_url, asset_type))
            .send()
            .await?;

        let api_response: ApiResponse<SupplyResponse> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Get commitment membership proof
    pub async fn get_commitment_proof(&self, cm: &F) -> Result<ProofResponse, Box<dyn Error>> {
        let hex = field_to_hex(cm);
        let response = self.client
            .get(format!("{}/proofs/commitment/{}", self.base_url, hex))
            .send()
            .await?;

        let api_response: ApiResponse<ProofResponse> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Get nullifier membership/non-membership proof
    pub async fn get_nullifier_proof(&self, nf: &F) -> Result<ProofResponse, Box<dyn Error>> {
        let hex = field_to_hex(nf);
        let response = self.client
            .get(format!("{}/proofs/nullifier/{}", self.base_url, hex))
            .send()
            .await?;

        let api_response: ApiResponse<ProofResponse> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    // ============ Batch Processing ============

    /// Process a batch of transactions
    pub async fn process_batch(&self) -> Result<String, Box<dyn Error>> {
        let response = self.client
            .post(format!("{}/batch/process", self.base_url))
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Get batch processing status
    pub async fn get_batch_status(&self) -> Result<String, Box<dyn Error>> {
        let response = self.client
            .get(format!("{}/batch/status", self.base_url))
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        if api_response.success {
            Ok(api_response.data.unwrap())
        } else {
            Err(api_response.error.unwrap_or("Unknown error".to_string()).into())
        }
    }

    /// Health check
    pub async fn health_check(&self) -> Result<bool, Box<dyn Error>> {
        let response = self.client
            .get(format!("{}/health", self.base_url))
            .send()
            .await?;

        let api_response: ApiResponse<String> = response.json().await?;
        Ok(api_response.success)
    }
}

// Helper functions

fn serialize_proof(proof: &Proof<ark_bn254::Bn254>) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn field_to_hex(field: &F) -> String {
    let mut bytes = Vec::new();
    field.serialize_compressed(&mut bytes).unwrap();
    format!("0x{}", hex::encode(bytes))
}

fn note_to_serializable(note: &Note) -> SerializableNote {
    SerializableNote {
        asset_type: note.asset_type,
        owner_addr: field_to_hex(&note.owner_addr),
        psi: note.psi,
        chain_hint: note.chain_hint,
        pool_id: note.pool_id,
    }
}