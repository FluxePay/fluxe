/// Generate actual proofs using Rapidsnark for Fluxe Transfer circuit
use ark_bn254::Fr as F;
use fluxe_circuits::transfer::TransferCircuit;
use fluxe_circuits::rapidsnark::*;
use fluxe_core::{
    Note, Amount,
    merkle::{IncrementalTree, SortedTree},
    crypto::{PedersenCommitment, PedersenParams, PedersenRandomness, poseidon_hash, domain_sep_to_field, DOM_NF, compute_ec_public_key},
};
use std::path::PathBuf;

fn create_transfer_circuit() -> TransferCircuit {
    let owner_sk = F::from(123u64);
    let (pk_x, pk_y) = compute_ec_public_key(owner_sk);
    let owner_addr = poseidon_hash(&[pk_x, pk_y]);
    let nk = F::from(111u64);

    let mut cmt_tree = IncrementalTree::new(16);
    let mut nft_tree = SortedTree::new(16);

    let params = PedersenParams::setup_value_commitment();
    let value_in = 100u64;
    let randomness_in = F::from(1u64);
    let v_comm_in = PedersenCommitment::commit(
        &params,
        value_in,
        &PedersenRandomness { r: randomness_in },
    );

    let mut psi_in = [0u8; 32];
    psi_in[0] = 1;
    let mut note_in = Note::new(1, v_comm_in, owner_addr, psi_in, 1);
    note_in.lineage_hash = F::from(1u64);
    note_in.compliance_hash = F::from(1u64);
    note_in.callbacks_hash = F::from(1u64);
    note_in.memo_hash = F::from(0u64);

    let cm_in = note_in.commitment();
    cmt_tree.append(cm_in);
    let cm_path = cmt_tree.get_path(0).unwrap();
    let cmt_root_old = cmt_tree.root();

    let psi_field = fluxe_core::utils::bytes_to_field(&note_in.psi);
    let nf = poseidon_hash(&vec![
        domain_sep_to_field(DOM_NF),
        nk,
        psi_field,
        cm_in,
    ]);

    let nft_root_old = nft_tree.root();
    let nm_proof = nft_tree.prove_non_membership(nf).unwrap();
    let insert_witness = nft_tree.insert_with_witness(nf).unwrap();
    let nft_root_new = nft_tree.root();

    let value_out = 90u64;
    let randomness_out = F::from(1u64);
    let v_comm_out = PedersenCommitment::commit(
        &params,
        value_out,
        &PedersenRandomness { r: randomness_out },
    );

    let mut psi_out = [0u8; 32];
    psi_out[0] = 2;
    let mut note_out = Note::new(1, v_comm_out, F::from(999u64), psi_out, 1);
    note_out.lineage_hash = poseidon_hash(&[note_in.lineage_hash, F::from(0u64)]);
    note_out.compliance_hash = F::from(1u64);
    note_out.callbacks_hash = F::from(1u64);
    note_out.memo_hash = F::from(0u64);

    let cm_out = note_out.commitment();
    let append_witness = cmt_tree.generate_append_witness(cm_out);
    cmt_tree.append(cm_out);
    let cmt_root_new = cmt_tree.root();

    let circuit_insert_witness = fluxe_circuits::gadgets::sorted_insert::SortedInsertWitness {
        target: insert_witness.target,
        range_proof: insert_witness.range_proof,
        new_leaf: insert_witness.new_leaf,
        updated_pred_leaf: insert_witness.updated_pred_leaf,
        new_leaf_path: insert_witness.new_leaf_path,
        pred_update_path: insert_witness.pred_update_path,
        height: insert_witness.height,
    };

    TransferCircuit {
        notes_in: vec![note_in],
        values_in: vec![value_in],
        value_randomness_in: vec![randomness_in],
        notes_out: vec![note_out],
        values_out: vec![value_out],
        value_randomness_out: vec![randomness_out],
        nks: vec![nk],
        owner_sks: vec![owner_sk],
        owner_pks: vec![(pk_x, pk_y)],
        cm_paths: vec![cm_path],
        nf_nonmembership_proofs: vec![Some(nm_proof.clone())],
        sanctions_nm_proofs_in: vec![None],
        sanctions_nm_proofs_out: vec![None],
        cmt_paths_out: vec![],
        nf_nonmembership: vec![Some(nm_proof)],
        source_pool_policies: vec![],
        dest_pool_policies: vec![],
        pool_policy_paths: vec![],
        cmt_appends_out: vec![append_witness],
        nf_insert_witnesses: vec![circuit_insert_witness],
        cmt_root_old,
        cmt_root_new,
        nft_root_old,
        nft_root_new,
        sanctions_root: F::from(0u64),
        pool_rules_root: F::from(0u64),
        nf_list: vec![nf],
        cm_list: vec![cm_out],
        fee: Amount::from(10u128),
    }
}

#[test]
fn test_generate_transfer_proof() {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║    RAPIDSNARK PROOF GENERATION - TRANSFER CIRCUIT        ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let circuit = create_transfer_circuit();

    // Setup paths
    let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("outputs")
        .join("transfer_proof");

    std::fs::create_dir_all(&base_dir).unwrap();

    let paths = RapidsnarkPaths::new(&base_dir, "transfer");
    paths.ensure_base_dir().unwrap();

    // Config
    let rapidsnark_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("rapidsnark");

    let ptau_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("pot17_final.ptau");

    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir)
        .with_powers_of_tau(&ptau_path);

    // Step 1: Export
    println!("Step 1: Exporting circuit to Circom format...");
    let export_start = std::time::Instant::now();

    let stats = export_to_circom_files(
        circuit,
        &paths.r1cs,
        &paths.witness,
    ).unwrap();

    let export_time = export_start.elapsed();
    println!("  ✓ Export completed in {:.2}s", export_time.as_secs_f64());
    println!("  Stats: {} constraints, {} public inputs",
             stats.num_constraints, stats.num_public_inputs);

    // Step 2: Setup (if needed)
    println!("\nStep 2: Circuit-specific setup...");
    if !paths.proving_key.exists() {
        println!("  Running groth16 setup...");
        let setup_start = std::time::Instant::now();

        let status = std::process::Command::new(&config.snarkjs_path)
            .arg("groth16")
            .arg("setup")
            .arg(&paths.r1cs)
            .arg(&ptau_path)
            .arg(&paths.proving_key)
            .status()
            .unwrap();

        assert!(status.success(), "Setup failed");

        let status = std::process::Command::new(&config.snarkjs_path)
            .arg("zkey")
            .arg("export")
            .arg("verificationkey")
            .arg(&paths.proving_key)
            .arg(&paths.verification_key)
            .status()
            .unwrap();

        assert!(status.success(), "VK export failed");

        let setup_time = setup_start.elapsed();
        println!("  ✓ Setup completed in {:.2}s", setup_time.as_secs_f64());
    } else {
        println!("  ✓ Setup already exists, skipping");
    }

    // Step 3: Prove with Rapidsnark
    println!("\nStep 3: Generating proof with Rapidsnark...");
    let prove_start = std::time::Instant::now();

    let proof_result = rapidsnark_prove(
        &config,
        &paths.proving_key,
        &paths.witness,
        &paths.proof,
        &paths.public_inputs,
    ).unwrap();

    let prove_time = prove_start.elapsed();
    println!("  ✓ Proof generated in {} ms", proof_result.proving_time_ms);

    // Step 4: Verify
    println!("\nStep 4: Verifying proof...");
    let verify_start = std::time::Instant::now();

    let verification = rapidsnark_verify(
        &config,
        &paths.verification_key,
        &paths.public_inputs,
        &paths.proof,
    ).unwrap();

    let verify_time = verify_start.elapsed();
    println!("  ✓ Verification: {} ({} ms)",
             if verification.is_valid { "VALID ✓" } else { "INVALID ✗" },
             verification.verification_time_ms);

    assert!(verification.is_valid, "Proof verification failed!");

    // Summary
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║                  PROOF GENERATED!                        ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ Export:        {:>7.2} s                                ║", export_time.as_secs_f64());
    println!("║ Proving:       {:>7} ms                               ║", proof_result.proving_time_ms);
    println!("║ Verification:  {:>7} ms                               ║", verification.verification_time_ms);
    println!("╠══════════════════════════════════════════════════════════╣");
    println!("║ Proof:         {}  ║", paths.proof.display());
    println!("║ Public inputs: {}  ║", paths.public_inputs.display());
    println!("╚══════════════════════════════════════════════════════════╝\n");
}
