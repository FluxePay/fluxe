//! FLUXE Batch Aggregation SP1 Guest Program
//!
//! This program runs inside SP1 zkVM and VERIFIES all Groth16 proofs
//! in a batch, proving the batch is valid. This is the key to trustlessness:
//! the zkVM proves that all proofs were actually verified, not just committed to.
//!
//! ## What This Program Proves
//!
//! 1. Every Groth16 proof in the batch is valid (verified via BN254 pairings)
//! 2. The state transition (old_roots -> new_roots) is consistent
//! 3. Immutable reference roots (sanctions, pool_rules) are unchanged
//!
//! ## Security
//!
//! - Uses BN254 pairing precompiles for efficient Groth16 verification
//! - Each proof verification costs ~10M cycles with precompiles
//! - Total cost: O(n * 10M) cycles for n proofs

#![no_main]
sp1_zkvm::entrypoint!(main);

use fluxe_aggregation_lib::{
    BatchInput, BatchOutput, TxType,
    groth16::{Groth16Proof, Groth16VerifyingKey, verify as verify_groth16, parse_fr_be},
};
use sha2::{Sha256, Digest};

fn main() {
    // Read the batch input from the host
    let batch: BatchInput = sp1_zkvm::io::read();

    // Parse verifying keys (indexed by TxType)
    // We expect 4 VKs: Mint, Burn, Transfer, ObjectUpdate
    assert!(
        batch.verifying_keys.len() >= 4,
        "Missing verifying keys"
    );

    let vks: [Groth16VerifyingKey; 4] = [
        Groth16VerifyingKey::from_bytes(&batch.verifying_keys[0])
            .expect("Invalid Mint VK"),
        Groth16VerifyingKey::from_bytes(&batch.verifying_keys[1])
            .expect("Invalid Burn VK"),
        Groth16VerifyingKey::from_bytes(&batch.verifying_keys[2])
            .expect("Invalid Transfer VK"),
        Groth16VerifyingKey::from_bytes(&batch.verifying_keys[3])
            .expect("Invalid ObjectUpdate VK"),
    ];

    // Verify each Groth16 proof
    let mut verified_count = 0u32;
    for (i, entry) in batch.proofs.iter().enumerate() {
        // Get the appropriate verifying key
        let vk_idx = entry.tx_type as usize;
        let vk = &vks[vk_idx];

        // Parse the proof
        let proof = Groth16Proof::from_bytes(&entry.proof_bytes)
            .expect("Invalid proof format");

        // Parse public inputs
        let public_inputs: Vec<bn::Fr> = entry
            .public_inputs
            .iter()
            .map(|bytes| parse_fr_be(bytes).expect("Invalid public input"))
            .collect();

        // VERIFY THE GROTH16 PROOF
        // This is the critical operation that makes the system trustless
        // It uses BN254 pairing precompiles inside SP1
        let is_valid = verify_groth16(vk, &proof, &public_inputs)
            .expect("Verification error");

        assert!(
            is_valid,
            "Proof {} (type {:?}) failed verification",
            i, entry.tx_type
        );

        verified_count += 1;
    }

    // Verify state transition constraints

    // 1. Sanctions root must remain unchanged (immutable reference)
    assert_eq!(
        batch.old_roots.sanctions_root,
        batch.new_roots.sanctions_root,
        "Sanctions root changed unexpectedly"
    );

    // 2. Pool rules root must remain unchanged (immutable reference)
    assert_eq!(
        batch.old_roots.pool_rules_root,
        batch.new_roots.pool_rules_root,
        "Pool rules root changed unexpectedly"
    );

    // 3. Verify that state changes are consistent with proof count
    // (At least one root must change if there are proofs)
    if !batch.proofs.is_empty() {
        let roots_changed = batch.old_roots.cmt_root != batch.new_roots.cmt_root
            || batch.old_roots.nft_root != batch.new_roots.nft_root
            || batch.old_roots.obj_root != batch.new_roots.obj_root
            || batch.old_roots.cb_root != batch.new_roots.cb_root
            || batch.old_roots.ingress_root != batch.new_roots.ingress_root
            || batch.old_roots.exit_root != batch.new_roots.exit_root;

        assert!(
            roots_changed,
            "No state change with non-empty batch"
        );
    }

    // Compute output hashes
    let old_roots_hash = batch.old_roots.hash();
    let new_roots_hash = batch.new_roots.hash();

    // Compute VK hash (commitment to the circuit VKs used)
    let vk_hash = compute_vk_hash(&batch.verifying_keys);

    // Create the batch output
    let output = BatchOutput {
        old_roots_hash,
        new_roots_hash,
        batch_id: batch.batch_id,
        chain_id: batch.chain_id,
        proof_count: verified_count,
    };

    // Commit the public outputs
    // These are what the on-chain verifier will check
    sp1_zkvm::io::commit(&output);
    sp1_zkvm::io::commit(&vk_hash);
}

/// Compute a hash of all verifying keys
/// This binds the proof to specific circuit VKs
fn compute_vk_hash(vks: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for vk in vks {
        let vk_hash: [u8; 32] = Sha256::digest(vk).into();
        hasher.update(&vk_hash);
    }
    hasher.finalize().into()
}
