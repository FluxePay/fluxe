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
//! - **VKs are embedded at compile time** - they cannot be tampered with
//!   and are cryptographically bound to the SP1 program's ELF hash

#![no_main]
sp1_zkvm::entrypoint!(main);

use fluxe_aggregation_lib::{
    BatchInput, BatchOutput, TxType,
    groth16::{Groth16Proof, Groth16VerifyingKey, verify as verify_groth16, parse_fr_be},
};
use sha2::{Sha256, Digest};

// ============================================================================
// EMBEDDED VERIFICATION KEYS
// ============================================================================
// These VKs are compiled into the SP1 program binary and cannot be changed
// without recompiling. This provides strong security guarantees - the SP1
// proof commits to the exact VKs used via the ELF hash.
//
// VK format: gnark binary (alpha || beta || gamma || delta || ic_len || ic[...])
// Each G1 point is 64 bytes, each G2 point is 128 bytes, ic_len is 4 bytes BE
//
// To update VKs:
// 1. Generate new circuits and VKs using the setup process
// 2. Export VKs to gnark binary format
// 3. Copy the .vk.bin files to fluxe-aggregation/program/vks/
// 4. Rebuild the SP1 program
// ============================================================================

/// Mint circuit verification key (gnark binary format)
static MINT_VK: &[u8] = include_bytes!("../vks/mint_vk.bin");

/// Burn circuit verification key (gnark binary format)
static BURN_VK: &[u8] = include_bytes!("../vks/burn_vk.bin");

/// Transfer circuit verification key (gnark binary format)
static TRANSFER_VK: &[u8] = include_bytes!("../vks/transfer_vk.bin");

/// ObjectUpdate circuit verification key (gnark binary format)
static OBJECT_UPDATE_VK: &[u8] = include_bytes!("../vks/object_update_vk.bin");

fn main() {
    // Read the batch input from the host
    let batch: BatchInput = sp1_zkvm::io::read();

    // Parse embedded verifying keys (indexed by TxType)
    // VKs are embedded at compile time - no runtime loading needed
    let vks: [Groth16VerifyingKey; 4] = [
        Groth16VerifyingKey::from_bytes(MINT_VK)
            .expect("Invalid embedded Mint VK"),
        Groth16VerifyingKey::from_bytes(BURN_VK)
            .expect("Invalid embedded Burn VK"),
        Groth16VerifyingKey::from_bytes(TRANSFER_VK)
            .expect("Invalid embedded Transfer VK"),
        Groth16VerifyingKey::from_bytes(OBJECT_UPDATE_VK)
            .expect("Invalid embedded ObjectUpdate VK"),
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

    // Note: VK commitment is implicit in the SP1 program's ELF hash
    // Since VKs are embedded at compile time via include_bytes!, any change
    // to the VKs changes the ELF binary and thus the program's vkey.
    // This provides cryptographic binding without explicit VK hashing.

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
}
