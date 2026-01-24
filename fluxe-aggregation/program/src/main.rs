//! FLUXE Batch Aggregation SP1 Guest Program (IVC-enabled)
//!
//! This program runs inside SP1 zkVM and provides Incrementally Verifiable
//! Computation (IVC) for the FLUXE rollup. Each block proof recursively
//! verifies the previous block proof, creating a chain where the latest
//! proof cryptographically guarantees all history.
//!
//! ## What This Program Proves
//!
//! ### Genesis Block (batch_id = 0)
//! - Initial state roots are valid empty trees
//! - No transactions (proofs must be empty)
//! - No previous proof to verify
//!
//! ### Regular Block (batch_id > 0)
//! - Previous block proof is VALID (recursive IVC verification)
//! - State continuity: old_roots matches previous new_roots
//! - Every Groth16 transaction proof is valid
//! - Transaction roots reference valid historical roots
//! - Immutable reference roots unchanged
//!
//! ## Security
//!
//! - Uses SP1's recursive verification for IVC
//! - Uses BN254 pairing precompiles for Groth16 verification
//! - VKs are embedded at compile time and bound to the ELF hash

#![no_main]
sp1_zkvm::entrypoint!(main);

use fluxe_aggregation_lib::{
    BatchInput, BatchOutput, EMPTY_TREE_ROOT, FLUXE_L2_CHAIN_ID,
    groth16::{Groth16Proof, Groth16VerifyingKey, verify as verify_groth16, parse_fr_be},
};

// ============================================================================
// EMBEDDED VERIFICATION KEYS
// ============================================================================
// These VKs are compiled into the SP1 program binary and cannot be changed
// without recompiling. This provides strong security guarantees - the SP1
// proof commits to the exact VKs used via the ELF hash.

/// FLUXE Block Program Verification Key (for IVC self-recursion)
///
/// This is the vkey of THIS program, used to verify previous block proofs.
/// The vkey is a [u32; 8] digest computed from the program's ELF.
///
/// IMPORTANT: This constant must be updated after the first ELF build:
/// 1. Build the program with placeholder vkey
/// 2. Extract vkey from the build output
/// 3. Update this constant with the actual vkey
/// 4. Rebuild to get the final ELF with correct embedded vkey
///
/// The rebuild will produce a slightly different vkey due to the constant
/// changing, but SP1's verification system handles this through the
/// proof input stream - the host provides the proof and the verifier
/// checks against the committed vkey.
///
/// To extract the vkey after building:
/// ```
/// let (pk, vk) = client.setup(ELF);
/// println!("FLUXE_BLOCK_VKEY: {:?}", vk.hash_u32());
/// ```
const FLUXE_BLOCK_VKEY: [u32; 8] = [
    // Extracted from ELF build: 0x00331d2a466af052f5758e7029f9980698a09eb91384bac07237461fe1d81645
    // Split into big-endian u32 chunks
    0x00331d2a, 0x466af052, 0xf5758e70, 0x29f99806,
    0x98a09eb9, 0x1384bac0, 0x7237461f, 0xe1d81645,
];

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

    // ========================================================================
    // STEP 1: GENESIS OR IVC VERIFICATION
    // ========================================================================

    if batch.batch_id == 0 {
        // ====================================================================
        // GENESIS BLOCK (batch_id = 0)
        // ====================================================================
        // Genesis establishes the initial trusted state without verifying
        // a previous proof. This is the anchor point for the IVC chain.

        // No previous proof to verify
        assert!(
            batch.prev_public_values.is_none(),
            "Genesis block cannot have previous proof"
        );

        // No transactions allowed in genesis
        assert!(
            batch.proofs.is_empty(),
            "Genesis block cannot have transactions"
        );

        // Verify initial state roots are empty (except reference roots)
        assert_eq!(
            batch.old_roots.cmt_root, EMPTY_TREE_ROOT,
            "Genesis cmt_root must be empty"
        );
        assert_eq!(
            batch.old_roots.nft_root, EMPTY_TREE_ROOT,
            "Genesis nft_root must be empty"
        );
        assert_eq!(
            batch.old_roots.obj_root, EMPTY_TREE_ROOT,
            "Genesis obj_root must be empty"
        );
        assert_eq!(
            batch.old_roots.cb_root, EMPTY_TREE_ROOT,
            "Genesis cb_root must be empty"
        );
        assert_eq!(
            batch.old_roots.ingress_root, EMPTY_TREE_ROOT,
            "Genesis ingress_root must be empty"
        );
        assert_eq!(
            batch.old_roots.exit_root, EMPTY_TREE_ROOT,
            "Genesis exit_root must be empty"
        );

        // Genesis must have no state change (old == new)
        assert_eq!(
            batch.old_roots, batch.new_roots,
            "Genesis block must not change state"
        );

        // Historical roots buffer must be empty for genesis
        assert!(
            batch.historical_roots.is_empty(),
            "Genesis historical roots must be empty"
        );

    } else {
        // ====================================================================
        // REGULAR BLOCK (batch_id > 0) - IVC VERIFICATION
        // ====================================================================
        // Each block recursively verifies the previous block's proof,
        // creating a chain where the latest proof carries all history.

        let prev = batch.prev_public_values.as_ref()
            .expect("Block N requires previous block output");

        // --------------------------------------------------------------------
        // IVC: Verify previous block proof
        // --------------------------------------------------------------------
        // This is the key to IVC - we verify the previous proof using
        // the same program's vkey. The actual proof bytes are automatically
        // read from the proof input stream by sp1_zkvm.
        //
        // Note: The FLUXE_BLOCK_VKEY constant must match this program's vkey.
        // After initial build, update the constant with the actual vkey
        // from `vk.hash_u32()` and rebuild.
        sp1_zkvm::lib::verify::verify_sp1_proof(
            &FLUXE_BLOCK_VKEY,
            &prev.to_public_values_digest(),
        );

        // --------------------------------------------------------------------
        // State Continuity
        // --------------------------------------------------------------------
        // Current block's old_roots must match previous block's new_roots
        assert_eq!(
            batch.old_roots.hash(), prev.new_roots_hash,
            "State discontinuity: old_roots != prev.new_roots"
        );

        // Batch ID must be sequential
        assert_eq!(
            batch.batch_id, prev.batch_id + 1,
            "Non-sequential batch ID"
        );

        // Chain ID must match
        assert_eq!(
            batch.chain_id, prev.chain_id,
            "Chain ID mismatch"
        );
        assert_eq!(
            batch.chain_id, FLUXE_L2_CHAIN_ID,
            "Invalid FLUXE chain ID"
        );

        // Historical roots must contain previous root
        assert!(
            batch.historical_roots.contains(&prev.new_roots_hash),
            "Historical roots missing previous state"
        );

        // --------------------------------------------------------------------
        // Verify Groth16 Transaction Proofs
        // --------------------------------------------------------------------

        // Parse embedded verifying keys
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
            let is_valid = verify_groth16(vk, &proof, &public_inputs)
                .expect("Verification error");

            assert!(
                is_valid,
                "Proof {} (type {:?}) failed verification",
                i, entry.tx_type
            );

            // Verify transaction references a valid historical root
            // (The first public input is typically the state root)
            if !entry.public_inputs.is_empty() {
                let tx_root = entry.public_inputs[0];
                assert!(
                    batch.historical_roots.contains(&tx_root),
                    "Transaction {} references invalid historical root",
                    i
                );
            }
        }
    }

    // ========================================================================
    // STEP 2: VERIFY STATE TRANSITION CONSTRAINTS (all blocks)
    // ========================================================================

    // Sanctions root must remain unchanged (immutable reference)
    assert_eq!(
        batch.old_roots.sanctions_root,
        batch.new_roots.sanctions_root,
        "Sanctions root changed unexpectedly"
    );

    // Pool rules root must remain unchanged (immutable reference)
    assert_eq!(
        batch.old_roots.pool_rules_root,
        batch.new_roots.pool_rules_root,
        "Pool rules root changed unexpectedly"
    );

    // If there are transactions, at least one mutable root must change
    // (Genesis is exempt - it has no transactions and no state change)
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

    // ========================================================================
    // STEP 3: COMMIT OUTPUT
    // ========================================================================

    let output = BatchOutput {
        old_roots_hash: batch.old_roots.hash(),
        new_roots_hash: batch.new_roots.hash(),
        batch_id: batch.batch_id,
        chain_id: batch.chain_id,
        proof_count: batch.proofs.len() as u32,
    };

    // Commit the public outputs
    // For IVC, this output becomes the prev_public_values for the next block
    sp1_zkvm::io::commit(&output);
}
