//! Groth16 Verification for FLUXE Bridge
//!
//! This module provides Groth16 proof verification using the groth16-solana crate
//! which leverages Solana's alt_bn128 precompiled syscalls for efficient verification.
//!
//! ## Verification Key Generation
//!
//! The FLUXE protocol uses a two-layer proof system:
//!
//! 1. **Individual Transaction Proofs**: Each transaction type (Mint, Burn, Transfer,
//!    ObjectUpdate) has its own circuit and VK. These proofs are verified inside SP1.
//!
//! 2. **Batch Aggregation Proof**: SP1 verifies all individual proofs and produces
//!    an aggregated proof. This batch proof is verified on-chain.
//!
//! ### VK Export Tool
//!
//! Use the export_vk tool to convert gnark binary VKs to Rust format:
//!
//! ```bash
//! cargo run --bin export_vk -p fluxe-circuits -- path/to/vk.bin --rust --name BATCH
//! ```
//!
//! ### Public Inputs Format
//!
//! The batch proof public inputs are:
//! - [0] State roots hash (32 bytes) - SHA256 of all 8 state tree roots
//! - [1] Batch ID (32 bytes, big-endian padded)
//! - [2] Transaction count (32 bytes, big-endian padded)

pub use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

/// Number of public inputs for FLUXE batch proof
/// Format: [state_roots_hash, batch_id, tx_count]
pub const FLUXE_NR_PUBLIC_INPUTS: usize = 3;

/// FLUXE Batch Verification Key
///
/// IMPORTANT: These are PLACEHOLDER values generated from a test circuit.
/// They must be replaced with the actual VK from the FLUXE batch circuit setup.
///
/// To generate the real VK:
/// 1. Run the FLUXE batch circuit setup
/// 2. Export using: `cargo run --bin export_vk -- batch_vk.bin --rust --name FLUXE`
/// 3. Replace the values below with the exported constants
///
/// The placeholder values below are derived from the mint circuit VK structure
/// to ensure the format is correct for groth16-solana verification.
pub const FLUXE_VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {
    nr_pubinputs: FLUXE_NR_PUBLIC_INPUTS,

    // Alpha (G1) - From groth16-solana test vector
    vk_alpha_g1: [
        45u8, 77u8, 154u8, 167u8, 227u8, 2u8, 217u8, 223u8, 65u8, 116u8, 157u8, 85u8, 7u8, 148u8, 157u8, 5u8,
        219u8, 234u8, 51u8, 251u8, 177u8, 108u8, 100u8, 59u8, 34u8, 245u8, 153u8, 162u8, 190u8, 109u8, 242u8, 226u8,
        20u8, 190u8, 221u8, 80u8, 60u8, 55u8, 206u8, 176u8, 97u8, 216u8, 236u8, 96u8, 32u8, 159u8, 227u8, 69u8,
        206u8, 137u8, 131u8, 10u8, 25u8, 35u8, 3u8, 1u8, 240u8, 118u8, 202u8, 255u8, 0u8, 77u8, 25u8, 38u8
    ],

    // Beta (G2) - From groth16-solana test vector
    vk_beta_g2: [
        9u8, 103u8, 3u8, 47u8, 203u8, 247u8, 118u8, 209u8, 175u8, 201u8, 133u8, 248u8, 136u8, 119u8, 241u8, 130u8,
        211u8, 132u8, 128u8, 166u8, 83u8, 242u8, 222u8, 202u8, 169u8, 121u8, 76u8, 188u8, 59u8, 243u8, 6u8, 12u8,
        14u8, 24u8, 120u8, 71u8, 173u8, 76u8, 121u8, 131u8, 116u8, 208u8, 214u8, 115u8, 43u8, 245u8, 1u8, 132u8,
        125u8, 214u8, 139u8, 192u8, 224u8, 113u8, 36u8, 30u8, 2u8, 19u8, 188u8, 127u8, 193u8, 61u8, 183u8, 171u8,
        48u8, 76u8, 251u8, 209u8, 224u8, 138u8, 112u8, 74u8, 153u8, 245u8, 232u8, 71u8, 217u8, 63u8, 140u8, 60u8,
        170u8, 253u8, 222u8, 196u8, 107u8, 122u8, 13u8, 55u8, 157u8, 166u8, 154u8, 77u8, 17u8, 35u8, 70u8, 167u8,
        23u8, 57u8, 193u8, 177u8, 164u8, 87u8, 168u8, 199u8, 49u8, 49u8, 35u8, 210u8, 77u8, 47u8, 145u8, 146u8,
        248u8, 150u8, 183u8, 198u8, 62u8, 234u8, 5u8, 169u8, 213u8, 127u8, 6u8, 84u8, 122u8, 208u8, 206u8, 200u8
    ],

    // Gamma (G2) - Standard BN254 generator point
    vk_gamma_g2: [
        25u8, 142u8, 147u8, 147u8, 146u8, 13u8, 72u8, 58u8, 114u8, 96u8, 191u8, 183u8, 49u8, 251u8, 93u8, 37u8,
        241u8, 170u8, 73u8, 51u8, 53u8, 169u8, 231u8, 18u8, 151u8, 228u8, 133u8, 183u8, 174u8, 243u8, 18u8, 194u8,
        24u8, 0u8, 222u8, 239u8, 18u8, 31u8, 30u8, 118u8, 66u8, 106u8, 0u8, 102u8, 94u8, 92u8, 68u8, 121u8,
        103u8, 67u8, 34u8, 212u8, 247u8, 94u8, 218u8, 221u8, 70u8, 222u8, 189u8, 92u8, 217u8, 146u8, 246u8, 237u8,
        9u8, 6u8, 137u8, 208u8, 88u8, 95u8, 240u8, 117u8, 236u8, 158u8, 153u8, 173u8, 105u8, 12u8, 51u8, 149u8,
        188u8, 75u8, 49u8, 51u8, 112u8, 179u8, 142u8, 243u8, 85u8, 172u8, 218u8, 220u8, 209u8, 34u8, 151u8, 91u8,
        18u8, 200u8, 94u8, 165u8, 219u8, 140u8, 109u8, 235u8, 74u8, 171u8, 113u8, 128u8, 141u8, 203u8, 64u8, 143u8,
        227u8, 209u8, 231u8, 105u8, 12u8, 67u8, 211u8, 123u8, 76u8, 230u8, 204u8, 1u8, 102u8, 250u8, 125u8, 170u8
    ],

    // Delta (G2) - From groth16-solana test vector
    vk_delta_g2: [
        29u8, 101u8, 86u8, 247u8, 6u8, 195u8, 12u8, 191u8, 43u8, 222u8, 235u8, 242u8, 147u8, 233u8, 121u8, 93u8,
        83u8, 252u8, 44u8, 61u8, 94u8, 229u8, 105u8, 232u8, 9u8, 253u8, 67u8, 31u8, 174u8, 9u8, 16u8, 187u8,
        27u8, 125u8, 210u8, 232u8, 114u8, 142u8, 123u8, 67u8, 44u8, 126u8, 11u8, 182u8, 127u8, 1u8, 20u8, 144u8,
        1u8, 164u8, 61u8, 63u8, 135u8, 177u8, 180u8, 193u8, 178u8, 98u8, 206u8, 69u8, 227u8, 229u8, 89u8, 66u8,
        41u8, 82u8, 242u8, 150u8, 164u8, 228u8, 129u8, 0u8, 233u8, 115u8, 15u8, 189u8, 40u8, 32u8, 52u8, 82u8,
        239u8, 56u8, 158u8, 185u8, 139u8, 27u8, 72u8, 139u8, 122u8, 110u8, 89u8, 64u8, 244u8, 137u8, 155u8, 220u8,
        27u8, 62u8, 173u8, 25u8, 4u8, 255u8, 70u8, 49u8, 164u8, 34u8, 141u8, 154u8, 59u8, 27u8, 209u8, 25u8,
        232u8, 157u8, 58u8, 143u8, 148u8, 105u8, 178u8, 66u8, 226u8, 156u8, 68u8, 197u8, 234u8, 139u8, 5u8, 176u8
    ],

    // IC points (4 total: IC[0] constant + 3 public inputs)
    vk_ic: &FLUXE_VK_IC,
};

/// IC points for FLUXE batch verification key
///
/// PLACEHOLDER: These values must come from the batch circuit trusted setup.
/// IC[0] is the constant term, IC[1..3] correspond to the 3 public inputs.
pub const FLUXE_VK_IC: [[u8; 64]; 4] = [
    // IC[0] - constant term (from groth16-solana test)
    [
        12u8, 192u8, 31u8, 5u8, 252u8, 153u8, 69u8, 152u8, 16u8, 193u8, 229u8, 27u8, 107u8, 12u8, 131u8, 157u8,
        181u8, 114u8, 177u8, 46u8, 213u8, 38u8, 159u8, 73u8, 102u8, 40u8, 81u8, 214u8, 58u8, 242u8, 73u8, 236u8,
        0u8, 58u8, 182u8, 252u8, 156u8, 30u8, 52u8, 250u8, 147u8, 222u8, 206u8, 111u8, 25u8, 4u8, 107u8, 115u8,
        113u8, 133u8, 43u8, 77u8, 19u8, 249u8, 34u8, 131u8, 134u8, 29u8, 211u8, 140u8, 237u8, 147u8, 30u8, 7u8
    ],
    // IC[1] - state_roots_hash coefficient
    [
        9u8, 110u8, 51u8, 213u8, 168u8, 169u8, 164u8, 244u8, 19u8, 76u8, 14u8, 226u8, 213u8, 125u8, 216u8, 90u8,
        119u8, 166u8, 116u8, 61u8, 176u8, 65u8, 159u8, 48u8, 229u8, 17u8, 174u8, 208u8, 151u8, 239u8, 129u8, 240u8,
        31u8, 23u8, 226u8, 142u8, 142u8, 189u8, 121u8, 137u8, 47u8, 204u8, 35u8, 136u8, 216u8, 198u8, 164u8, 12u8,
        93u8, 183u8, 45u8, 207u8, 112u8, 240u8, 113u8, 41u8, 111u8, 19u8, 197u8, 177u8, 167u8, 71u8, 172u8, 125u8
    ],
    // IC[2] - batch_id coefficient
    [
        42u8, 196u8, 14u8, 64u8, 95u8, 212u8, 162u8, 19u8, 5u8, 80u8, 227u8, 221u8, 1u8, 190u8, 42u8, 223u8,
        97u8, 165u8, 33u8, 109u8, 138u8, 210u8, 40u8, 82u8, 231u8, 37u8, 29u8, 98u8, 180u8, 32u8, 101u8, 225u8,
        38u8, 201u8, 17u8, 234u8, 168u8, 4u8, 165u8, 151u8, 1u8, 204u8, 196u8, 33u8, 147u8, 161u8, 210u8, 91u8,
        200u8, 239u8, 230u8, 152u8, 163u8, 3u8, 232u8, 1u8, 33u8, 55u8, 28u8, 149u8, 241u8, 133u8, 25u8, 207u8
    ],
    // IC[3] - tx_count coefficient
    [
        37u8, 193u8, 7u8, 139u8, 47u8, 18u8, 214u8, 151u8, 196u8, 40u8, 110u8, 111u8, 149u8, 1u8, 58u8, 190u8,
        105u8, 197u8, 122u8, 12u8, 98u8, 38u8, 24u8, 5u8, 123u8, 31u8, 26u8, 50u8, 18u8, 175u8, 245u8, 140u8,
        26u8, 182u8, 233u8, 126u8, 204u8, 44u8, 225u8, 78u8, 38u8, 138u8, 242u8, 127u8, 3u8, 31u8, 89u8, 84u8,
        137u8, 139u8, 182u8, 94u8, 88u8, 190u8, 177u8, 253u8, 207u8, 84u8, 232u8, 115u8, 231u8, 205u8, 235u8, 186u8
    ],
];

/// Verify a FLUXE batch proof using groth16-solana
///
/// # Arguments
/// * `proof_a` - Proof A point (G1, 64 bytes)
/// * `proof_b` - Proof B point (G2, 128 bytes)
/// * `proof_c` - Proof C point (G1, 64 bytes)
/// * `public_inputs` - Public inputs array (32 bytes each, big-endian)
///
/// # Returns
/// `Ok(())` if proof is valid, `Err` otherwise
///
/// # Example
/// ```ignore
/// let result = verify_fluxe_proof(
///     &proof_a,
///     &proof_b,
///     &proof_c,
///     &[state_roots_hash, batch_id_bytes, tx_count_bytes],
/// );
/// ```
pub fn verify_fluxe_proof<const N: usize>(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs: &[[u8; 32]; N],
) -> Result<(), groth16_solana::errors::Groth16Error> {
    let mut verifier = Groth16Verifier::new(
        proof_a,
        proof_b,
        proof_c,
        public_inputs,
        &FLUXE_VERIFYING_KEY,
    )?;

    verifier.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vk_structure() {
        // Verify the VK has correct structure
        assert_eq!(FLUXE_VERIFYING_KEY.nr_pubinputs, FLUXE_NR_PUBLIC_INPUTS);
        assert_eq!(FLUXE_VK_IC.len(), FLUXE_NR_PUBLIC_INPUTS + 1);
    }

    #[test]
    fn test_g1_point_format() {
        // G1 points should be 64 bytes (32 for x, 32 for y)
        assert_eq!(FLUXE_VERIFYING_KEY.vk_alpha_g1.len(), 64);
        for ic in FLUXE_VK_IC.iter() {
            assert_eq!(ic.len(), 64);
        }
    }

    #[test]
    fn test_g2_point_format() {
        // G2 points should be 128 bytes
        assert_eq!(FLUXE_VERIFYING_KEY.vk_beta_g2.len(), 128);
        assert_eq!(FLUXE_VERIFYING_KEY.vk_gamma_g2.len(), 128);
        assert_eq!(FLUXE_VERIFYING_KEY.vk_delta_g2.len(), 128);
    }
}
