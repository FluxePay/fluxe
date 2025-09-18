use ark_bls12_381::Fr as F;

/// Domain separator for note commitments
pub const DOM_NOTE: &[u8; 32] = b"FLUXE_NOTE_COMMITMENT___________";

/// Domain separator for nullifiers  
pub const DOM_NF: &[u8; 32] = b"FLUXE_NULLIFIER_________________";

/// Domain separator for zk-objects
pub const DOM_OBJ: &[u8; 32] = b"FLUXE_ZKOBJECT__________________";

/// Domain separator for callbacks
pub const DOM_CB: &[u8; 32] = b"FLUXE_CALLBACK__________________";

/// Domain separator for pools
pub const DOM_POOL: &[u8; 32] = b"FLUXE_POOL______________________";

/// Domain separator for exit receipts
pub const DOM_EXIT: &[u8; 32] = b"FLUXE_EXIT_RECEIPT______________";

/// Domain separator for ingress receipts
pub const DOM_INGRESS: &[u8; 32] = b"FLUXE_INGRESS_RECEIPT___________";

/// Convert domain separator to field element
pub fn domain_sep_to_field(sep: &[u8; 32]) -> F {
    crate::utils::bytes_to_field(sep)
}