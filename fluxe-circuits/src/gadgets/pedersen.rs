//! INSECURE / REMOVED:
//! This module previously exposed a PedersenCommitmentVar that pretended to verify an opening.
//! It is now disabled at compile-time to prevent accidental inclusion. Use `pedersen_ec` (Jubjub)
//! with a *matching* native implementation, or treat commitments as opaque F elements with no opening.

compile_error!("gadgets::pedersen is disabled. Use gadgets::pedersen_ec (matched curve) or model commitments as opaque fields (no opening).");