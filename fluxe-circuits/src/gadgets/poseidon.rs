use ark_bls12_381::Fr as F;
use ark_crypto_primitives::crh::{
    poseidon::constraints::CRHGadget,
    CRHScheme, CRHSchemeGadget,
};
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use fluxe_core::crypto::poseidon::gen_poseidon_params;

/// Poseidon hash gadget for circuits
pub fn poseidon_hash_zk(input: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
    use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
    
    // Always use rate 8 for consistency with native poseidon_hash
    let params = gen_poseidon_params(8, false);
    let params_var = CRHParametersVar { parameters: params };
    CRHGadget::evaluate(&params_var, input)
}