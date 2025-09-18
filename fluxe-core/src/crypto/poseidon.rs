use ark_bls12_381::Fr as F;
use ark_crypto_primitives::{
    crh::{
        poseidon::{self},
        CRHScheme,
    },
    sponge::{
        poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge, PoseidonDefaultConfigEntry},
        CryptographicSponge,
    },
};
use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

/// Generate Poseidon parameters for BLS12-381
pub fn gen_poseidon_params(rate: usize, optimized_for_weights: bool) -> PoseidonConfig<F> {
    let params_set = if !optimized_for_weights {
        [
            PoseidonDefaultConfigEntry::new(2, 17, 8, 31, 0),
            PoseidonDefaultConfigEntry::new(3, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(4, 5, 8, 56, 0),
            PoseidonDefaultConfigEntry::new(5, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(6, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(7, 5, 8, 57, 0),
            PoseidonDefaultConfigEntry::new(8, 5, 8, 57, 0),
        ]
    } else {
        [
            PoseidonDefaultConfigEntry::new(2, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(3, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(4, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(5, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(6, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(7, 257, 8, 13, 0),
            PoseidonDefaultConfigEntry::new(8, 257, 8, 13, 0),
        ]
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                F::MODULUS_BIT_SIZE as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return PoseidonConfig {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            };
        }
    }

    panic!("could not generate poseidon params");
}

/// Poseidon hash function for field elements
pub fn poseidon_hash(input: &[F]) -> F {
    // Always use rate 8 for consistency across all hashes
    // This ensures the same parameters are used in both native and circuit contexts
    let params = gen_poseidon_params(8, false);
    poseidon::CRH::evaluate(&params, input).unwrap()
}

/// Poseidon hash function for ZK circuits
pub fn poseidon_hash_zk(input: &[FpVar<F>]) -> Result<FpVar<F>, SynthesisError> {
    use ark_crypto_primitives::crh::constraints::CRHSchemeGadget;
    use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, CRHParametersVar};
    
    // Use same rate as native poseidon_hash for consistency
    let params = gen_poseidon_params(8, false);
    let params_var = CRHParametersVar { parameters: params };
    CRHGadget::evaluate(&params_var, input)
}

/// Poseidon-2 hash function (optimized version)
pub fn poseidon2_hash(input: &[F]) -> F {
    // Using standard Poseidon for now, can optimize later
    poseidon_hash(input)
}

/// Create a Poseidon sponge for absorption/squeezing
pub fn create_poseidon_sponge() -> PoseidonSponge<F> {
    let config = gen_poseidon_params(2, false);
    PoseidonSponge::new(&config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_poseidon_hash() {
        let mut rng = thread_rng();
        let input = vec![F::rand(&mut rng), F::rand(&mut rng)];
        let output = poseidon_hash(&input);
        
        // Hash should be deterministic
        let output2 = poseidon_hash(&input);
        assert_eq!(output, output2);
    }

    #[test]
    fn test_poseidon_sponge() {
        let mut rng = thread_rng();
        let mut sponge = create_poseidon_sponge();
        
        let input = F::rand(&mut rng);
        sponge.absorb(&input);
        
        let output = sponge.squeeze_field_elements::<F>(1);
        assert_eq!(output.len(), 1);
    }
}