use ark_bls12_381::Fr as F;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_std::rand::thread_rng;
use ark_ff::UniformRand;

use fluxe_circuits::gadgets::auth::AuthGadget;
use fluxe_circuits::utils::ec_helpers::compute_owner_address_circuit_compatible;

#[test]
fn test_ec_auth_two_owners() {
    println!("\n=== Testing EC auth for two owners ===\n");
    let mut rng = thread_rng();
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Generate two owner secret keys
    let owner_sk1 = F::rand(&mut rng);
    let owner_sk2 = F::rand(&mut rng);
    
    println!("Owner SK 1: {:?}", owner_sk1);
    println!("Owner SK 2: {:?}", owner_sk2);
    
    // Compute expected addresses
    let expected_addr1 = compute_owner_address_circuit_compatible(owner_sk1);
    let expected_addr2 = compute_owner_address_circuit_compatible(owner_sk2);
    
    println!("\nExpected addr 1: {:?}", expected_addr1);
    println!("Expected addr 2: {:?}", expected_addr2);
    
    // Create witness variables
    let owner_sk1_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk1)).unwrap();
    let owner_sk2_var = FpVar::new_witness(cs.clone(), || Ok(owner_sk2)).unwrap();
    
    let expected_addr1_var = FpVar::new_witness(cs.clone(), || Ok(expected_addr1)).unwrap();
    let expected_addr2_var = FpVar::new_witness(cs.clone(), || Ok(expected_addr2)).unwrap();
    
    println!("\nConstraints before EC auth: {}", cs.num_constraints());
    
    // Process first owner
    println!("\nProcessing owner 1:");
    let (pk1_x_fq, pk1_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk1_var).unwrap();
    let computed_addr1 = AuthGadget::compute_owner_address_from_fq(cs.clone(), &pk1_x_fq, &pk1_y_fq).unwrap();
    computed_addr1.enforce_equal(&expected_addr1_var).unwrap();
    
    let constraints_after_1 = cs.num_constraints();
    println!("  Constraints after owner 1: {} (+{})", constraints_after_1, constraints_after_1);
    
    // Process second owner
    println!("\nProcessing owner 2:");
    let (pk2_x_fq, pk2_y_fq) = AuthGadget::scalar_mult_generator(cs.clone(), &owner_sk2_var).unwrap();
    let computed_addr2 = AuthGadget::compute_owner_address_from_fq(cs.clone(), &pk2_x_fq, &pk2_y_fq).unwrap();
    computed_addr2.enforce_equal(&expected_addr2_var).unwrap();
    
    let constraints_after_2 = cs.num_constraints();
    println!("  Constraints after owner 2: {} (+{})", 
        constraints_after_2, constraints_after_2 - constraints_after_1);
    
    // Check satisfaction
    if !cs.is_satisfied().unwrap() {
        if let Ok(Some(unsat)) = cs.which_is_unsatisfied() {
            panic!("❌ First unsatisfied constraint: {}", unsat);
        }
        panic!("Constraints not satisfied!");
    } else {
        println!("\n✅ All EC auth constraints satisfied!");
    }
}