//! Benchmark comparing rapidsnark vs native arkworks proving
//!
//! Run with: cargo bench --bench rapidsnark_comparison

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey};
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_snark::SNARK;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use fluxe_circuits::rapidsnark::*;
use rand::thread_rng;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Simple circuit for benchmarking: computes a^2 + b^2 = c
#[derive(Clone)]
struct SimpleSquareCircuit {
    a: Fr,
    b: Fr,
    c: Fr,
}

impl ConstraintSynthesizer<Fr> for SimpleSquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let a_var = FpVar::new_witness(cs.clone(), || Ok(self.a))?;
        let b_var = FpVar::new_witness(cs.clone(), || Ok(self.b))?;
        let c_var = FpVar::new_input(cs, || Ok(self.c))?;

        // a^2
        let a_squared = &a_var * &a_var;
        // b^2
        let b_squared = &b_var * &b_var;
        // a^2 + b^2
        let sum = a_squared + b_squared;

        sum.enforce_equal(&c_var)?;

        Ok(())
    }
}

/// More complex circuit: nested multiplications and additions
#[derive(Clone)]
struct ComplexCircuit {
    inputs: Vec<Fr>,
    expected: Fr,
}

impl ConstraintSynthesizer<Fr> for ComplexCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut vars = Vec::new();
        for inp in self.inputs.iter() {
            vars.push(FpVar::new_witness(cs.clone(), || Ok(*inp))?);
        }

        let result_var = FpVar::new_input(cs, || Ok(self.expected))?;

        // Compute: ((a * b) + (c * d)) * ((e * f) + (g * h))
        let ab = &vars[0] * &vars[1];
        let cd = &vars[2] * &vars[3];
        let ef = &vars[4] * &vars[5];
        let gh = &vars[6] * &vars[7];

        let left = ab + cd;
        let right = ef + gh;
        let result = left * right;

        result.enforce_equal(&result_var)?;

        Ok(())
    }
}

fn setup_simple_circuit() -> (ProvingKey<Bn254>, Fr, Fr, Fr) {
    let mut rng = thread_rng();
    let a = Fr::from(3u32);
    let b = Fr::from(4u32);
    let c = Fr::from(25u32); // 3^2 + 4^2 = 9 + 16 = 25

    let circuit = SimpleSquareCircuit { a, b, c };
    let (pk, _vk) = Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(circuit, &mut rng)
        .expect("Setup failed");

    (pk, a, b, c)
}

fn setup_complex_circuit() -> (ProvingKey<Bn254>, Vec<Fr>, Fr) {
    let mut rng = thread_rng();
    let inputs = vec![
        Fr::from(2u32), Fr::from(3u32),
        Fr::from(4u32), Fr::from(5u32),
        Fr::from(6u32), Fr::from(7u32),
        Fr::from(8u32), Fr::from(9u32),
    ];

    // (2*3 + 4*5) * (6*7 + 8*9) = (6 + 20) * (42 + 72) = 26 * 114 = 2964
    let expected = Fr::from(2964u32);

    let circuit = ComplexCircuit {
        inputs: inputs.clone(),
        expected,
    };

    let (pk, _vk) = Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(circuit.clone(), &mut rng)
        .expect("Setup failed");

    (pk, inputs, expected)
}

fn bench_arkworks_proving(c: &mut Criterion) {
    let mut group = c.benchmark_group("arkworks_native");

    // Simple circuit
    {
        let (pk, a, b, c_val) = setup_simple_circuit();
        let mut rng = thread_rng();

        group.bench_function("simple_circuit", |bench| {
            bench.iter(|| {
                let circuit = SimpleSquareCircuit { a, b, c: c_val };
                Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit, &mut rng)
                    .expect("Proof generation failed")
            });
        });
    }

    // Complex circuit
    {
        let (pk, inputs, expected) = setup_complex_circuit();
        let mut rng = thread_rng();

        group.bench_function("complex_circuit", |bench| {
            bench.iter(|| {
                let circuit = ComplexCircuit {
                    inputs: inputs.clone(),
                    expected,
                };
                Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit, &mut rng)
                    .expect("Proof generation failed")
            });
        });
    }

    group.finish();
}

fn bench_rapidsnark_proving(c: &mut Criterion) {
    // Check if rapidsnark is available
    let rapidsnark_dir = PathBuf::from("../rapidsnark");
    if !rapidsnark_dir.exists() {
        println!("Skipping rapidsnark benchmarks - rapidsnark not found at ../rapidsnark");
        return;
    }

    let mut group = c.benchmark_group("rapidsnark");
    group.measurement_time(Duration::from_secs(30));

    let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir);

    // Simple circuit
    {
        let base_dir = PathBuf::from("outputs/bench_simple");
        std::fs::create_dir_all(&base_dir).ok();
        let paths = RapidsnarkPaths::new(&base_dir, "simple");

        // Setup once
        let a = Fr::from(3u32);
        let b = Fr::from(4u32);
        let c_val = Fr::from(25u32);
        let circuit = SimpleSquareCircuit { a, b, c: c_val };

        export_to_circom_files(circuit.clone(), &paths.r1cs, &paths.witness).ok();
        complete_setup(&config, &paths.r1cs, &paths.proving_key, &paths.verification_key, 8).ok();

        group.bench_function("simple_circuit", |bench| {
            bench.iter_custom(|iters| {
                let mut total = Duration::ZERO;

                for _ in 0..iters {
                    // Export witness
                    let circuit = SimpleSquareCircuit { a, b, c: c_val };
                    export_to_circom_files(circuit, &paths.r1cs, &paths.witness).ok();

                    // Prove (timed)
                    let start = Instant::now();
                    rapidsnark_prove(
                        &config,
                        &paths.proving_key,
                        &paths.witness,
                        &paths.proof,
                        &paths.public_inputs,
                    ).ok();
                    total += start.elapsed();
                }

                total
            });
        });
    }

    // Complex circuit
    {
        let base_dir = PathBuf::from("outputs/bench_complex");
        std::fs::create_dir_all(&base_dir).ok();
        let paths = RapidsnarkPaths::new(&base_dir, "complex");

        let inputs = vec![
            Fr::from(2u32), Fr::from(3u32),
            Fr::from(4u32), Fr::from(5u32),
            Fr::from(6u32), Fr::from(7u32),
            Fr::from(8u32), Fr::from(9u32),
        ];
        let expected = Fr::from(2964u32);
        let circuit = ComplexCircuit { inputs: inputs.clone(), expected };

        export_to_circom_files(circuit.clone(), &paths.r1cs, &paths.witness).ok();
        complete_setup(&config, &paths.r1cs, &paths.proving_key, &paths.verification_key, 10).ok();

        group.bench_function("complex_circuit", |bench| {
            bench.iter_custom(|iters| {
                let mut total = Duration::ZERO;

                for _ in 0..iters {
                    let circuit = ComplexCircuit { inputs: inputs.clone(), expected };
                    export_to_circom_files(circuit, &paths.r1cs, &paths.witness).ok();

                    let start = Instant::now();
                    rapidsnark_prove(
                        &config,
                        &paths.proving_key,
                        &paths.witness,
                        &paths.proof,
                        &paths.public_inputs,
                    ).ok();
                    total += start.elapsed();
                }

                total
            });
        });
    }

    group.finish();
}

fn bench_comparison(c: &mut Criterion) {
    let rapidsnark_dir = PathBuf::from("../rapidsnark");
    if !rapidsnark_dir.exists() {
        println!("Skipping comparison - rapidsnark not found");
        return;
    }

    let mut group = c.benchmark_group("comparison");
    group.measurement_time(Duration::from_secs(30));

    let a = Fr::from(3u32);
    let b = Fr::from(4u32);
    let c_val = Fr::from(25u32);

    // Arkworks native
    {
        let (pk, _, _, _) = setup_simple_circuit();
        let mut rng = thread_rng();

        group.bench_function("arkworks", |bench| {
            bench.iter(|| {
                let circuit = SimpleSquareCircuit { a, b, c: c_val };
                Groth16::<Bn254, LibsnarkReduction>::prove(&pk, circuit, &mut rng)
            });
        });
    }

    // Rapidsnark
    {
        let config = RapidsnarkConfig::from_local_build(&rapidsnark_dir);
        let base_dir = PathBuf::from("outputs/bench_comparison");
        std::fs::create_dir_all(&base_dir).ok();
        let paths = RapidsnarkPaths::new(&base_dir, "simple");

        let circuit = SimpleSquareCircuit { a, b, c: c_val };
        export_to_circom_files(circuit, &paths.r1cs, &paths.witness).ok();
        complete_setup(&config, &paths.r1cs, &paths.proving_key, &paths.verification_key, 8).ok();

        group.bench_function("rapidsnark", |bench| {
            bench.iter_custom(|iters| {
                let mut total = Duration::ZERO;

                for _ in 0..iters {
                    let circuit = SimpleSquareCircuit { a, b, c: c_val };
                    export_to_circom_files(circuit, &paths.r1cs, &paths.witness).ok();

                    let start = Instant::now();
                    rapidsnark_prove(
                        &config,
                        &paths.proving_key,
                        &paths.witness,
                        &paths.proof,
                        &paths.public_inputs,
                    ).ok();
                    total += start.elapsed();
                }

                total
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_arkworks_proving,
    bench_rapidsnark_proving,
    bench_comparison
);
criterion_main!(benches);
