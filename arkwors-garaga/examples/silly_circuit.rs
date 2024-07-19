// This circuit is pasted from ark_groth16

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng, UniformRand,
};
use arkwors_garaga::{ElipticCurveId, Groth16VerifierConfiguration, Groth16VerifierInputs};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a *= &b;
            Ok(a)
        })?;

        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;

        Ok(())
    }
}

fn generate_garaga_jsons<E>(n_iters: usize, dump_dir: &Path)
where
    E: Pairing,
{
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

    let (pk, vk) = Groth16::<E>::setup(MySillyCircuit { a: None, b: None }, &mut rng).unwrap();
    let pvk = prepare_verifying_key::<E>(&vk);

    // Serialize and write verifier config
    {
        let config = Groth16VerifierConfiguration::new(ElipticCurveId::Bn254, vk.clone());
        let config_json_file =
            std::fs::File::create(dump_dir.to_path_buf().join("verifier_config.json"))
                .expect("failed to create and/or open the `verifier_config.json` file");
        serde_json::to_writer(config_json_file, &config)
            .expect("should be able to serialize the verifier config");
    }

    for _ in 0..n_iters {
        let a = E::ScalarField::rand(&mut rng);
        let b = E::ScalarField::rand(&mut rng);
        let mut c = a;
        c *= b;

        let proof = Groth16::<E>::prove(
            &pk,
            MySillyCircuit {
                a: Some(a),
                b: Some(b),
            },
            &mut rng,
        )
        .unwrap();

        assert!(Groth16::<E>::verify_with_processed_vk(&pvk, &[c], &proof).unwrap());
        // Serialize and write verifier inputs
        {
            let inputs = Groth16VerifierInputs::new(ElipticCurveId::Bn254, proof, vec![c]);
            let input_json_file = std::fs::File::create(
                dump_dir
                    .to_path_buf()
                    .join(format!("verifier_inputs_{}.json", c)),
            )
            .expect("failed to create and/or open the `verifier_input.json` file");
            serde_json::to_writer(input_json_file, &inputs)
                .expect("should be able to serialize the verifier config");
        }
    }
}

/// Run the `SillyCircuit` `n_iters`, verify the generated proof and dump the garaga verifier `.json` files under `output_dir`
///
/// * Args
/// 1) `n_iters`: the number of times you want to run the circuit with a different input
/// 2) `output_dir`: the path to an existing directory under which you want to write the `.json` files generated  
///
/// * Usase
/// ```shell
/// mkdir /tmp/silly_circuit_verifier/
/// cargo run --example silly_circuit 3 /tmp/silly_circuit_verifier/
/// ```
fn main() {
    let (n_iters, dir_output) = {
        let mut args = std::env::args();
        let n_iters = args.nth(1).expect("two argument should be passed");
        let n_iters = str::parse::<u8>(&n_iters).expect("first argument should be a valid u8");
        let output_dir = args.next().expect("two argument should be passed");
        let dir_output = PathBuf::from_str(&output_dir).unwrap();
        assert!(
            dir_output.exists() && dir_output.is_dir(),
            "second arg should be a valid path to an existing directory"
        );

        (n_iters, dir_output)
    };

    generate_garaga_jsons::<ark_bn254::Bn254>(n_iters.into(), &dir_output);
}
