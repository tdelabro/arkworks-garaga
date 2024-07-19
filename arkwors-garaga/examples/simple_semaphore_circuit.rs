use std::{path::PathBuf, str::FromStr};

use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_groth16::{prepare_verifying_key, Groth16};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, uint8::UInt8};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use arkwors_garaga::{ElipticCurveId, Groth16VerifierConfiguration, Groth16VerifierInputs};

struct IsPartOfPublicInputsCircuit<'a, const N_PUBLIC_INPUTS: usize> {
    secret_value: Option<u8>,
    public_inputs: Option<&'a [u8; N_PUBLIC_INPUTS]>,
}

// Those constraints make sure the that secret is present in the public input values,
// wihout revealing it's actual value
impl<'a, const N_PUBLIC_INPUTS: usize, ConstraintF: Field> ConstraintSynthesizer<ConstraintF>
    for IsPartOfPublicInputsCircuit<'a, N_PUBLIC_INPUTS>
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let secret_value = UInt8::new_witness(cs.clone(), || {
            self.secret_value
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut is_found = Boolean::new_constant(cs.clone(), false)?;

        for i in 0..N_PUBLIC_INPUTS {
            let public_inputs = self
                .public_inputs
                .as_ref()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let public_input = UInt8::new_input(cs.clone(), || {
                public_inputs
                    .get(i)
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
            let is_eq = public_input.is_eq(&secret_value)?;

            is_found = is_found.or(&is_eq)?;
        }

        is_found.enforce_equal(&Boolean::constant(true))?;
        Ok(())
    }
}

/// Run the `IsPartOfPublicInputsCircuit`
///
/// * Args
/// 1) `output_dir`: the path to an existing directory under which you want to write the `.json` files generated  
/// 2) `secret`: the value you want to prove is part of the public input without revealing it
/// ..) `public_inputs`: a varialbe number of other numbers that will be used as the public inputs to the circuit
///
/// * Usase
/// ```shell
/// mkdir /tmp/simple_semaphore_circuit_verifier/
/// cargo run --example simple_semaphore_circuit /tmp/simple_semaphore_circuit_verifier/ 42 1 21 42
/// ```
///
/// In order to be able to generate a proof, the secret should be part of the public inputs too.
/// The number of public input is constrained by the `N_PUB_INPUTS` constant.
fn main() {
    // Edit this const to change the number of public inputs
    const N_PUB_INPUTS: usize = 3;

    // Read args
    let (secret_value, output_dir, public_inputs) = {
        let mut args = std::env::args();
        let output_dir = args.nth(1).expect("multiple argument should be passed");
        let dir_output = PathBuf::from_str(&output_dir).unwrap();
        assert!(
            dir_output.exists() && dir_output.is_dir(),
            "second arg should be a valid path to an existing directory"
        );

        let secret = str::parse::<u8>(&args.next().expect("multiple argument should be passed"))
            .expect("all args except the first should be valid u8");

        let mut public_inputs = [0u8; N_PUB_INPUTS];
        let mut n_inputs = 0;
        for (i, arg) in args.enumerate() {
            public_inputs[i] =
                str::parse::<u8>(&arg).expect("all args except the first should be valid u8");
            n_inputs += 1;
        }
        assert_eq!(n_inputs, N_PUB_INPUTS, "invalid number of inputs");

        (secret, dir_output, public_inputs)
    };

    // Setup circuit and generate keys
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(
        IsPartOfPublicInputsCircuit::<N_PUB_INPUTS> {
            secret_value: None,
            public_inputs: Some(&[0u8; N_PUB_INPUTS]),
        },
        &mut rng,
    )
    .unwrap();
    let pvk = prepare_verifying_key::<ark_bn254::Bn254>(&vk);
    // Serialize and write verifier config
    {
        let config = Groth16VerifierConfiguration::new(ElipticCurveId::Bn254, vk.clone());
        let config_json_file = std::fs::File::create(output_dir.to_path_buf().join(format!(
            "verifier_config_for_secret_{}_and_{}_pub_inputs.json",
            secret_value, N_PUB_INPUTS
        )))
        .expect("failed to create and/or open the `verifier_config.json` file");
        serde_json::to_writer(config_json_file, &config)
            .expect("should be able to serialize the verifier config");
    }

    // Generate proof
    let proof = Groth16::<ark_bn254::Bn254>::prove(
        &pk,
        IsPartOfPublicInputsCircuit::<N_PUB_INPUTS> {
            secret_value: Some(secret_value),
            public_inputs: Some(&public_inputs),
        },
        &mut rng,
    )
    .unwrap();

    // We use ark::Uint8 as inputs, each one is represented as a sequence of 8 ark::Boolean.
    // Meaning we have to feed the verifier 8 times more values than our number of public inputs
    let mut verifier_inputs = Vec::with_capacity(public_inputs.len() * 8);
    for input in public_inputs {
        for i in 0..8 {
            let mask = 1 << i;
            verifier_inputs.push(<ark_bn254::Bn254 as Pairing>::ScalarField::from(
                mask & input != 0,
            ));
        }
    }

    // Verify proof
    assert!(
        Groth16::<ark_bn254::Bn254>::verify_with_processed_vk(&pvk, &verifier_inputs, &proof)
            .unwrap()
    );

    // Serialize and write verifier inputs
    {
        let mut list_of_pub_inputs_as_string = String::new();
        for v in public_inputs {
            list_of_pub_inputs_as_string.push_str(&format!("_{v}"));
        }

        let inputs = Groth16VerifierInputs::new(ElipticCurveId::Bn254, proof, verifier_inputs);
        let input_json_file = std::fs::File::create(output_dir.to_path_buf().join(format!(
            "verifier_inputs_for_secret_{}_and_{}_pub_inputs{}.json",
            secret_value, N_PUB_INPUTS, list_of_pub_inputs_as_string
        )))
        .expect("failed to create and/or open the `verifier_input.json` file");
        serde_json::to_writer(input_json_file, &inputs)
            .expect("should be able to serialize the verifier config");
    }
}
