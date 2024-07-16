mod groth_16_verifier_inputs {
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng, UniformRand,
    };

    use ark_ec::pairing::Pairing;
    use ark_groth16::Proof;

    use crate::Groth16VerifierInputs;

    #[test]
    fn new_and_getters() {
        let proof = Proof::<ark_bn254::Bn254>::default();

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let a = <ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let b = <ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let public_inputs = vec![a, b];

        let inputs = Groth16VerifierInputs::new(proof.clone(), public_inputs.clone());
        assert_eq!(inputs.proof(), &proof);
        assert_eq!(inputs.public_inputs(), &public_inputs);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn two_way_serde() {
        let proof = Proof::<ark_bn254::Bn254>::default();

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let a = <ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let b = <ark_bn254::Bn254 as Pairing>::ScalarField::rand(&mut rng);
        let public_inputs = vec![a, b];

        let inputs = Groth16VerifierInputs::new(proof.clone(), public_inputs.clone());
        let serialized_inputs = serde_json::to_vec(&inputs).unwrap();
        let deserialized_inputs: Groth16VerifierInputs<ark_bn254::Bn254> =
            serde_json::from_slice(&serialized_inputs[..]).unwrap();

        assert_eq!(inputs, deserialized_inputs);
    }
}
