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

        let inputs = Groth16VerifierInputs::new(
            crate::ElipticCurveId::Bn254,
            proof.clone(),
            public_inputs.clone(),
        );
        assert_eq!(inputs.proof(), &proof);
        assert_eq!(inputs.public_inputs(), &public_inputs);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serialization() {
        use serde_test::{assert_ser_tokens, Token};

        let proof = Proof::<ark_bn254::Bn254>::default();

        let a = <ark_bn254::Bn254 as Pairing>::ScalarField::from(1u8);
        let b = <ark_bn254::Bn254 as Pairing>::ScalarField::from(2u8);
        let public_inputs = vec![a, b];

        let inputs = Groth16VerifierInputs::new(
            crate::ElipticCurveId::Bn254,
            proof.clone(),
            public_inputs.clone(),
        );
        assert_ser_tokens(
            &inputs,
            &[
                Token::Struct {
                    name: "Groth16VerifierInputs",
                    len: 3,
                },
                Token::Str("eliptic_curve_id"),
                Token::U8(0),
                Token::Str("proof"),
                Token::Struct {
                    name: "Proof",
                    len: 3,
                },
                Token::Str("a"),
                Token::Struct {
                    name: "G1Point",
                    len: 2,
                },
                Token::Str("x"),
                Token::Str("0x0"),
                Token::Str("y"),
                Token::Str("0x0"),
                Token::StructEnd,
                Token::Str("b"),
                Token::Struct {
                    name: "G2Point",
                    len: 2,
                },
                Token::Str("x"),
                Token::Tuple { len: 2 },
                Token::Str("0x0"),
                Token::Str("0x0"),
                Token::TupleEnd,
                Token::Str("y"),
                Token::Tuple { len: 2 },
                Token::Str("0x0"),
                Token::Str("0x0"),
                Token::TupleEnd,
                Token::StructEnd,
                Token::Str("c"),
                Token::Struct {
                    name: "G1Point",
                    len: 2,
                },
                Token::Str("x"),
                Token::Str("0x0"),
                Token::Str("y"),
                Token::Str("0x0"),
                Token::StructEnd,
                Token::StructEnd,
                Token::Str("public_inputs"),
                Token::Seq { len: Some(2) },
                Token::String("0x1"),
                Token::String("0x2"),
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );

        assert_eq!(
            &serde_json::to_string(&inputs).unwrap(),
            r#"{"eliptic_curve_id":0,"proof":{"a":{"x":"0x0","y":"0x0"},"b":{"x":["0x0","0x0"],"y":["0x0","0x0"]},"c":{"x":"0x0","y":"0x0"}},"public_inputs":["0x1","0x2"]}"#
        );
    }
}
