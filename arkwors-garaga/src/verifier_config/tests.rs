mod groth_16_verifier_configuration {
    use crate::{ElipticCurveId, Groth16VerifierConfiguration};
    use serde_test::{assert_ser_tokens, Token};

    use ark_groth16::VerifyingKey;

    #[test]
    fn new_and_getters() {
        let verifying_key = VerifyingKey::<ark_bn254::Bn254>::default();

        let config =
            Groth16VerifierConfiguration::new(ElipticCurveId::Bn254, verifying_key.clone());
        assert_eq!(config.eliptic_curve_id(), ElipticCurveId::Bn254);
        assert_eq!(config.verifying_key(), &verifying_key);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serialization() {
        let verifying_key = VerifyingKey::<ark_bn254::Bn254>::default();

        let config = Groth16VerifierConfiguration::new(ElipticCurveId::Bn254, verifying_key);
        assert_ser_tokens(
            &config,
            &[
                Token::Struct {
                    name: "Groth16VerifierConfiguration",
                    len: 2,
                },
                Token::Str("eliptic_curve_id"),
                Token::UnitVariant {
                    name: "ElipticCurveId",
                    variant: "bn254",
                },
                Token::Str("verifying_key"),
                Token::Struct {
                    name: "VerifyingKey",
                    len: 5,
                },
                Token::Str("alpha_g1"),
                Token::Struct {
                    name: "G1Point",
                    len: 2,
                },
                Token::Str("x"),
                Token::Str("0x0"),
                Token::Str("y"),
                Token::Str("0x0"),
                Token::StructEnd,
                Token::Str("beta_g2"),
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
                Token::Str("gamma_g2"),
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
                Token::Str("delta_g2"),
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
                Token::Str("ic"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
                Token::StructEnd,
            ],
        );

        assert_eq!(
            &serde_json::to_string(&config).unwrap(),
            r#"{"eliptic_curve_id":"bn254","verifying_key":{"alpha_g1":{"x":"0x0","y":"0x0"},"beta_g2":{"x":["0x0","0x0"],"y":["0x0","0x0"]},"gamma_g2":{"x":["0x0","0x0"],"y":["0x0","0x0"]},"delta_g2":{"x":["0x0","0x0"],"y":["0x0","0x0"]},"ic":[]}}"#
        )
    }
}
