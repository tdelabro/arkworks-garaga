mod eliptic_curve_id {
    use assert_matches::assert_matches;

    use crate::ElipticCurveId;
    use crate::TryElipticCurveFromU8Error;

    #[test]
    fn from_u8() {
        assert_eq!(ElipticCurveId::try_from(0).unwrap(), ElipticCurveId::Bn254);
        assert_eq!(
            ElipticCurveId::try_from(1).unwrap(),
            ElipticCurveId::Bls12_381
        );
        assert_matches!(
            ElipticCurveId::try_from(2),
            Err(TryElipticCurveFromU8Error::InvalidElipticCurveId(2))
        );
    }

    #[test]
    fn into_u8() {
        assert_eq!(u8::from(ElipticCurveId::Bn254), 0u8);
        assert_eq!(u8::from(ElipticCurveId::Bls12_381), 1u8);
    }
}

mod groth_16_verifier_configuration {
    use crate::{ElipticCurveId, Groth16VerifierConfiguration};

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
    fn two_way_serde() {
        let verifying_key = VerifyingKey::<ark_bn254::Bn254>::default();

        let config = Groth16VerifierConfiguration::new(ElipticCurveId::Bn254, verifying_key);
        let serialized_config = serde_json::to_vec(&config).unwrap();
        let deserialized_config: Groth16VerifierConfiguration<ark_bn254::Bn254> =
            serde_json::from_slice(&serialized_config[..]).unwrap();

        assert_eq!(config, deserialized_config);
    }
}
