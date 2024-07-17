/// This crate provide logic to (de)serialize Arkworks outputs as valid Garaga inputs  
///
/// In order to generate the Starket verifier contract, Garaga expect a .json containing:
/// - the id of the eliptic curve used  
/// - the verifying key for the circuit
/// The `Groth16VerifierConfiguration` allow for this serialization.
///
/// In order to generate the payload for verifying a specifc run of the circuit, Garaga expect a .json containing:
/// - the proof
/// - the public inputs

#[cfg(feature = "serde")]
mod serde;
mod verifier_config;
pub use verifier_config::*;
mod verifier_inputs;
pub use verifier_inputs::*;

/// Map each eliptic curve supported by Garaga to it's identifier, an u8.
///
/// The curve to u8 mapping is defined by Garaga standard
/// TODO: link to the Garaga documentation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize), serde(into = "u8"))]
pub enum ElipticCurveId {
    Bn254 = 0,
    Bls12_381 = 1,
}

impl From<ElipticCurveId> for u8 {
    fn from(value: ElipticCurveId) -> Self {
        match value {
            ElipticCurveId::Bn254 => 0,
            ElipticCurveId::Bls12_381 => 1,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TryElipticCurveFromU8Error {
    /// Garaga only recognise a limited number of ids
    /// TODO: link to the Garaga documentation
    InvalidElipticCurveId(u8),
}

impl core::fmt::Display for TryElipticCurveFromU8Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryElipticCurveFromU8Error::InvalidElipticCurveId(id) => {
                write!(f, "unknown eliptic curve id `{}`", id)
            }
        }
    }
}

impl std::error::Error for TryElipticCurveFromU8Error {}

impl TryFrom<u8> for ElipticCurveId {
    type Error = TryElipticCurveFromU8Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ElipticCurveId::Bn254),
            1 => Ok(ElipticCurveId::Bls12_381),
            _ => Err(TryElipticCurveFromU8Error::InvalidElipticCurveId(value)),
        }
    }
}

#[cfg(test)]
mod tests {
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
}
