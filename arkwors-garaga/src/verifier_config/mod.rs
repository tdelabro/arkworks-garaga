#[cfg(test)]
mod tests;

use ark_ec::pairing::Pairing;
use ark_groth16::VerifyingKey;

/// Map each eliptic curve supported by Garaga to it's identifier, an u8.
///
/// The curve to u8 mapping is defined by Garaga standard
/// TODO: link to the Garaga documentation
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

/// Everything needed to initialize a verfier contract for a specific groth16 circuit
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Groth16VerifierConfiguration<E: Pairing> {
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_eliptic_curve_id"),
        serde(deserialize_with = "impl_serde::deserialize_eliptic_curve_id")
    )]
    eliptic_curve_id: ElipticCurveId,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_verifying_key"),
        serde(deserialize_with = "impl_serde::deserialize_verifying_key")
    )]
    verifying_key: VerifyingKey<E>,
}

impl<E: Pairing> Groth16VerifierConfiguration<E> {
    pub fn new(eliptic_curve_id: ElipticCurveId, verifying_key: VerifyingKey<E>) -> Self {
        Self {
            eliptic_curve_id,
            verifying_key,
        }
    }

    pub fn eliptic_curve_id(&self) -> ElipticCurveId {
        self.eliptic_curve_id
    }

    pub fn verifying_key(&self) -> &VerifyingKey<E> {
        &self.verifying_key
    }
}

#[cfg(feature = "serde")]
mod impl_serde {
    use crate::ElipticCurveId;

    use super::Pairing;
    use ark_groth16::VerifyingKey;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::Deserializer;
    use serde::{Deserialize, Serialize, Serializer};

    pub(super) fn serialize_verifying_key<S: Serializer, E: Pairing>(
        vk: &VerifyingKey<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut verifying_key = Vec::new();
        vk.serialize_compressed(&mut verifying_key).map_err(|e| {
            serde::ser::Error::custom(format!(
                "failed to generate a compressed verifying key: {e}"
            ))
        })?;

        verifying_key.serialize(serializer)
    }

    pub(super) fn serialize_eliptic_curve_id<S: Serializer>(
        id: &ElipticCurveId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        u8::from(*id).serialize(serializer)
    }

    pub(super) fn deserialize_verifying_key<'de, D, E: Pairing>(
        deserializer: D,
    ) -> Result<VerifyingKey<E>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let compressed_verifying_key: Vec<u8> = Deserialize::deserialize(deserializer)?;

        VerifyingKey::<E>::deserialize_compressed(&compressed_verifying_key[..]).map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to deserialize the compressed `verifying_key` field: {e}"
            ))
        })
    }

    pub(super) fn deserialize_eliptic_curve_id<'de, D>(
        deserializer: D,
    ) -> Result<ElipticCurveId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let id: u8 = Deserialize::deserialize(deserializer)?;

        ElipticCurveId::try_from(id).map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to deserialize the `eliptic_curve_id` field: {e}"
            ))
        })
    }
}
