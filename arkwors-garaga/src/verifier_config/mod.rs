#[cfg(test)]
mod tests;

use ark_ec::pairing::Pairing;
use ark_groth16::VerifyingKey;

use crate::ElipticCurveId;

/// Everything needed to initialize a verfier contract for a specific groth16 circuit
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Groth16VerifierConfiguration<E: Pairing> {
    eliptic_curve_id: ElipticCurveId,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_verifying_key")
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
    use crate::serde::VerifyingKey as SerdeVerifyingKey;

    use ark_ec::pairing::Pairing;
    use ark_groth16::VerifyingKey;
    use serde::{Serialize, Serializer};

    pub(super) fn serialize_verifying_key<S: Serializer, E: Pairing>(
        verifying_key: &VerifyingKey<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let vk = SerdeVerifyingKey::from(verifying_key);
        vk.serialize(serializer)
    }
}
