use ark_ec::pairing::Pairing;
use ark_groth16::Proof;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Groth16VerifierInputs<E: Pairing> {
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_proof"),
        serde(deserialize_with = "impl_serde::deserialize_proof")
    )]
    proof: Proof<E>,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_public_inputs::<_, E>"),
        serde(deserialize_with = "impl_serde::deserialize_public_inputs::<_, E>")
    )]
    public_inputs: Vec<E::ScalarField>,
}

impl<E: Pairing> Groth16VerifierInputs<E> {
    pub fn new(proof: Proof<E>, public_inputs: Vec<E::ScalarField>) -> Self {
        Self {
            proof,
            public_inputs,
        }
    }

    pub fn proof(&self) -> &Proof<E> {
        &self.proof
    }

    pub fn public_inputs(&self) -> &Vec<E::ScalarField> {
        &self.public_inputs
    }
}

#[cfg(feature = "serde")]
mod impl_serde {
    use super::Pairing;
    use ark_groth16::Proof;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use serde::Deserializer;
    use serde::{Deserialize, Serialize, Serializer};

    pub(super) fn serialize_proof<S: Serializer, E: Pairing>(
        proof: &Proof<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut compressed_proof = Vec::new();
        proof
            .serialize_compressed(&mut compressed_proof)
            .map_err(|e| {
                serde::ser::Error::custom(format!("failed to generate a compressed proof: {e}"))
            })?;

        compressed_proof.serialize(serializer)
    }

    pub(super) fn serialize_public_inputs<S: Serializer, E: Pairing>(
        public_inputs: &Vec<E::ScalarField>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut compressed_public_inputs = Vec::new();
        public_inputs
            .serialize_compressed(&mut compressed_public_inputs)
            .map_err(|e| {
                serde::ser::Error::custom(format!(
                    "failed to generate compressed public inputs: {e}"
                ))
            })?;

        compressed_public_inputs.serialize(serializer)
    }

    pub(super) fn deserialize_proof<'de, D, E>(deserializer: D) -> Result<Proof<E>, D::Error>
    where
        D: Deserializer<'de>,
        E: Pairing,
    {
        let compressed_proof: Vec<u8> = Deserialize::deserialize(deserializer)?;

        Proof::<E>::deserialize_compressed(&compressed_proof[..]).map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to deserialize the compressed `proof` field: {e}"
            ))
        })
    }

    pub(super) fn deserialize_public_inputs<'de, D, E>(
        deserializer: D,
    ) -> Result<Vec<E::ScalarField>, D::Error>
    where
        D: Deserializer<'de>,
        E: Pairing,
    {
        let compressed_public_inputs: Vec<u8> = Deserialize::deserialize(deserializer)?;

        Vec::<E::ScalarField>::deserialize_compressed(&compressed_public_inputs[..]).map_err(|e| {
            serde::de::Error::custom(format!(
                "failed to deserialize the compressed `public_inputs` field: {e}"
            ))
        })
    }
}
