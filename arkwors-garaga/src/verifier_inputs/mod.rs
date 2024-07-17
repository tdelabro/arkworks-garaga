use ark_ec::pairing::Pairing;
use ark_groth16::Proof;

use crate::ElipticCurveId;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Groth16VerifierInputs<E: Pairing> {
    eliptic_curve_id: ElipticCurveId,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_proof")
    )]
    proof: Proof<E>,
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "impl_serde::serialize_public_inputs::<_, E>")
    )]
    public_inputs: Vec<E::ScalarField>,
}

impl<E: Pairing> Groth16VerifierInputs<E> {
    pub fn new(
        eliptic_curve_id: ElipticCurveId,
        proof: Proof<E>,
        public_inputs: Vec<E::ScalarField>,
    ) -> Self {
        Self {
            eliptic_curve_id,
            proof,
            public_inputs,
        }
    }

    pub fn eliptic_curve_id(&self) -> ElipticCurveId {
        self.eliptic_curve_id
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
    use crate::serde::Proof as SerdeProof;
    use ark_ec::pairing::Pairing;
    use ark_groth16::Proof;
    use num_bigint::BigUint;
    use serde::{Serialize, Serializer};

    pub(super) fn serialize_proof<S: Serializer, E: Pairing>(
        proof: &Proof<E>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let p = SerdeProof::from(proof);
        p.serialize(serializer)
    }

    pub(super) fn serialize_public_inputs<S: Serializer, E: Pairing>(
        public_inputs: &[E::ScalarField],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let hex_strings = public_inputs
            .iter()
            .map(|&v| {
                let bi: BigUint = <E::ScalarField as Into<BigUint>>::into(v);
                format!("{:#01x}", bi)
            })
            .collect::<Vec<String>>();

        hex_strings.serialize(serializer)
    }
}
