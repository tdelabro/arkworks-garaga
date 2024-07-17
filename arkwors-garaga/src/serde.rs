use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::Field;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(crate) struct G1Point {
    x: String,
    y: String,
}

impl G1Point {
    pub fn from_ark<E: Pairing>(value: &E::G1Affine) -> Self {
        let (x, y) = match <E::G1Affine as AffineRepr>::xy(value) {
            Some(v) => v,
            None => {
                return G1Point {
                    x: "0x0".to_string(),
                    y: "0x0".to_string(),
                }
            }
        };

        let x: BigUint  = <<<E as ark_ec::pairing::Pairing>::G1Affine as ark_ec::AffineRepr>::BaseField as Field>::to_base_prime_field_elements(x).next().unwrap().into();
        let y: BigUint  = <<<E as ark_ec::pairing::Pairing>::G1Affine as ark_ec::AffineRepr>::BaseField as Field>::to_base_prime_field_elements(y).next().unwrap().into();

        Self {
            x: format!("{:#01x}", x),
            y: format!("{:#01x}", y),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct G2Point {
    x: [String; 2],
    y: [String; 2],
}
impl G2Point {
    pub fn from_ark<E: Pairing>(value: &E::G2Affine) -> Self {
        let (x, y) = match <E::G2Affine as AffineRepr>::xy(value) {
            Some(v) => v,
            None => {
                return G2Point {
                    x: ["0x0".to_string(), "0x0".to_string()],
                    y: ["0x0".to_string(), "0x0".to_string()],
                }
            }
        };

        let mut x = <<<E as ark_ec::pairing::Pairing>::G2Affine as ark_ec::AffineRepr>::BaseField as Field>::to_base_prime_field_elements(x);
        let mut y = <<<E as ark_ec::pairing::Pairing>::G2Affine as ark_ec::AffineRepr>::BaseField as Field>::to_base_prime_field_elements(y);
        let x_c0: BigUint = x.next().unwrap().into();
        let x_c1: BigUint = x.next().unwrap().into();
        let y_c0: BigUint = y.next().unwrap().into();
        let y_c1: BigUint = y.next().unwrap().into();

        Self {
            x: [format!("{:#01x}", x_c0), format!("{:#01x}", x_c1)],
            y: [format!("{:#01x}", y_c0), format!("{:#01x}", y_c1)],
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct VerifyingKey {
    pub alpha_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g2: G2Point,
    pub ic: Vec<G1Point>,
}

impl<E: Pairing> From<&ark_groth16::VerifyingKey<E>> for VerifyingKey {
    fn from(value: &ark_groth16::VerifyingKey<E>) -> Self {
        Self {
            alpha_g1: G1Point::from_ark::<E>(&value.alpha_g1),
            beta_g2: G2Point::from_ark::<E>(&value.beta_g2),
            gamma_g2: G2Point::from_ark::<E>(&value.gamma_g2),
            delta_g2: G2Point::from_ark::<E>(&value.delta_g2),
            ic: value
                .gamma_abc_g1
                .iter()
                .map(|v| G1Point::from_ark::<E>(v))
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Proof {
    pub a: G1Point,
    pub b: G2Point,
    pub c: G1Point,
}

impl<E: Pairing> From<&ark_groth16::Proof<E>> for Proof {
    fn from(value: &ark_groth16::Proof<E>) -> Self {
        Self {
            a: G1Point::from_ark::<E>(&value.a),
            b: G2Point::from_ark::<E>(&value.b),
            c: G1Point::from_ark::<E>(&value.c),
        }
    }
}
