/// This crate provide logic to (de)serialize Arkworks outputs as valid Garaga inputs  
///
/// In order to generate the Starket verifier contract, Garaga expect a .json containing:
/// - the id of the eliptic curve used  
/// - the verifying key for the circuit
/// The `Groth16VerifierConfiguration` allow for this serialization.
///
/// In order to generate the payload for verifying a specifc run of the circuit, Garaga expect a .json containing:
/// - the public inputs
/// - the proof
mod verifier_config;
pub use verifier_config::*;
mod verifier_inputs;
pub use verifier_inputs::*;
