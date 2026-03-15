//! Opérations de signature SLH-DSA

use alloc::vec::Vec;
use slh_dsa::{SigningKey, VerifyingKey, Signature, Error};

/// Signe un message avec SLH-DSA
pub fn sign_message<Params: slh_dsa::SlhDsa, R: rand::RngCore>(
    signing_key: &SigningKey<Params>,
    message: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let signature = signing_key.sign(message, rng)?;
    Ok(signature.to_bytes().to_vec())
}

/// Vérifie une signature SLH-DSA
pub fn verify_signature<Params: slh_dsa::SlhDsa>(
    verifying_key: &VerifyingKey<Params>,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<(), Error> {
    let signature = Signature::try_from(signature_bytes)?;
    verifying_key.verify(message, &signature)
}