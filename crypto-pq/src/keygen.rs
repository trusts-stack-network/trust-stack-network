//! Génération de clés SLH-DSA

use alloc::vec::Vec;
use rand::RngCore;
use slh_dsa::{SigningKey, VerifyingKey};

/// Génère une paire de clés SLH-DSA-SHA2-128s
pub fn generate_keypair<R: RngCore>(rng: &mut R) -> (SigningKey<Sha2_128s>, VerifyingKey<Sha2_128s>) 
where
    Sha2_128s: slh_dsa::SlhDsa,
{
    let signing_key = SigningKey::generate(rng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sérialise une clé de signature
pub fn serialize_signing_key<Params: slh_dsa::SlhDsa>(
    key: &SigningKey<Params>
) -> Vec<u8> {
    key.to_bytes().to_vec()
}