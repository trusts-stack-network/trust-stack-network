//! Binding signature for proving value balance in shielded transactions.
//!
//! The binding signature proves that:
//!   sum(spend_values) = sum(output_values) + fee
//!
//! This is done using Pedersen commitments and Schnorr signatures:
//! 1. Each spend/output has a value commitment: v*G + r*H
//! 2. Due to homomorphic property: sum(spend_commits) - sum(output_commits) - fee*G = r_balance*H
//! 3. The binding signature proves knowledge of r_balance

use ark_bn254::{Fr, G1Affine, G1Projective as G1};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::RngCore;
use blake2::{Blake2b512, Digest};

use super::commitment::{VALUE_GENERATOR_G, VALUE_GENERATOR_H};

/// A Schnorr signature for the binding signature.
#[derive(Clone, Debug)]
pub struct BindingSchnorrSignature {
    /// The R component (commitment point)
    pub r_point: G1Affine,
    /// The s component (scalar response)
    pub s_scalar: Fr,
}

impl BindingSchnorrSignature {
    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // R point (compressed G1 = 32 bytes for BN254)
        self.r_point.serialize_compressed(&mut bytes).unwrap();
        // s scalar (32 bytes)
        let s_bytes = self.s_scalar.into_bigint().to_bytes_le();
        bytes.extend_from_slice(&s_bytes);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 64 {
            return Err("Binding signature too short");
        }

        // R point is first 32 bytes (compressed G1 on BN254)
        let r_point = G1Affine::deserialize_compressed(&bytes[..32])
            .map_err(|_| "Failed to deserialize R point")?;

        // s scalar is next 32 bytes
        let s_scalar = Fr::from_le_bytes_mod_order(&bytes[32..64]);

        Ok(Self { r_point, s_scalar })
    }

    /// Get the size in bytes.
    pub fn size(&self) -> usize {
        64 // 32 bytes R + 32 bytes s
    }
}

/// Create a binding signature.
///
/// The binding private key is the sum of all spend randomness minus
/// the sum of all output randomness. This proves value balance.
///
/// # Arguments
/// * `binding_randomness` - The sum of spend randomness minus output randomness
/// * `message` - The message to sign (typically transaction hash)
/// * `rng` - Random number generator
pub fn create_binding_signature<R: RngCore>(
    binding_randomness: &Fr,
    message: &[u8],
    rng: &mut R,
) -> BindingSchnorrSignature {
    // The binding public key is: binding_randomness * H
    // (This equals sum(spend_commits) - sum(output_commits) - fee*G)

    // Generate random nonce k
    let k = Fr::rand(rng);

    // R = k * H
    let r_point = (*VALUE_GENERATOR_H * k).into_affine();

    // Compute challenge: c = H(R || binding_pubkey || message)
    let binding_pubkey = (*VALUE_GENERATOR_H * *binding_randomness).into_affine();
    let challenge = compute_challenge(&r_point, &binding_pubkey, message);

    // s = k + c * binding_randomness
    let s_scalar = k + challenge * binding_randomness;

    BindingSchnorrSignature { r_point, s_scalar }
}

/// Verify a binding signature.
///
/// # Arguments
/// * `signature` - The binding signature to verify
/// * `binding_pubkey` - The binding public key (sum of spend commits - output commits - fee*G)
/// * `message` - The signed message
pub fn verify_binding_signature(
    signature: &BindingSchnorrSignature,
    binding_pubkey: &G1Affine,
    message: &[u8],
) -> bool {
    // Compute challenge: c = H(R || binding_pubkey || message)
    let challenge = compute_challenge(&signature.r_point, binding_pubkey, message);

    // Verify: s * H == R + c * binding_pubkey
    let lhs = *VALUE_GENERATOR_H * signature.s_scalar;
    let rhs = signature.r_point.into_group() + (*binding_pubkey * challenge);

    lhs == rhs
}

/// Compute the Fiat-Shamir challenge for the Schnorr signature.
fn compute_challenge(r_point: &G1Affine, pubkey: &G1Affine, message: &[u8]) -> Fr {
    let mut hasher = Blake2b512::new();
    hasher.update(b"TSN_BindingSignature");

    // Serialize R point
    let mut r_bytes = Vec::new();
    r_point.serialize_compressed(&mut r_bytes).unwrap();
    hasher.update(&r_bytes);

    // Serialize public key
    let mut pk_bytes = Vec::new();
    pubkey.serialize_compressed(&mut pk_bytes).unwrap();
    hasher.update(&pk_bytes);

    // Add message
    hasher.update(message);

    let hash = hasher.finalize();
    Fr::from_le_bytes_mod_order(&hash)
}

/// Compute the binding public key from transaction components.
///
/// binding_pubkey = sum(spend_value_commits) - sum(output_value_commits) - fee * G
///
/// If the transaction is balanced, this equals: total_randomness * H
pub fn compute_binding_pubkey(
    spend_commits: &[[u8; 32]],
    output_commits: &[[u8; 32]],
    fee: u64,
) -> Result<G1Affine, &'static str> {
    let mut balance = G1::zero();

    // Add spend commitments
    for commit_bytes in spend_commits {
        let commit = G1Affine::deserialize_compressed(&commit_bytes[..])
            .map_err(|_| "Failed to deserialize spend commitment")?;
        balance = balance + commit;
    }

    // Subtract output commitments
    for commit_bytes in output_commits {
        let commit = G1Affine::deserialize_compressed(&commit_bytes[..])
            .map_err(|_| "Failed to deserialize output commitment")?;
        balance = balance - commit;
    }

    // Subtract fee commitment (fee * G, with zero randomness)
    let fee_scalar = Fr::from(fee);
    balance = balance - (*VALUE_GENERATOR_G * fee_scalar);

    Ok(balance.into_affine())
}

/// Compute the transaction hash for binding signature.
pub fn compute_binding_message(
    spend_nullifiers: &[[u8; 32]],
    output_commitments: &[[u8; 32]],
    fee: u64,
) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    hasher.update(b"TSN_BindingMessage");

    // Include all nullifiers
    for nf in spend_nullifiers {
        hasher.update(nf);
    }

    // Include all output commitments
    for cm in output_commitments {
        hasher.update(cm);
    }

    // Include fee
    hasher.update(&fee.to_le_bytes());

    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::rngs::StdRng;

    #[test]
    fn test_binding_signature_roundtrip() {
        let mut rng = StdRng::seed_from_u64(12345);

        // Create a random binding randomness (simulating balanced transaction)
        let binding_randomness = Fr::rand(&mut rng);
        let message = b"test transaction";

        // Create signature
        let sig = create_binding_signature(&binding_randomness, message, &mut rng);

        // Compute binding pubkey
        let binding_pubkey = (*VALUE_GENERATOR_H * binding_randomness).into_affine();

        // Verify
        assert!(verify_binding_signature(&sig, &binding_pubkey, message));

        // Wrong message should fail
        assert!(!verify_binding_signature(&sig, &binding_pubkey, b"wrong message"));

        // Wrong pubkey should fail
        let wrong_randomness = Fr::rand(&mut rng);
        let wrong_pubkey = (*VALUE_GENERATOR_H * wrong_randomness).into_affine();
        assert!(!verify_binding_signature(&sig, &wrong_pubkey, message));
    }

    #[test]
    fn test_binding_signature_serialization() {
        let mut rng = StdRng::seed_from_u64(12345);
        let binding_randomness = Fr::rand(&mut rng);
        let message = b"test";

        let sig = create_binding_signature(&binding_randomness, message, &mut rng);
        let bytes = sig.to_bytes();
        let recovered = BindingSchnorrSignature::from_bytes(&bytes).unwrap();

        assert_eq!(sig.r_point, recovered.r_point);
        assert_eq!(sig.s_scalar, recovered.s_scalar);
    }
}
