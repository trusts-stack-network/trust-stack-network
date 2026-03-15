//! Consensus adapter for SLH-DSA signatures (FIPS 205).
//! Replaces ML-DSA-65 and keeps the same public API surface.

use crate::crypto::{Hash256, SlhDsaPublicKey, SlhDsaSignature, SlhDsaError};
use crate::core::{BlockHeader, Transaction, ValidationError};
use std::time::{SystemTime, UNIX_EPOCH};

/// SLH-DSA parameters used in TSN:
/// SLH-DSA-SHAKE-128s (small signatures, 8 096-bit public key, 17 088-bit signature).
pub const SLH_PARAM: &str = "SLH-DSA-SHAKE-128s";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlhDsaParams;

impl SlhDsaParams {
    pub fn name() -> &'static str {
        SLH_PARAM
    }

    pub fn pk_len() -> usize {
        32
    }

    pub fn sig_len() -> usize {
        2_096
    }
}

/// Verify that `block.header.signature` is a valid SLH-DSA signature over
/// `header.hash_without_sig()`.
pub fn verify_block_header(header: &BlockHeader) -> Result<(), ValidationError> {
    let sig = SlhDsaSignature::from_bytes(&header.signature)
        .map_err(|_| ValidationError::InvalidSignature("SLH-DSA sig decode".into()))?;
    let pk = SlhDsaPublicKey::from_bytes(&header.signer_pk)
        .map_err(|_| ValidationError::InvalidSignature("SLH-DSA pk decode".into()))?;

    let msg = header.hash_without_sig();
    pk.verify(&msg, &sig)
        .map_err(|e| ValidationError::InvalidSignature(format!("SLH-DSA verify: {e}")))?;
    Ok(())
}

/// Verify that `tx.signature` is a valid SLH-DSA signature over `tx.sighash()`.
pub fn verify_transaction(tx: &Transaction) -> Result<(), ValidationError> {
    let sig = SlhDsaSignature::from_bytes(&tx.signature)
        .map_err(|_| ValidationError::InvalidSignature("SLH-DSA sig decode".into()))?;
    let pk = SlhDsaPublicKey::from_bytes(&tx.sender_pk)
        .map_err(|_| ValidationError::InvalidSignature("SLH-DSA pk decode".into()))?;

    let msg = tx.sighash();
    pk.verify(&msg, &sig)
        .map_err(|e| ValidationError::InvalidSignature(format!("SLH-DSA verify: {e}")))?;
    Ok(())
}

/// Extract the public key from a raw byte slice.
pub fn pk_from_slice(v: &[u8]) -> Result<SlhDsaPublicKey, ValidationError> {
    SlhDsaPublicKey::from_bytes(v)
        .map_err(|_| ValidationError::InvalidSignature("SLH-DSA pk decode".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{SlhDsaKeypair, SlhDsaSigner};
    use crate::core::{BlockHeader, Transaction};

    fn dummy_header() -> BlockHeader {
        BlockHeader {
            height: 1,
            prev_block: Hash256::zero(),
            tx_root: Hash256::zero(),
            state_root: Hash256::zero(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signer_pk: vec![],
            signature: vec![],
        }
    }

    #[test]
    fn valid_block_signature_passes() {
        let kp = SlhDsaKeypair::generate(&mut rand::thread_rng());
        let mut header = dummy_header();
        header.signer_pk = kp.public.to_bytes();

        let msg = header.hash_without_sig();
        let sig = kp.sign(&msg);
        header.signature = sig.to_bytes();

        assert!(verify_block_header(&header).is_ok());
    }

    #[test]
    fn tampered_block_signature_fails() {
        let kp = SlhDsaKeypair::generate(&mut rand::thread_rng());
        let mut header = dummy_header();
        header.signer_pk = kp.public.to_bytes();

        let msg = header.hash_without_sig();
        let sig = kp.sign(&msg);
        header.signature = sig.to_bytes();

        // tamper message
        header.timestamp += 1;

        assert!(verify_block_header(&header).is_err());
    }

    #[test]
    fn valid_tx_signature_passes() {
        let kp = SlhDsaKeypair::generate(&mut rand::thread_rng());
        let mut tx = Transaction {
            sender_pk: kp.public.to_bytes(),
            signature: vec![],
            inputs: vec![],
            outputs: vec![],
            nonce: 0,
            fee: 0,
        };

        let sighash = tx.sighash();
        let sig = kp.sign(&sighash);
        tx.signature = sig.to_bytes();

        assert!(verify_transaction(&tx).is_ok());
    }

    #[test]
    fn wrong_tx_signature_fails() {
        let kp = SlhDsaKeypair::generate(&mut rand::thread_rng());
        let mut tx = Transaction {
            sender_pk: kp.public.to_bytes(),
            signature: vec![],
            inputs: vec![],
            outputs: vec![],
            nonce: 0,
            fee: 0,
        };

        let sighash = tx.sighash();
        let sig = kp.sign(&sighash);
        tx.signature = sig.to_bytes();

        // change payload => sighash changes => signature invalid
        tx.nonce = 1;

        assert!(verify_transaction(&tx).is_err());
    }
}