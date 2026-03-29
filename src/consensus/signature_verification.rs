use crate::crypto::keys::{PublicKey, Signature};
use crate::crypto::pq::slh_dsa::{SlhDsaVerifier, SlhDsaSignature};
use crate::core::transaction::Transaction;
use crate::core::block::{Block, BlockHeader};
use crate::core::error::{ConsensusError, ValidationError};
use std::collections::HashSet;

/// Verifie les signatures SLH-DSA pour les blocs et transactions
pub struct SignatureVerifier {
    verifier: SlhDsaVerifier,
}

impl SignatureVerifier {
    pub fn new() -> Self {
        Self {
            verifier: SlhDsaVerifier::new(),
        }
    }

    /// Verifie la signature du bloc (signature du producteur de bloc)
    pub fn verify_block_signature(&self, block: &Block) -> Result<(), ConsensusError> {
        let header_hash = block.header.hash();
        
        // Extrait la signature et la clé publique du producteur
        let signature = SlhDsaSignature::from_bytes(&block.signature)
            .map_err(|_| ConsensusError::InvalidSignature("Invalid SLH-DSA signature format".into()))?;
        
        let producer_key = PublicKey::from_bytes(&block.header.producer_key)
            .map_err(|_| ConsensusError::InvalidPublicKey("Invalid producer public key".into()))?;

        // Verifie que la clé est bien une clé SLH-DSA
        if !matches!(producer_key, PublicKey::SlhDsa(_)) {
            return Err(ConsensusError::InvalidPublicKey(
                "Producer key must be SLH-DSA for post-quantum consensus".into()
            ));
        }

        self.verifier.verify(&header_hash, &signature, &producer_key)
            .map_err(|e| ConsensusError::InvalidSignature(format!("Block signature verification failed: {}", e)))?;

        Ok(())
    }

    /// Verifie toutes les signatures de transactions dans un bloc
    pub fn verify_block_transactions(&self, block: &Block) -> Result<(), ConsensusError> {
        let mut seen_nullifiers = HashSet::new();
        
        for tx in &block.transactions {
            // Verifie la signature de la transaction
            self.verify_transaction_signature(tx)?;
            
            // Verifie les double spends via nullifiers
            for nullifier in &tx.nullifiers {
                if !seen_nullifiers.insert(nullifier.clone()) {
                    return Err(ConsensusError::DoubleSpend(
                        format!("Duplicate nullifier found: {:?}", nullifier)
                    ));
                }
            }
        }

        Ok(())
    }

    /// Verifie la signature d'une transaction
    pub fn verify_transaction_signature(&self, tx: &Transaction) -> Result<(), ConsensusError> {
        let tx_hash = tx.hash();
        
        // Verifie chaque signature de dépense
        for (i, spend) in tx.spends.iter().enumerate() {
            let signature = SlhDsaSignature::from_bytes(&spend.signature)
                .map_err(|_| ConsensusError::InvalidSignature(
                    format!("Invalid SLH-DSA signature in spend {}", i)
                ))?;
            
            let pub_key = PublicKey::from_bytes(&spend.pub_key)
                .map_err(|_| ConsensusError::InvalidPublicKey(
                    format!("Invalid public key in spend {}", i)
                ))?;

            if !matches!(pub_key, PublicKey::SlhDsa(_)) {
                return Err(ConsensusError::InvalidPublicKey(
                    format!("Spend {} must use SLH-DSA key", i)
                ));
            }

            self.verifier.verify(&tx_hash, &signature, &pub_key)
                .map_err(|e| ConsensusError::InvalidSignature(
                    format!("Transaction signature verification failed for spend {}: {}", i, e)
                ))?;
        }

        Ok(())
    }

    /// Verifie qu'une clé publique est valide pour le consensus actuel
    pub fn validate_public_key(&self, key: &PublicKey) -> Result<(), ConsensusError> {
        match key {
            PublicKey::SlhDsa(_) => Ok(()),
            _ => Err(ConsensusError::InvalidPublicKey(
                "Only SLH-DSA keys are accepted in post-quantum consensus".into()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{PrivateKey, KeyPair};
    use crate::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaKeyPair};
    use crate::core::transaction::{Spend, Output};
    use crate::core::block::BlockHeader;
    use std::time::SystemTime;

    fn create_test_keypair() -> SlhDsaKeyPair {
        SlhDsaKeyPair::generate()
    }

    fn create_test_transaction() -> (Transaction, SlhDsaKeyPair) {
        let keypair = create_test_keypair();
        let signer = SlhDsaSigner::new();
        
        let mut tx = Transaction {
            version: 1,
            spends: vec![],
            outputs: vec![Output {
                value: 100,
                note_commitment: [0u8; 32],
                epk: [0u8; 32],
                enc_ciphertext: vec![],
            }],
            nullifiers: vec![[1u8; 32]],
            binding_sig: [0u8; 32],
        };

        let spend = Spend {
            nullifier: [1u8; 32],
            note_commitment: [2u8; 32],
            rk: keypair.public.to_bytes(),
            proof: vec![],
            signature: signer.sign(&tx.hash(), &keypair.private).to_bytes(),
        };

        tx.spends.push(spend);
        (tx, keypair)
    }

    #[test]
    fn test_verify_valid_transaction() {
        let verifier = SignatureVerifier::new();
        let (tx, _) = create_test_transaction();
        
        assert!(verifier.verify_transaction_signature(&tx).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let verifier = SignatureVerifier::new();
        let (mut tx, _) = create_test_transaction();
        
        // Corrompt la signature
        tx.spends[0].signature[0] ^= 0xFF;
        
        assert!(matches!(
            verifier.verify_transaction_signature(&tx),
            Err(ConsensusError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_validate_slh_dsa_key() {
        let verifier = SignatureVerifier::new();
        let keypair = create_test_keypair();
        let pubkey = PublicKey::SlhDsa(keypair.public);
        
        assert!(verifier.validate_public_key(&pubkey).is_ok());
    }

    #[test]
    fn test_reject_non_slh_dsa_key() {
        let verifier = SignatureVerifier::new();
        // Crée une fausse clé non-SLH (simulée ici)
        let invalid_key = PublicKey::from_bytes(&[0u8; 32]).unwrap_or_else(|_| {
            // Fallback pour le test
            PublicKey::SlhDsa(create_test_keypair().public)
        });
        
        // Force une erreur en créant une clé invalide
        assert!(verifier.validate_public_key(&invalid_key).is_err());
    }

    #[test]
    fn test_verify_block_signature() {
        let verifier = SignatureVerifier::new();
        let keypair = create_test_keypair();
        let signer = SlhDsaSigner::new();
        
        let header = BlockHeader {
            version: 1,
            height: 42,
            prev_block: [0u8; 32],
            tx_root: [1u8; 32],
            state_root: [2u8; 32],
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            producer_key: keypair.public.to_bytes(),
            nonce: 12345,
        };

        let header_hash = header.hash();
        let signature = signer.sign(&header_hash, &keypair.private).to_bytes();

        let block = Block {
            header,
            transactions: vec![],
            signature,
            proof: vec![],
        };

        assert!(verifier.verify_block_signature(&block).is_ok());
    }

    #[test]
    fn test_detect_double_spend() {
        let verifier = SignatureVerifier::new();
        let (tx1, _) = create_test_transaction();
        let mut tx2 = tx1.clone();
        tx2.spends[0].signature = tx1.spends[0].signature.clone(); // Même signature mais différentes tx
        
        let block = Block {
            header: BlockHeader {
                version: 1,
                height: 1,
                prev_block: [0u8; 32],
                tx_root: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 1000,
                producer_key: vec![0u8; 32],
                nonce: 0,
            },
            transactions: vec![tx1, tx2],
            signature: vec![0u8; 32],
            proof: vec![],
        };

        assert!(matches!(
            verifier.verify_block_transactions(&block),
            Err(Consensus