//! Consensus SLH-DSA - Signature stateful
//! 
//! ⚠️  AVERTISSEMENT DE SÉCURITÉ: SLH-DSA est une signature stateful.
//!    - Un même état ne doit JAMAIS être réutilisé
//!    - L'état doit être persistant et atomique
//!    - En cas de désynchronisation, le nœud doit s'arrêter
//! 
//! Cette implémentation inclut des garde-fous stricts pour empêcher
//! la réutilisation d'état, mais ne peut pas garantir la sécurité
//! dans un environnement distribué réel.

use crate::crypto::pq::slh_dsa::{SlhDsaSigner, SlhDsaVerifier, SlhDsaError};
use crate::core::block::{Block, BlockHeader};
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use serde::{Serialize, Deserialize};

/// Erreurs de validation SLH-DSA
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum SlhDsaConsensusError {
    #[error("État SLH-DSA désynchronisé - arrêt du nœud requis")]
    StateDesync,
    #[error("Signature SLH-DSA invalide")]
    InvalidSignature,
    #[error("Réutilisation d'état détectée - attaque potentielle")]
    StateReuseDetected,
    #[error("Erreur interne SLH-DSA: {0}")]
    InternalError(String),
}

/// État d'un validateur SLH-DSA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlhDsaValidatorState {
    /// Dernier compteur utilisé
    pub last_counter: u64,
    /// Hash du dernier bloc validé
    pub last_block_hash: Hash,
    /// Nombre de signatures effectuées
    pub signature_count: u64,
}

/// Gestionnaire d'état SLH-DSA
/// 
/// Thread-safe avec verrouillage strict pour prévenir
/// toute utilisation concurrente de l'état
pub struct SlhDsaStateManager {
    state: Arc<Mutex<SlhDsaValidatorState>>,
    max_signatures: u64,
}

impl SlhDsaStateManager {
    /// Crée un nouveau gestionnaire d'état
    pub fn new(initial_counter: u64, max_signatures: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(SlhDsaValidatorState {
                last_counter: initial_counter,
                last_block_hash: Hash::zero(),
                signature_count: 0,
            })),
            max_signatures,
        }
    }

    /// Met à jour l'état après une signature réussie
    /// 
    /// # Panics
    /// Si l'état est corrompu ou dépassé - par sécurité
    pub fn update_signature_state(&self, new_counter: u64, block_hash: Hash) -> Result<(), SlhDsaConsensusError> {
        let mut state = self.state.lock()
            .map_err(|_| SlhDsaConsensusError::InternalError("Mutex poisoned".to_string()))?;
        
        // Vérification anti-réutilisation
        if new_counter <= state.last_counter {
            panic!("CRITICAL: Réutilisation d'état SLH-DSA détectée - arrêt immédiat");
        }
        
        // Vérification de limite
        state.signature_count += 1;
        if state.signature_count > self.max_signatures {
            return Err(SlhDsaConsensusError::StateDesync);
        }
        
        state.last_counter = new_counter;
        state.last_block_hash = block_hash;
        
        Ok(())
    }

    /// Obtient une copie de l'état actuel
    pub fn get_state(&self) -> SlhDsaValidatorState {
        // Mutex poisoning means a previous holder panicked — propagate
        self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned")
            .clone()
    }

    /// Vérifie si l'état est proche de la limite
    pub fn is_near_limit(&self) -> bool {
        let state = self.state.lock()
            .expect("CRITICAL: SlhDsaStateManager mutex poisoned");
        state.signature_count >= self.max_signatures - 1000
    }
}

/// Validateur de consensus SLH-DSA
pub struct SlhDsaConsensus {
    state_manager: Arc<SlhDsaStateManager>,
    verifier: SlhDsaVerifier,
}

impl SlhDsaConsensus {
    pub fn new(state_manager: Arc<SlhDsaStateManager>, verifier: SlhDsaVerifier) -> Self {
        Self {
            state_manager,
            verifier,
        }
    }

    /// Valide la signature d'un bloc
    /// 
    /// # Errors
    /// Retourne une erreur si la signature est invalide ou si l'état est compromis
    pub fn validate_block_signature(&self, block: &Block) -> Result<(), SlhDsaConsensusError> {
        // Vérifier que l'état n'est pas proche de la limite
        if self.state_manager.is_near_limit() {
            return Err(SlhDsaConsensusError::StateDesync);
        }

        // Obtenir le message signé (hash du bloc)
        let message = block.hash().as_bytes();
        
        // Extraire la signature et le compteur du bloc
        let (signature, counter) = self.extract_signature_data(block)?;
        
        // Vérifier la signature
        self.verifier
            .verify(&message, &signature, counter)
            .map_err(|e| match e {
                SlhDsaError::InvalidSignature => SlhDsaConsensusError::InvalidSignature,
                _ => SlhDsaConsensusError::InternalError(format!("Vérification échouée: {:?}", e)),
            })?;

        // Mettre à jour l'état
        self.state_manager
            .update_signature_state(counter, block.hash())
            .map_err(|_| SlhDsaConsensusError::StateReuseDetected)?;

        Ok(())
    }

    /// Valide la signature d'une transaction
    pub fn validate_transaction_signature(&self, tx: &Transaction) -> Result<(), SlhDsaConsensusError> {
        // Pour les transactions, on utilise une clé différente et un compteur séparé
        // Cette implémentation dépend du format de transaction
        // TODO: Implémenter selon le format de transaction TSN
        Ok(())
    }

    /// Extrait la signature et le compteur des données du bloc
    fn extract_signature_data(&self, block: &Block) -> Result<(Vec<u8>, u64), SlhDsaConsensusError> {
        // Le format dépend de l'implémentation du bloc TSN
        // Hypothèse: le bloc contient champ signature et counter
        block
            .get_signature_data()
            .ok_or_else(|| SlhDsaConsensusError::InternalError("Données de signature manquantes".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::Hash;
    use rand::Rng;

    struct MockBlock {
        hash: Hash,
        signature: Vec<u8>,
        counter: u64,
    }

    impl MockBlock {
        fn new(counter: u64) -> Self {
            let mut rng = rand::thread_rng();
            let mut hash_bytes = [0u8; 32];
            rng.fill(&mut hash_bytes);
            
            Self {
                hash: Hash::from_bytes(&hash_bytes),
                signature: vec![0u8; 64], // Signature mock
                counter,
            }
        }
    }

    impl Block for MockBlock {
        fn hash(&self) -> Hash {
            self.hash
        }

        fn get_signature_data(&self) -> Option<(Vec<u8>, u64)> {
            Some((self.signature.clone(), self.counter))
        }
    }

    #[test]
    fn test_state_manager_prevents_reuse() {
        let manager = SlhDsaStateManager::new(0, 1000);
        
        // Première mise à jour devrait réussir
        assert!(manager.update_signature_state(1,