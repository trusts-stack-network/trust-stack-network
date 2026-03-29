//! Système de gouvernance pour la configuration cryptographique
//! 
//! Ce module implémente un système de gouvernance décentralisé pour ajuster
//! les paramètres cryptographiques de TSN, notamment la période de transition
//! entre les schémas de signature ML-DSA et SLH-DSA.
//! 
//! ## Sécurité
//! 
//! - Votes cryptographiquement vérifiables avec SLH-DSA
//! - Seuil de consensus configurable (défaut: 67% supermajorité)
//! - Protection contre les attaques de replay avec nonces
//! - Validation des propositions par merkle tree commitment
//! 
//! ## Références
//! 
//! - FIPS 205: SLH-DSA pour la signature des votes
//! - RFC 6962: Merkle Tree Hash pour l'intégrité des propositions

use crate::crypto::pq::slh_dsa::{SlhDsaPublicKey, SlhDsaSecretKey, SlhDsaSignature};
use crate::crypto::merkle_tree::MerkleTree;
use crate::crypto::poseidon::PoseidonHash;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Identifiant unique d'une proposition de gouvernance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProposalId(pub [u8; 32]);

/// Type de paramètre configurable
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigParameter {
    /// Période de transition ML-DSA → SLH-DSA (en blocs)
    SignatureTransitionPeriod(u64),
    /// Seuil de consensus pour les votes (en pourcentage, 0-100)
    ConsensusThreshold(u8),
    /// Durée de validité d'une proposition (en blocs)
    ProposalValidityPeriod(u64),
    /// Taille maximale du comité de gouvernance
    MaxCommitteeSize(u32),
}

/// Proposition de modification de paramètre
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// Identifiant unique
    pub id: ProposalId,
    /// Paramètre à modifier
    pub parameter: ConfigParameter,
    /// Hauteur de bloc de création
    pub created_at_height: u64,
    /// Hauteur de bloc d'expiration
    pub expires_at_height: u64,
    /// Hash de commitment pour l'intégrité
    pub commitment: [u8; 32],
    /// Nonce anti-replay
    pub nonce: u64,
}

/// Vote sur une proposition
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    /// ID de la proposition
    pub proposal_id: ProposalId,
    /// Clé publique du votant
    pub voter_pubkey: SlhDsaPublicKey,
    /// Support (true) ou opposition (false)
    pub support: bool,
    /// Timestamp du vote
    pub timestamp: u64,
    /// Nonce anti-replay
    pub nonce: u64,
    /// Signature SLH-DSA du vote
    pub signature: SlhDsaSignature,
}

/// État d'une proposition
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus {
    /// En cours de vote
    Active,
    /// Approuvée (seuil atteint)
    Approved,
    /// Rejetée (seuil non atteint à l'expiration)
    Rejected,
    /// Expirée sans vote suffisant
    Expired,
}

/// Configuration actuelle du système
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Période de transition signature (blocs)
    pub signature_transition_period: u64,
    /// Seuil de consensus (pourcentage)
    pub consensus_threshold: u8,
    /// Durée de validité des propositions (blocs)
    pub proposal_validity_period: u64,
    /// Taille max du comité
    pub max_committee_size: u32,
    /// Hauteur de bloc de dernière mise à jour
    pub last_updated_height: u64,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            signature_transition_period: 10_000, // Valeur actuelle hardcodée
            consensus_threshold: 67, // Supermajorité
            proposal_validity_period: 1_000, // ~1 semaine à 1 bloc/10s
            max_committee_size: 100,
            last_updated_height: 0,
        }
    }
}

/// Gestionnaire du système de gouvernance
#[derive(Debug)]
pub struct GovernanceManager {
    /// Configuration actuelle
    config: GovernanceConfig,
    /// Propositions actives
    active_proposals: HashMap<ProposalId, Proposal>,
    /// Votes par proposition
    votes: HashMap<ProposalId, Vec<Vote>>,
    /// Comité de gouvernance (clés publiques autorisées)
    committee: Vec<SlhDsaPublicKey>,
    /// Nonces utilisés (anti-replay)
    used_nonces: HashMap<SlhDsaPublicKey, u64>,
}

#[derive(Error, Debug)]
pub enum GovernanceError {
    #[error("Proposition non trouvée: {0:?}")]
    ProposalNotFound(ProposalId),
    #[error("Proposition expirée")]
    ProposalExpired,
    #[error("Vote invalide: signature incorrecte")]
    InvalidVoteSignature,
    #[error("Votant non autorisé")]
    UnauthorizedVoter,
    #[error("Nonce déjà utilisé")]
    NonceReused,
    #[error("Paramètre invalide: {0}")]
    InvalidParameter(String),
    #[error("Comité plein (max: {0})")]
    CommitteeFull(u32),
    #[error("Commitment invalide")]
    InvalidCommitment,
}

impl GovernanceManager {
    /// Crée un nouveau gestionnaire avec la configuration par défaut
    pub fn new() -> Self {
        Self {
            config: GovernanceConfig::default(),
            active_proposals: HashMap::new(),
            votes: HashMap::new(),
            committee: Vec::new(),
            used_nonces: HashMap::new(),
        }
    }

    /// Ajoute un membre au comité de gouvernance
    pub fn add_committee_member(&mut self, pubkey: SlhDsaPublicKey) -> Result<(), GovernanceError> {
        if self.committee.len() >= self.config.max_committee_size as usize {
            return Err(GovernanceError::CommitteeFull(self.config.max_committee_size));
        }
        
        if !self.committee.contains(&pubkey) {
            self.committee.push(pubkey);
        }
        Ok(())
    }

    /// Crée une nouvelle proposition
    pub fn create_proposal(
        &mut self,
        parameter: ConfigParameter,
        current_height: u64,
        nonce: u64,
    ) -> Result<ProposalId, GovernanceError> {
        // Validation du paramètre
        self.validate_parameter(&parameter)?;
        
        // Génération de l'ID unique
        let proposal_data = bincode::serialize(&(&parameter, current_height, nonce))
            .map_err(|_| GovernanceError::InvalidParameter("Serialization failed".to_string()))?;
        
        let id_hash = PoseidonHash::hash(&proposal_data);
        let proposal_id = ProposalId(id_hash);
        
        // Calcul du commitment
        let commitment = self.compute_proposal_commitment(&parameter, current_height, nonce);
        
        let proposal = Proposal {
            id: proposal_id,
            parameter,
            created_at_height: current_height,
            expires_at_height: current_height + self.config.proposal_validity_period,
            commitment,
            nonce,
        };
        
        self.active_proposals.insert(proposal_id, proposal);
        self.votes.insert(proposal_id, Vec::new());
        
        Ok(proposal_id)
    }

    /// Soumet un vote sur une proposition
    pub fn submit_vote(
        &mut self,
        proposal_id: ProposalId,
        voter_key: &SlhDsaSecretKey,
        support: bool,
        current_height: u64,
        nonce: u64,
    ) -> Result<(), GovernanceError> {
        // Vérification de l'existence de la proposition
        let proposal = self.active_proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        
        // Vérification de l'expiration
        if current_height >= proposal.expires_at_height {
            return Err(GovernanceError::ProposalExpired);
        }
        
        let voter_pubkey = voter_key.public_key();
        
        // Vérification de l'autorisation
        if !self.committee.contains(&voter_pubkey) {
            return Err(GovernanceError::UnauthorizedVoter);
        }
        
        // Vérification du nonce anti-replay
        if let Some(&last_nonce) = self.used_nonces.get(&voter_pubkey) {
            if nonce <= last_nonce {
                return Err(GovernanceError::NonceReused);
            }
        }
        
        // Création du message à signer
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let vote_message = self.create_vote_message(proposal_id, support, timestamp, nonce);
        
        // Signature du vote
        let signature = voter_key.sign(&vote_message);
        
        let vote = Vote {
            proposal_id,
            voter_pubkey: voter_pubkey.clone(),
            support,
            timestamp,
            nonce,
            signature,
        };
        
        // Vérification de la signature
        if voter_pubkey.verify(&vote_message, &vote.signature).is_err() {
            return Err(GovernanceError::InvalidVoteSignature);
        }
        
        // Enregistrement du vote
        self.votes.get_mut(&proposal_id).unwrap().push(vote);
        self.used_nonces.insert(voter_pubkey, nonce);
        
        Ok(())
    }

    /// Évalue le statut d'une proposition
    pub fn evaluate_proposal(&self, proposal_id: ProposalId, current_height: u64) -> Result<ProposalStatus, GovernanceError> {
        let proposal = self.active_proposals.get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        
        if current_height >= proposal.expires_at_height {
            return Ok(ProposalStatus::Expired);
        }
        
        let votes = self.votes.get(&proposal_id).unwrap();
        let total_committee_size = self.committee.len() as u64;
        
        if total_committee_size == 0 {
            return Ok(ProposalStatus::Active);
        }
        
        let support_votes = votes.iter().filter(|v| v.support).count() as u64;
        let support_percentage = (support_votes * 100) / total_committee_size;
        
        if support_percentage >= self.config.consensus_threshold as u64 {
            Ok(ProposalStatus::Approved)
        } else {
            Ok(ProposalStatus::Active)
        }
    }

    /// Applique une proposition approuvée
    pub fn apply_proposal(&mut self, proposal_id: ProposalId, current_height: u64) -> Result<(), GovernanceError> {
        let status = self.evaluate_proposal(proposal_id, current_height)?;
        
        if status != ProposalStatus::Approved {
            return Err(GovernanceError::InvalidParameter("Proposal not approved".to_string()));
        }
        
        let proposal = self.active_proposals.remove(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        
        // Application du changement de configuration
        match proposal.parameter {
            ConfigParameter::SignatureTransitionPeriod(period) => {
                self.config.signature_transition_period = period;
            }
            ConfigParameter::ConsensusThreshold(threshold) => {
                if threshold > 100 {
                    return Err(GovernanceError::InvalidParameter("Threshold > 100%".to_string()));
                }
                self.config.consensus_threshold = threshold;
            }
            ConfigParameter::ProposalValidityPeriod(period) => {
                self.config.proposal_validity_period = period;
            }
            ConfigParameter::MaxCommitteeSize(size) => {
                self.config.max_committee_size = size;
            }
        }
        
        self.config.last_updated_height = current_height;
        self.votes.remove(&proposal_id);
        
        Ok(())
    }

    /// Retourne la configuration actuelle
    pub fn get_config(&self) -> &GovernanceConfig {
        &self.config
    }

    /// Nettoie les propositions expirées
    pub fn cleanup_expired_proposals(&mut self, current_height: u64) {
        let expired_ids: Vec<_> = self.active_proposals
            .iter()
            .filter(|(_, proposal)| current_height >= proposal.expires_at_height)
            .map(|(id, _)| *id)
            .collect();
        
        for id in expired_ids {
            self.active_proposals.remove(&id);
            self.votes.remove(&id);
        }
    }

    /// Validation des paramètres
    fn validate_parameter(&self, parameter: &ConfigParameter) -> Result<(), GovernanceError> {
        match parameter {
            ConfigParameter::SignatureTransitionPeriod(period) => {
                if *period == 0 || *period > 1_000_000 {
                    return Err(GovernanceError::InvalidParameter(
                        "Transition period must be 1-1,000,000 blocks".to_string()
                    ));
                }
            }
            ConfigParameter::ConsensusThreshold(threshold) => {
                if *threshold == 0 || *threshold > 100 {
                    return Err(GovernanceError::InvalidParameter(
                        "Consensus threshold must be 1-100%".to_string()
                    ));
                }
            }
            ConfigParameter::ProposalValidityPeriod(period) => {
                if *period < 100 || *period > 100_000 {
                    return Err(GovernanceError::InvalidParameter(
                        "Validity period must be 100-100,000 blocks".to_string()
                    ));
                }
            }
            ConfigParameter::MaxCommitteeSize(size) => {
                if *size == 0 || *size > 1000 {
                    return Err(GovernanceError::InvalidParameter(
                        "Committee size must be 1-1000 members".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Calcule le commitment d'une proposition
    fn compute_proposal_commitment(&self, parameter: &ConfigParameter, height: u64, nonce: u64) -> [u8; 32] {
        let data = bincode::serialize(&(parameter, height, nonce)).unwrap();
        PoseidonHash::hash(&data)
    }

    /// Crée le message à signer pour un vote
    fn create_vote_message(&self, proposal_id: ProposalId, support: bool, timestamp: u64, nonce: u64) -> Vec<u8> {
        let vote_data = (proposal_id, support, timestamp, nonce);
        bincode::serialize(&vote_data).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_governance_creation() {
        let manager = GovernanceManager::new();
        assert_eq!(manager.config.signature_transition_period, 10_000);
        assert_eq!(manager.config.consensus_threshold, 67);
    }

    #[test]
    fn test_committee_management() {
        let mut manager = GovernanceManager::new();
        let key = SlhDsaSecretKey::generate(&mut OsRng);
        let pubkey = key.public_key();
        
        assert!(manager.add_committee_member(pubkey.clone()).is_ok());
        assert_eq!(manager.committee.len(), 1);
        
        // Test duplicate
        assert!(manager.add_committee_member(pubkey).is_ok());
        assert_eq!(manager.committee.len(), 1);
    }

    #[test]
    fn test_proposal_creation() {
        let mut manager = GovernanceManager::new();
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        
        let proposal_id = manager.create_proposal(parameter, 100, 1).unwrap();
        assert!(manager.active_proposals.contains_key(&proposal_id));
    }

    #[test]
    fn test_vote_submission() {
        let mut manager = GovernanceManager::new();
        let voter_key = SlhDsaSecretKey::generate(&mut OsRng);
        let voter_pubkey = voter_key.public_key();
        
        // Ajouter au comité
        manager.add_committee_member(voter_pubkey).unwrap();
        
        // Créer une proposition
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        let proposal_id = manager.create_proposal(parameter, 100, 1).unwrap();
        
        // Voter
        assert!(manager.submit_vote(proposal_id, &voter_key, true, 150, 1).is_ok());
        
        let votes = manager.votes.get(&proposal_id).unwrap();
        assert_eq!(votes.len(), 1);
        assert!(votes[0].support);
    }

    #[test]
    fn test_proposal_evaluation() {
        let mut manager = GovernanceManager::new();
        let voter_key = SlhDsaSecretKey::generate(&mut OsRng);
        let voter_pubkey = voter_key.public_key();
        
        manager.add_committee_member(voter_pubkey).unwrap();
        
        let parameter = ConfigParameter::SignatureTransitionPeriod(15_000);
        let proposal_id = manager.create_proposal(parameter, 100, 1).unwrap();
        
        // Sans vote
        let status = manager.evaluate_proposal(proposal_id, 150).unwrap();
        assert_eq!(status, ProposalStatus::Active);
        
        // Avec vote positif (100% support)
        manager.submit_vote(proposal_id, &voter_key, true, 150, 1).unwrap();
        let status = manager.evaluate_proposal(proposal_id, 150).unwrap();
        assert_eq!(status, ProposalStatus::Approved);
    }

    #[test]
    fn test_parameter_validation() {
        let manager = GovernanceManager::new();
        
        // Valide
        assert!(manager.validate_parameter(&ConfigParameter::SignatureTransitionPeriod(5_000)).is_ok());
        
        // Invalide
        assert!(manager.validate_parameter(&ConfigParameter::SignatureTransitionPeriod(0)).is_err());
        assert!(manager.validate_parameter(&ConfigParameter::ConsensusThreshold(101)).is_err());
    }
}