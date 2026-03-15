//! Couche d'adaptation ZK pour TSN - Migration Plonky2 → Plonky3
//!
//! Ce module fournit une abstraction unifiée sur les systèmes de preuve ZK,
//! permettant une migration progressive de Plonky2 vers Plonky3.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Application TSN                 │
//! ├─────────────────────────────────────────┤
//! │    ZkProofSystem (trait commun)         │
//! ├─────────────────────────────────────────┤
//! │  Plonky2Adapter    │  Plonky3Adapter    │
//! ├─────────────────────────────────────────┤
//! │  plonky2::plonk    │  p3-uni-stark/AIR  │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Feature Flags
//!
//! - `zk-plonky2` : Active le backend Plonky2 (legacy, stable)
//! - `zk-plonky3` : Active le backend Plonky3 (défaut, AIR-based)
//! - `zk-compat` : Active les deux backends avec sélection runtime
//!
//! ## Security Considerations
//!
//! - Les preuves Plonky2 utilisent FRI (post-quantique, hash-based)
//! - Les preuves Plonky3 utilisent FRI + AIR (post-quantique, Poseidon2 natif)
//! - Les deux fournissent ~128 bits de sécurité post-quantique
//!
//! Références:
//! - Plonky2: https://github.com/0xPolygonZero/plonky2
//! - Plonky3: https://github.com/Plonky3/Plonky3

use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Version du système de preuve utilisée
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum ZkSystemVersion {
    /// Plonky2 STARKs - système legacy, post-quantique pur
    Plonky2,
    /// Plonky3 AIR - système actuel, FRI + Poseidon2 natif sur Goldilocks
    Plonky3,
}

impl ZkSystemVersion {
    /// Retourne l'identifiant de version pour la sérialisation
    pub fn as_u8(&self) -> u8 {
        match self {
            ZkSystemVersion::Plonky2 => 1,
            ZkSystemVersion::Plonky3 => 3,
        }
    }

    /// Parse l'identifiant de version
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ZkSystemVersion::Plonky2),
            3 => Some(ZkSystemVersion::Plonky3),
            _ => None,
        }
    }
}

/// Erreurs du système de preuve ZK
#[derive(Debug, Error)]
pub enum ZkAdapterError {
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),

    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    #[error("Unsupported proof system: {0}")]
    UnsupportedSystem(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Balance mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    BalanceMismatch { inputs: u64, outputs: u64, fee: u64 },
}

/// Preuve ZK générique indépendante du backend
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    /// Version du système de preuve
    pub version: ZkSystemVersion,
    /// Données de la preuve (format spécifique au backend)
    #[serde(with = "hex_serde")]
    pub proof_data: Vec<u8>,
    /// Entrées publiques sérialisées
    #[serde(with = "hex_serde")]
    pub public_inputs: Vec<u8>,
    /// Métadonnées additionnelles (taille, timestamp, etc.)
    pub metadata: ProofMetadata,
}

/// Métadonnées d'une preuve
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Taille de la preuve en bytes
    pub proof_size: usize,
    /// Nombre de contraintes dans le circuit
    pub constraint_count: Option<usize>,
    /// Temps de génération en ms (si mesuré)
    pub generation_time_ms: Option<u64>,
    /// Version du circuit
    pub circuit_version: u32,
}

impl ZkProof {
    /// Crée une nouvelle preuve
    pub fn new(
        version: ZkSystemVersion,
        proof_data: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Self {
        let proof_size = proof_data.len();
        Self {
            version,
            proof_data,
            public_inputs,
            metadata: ProofMetadata {
                proof_size,
                ..Default::default()
            },
        }
    }

    /// Retourne la taille totale de la preuve
    pub fn size(&self) -> usize {
        self.proof_data.len() + self.public_inputs.len()
    }

    /// Vérifie que la preuve est du format attendu
    pub fn validate_format(&self) -> Result<(), ZkAdapterError> {
        if self.proof_data.is_empty() {
            return Err(ZkAdapterError::InvalidProofFormat(
                "Empty proof data".to_string(),
            ));
        }
        if self.proof_data.len() > MAX_PROOF_SIZE {
            return Err(ZkAdapterError::InvalidProofFormat(format!(
                "Proof too large: {} bytes (max: {})",
                self.proof_data.len(),
                MAX_PROOF_SIZE
            )));
        }
        Ok(())
    }
}

/// Taille maximale d'une preuve (protection DoS)
pub const MAX_PROOF_SIZE: usize = 500 * 1024; // 500 KB

/// Entrées publiques d'une transaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionPublicInputs {
    /// Racines Merkle (une par spend)
    pub merkle_roots: Vec<[u8; 32]>,
    /// Nullifiers (un par spend)
    pub nullifiers: Vec<[u8; 32]>,
    /// Commitments des notes (un par output)
    pub note_commitments: Vec<[u8; 32]>,
    /// Frais de transaction
    pub fee: u64,
}

/// Témoin pour le spending d'une note
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SpendWitness {
    /// Valeur de la note (privée)
    pub value: u64,
    /// Hash de la clé publique du destinataire (privée)
    pub recipient_pk_hash: [u8; 32],
    /// Randomness de la note (privée)
    #[zeroize(skip)]
    pub randomness: [u8; 32],
    /// Clé de nullification (privée)
    #[zeroize(skip)]
    pub nullifier_key: [u8; 32],
    /// Position dans l'arbre de commitments
    pub position: u64,
    /// Témoin Merkle (chemin + racine)
    pub merkle_path: Vec<[u8; 32]>,
    /// Index de la feuille
    pub leaf_index: usize,
}

/// Témoin pour la création d'une output
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct OutputWitness {
    /// Valeur de la note
    pub value: u64,
    /// Hash de la clé publique du destinataire
    pub recipient_pk_hash: [u8; 32],
    /// Randomness pour le commitment
    #[zeroize(skip)]
    pub randomness: [u8; 32],
}

/// Trait principal pour les systèmes de preuve ZK
///
/// Ce trait définit l'interface commune entre Plonky2 et Plonky3.
/// Les implémentations doivent garantir:
/// - La soundness: une preuve invalide ne passe pas la vérification
/// - La completeness: une preuve valide passe toujours
/// - La zero-knowledge: pas de fuite d'information
pub trait ZkProofSystem: Send + Sync {
    /// Génère une preuve de transaction
    ///
    /// # Arguments
    /// * `spends` - Témoins pour les notes dépensées
    /// * `outputs` - Témoins pour les notes créées
    /// * `fee` - Frais de transaction
    ///
    /// # Security
    /// - Les témoins sont zeroizés après usage
    /// - Utilise OsRng pour la randomness
    fn prove_transaction(
        &self,
        spends: &[SpendWitness],
        outputs: &[OutputWitness],
        fee: u64,
    ) -> Result<ZkProof, ZkAdapterError>;

    /// Vérifie une preuve de transaction
    ///
    /// # Arguments
    /// * `proof` - La preuve à vérifier
    /// * `public_inputs` - Les entrées publiques
    fn verify_transaction(
        &self,
        proof: &ZkProof,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<bool, ZkAdapterError>;

    /// Retourne la version du système
    fn version(&self) -> ZkSystemVersion;

    /// Retourne le nombre maximum de spends supportés
    fn max_spends(&self) -> usize;

    /// Retourne le nombre maximum d'outputs supportés
    fn max_outputs(&self) -> usize;

    /// Précharge les paramètres du circuit (optimisation)
    fn preload_circuit_params(&mut self) -> Result<(), ZkAdapterError>;
}

/// Factory pour créer le système de preuve approprié
pub struct ZkSystemFactory;

impl ZkSystemFactory {
    /// Crée le système de preuve par défaut (Plonky3)
    pub fn create_default() -> Result<Box<dyn ZkProofSystem>, ZkAdapterError> {
        Ok(Box::new(plonky3_adapter::Plonky3Adapter::new()?))
    }

    /// Crée un système de preuve spécifique
    pub fn create(version: ZkSystemVersion) -> Result<Box<dyn ZkProofSystem>, ZkAdapterError> {
        match version {
            ZkSystemVersion::Plonky2 => {
                Ok(Box::new(plonky2_adapter::Plonky2Adapter::new()?))
            }
            ZkSystemVersion::Plonky3 => {
                Ok(Box::new(plonky3_adapter::Plonky3Adapter::new()?))
            }
        }
    }
}

// Backend modules
pub mod plonky2_adapter;
pub mod plonky3_adapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_serialization() {
        assert_eq!(ZkSystemVersion::Plonky2.as_u8(), 1);
        assert_eq!(ZkSystemVersion::Plonky3.as_u8(), 3);
        assert_eq!(ZkSystemVersion::from_u8(1), Some(ZkSystemVersion::Plonky2));
        assert_eq!(ZkSystemVersion::from_u8(3), Some(ZkSystemVersion::Plonky3));
        assert_eq!(ZkSystemVersion::from_u8(2), None); // Halo2 removed
        assert_eq!(ZkSystemVersion::from_u8(99), None);
    }

    #[test]
    fn test_proof_validation() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![1, 2, 3],
            vec![4, 5],
        );
        assert!(proof.validate_format().is_ok());
        assert_eq!(proof.size(), 5);
    }

    #[test]
    fn test_proof_empty_validation() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![],
            vec![],
        );
        assert!(proof.validate_format().is_err());
    }

    #[test]
    fn test_proof_oversized() {
        let proof = ZkProof::new(
            ZkSystemVersion::Plonky3,
            vec![0u8; MAX_PROOF_SIZE + 1],
            vec![],
        );
        assert!(proof.validate_format().is_err());
    }
}

// Helper pour la sérialisation hex
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
