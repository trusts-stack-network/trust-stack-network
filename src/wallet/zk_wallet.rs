//! Wallet support pour les preuves ZK Halo2
//! 
//! Génère et gère les preuves ZK pour les transactions privées

use crate::crypto::proof::ZkProof;
use crate::crypto::commitment::NoteCommitment;
use crate::crypto::note::Note;
use crate::crypto::nullifier::Nullifier;
use ark_bn254::Fr;
// use ark_ff::UniformRand;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
    },
    poly::{
//         commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        VerificationStrategy,
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use lru::LruCache;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
// use zeroize::Zeroize;

/// Configuration pour la génération de preuves ZK
#[derive(Clone, Debug)]
pub struct ProofConfig {
    /// Degré du polynôme pour les paramètres KZG
    pub k: u32,
    /// Timeout pour la génération de preuve
    pub timeout: Duration,
    /// Taille maximale du cache
    pub cache_size: usize,
}

impl Default for ProofConfig {
    fn default() -> Self {
        Self {
            k: 17, // 2^17 = 131072 contraintes
            timeout: Duration::from_secs(30),
            cache_size: 100,
        }
    }
}

/// Circuit Halo2 pour les preuves de note
#[derive(Clone, Debug)]
pub struct NoteCircuit {
    /// Valeur de la note (privée)
    pub value: Value<Fr>,
    /// Randomness de la note (privé)
    pub randomness: Value<Fr>,
    /// Hash de la clé publique du destinataire (privé)
    pub recipient_pk_hash: Value<Fr>,
    /// Commitment de la note (public)
    pub commitment: Value<Fr>,
}

impl Circuit<Fr> for NoteCircuit {
    type Config = NoteConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            value: Value::unknown(),
            randomness: Value::unknown(),
            recipient_pk_hash: Value::unknown(),
            commitment: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let constant = meta.fixed_column();

        meta.enable_constant(constant);
        meta.enable_equality(instance);
        for column in &advice {
            meta.enable_equality(*column);
        }

        NoteConfig {
            advice,
            instance,
            constant,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Implémentation simplifiée du circuit
        layouter.assign_region(
            || "note commitment",
            |mut region| {
                // Assigne les valeurs privées
                let value_cell = region.assign_advice(
                    || "value",
                    config.advice[0],
                    0,
                    || self.value,
                )?;

                let randomness_cell = region.assign_advice(
                    || "randomness",
                    config.advice[1],
                    0,
                    || self.randomness,
                )?;

                let recipient_cell = region.assign_advice(
                    || "recipient",
                    config.advice[2],
                    0,
                    || self.recipient_pk_hash,
                )?;

                // Calcule le commitment (simplifié)
                let commitment_cell = region.assign_advice(
                    || "commitment",
                    config.advice[0],
                    1,
                    || self.commitment,
                )?;

                // Expose le commitment comme instance publique
                region.constrain_instance(commitment_cell.cell(), config.instance, 0)?;

                Ok(())
            },
        )
    }
}

/// Configuration du circuit de note
#[derive(Clone, Debug)]
pub struct NoteConfig {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    constant: Column<Fixed>,
}

/// Statistiques de performance pour les preuves ZK
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofStats {
    /// Nombre total de preuves générées
    pub total_proofs: u64,
    /// Temps moyen de génération (en ms)
    pub avg_generation_time_ms: f64,
    /// Temps minimum de génération (en ms)
    pub min_generation_time_ms: u64,
    /// Temps maximum de génération (en ms)
    pub max_generation_time_ms: u64,
    /// Nombre de preuves en cache
    pub cached_proofs: usize,
    /// Taux de réussite du cache (0.0 à 1.0)
    pub cache_hit_rate: f64,
}

impl Default for ProofStats {
    fn default() -> Self {
        Self {
            total_proofs: 0,
            avg_generation_time_ms: 0.0,
            min_generation_time_ms: u64::MAX,
            max_generation_time_ms: 0,
            cached_proofs: 0,
            cache_hit_rate: 0.0,
        }
    }
}

/// Gestionnaire de preuves ZK pour le wallet
pub struct ZkWallet {
    /// Cache des preuves générées (indexé par commitment)
    proof_cache: LruCache<[u8; 32], ZkProof>,
    /// Paramètres KZG pour Halo2
    params: Arc<ParamsKZG<ark_bn254::Bn254>>,
    /// Clé de vérification
    verifying_key: Arc<VerifyingKey<ark_bn254::G1Affine>>,
    /// Clé de preuve
    proving_key: Arc<ProvingKey<ark_bn254::G1Affine>>,
    /// Configuration
    config: ProofConfig,
    /// Statistiques de performance
    stats: Arc<Mutex<ProofStats>>,
    /// Compteur de hits/miss du cache
    cache_hits: u64,
    cache_misses: u64,
}

impl ZkWallet {
    /// Crée un nouveau wallet ZK avec la configuration par défaut
    pub fn new() -> Result<Self, WalletError> {
        Self::with_config(ProofConfig::default())
    }

    /// Crée un nouveau wallet ZK avec une configuration personnalisée
    pub fn with_config(config: ProofConfig) -> Result<Self, WalletError> {
        // Génère les paramètres KZG
        let params = ParamsKZG::<ark_bn254::Bn254>::setup(config.k, OsRng);
        let params = Arc::new(params);

        // Crée le circuit vide pour la génération des clés
        let empty_circuit = NoteCircuit {
            value: Value::unknown(),
            randomness: Value::unknown(),
            recipient_pk_hash: Value::unknown(),
            commitment: Value::unknown(),
        };

        // Génère les clés de vérification et de preuve
        let vk = keygen_vk(&params, &empty_circuit)
            .map_err(|e| WalletError::SetupError(format!("Erreur génération VK: {:?}", e)))?;
        let pk = keygen_pk(&params, vk.clone(), &empty_circuit)
            .map_err(|e| WalletError::SetupError(format!("Erreur génération PK: {:?}", e)))?;

        Ok(Self {
            proof_cache: LruCache::new(
                NonZeroUsize::new(config.cache_size)
                    .unwrap_or(NonZeroUsize::new(1).unwrap()) // fallback to 1 if cache_size is 0
            ),
            params,
            verifying_key: Arc::new(vk),
            proving_key: Arc::new(pk),
            config,
            stats: Arc::new(Mutex::new(ProofStats::default())),
            cache_hits: 0,
            cache_misses: 0,
        })
    }

    /// Génère une preuve ZK pour une note
    pub fn prove_note(&mut self, note: &Note) -> Result<ZkProof, WalletError> {
        let start_time = Instant::now();
        let commitment = note.commitment();
        let commitment_bytes = commitment.to_bytes();
        
        // Vérifie le cache
        if let Some(proof) = self.proof_cache.get(&commitment_bytes) {
            self.cache_hits += 1;
            self.update_cache_stats();
            return Ok(proof.clone());
        }
        
        self.cache_misses += 1;

        // Convertit les valeurs en éléments de champ
        let value_fr = Fr::from(note.value);
        let recipient_fr = Fr::from_le_bytes_mod_order(&note.recipient_pk_hash);
        let commitment_fr = Fr::from_le_bytes_mod_order(&commitment_bytes);

        // Crée le circuit avec les valeurs réelles
        let circuit = NoteCircuit {
            value: Value::known(value_fr),
            randomness: Value::known(note.randomness),
            recipient_pk_hash: Value::known(recipient_fr),
            commitment: Value::known(commitment_fr),
        };

        // Génère la preuve
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        let instances = &[&[commitment_fr]];
        
        create_proof::<
            KZGCommitmentScheme<ark_bn254::Bn254>,
            ProverSHPLONK<'_, ark_bn254::Bn254>,
            Challenge255<ark_bn254::G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, ark_bn254::G1Affine, Challenge255<ark_bn254::G1Affine>>,
            _,
        >(
            &self.params,
            &self.proving_key,
            &[circuit],
            instances,
            OsRng,
            &mut transcript,
        )
        .map_err(|e| WalletError::ProofError(format!("Erreur génération preuve: {:?}", e)))?;

        let proof_bytes = transcript.finalize();
        let proof = ZkProof::from_bytes(&proof_bytes)?;
        
        // Cache la preuve
        self.proof_cache.put(commitment_bytes, proof.clone());
        
        // Met à jour les statistiques
        let generation_time = start_time.elapsed();
        self.update_stats(generation_time);
        self.update_cache_stats();
        
        Ok(proof)
    }
    
    /// Vérifie une preuve ZK
    pub fn verify_proof(&self, proof: &ZkProof, commitment: &NoteCommitment) -> Result<bool, WalletError> {
        let commitment_bytes = commitment.to_bytes();
        let commitment_fr = Fr::from_le_bytes_mod_order(&commitment_bytes);
        
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof.to_bytes());
        let instances = &[&[commitment_fr]];
        
        let strategy = SingleStrategy::new(&self.params);
        let result = verify_proof::<
            KZGCommitmentScheme<ark_bn254::Bn254>,
            VerifierSHPLONK<'_, ark_bn254::Bn254>,
            Challenge255<ark_bn254::G1Affine>,
            Blake2bRead<&[u8], ark_bn254::G1Affine, Challenge255<ark_bn254::G1Affine>>,
            SingleStrategy<'_, ark_bn254::Bn254>,
        >(
            &self.params,
            &self.verifying_key,
            strategy,
            instances,
            &mut transcript,
        );
        
        match result {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Génère une preuve de nullifier
//     pub fn prove_nullifier(&mut self, note: &Note, nullifier: &Nullifier) -> Result<ZkProof, WalletError> {
        // Pour l'instant, utilise la même logique que prove_note
        // Dans une implémentation complète, il faudrait un circuit séparé
        self.prove_note(note)
    }

    /// Vide le cache des preuves
    pub fn clear_cache(&mut self) {
        self.proof_cache.clear();
        self.cache_hits = 0;
        self.cache_misses = 0;
        self.update_cache_stats();
    }

    /// Retourne les statistiques de performance
    pub fn get_stats(&self) -> ProofStats {
        self.stats.lock()
            .unwrap_or_else(|e| e.into_inner()) // recover from poisoned mutex
            .clone()
    }

    /// Retourne la taille actuelle du cache
    pub fn cache_size(&self) -> usize {
        self.proof_cache.len()
    }

    /// Retourne la configuration actuelle
    pub fn config(&self) -> &ProofConfig {
        &self.config
    }

    /// Met à jour les statistiques après génération d'une preuve
    fn update_stats(&self, generation_time: Duration) {
        let mut stats = self.stats.lock()
            .unwrap_or_else(|e| e.into_inner());
        let time_ms = generation_time.as_millis() as u64;
        
        stats.total_proofs += 1;
        
        // Met à jour les temps min/max
        if time_ms < stats.min_generation_time_ms {
            stats.min_generation_time_ms = time_ms;
        }
        if time_ms > stats.max_generation_time_ms {
            stats.max_generation_time_ms = time_ms;
        }
        
        // Calcule la moyenne mobile
        let total = stats.total_proofs as f64;
        stats.avg_generation_time_ms = 
            (stats.avg_generation_time_ms * (total - 1.0) + time_ms as f64) / total;
    }

    /// Met à jour les statistiques du cache
    fn update_cache_stats(&self) {
        let mut stats = self.stats.lock()
            .unwrap_or_else(|e| e.into_inner());
        stats.cached_proofs = self.proof_cache.len();
        
        let total_requests = self.cache_hits + self.cache_misses;
        if total_requests > 0 {
            stats.cache_hit_rate = self.cache_hits as f64 / total_requests as f64;
        }
    }
}

impl Default for ZkWallet {
    fn default() -> Self {
        Self::new().expect("INIT: ZkWallet default initialization failed — check KZG params")
    }
}

impl Drop for ZkWallet {
    fn drop(&mut self) {
        // Nettoie les secrets en mémoire
        self.proof_cache.clear();
    }
}

/// Erreurs du wallet ZK
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Erreur de preuve: {0}")]
    ProofError(String),
    
    #[error("Erreur de note: {0}")]
    NoteError(String),
    
    #[error("Erreur de setup: {0}")]
    SetupError(String),
    
    #[error("Erreur de sérialisation: {0}")]
    SerializationError(String),
    
    #[error("Timeout lors de la génération de preuve")]
    TimeoutError,
    
    #[error("Paramètres invalides: {0}")]
    InvalidParams(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_zk_wallet_creation() {
        let wallet = ZkWallet::new();
        assert!(wallet.is_ok());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        // Crée une note de test
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        let commitment = note.commitment();
        
        // Génère une preuve
        let proof_result = wallet.prove_note(&note);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        
        // Vérifie la preuve
        let verification_result = wallet.verify_proof(&proof, &commitment);
        assert!(verification_result.is_ok());
        assert!(verification_result.unwrap());
    }

    #[test]
    fn test_proof_caching() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        // Première génération (miss du cache)
        let proof1 = wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Deuxième génération (hit du cache)
        let proof2 = wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Les preuves doivent être identiques
        assert_eq!(proof1.to_bytes(), proof2.to_bytes());
    }

    #[test]
    fn test_cache_clearing() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        // Génère une preuve pour remplir le cache
        wallet.prove_note(&note).unwrap();
        assert_eq!(wallet.cache_size(), 1);
        
        // Vide le cache
        wallet.clear_cache();
        assert_eq!(wallet.cache_size(), 0);
    }

    #[test]
    fn test_stats_tracking() {
        let mut wallet = ZkWallet::new().unwrap();
        let mut rng = OsRng;
        
        let recipient_pk_hash = [1u8; 32];
        let note = Note::new(1000, recipient_pk_hash, &mut rng);
        
        let initial_stats = wallet.get_stats();
        assert_eq!(initial_stats.total_proofs, 0);
        
        // Génère une preuve
        wallet.prove_note(&note).unwrap();
        
        let updated_stats = wallet.get_stats();
        assert_eq!(updated_stats.total_proofs, 1);
        assert!(updated_stats.avg_generation_time_ms > 0.0);
    }
}