//! Mempool avancé avec gestion intelligente de la mémoire.
//!
//! Cette version améliore le mempool original avec :
//! - Gestion de pression mémoire avec éviction intelligente
//! - Anti-DoS avec rate limiting par peer
//! - Prioritisation basée sur les frais et l'ancienneté
//! - Métriques détaillées pour monitoring
//! - Support async complet avec tokio

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Mutex};
use tracing::{debug, info, warn, error};

use crate::core::{ShieldedState, ShieldedTransaction, Transaction};
use crate::network::mempool_manager::{MempoolMemoryManager, MempoolMemoryConfig, MempoolError};
use crate::network::types::{TransactionId, TransactionV1, TransactionV2};
use crate::network::anti_dos::RateLimiter;

/// Configuration du mempool avancé.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolV2Config {
    /// Configuration du gestionnaire de mémoire.
    pub memory: MempoolMemoryConfig,
    
    /// Limite de transactions par peer par minute.
    pub max_tx_per_peer_per_minute: u32,
    
    /// Taille maximale d'une transaction en bytes.
    pub max_transaction_size: usize,
    
    /// Frais minimum absolu (anti-spam).
    pub min_absolute_fee: u64,
    
    /// Activer la validation stricte des transactions.
    pub strict_validation: bool,
    
    /// Intervalle de nettoyage des peers inactifs.
    pub peer_cleanup_interval_seconds: u64,
}

impl Default for MempoolV2Config {
    fn default() -> Self {
        Self {
            memory: MempoolMemoryConfig::default(),
            max_tx_per_peer_per_minute: 100,
            max_transaction_size: 1024 * 1024, // 1 MB
            min_absolute_fee: 1000, // 1000 sats minimum
            strict_validation: true,
            peer_cleanup_interval_seconds: 300, // 5 minutes
        }
    }
}

/// Statistiques détaillées du mempool.
#[derive(Clone, Debug, Default, Serialize)]
pub struct MempoolV2Stats {
    /// Nombre de transactions V1.
    pub v1_transactions: usize,
    
    /// Nombre de transactions V2.
    pub v2_transactions: usize,
    
    /// Nombre total de transactions.
    pub total_transactions: usize,
    
    /// Nombre de nullifiers en attente.
    pub pending_nullifiers: usize,
    
    /// Nombre total d'ajouts de transactions.
    pub total_adds: u64,
    
    /// Nombre total de rejets.
    pub total_rejections: u64,
    
    /// Nombre de rejets par double-spend.
    pub double_spend_rejections: u64,
    
    /// Nombre de rejets par frais insuffisants.
    pub fee_rejections: u64,
    
    /// Nombre de rejets par rate limiting.
    pub rate_limit_rejections: u64,
    
    /// Nombre de rejets par validation.
    pub validation_rejections: u64,
    
    /// Statistiques mémoire.
    pub memory_stats: crate::network::mempool_manager::MemoryStats,
    
    /// Frais moyen par transaction.
    pub average_fee: f64,
    
    /// Taille moyenne des transactions.
    pub average_size: f64,
    
    /// Dernière mise à jour des statistiques.
    pub last_updated: u64,
}

/// Informations sur un peer pour rate limiting.
#[derive(Debug, Clone)]
struct PeerInfo {
    /// Nombre de transactions soumises dans la fenêtre actuelle.
    tx_count: u32,
    
    /// Début de la fenêtre de rate limiting.
    window_start: Instant,
    
    /// Dernière activité du peer.
    last_activity: Instant,
    
    /// Score de réputation (0.0 = mauvais, 1.0 = excellent).
    reputation: f64,
}

impl PeerInfo {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            tx_count: 0,
            window_start: now,
            last_activity: now,
            reputation: 1.0, // Commencer avec une bonne réputation
        }
    }
    
    /// Vérifier si le peer peut soumettre une transaction.
    fn can_submit(&mut self, max_per_minute: u32) -> bool {
        let now = Instant::now();
        
        // Reset de la fenêtre si plus d'une minute s'est écoulée
        if now.duration_since(self.window_start) >= Duration::from_secs(60) {
            self.tx_count = 0;
            self.window_start = now;
        }
        
        self.last_activity = now;
        
        if self.tx_count >= max_per_minute {
            // Pénaliser la réputation pour spam
            self.reputation = (self.reputation * 0.9).max(0.1);
            false
        } else {
            self.tx_count += 1;
            // Améliorer légèrement la réputation pour comportement normal
            self.reputation = (self.reputation * 1.001).min(1.0);
            true
        }
    }
    
    /// Vérifier si le peer est inactif.
    fn is_inactive(&self, timeout: Duration) -> bool {
        self.last_activity.elapsed() > timeout
    }
}

/// Mempool avancé avec gestion intelligente de la mémoire.
pub struct MempoolV2 {
    /// Configuration.
    config: MempoolV2Config,
    
    /// Transactions V1 en attente.
    v1_transactions: Arc<RwLock<HashMap<TransactionId, ShieldedTransaction>>>,
    
    /// Transactions V2 en attente.
    v2_transactions: Arc<RwLock<HashMap<TransactionId, Transaction>>>,
    
    /// Nullifiers en attente (détection double-spend).
    pending_nullifiers: Arc<RwLock<HashSet<[u8; 32]>>>,
    
    /// Gestionnaire de mémoire.
    memory_manager: MempoolMemoryManager,
    
    /// Informations des peers pour rate limiting.
    peer_info: Arc<RwLock<HashMap<String, PeerInfo>>>,
    
    /// Statistiques.
    stats: Arc<RwLock<MempoolV2Stats>>,
    
    /// État de validation.
    shielded_state: Option<Arc<RwLock<ShieldedState>>>,
}

impl MempoolV2 {
    /// Créer un nouveau mempool avancé.
    pub fn new(config: MempoolV2Config) -> Self {
        let memory_manager = MempoolMemoryManager::new(config.memory.clone());
        
        Self {
            config,
            v1_transactions: Arc::new(RwLock::new(HashMap::new())),
            v2_transactions: Arc::new(RwLock::new(HashMap::new())),
            pending_nullifiers: Arc::new(RwLock::new(HashSet::new())),
            memory_manager,
            peer_info: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(MempoolV2Stats::default())),
            shielded_state: None,
        }
    }
    
    /// Configurer l'état shielded pour validation.
    pub fn set_shielded_state(&mut self, state: Arc<RwLock<ShieldedState>>) {
        self.shielded_state = Some(state);
    }
    
    /// Ajouter une transaction V1 au mempool.
    pub async fn add_transaction(
        &self,
        tx: ShieldedTransaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v1(&tx);
        let tx_fee = tx.fee;
        
        // Vérifications préliminaires
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;
        
        // Vérifier si la transaction existe déjà
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }
        
        // Vérifier les nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier.0) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }
        
        // Validation stricte si activée
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v1(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }
        
        // Vérifier la pression mémoire
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Ajouter la transaction
        {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.insert(tx_hash, tx.clone());
        }
        
        // Ajouter les nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier.0);
            }
        }
        
        // Mettre à jour les statistiques
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v1_transactions += 1;
            stats.total_transactions += 1;
        }
        
        info!("Transaction V1 ajoutée au mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Ajouter une transaction V2 au mempool.
    pub async fn add_transaction_v2(
        &self,
        tx: Transaction,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        let tx_hash = tx.hash();
        let tx_size = self.estimate_transaction_size_v2(&tx);
        let tx_fee = tx.fee();
        
        // Vérifications préliminaires
        self.validate_transaction_basic(tx_size, tx_fee, peer_id).await?;
        
        // Vérifier si la transaction existe déjà
        if self.contains(&tx_hash).await {
            self.increment_rejection_stat("duplicate").await;
            return Err(MempoolV2Error::DuplicateTransaction);
        }
        
        // Vérifier les nullifiers (double-spend)
        {
            let pending_nullifiers = self.pending_nullifiers.read().await;
            for nullifier in tx.nullifiers() {
                if pending_nullifiers.contains(&nullifier) {
                    self.increment_rejection_stat("double_spend").await;
                    return Err(MempoolV2Error::DoubleSpend);
                }
            }
        }
        
        // Validation stricte si activée
        if self.config.strict_validation {
            if let Some(state) = &self.shielded_state {
                let state_guard = state.read().await;
                if !self.validate_transaction_v2(&tx, &state_guard).await {
                    self.increment_rejection_stat("validation").await;
                    return Err(MempoolV2Error::ValidationFailed);
                }
            }
        }
        
        // Vérifier la pression mémoire
        self.memory_manager
            .add_transaction(tx_hash, tx_size, tx_fee)
            .await
            .map_err(|e| match e {
                MempoolError::MemoryPressure => MempoolV2Error::MemoryPressure,
                MempoolError::InsufficientFeeRate => MempoolV2Error::InsufficientFee,
                _ => MempoolV2Error::Internal(e.to_string()),
            })?;
        
        // Ajouter la transaction
        {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.insert(tx_hash, tx.clone());
        }
        
        // Ajouter les nullifiers
        {
            let mut pending_nullifiers = self.pending_nullifiers.write().await;
            for nullifier in tx.nullifiers() {
                pending_nullifiers.insert(nullifier);
            }
        }
        
        // Mettre à jour les statistiques
        {
            let mut stats = self.stats.write().await;
            stats.total_adds += 1;
            stats.v2_transactions += 1;
            stats.total_transactions += 1;
        }
        
        info!("Transaction V2 ajoutée au mempool: {} (fee: {}, size: {})", 
              hex::encode(&tx_hash), tx_fee, tx_size);
        
        Ok(())
    }
    
    /// Validations de base communes.
    async fn validate_transaction_basic(
        &self,
        size: usize,
        fee: u64,
        peer_id: Option<&str>,
    ) -> Result<(), MempoolV2Error> {
        // Vérifier la taille
        if size > self.config.max_transaction_size {
            self.increment_rejection_stat("size").await;
            return Err(MempoolV2Error::TransactionTooLarge);
        }
        
        // Vérifier les frais minimum
        if fee < self.config.min_absolute_fee {
            self.increment_rejection_stat("fee").await;
            return Err(MempoolV2Error::InsufficientFee);
        }
        
        // Rate limiting par peer
        if let Some(peer) = peer_id {
            let can_submit = {
                let mut peers = self.peer_info.write().await;
                let peer_info = peers.entry(peer.to_string()).or_insert_with(PeerInfo::new);
                peer_info.can_submit(self.config.max_tx_per_peer_per_minute)
            };
            
            if !can_submit {
                self.increment_rejection_stat("rate_limit").await;
                return Err(MempoolV2Error::RateLimited);
            }
        }
        
        Ok(())
    }
    
    /// Validation spécifique V1.
    /// Validates anchors and nullifiers against state (basic validation).
    /// Full ZK proof verification is done at block validation time.
    async fn validate_transaction_v1(
        &self,
        tx: &ShieldedTransaction,
        state: &ShieldedState,
    ) -> bool {
        match state.validate_transaction_basic(tx) {
            Ok(()) => true,
            Err(e) => {
                warn!("Mempool V1 validation failed: {}", e);
                false
            }
        }
    }

    /// Validation spécifique V2.
    /// Validates anchors, nullifiers, and ownership signatures against state.
    /// Full STARK proof verification is done at block validation time.
    async fn validate_transaction_v2(
        &self,
        tx: &Transaction,
        state: &ShieldedState,
    ) -> bool {
        match tx {
            Transaction::V1(v1_tx) => {
                match state.validate_transaction_basic(v1_tx) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!("Mempool V2 validation (V1 tx) failed: {}", e);
                        false
                    }
                }
            }
            Transaction::V2(v2_tx) => {
                match state.validate_transaction_v2_basic(v2_tx) {
                    Ok(()) => true,
                    Err(e) => {
                        warn!("Mempool V2 validation failed: {}", e);
                        false
                    }
                }
            }
            Transaction::Migration(_) => {
                // Migration transactions are validated during block processing
                true
            }
        }
    }
    
    /// Supprimer une transaction du mempool.
    pub async fn remove_transaction(&self, tx_hash: &TransactionId) -> bool {
        let mut removed = false;
        
        // Supprimer de V1
        if let Some(tx) = {
            let mut v1_txs = self.v1_transactions.write().await;
            v1_txs.remove(tx_hash)
        } {
            // Supprimer les nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier.0);
                }
            }
            
            // Supprimer du gestionnaire de mémoire
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Mettre à jour les statistiques
            {
                let mut stats = self.stats.write().await;
                stats.v1_transactions = stats.v1_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }
            
            removed = true;
        }
        
        // Supprimer de V2
        if let Some(tx) = {
            let mut v2_txs = self.v2_transactions.write().await;
            v2_txs.remove(tx_hash)
        } {
            // Supprimer les nullifiers
            {
                let mut pending_nullifiers = self.pending_nullifiers.write().await;
                for nullifier in tx.nullifiers() {
                    pending_nullifiers.remove(&nullifier);
                }
            }
            
            // Supprimer du gestionnaire de mémoire
            self.memory_manager.remove_transaction(tx_hash).await;
            
            // Mettre à jour les statistiques
            {
                let mut stats = self.stats.write().await;
                stats.v2_transactions = stats.v2_transactions.saturating_sub(1);
                stats.total_transactions = stats.total_transactions.saturating_sub(1);
            }
            
            removed = true;
        }
        
        if removed {
            debug!("Transaction supprimée du mempool: {}", hex::encode(tx_hash));
        }
        
        removed
    }
    
    /// Vérifier si une transaction est dans le mempool.
    pub async fn contains(&self, tx_hash: &TransactionId) -> bool {
        let v1_contains = self.v1_transactions.read().await.contains_key(tx_hash);
        let v2_contains = self.v2_transactions.read().await.contains_key(tx_hash);
        v1_contains || v2_contains
    }
    
    /// Obtenir les transactions par priorité pour mining.
    pub async fn get_transactions_for_mining(&self, limit: usize) -> (Vec<ShieldedTransaction>, Vec<Transaction>) {
        // Obtenir les IDs triés par priorité
        let priority_ids = self.memory_manager.get_transactions_by_priority(limit * 2).await;
        
        let mut v1_txs = Vec::new();
        let mut v2_txs = Vec::new();
        
        let v1_map = self.v1_transactions.read().await;
        let v2_map = self.v2_transactions.read().await;
        
        for tx_id in priority_ids {
            if v1_txs.len() + v2_txs.len() >= limit {
                break;
            }
            
            if let Some(tx) = v1_map.get(&tx_id) {
                v1_txs.push(tx.clone());
            } else if let Some(tx) = v2_map.get(&tx_id) {
                v2_txs.push(tx.clone());
            }
        }
        
        (v1_txs, v2_txs)
    }
    
    /// Supprimer les transactions confirmées.
    pub async fn remove_confirmed_transactions(&self, tx_hashes: &[TransactionId]) {
        for hash in tx_hashes {
            self.remove_transaction(hash).await;
        }
        
        info!("Supprimé {} transactions confirmées du mempool", tx_hashes.len());
    }
    
    /// Supprimer les transactions avec des nullifiers dépensés.
    pub async fn remove_spent_nullifiers(&self, spent_nullifiers: &[[u8; 32]]) {
        let mut to_remove = Vec::new();
        
        // Identifier les transactions à supprimer
        {
            let v1_txs = self.v1_transactions.read().await;
            for (hash, tx) in v1_txs.iter() {
                for nullifier in tx.nullifiers() {
                    if spent_nullifiers.contains(&nullifier.0) {
                        to_remove.push(*hash);
                        break;
                    }
                }
            }
        }
        
        {
            let v2_txs = self.v2_transactions.read().await;
            for (hash, tx) in v2_txs.iter() {
                for nullifier in tx.nullifiers() {
                    if spent_nullifiers.contains(&nullifier) {
                        to_remove.push(*hash);
                        break;
                    }
                }
            }
        }
        
        // Supprimer les transactions identifiées
        for hash in &to_remove {
            self.remove_transaction(hash).await;
        }
        
        if !to_remove.is_empty() {
            info!("Supprimé {} transactions avec nullifiers dépensés", to_remove.len());
        }
    }
    
    /// Nettoyage périodique.
    pub async fn cleanup(&self) -> Result<usize, MempoolV2Error> {
        let mut total_cleaned = 0;
        
        // Nettoyage du gestionnaire de mémoire
        total_cleaned += self.memory_manager.cleanup().await
            .map_err(|e| MempoolV2Error::Internal(e.to_string()))?;
        
        // Nettoyage des peers inactifs
        let inactive_timeout = Duration::from_secs(self.config.peer_cleanup_interval_seconds * 2);
        {
            let mut peers = self.peer_info.write().await;
            let before_count = peers.len();
            peers.retain(|_, info| !info.is_inactive(inactive_timeout));
            let cleaned_peers = before_count - peers.len();
            if cleaned_peers > 0 {
                debug!("Nettoyé {} peers inactifs", cleaned_peers);
            }
        }
        
        // Mettre à jour les statistiques
        self.update_stats().await;
        
        Ok(total_cleaned)
    }
    
    /// Mettre à jour les statistiques.
    async fn update_stats(&self) {
        let v1_count = self.v1_transactions.read().await.len();
        let v2_count = self.v2_transactions.read().await.len();
        let nullifiers_count = self.pending_nullifiers.read().await.len();
        let memory_stats = self.memory_manager.get_stats().await;
        
        let mut stats = self.stats.write().await;
        stats.v1_transactions = v1_count;
        stats.v2_transactions = v2_count;
        stats.total_transactions = v1_count + v2_count;
        stats.pending_nullifiers = nullifiers_count;
        stats.memory_stats = memory_stats;
        stats.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Calculer les moyennes
        if stats.total_transactions > 0 {
            stats.average_fee = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
            stats.average_size = memory_stats.current_memory_bytes as f64 / stats.total_transactions as f64;
        }
    }
    
    /// Incrémenter les statistiques de rejet.
    async fn increment_rejection_stat(&self, reason: &str) {
        let mut stats = self.stats.write().await;
        stats.total_rejections += 1;
        
        match reason {
            "double_spend" => stats.double_spend_rejections += 1,
            "fee" => stats.fee_rejections += 1,
            "rate_limit" => stats.rate_limit_rejections += 1,
            "validation" => stats.validation_rejections += 1,
            _ => {}
        }
    }
    
    /// Obtenir les statistiques.
    pub async fn get_stats(&self) -> MempoolV2Stats {
        self.update_stats().await;
        self.stats.read().await.clone()
    }
    
    /// Estimer la taille d'une transaction V1.
    fn estimate_transaction_size_v1(&self, tx: &ShieldedTransaction) -> usize {
        // Estimation basique - à améliorer avec la sérialisation réelle
        std::mem::size_of::<ShieldedTransaction>() + 
        tx.nullifiers().len() * 32 + 
        tx.commitments().len() * 32
    }
    
    /// Estimer la taille d'une transaction V2.
    fn estimate_transaction_size_v2(&self, tx: &Transaction) -> usize {
        // Estimation basique - à améliorer avec la sérialisation réelle
        match tx {
            Transaction::V1(_) => 1000, // Estimation
            Transaction::V2(_) => 1500, // Estimation plus grande pour post-quantique
            Transaction::Migration(_) => 2000, // Estimation pour migration
        }
    }
    
    /// Démarrer les tâches de nettoyage automatique.
    pub async fn start_background_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();
        
        // Tâche de nettoyage du gestionnaire de mémoire
        handles.push(self.memory_manager.start_cleanup_task().await);
        
        // Tâche de nettoyage général du mempool
        let mempool = self.clone();
        let cleanup_interval = Duration::from_secs(self.config.peer_cleanup_interval_seconds);
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = mempool.cleanup().await {
                    warn!("Erreur lors du nettoyage du mempool: {:?}", e);
                }
            }
        }));
        
        handles
    }
}

// Implémentation de Clone pour permettre l'utilisation dans les tâches async
impl Clone for MempoolV2 {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            v1_transactions: Arc::clone(&self.v1_transactions),
            v2_transactions: Arc::clone(&self.v2_transactions),
            pending_nullifiers: Arc::clone(&self.pending_nullifiers),
            memory_manager: self.memory_manager.clone(),
            peer_info: Arc::clone(&self.peer_info),
            stats: Arc::clone(&self.stats),
            shielded_state: self.shielded_state.clone(),
        }
    }
}

/// Erreurs du mempool avancé.
#[derive(Debug, thiserror::Error)]
pub enum MempoolV2Error {
    #[error("Transaction déjà présente dans le mempool")]
    DuplicateTransaction,
    
    #[error("Double-spend détecté")]
    DoubleSpend,
    
    #[error("Transaction trop volumineuse")]
    TransactionTooLarge,
    
    #[error("Frais insuffisants")]
    InsufficientFee,
    
    #[error("Rate limit dépassé pour ce peer")]
    RateLimited,
    
    #[error("Validation de la transaction échouée")]
    ValidationFailed,
    
    #[error("Pression mémoire - mempool plein")]
    MemoryPressure,
    
    #[error("Erreur interne: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::ShieldedTransaction;
    
    #[tokio::test]
    async fn test_mempool_v2_basic() {
        let config = MempoolV2Config::default();
        let mempool = MempoolV2::new(config);
        
        // Créer une transaction de test
        let tx = ShieldedTransaction::default(); // Placeholder
        
        // Ajouter la transaction
        let result = mempool.add_transaction(tx, Some("peer1")).await;
        // Note: ce test échouera car ShieldedTransaction::default() n'existe pas
        // Il faut créer une transaction valide pour les vrais tests
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let mut config = MempoolV2Config::default();
        config.max_tx_per_peer_per_minute = 2;
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implémenter des tests avec de vraies transactions
    }
    
    #[tokio::test]
    async fn test_memory_pressure() {
        let mut config = MempoolV2Config::default();
        config.memory.max_memory_bytes = 1024; // Très petit pour forcer l'éviction
        
        let mempool = MempoolV2::new(config);
        
        // TODO: Implémenter des tests de pression mémoire
    }
}