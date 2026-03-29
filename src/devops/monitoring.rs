//! Monitoring système pour les nœuds TSN avec métriques Prometheus.
//!
//! Ce module expose les métriques clés du nœud TSN :
//! - Block height (hauteur de la blockchain)
//! - Peer count (nombre de pairs connectés)
//! - Mempool size (taille du mempool)
//! - P2P latency (latence réseau peer-to-peer)
//! - Mining stats (statistiques de minage)
//! - Transaction throughput (débit des transactions)

use prometheus::{
    Counter, Gauge, Histogram, Registry, Encoder, TextEncoder,
    HistogramOpts, Opts, Result as PrometheusResult,
};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{info, warn, error};

use crate::core::ShieldedBlockchain;
use crate::network::{Mempool, AppState};

/// Métriques Prometheus pour le monitoring du nœud TSN
pub struct TsnMetrics {
    /// Registry Prometheus pour toutes les métriques
    pub registry: Registry,
    
    // === MÉTRIQUES BLOCKCHAIN ===
    /// Hauteur actuelle de la blockchain
    pub block_height: Gauge,
    /// Nombre total de blocs minés
    pub blocks_total: Counter,
    /// Temps de traitement des blocs (en secondes)
    pub block_processing_duration: Histogram,
    /// Taille moyenne des blocs (en bytes)
    pub block_size_bytes: Histogram,
    
    // === MÉTRIQUES RÉSEAU ===
    /// Nombre de pairs connectés
    pub peer_count: Gauge,
    /// Latence P2P moyenne (en millisecondes)
    pub p2p_latency_ms: Histogram,
    /// Nombre de messages P2P reçus
    pub p2p_messages_received: Counter,
    /// Nombre de messages P2P envoyés
    pub p2p_messages_sent: Counter,
    /// Erreurs de synchronisation réseau
    pub sync_errors_total: Counter,
    
    // === MÉTRIQUES MEMPOOL ===
    /// Taille actuelle du mempool (nombre de transactions)
    pub mempool_size: Gauge,
    /// Transactions V1 en attente
    pub mempool_v1_transactions: Gauge,
    /// Transactions V2 en attente
    pub mempool_v2_transactions: Gauge,
    /// Transactions rejetées (invalides)
    pub mempool_rejected_transactions: Counter,
    
    // === MÉTRIQUES MINING ===
    /// Hashrate actuel (hashes par seconde)
    pub mining_hashrate_hps: Gauge,
    /// Nombre de tentatives de minage
    pub mining_attempts_total: Counter,
    /// Blocs minés avec succès
    pub mining_blocks_found: Counter,
    /// Temps de minage du dernier bloc (en millisecondes)
    pub mining_last_block_time_ms: Gauge,
    
    // === MÉTRIQUES TRANSACTIONS ===
    /// Transactions soumises au total
    pub transactions_submitted_total: Counter,
    /// Transactions confirmées
    pub transactions_confirmed_total: Counter,
    /// Frais de transaction moyens
    pub transaction_fees_avg: Histogram,
    /// Temps de confirmation des transactions
    pub transaction_confirmation_time: Histogram,
    
    // === MÉTRIQUES SYSTÈME ===
    /// Uptime du nœud (en secondes)
    pub node_uptime_seconds: Gauge,
    /// Utilisation mémoire (en bytes)
    pub memory_usage_bytes: Gauge,
    /// Taille de la base de données (en bytes)
    pub database_size_bytes: Gauge,
}

impl TsnMetrics {
    /// Crée une nouvelle instance des métriques TSN
    pub fn new() -> PrometheusResult<Self> {
        let registry = Registry::new();
        
        // === MÉTRIQUES BLOCKCHAIN ===
        let block_height = Gauge::with_opts(Opts::new(
            "tsn_block_height",
            "Hauteur actuelle de la blockchain TSN"
        ))?;
        
        let blocks_total = Counter::with_opts(Opts::new(
            "tsn_blocks_total",
            "Nombre total de blocs minés"
        ))?;
        
        let block_processing_duration = Histogram::with_opts(HistogramOpts::new(
            "tsn_block_processing_duration_seconds",
            "Temps de traitement des blocs en secondes"
        ))?;
        
        let block_size_bytes = Histogram::with_opts(HistogramOpts::new(
            "tsn_block_size_bytes",
            "Taille des blocs en bytes"
        ))?;
        
        // === MÉTRIQUES RÉSEAU ===
        let peer_count = Gauge::with_opts(Opts::new(
            "tsn_peer_count",
            "Nombre de pairs connectés"
        ))?;
        
        let p2p_latency_ms = Histogram::with_opts(HistogramOpts::new(
            "tsn_p2p_latency_milliseconds",
            "Latence P2P en millisecondes"
        ).buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0]))?;
        
        let p2p_messages_received = Counter::with_opts(Opts::new(
            "tsn_p2p_messages_received_total",
            "Nombre de messages P2P reçus"
        ))?;
        
        let p2p_messages_sent = Counter::with_opts(Opts::new(
            "tsn_p2p_messages_sent_total",
            "Nombre de messages P2P envoyés"
        ))?;
        
        let sync_errors_total = Counter::with_opts(Opts::new(
            "tsn_sync_errors_total",
            "Erreurs de synchronisation réseau"
        ))?;
        
        // === MÉTRIQUES MEMPOOL ===
        let mempool_size = Gauge::with_opts(Opts::new(
            "tsn_mempool_size",
            "Taille actuelle du mempool (nombre de transactions)"
        ))?;
        
        let mempool_v1_transactions = Gauge::with_opts(Opts::new(
            "tsn_mempool_v1_transactions",
            "Transactions V1 en attente dans le mempool"
        ))?;
        
        let mempool_v2_transactions = Gauge::with_opts(Opts::new(
            "tsn_mempool_v2_transactions",
            "Transactions V2 en attente dans le mempool"
        ))?;
        
        let mempool_rejected_transactions = Counter::with_opts(Opts::new(
            "tsn_mempool_rejected_transactions_total",
            "Transactions rejetées (invalides)"
        ))?;
        
        // === MÉTRIQUES MINING ===
        let mining_hashrate_hps = Gauge::with_opts(Opts::new(
            "tsn_mining_hashrate_hps",
            "Hashrate actuel en hashes par seconde"
        ))?;
        
        let mining_attempts_total = Counter::with_opts(Opts::new(
            "tsn_mining_attempts_total",
            "Nombre total de tentatives de minage"
        ))?;
        
        let mining_blocks_found = Counter::with_opts(Opts::new(
            "tsn_mining_blocks_found_total",
            "Blocs minés avec succès"
        ))?;
        
        let mining_last_block_time_ms = Gauge::with_opts(Opts::new(
            "tsn_mining_last_block_time_milliseconds",
            "Temps de minage du dernier bloc en millisecondes"
        ))?;
        
        // === MÉTRIQUES TRANSACTIONS ===
        let transactions_submitted_total = Counter::with_opts(Opts::new(
            "tsn_transactions_submitted_total",
            "Transactions soumises au total"
        ))?;
        
        let transactions_confirmed_total = Counter::with_opts(Opts::new(
            "tsn_transactions_confirmed_total",
            "Transactions confirmées"
        ))?;
        
        let transaction_fees_avg = Histogram::with_opts(HistogramOpts::new(
            "tsn_transaction_fees_avg",
            "Frais de transaction moyens"
        ))?;
        
        let transaction_confirmation_time = Histogram::with_opts(HistogramOpts::new(
            "tsn_transaction_confirmation_time_seconds",
            "Temps de confirmation des transactions en secondes"
        ))?;
        
        // === MÉTRIQUES SYSTÈME ===
        let node_uptime_seconds = Gauge::with_opts(Opts::new(
            "tsn_node_uptime_seconds",
            "Uptime du nœud en secondes"
        ))?;
        
        let memory_usage_bytes = Gauge::with_opts(Opts::new(
            "tsn_memory_usage_bytes",
            "Utilisation mémoire en bytes"
        ))?;
        
        let database_size_bytes = Gauge::with_opts(Opts::new(
            "tsn_database_size_bytes",
            "Taille de la base de données en bytes"
        ))?;
        
        // Enregistrer toutes les métriques
        registry.register(Box::new(block_height.clone()))?;
        registry.register(Box::new(blocks_total.clone()))?;
        registry.register(Box::new(block_processing_duration.clone()))?;
        registry.register(Box::new(block_size_bytes.clone()))?;
        
        registry.register(Box::new(peer_count.clone()))?;
        registry.register(Box::new(p2p_latency_ms.clone()))?;
        registry.register(Box::new(p2p_messages_received.clone()))?;
        registry.register(Box::new(p2p_messages_sent.clone()))?;
        registry.register(Box::new(sync_errors_total.clone()))?;
        
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(mempool_v1_transactions.clone()))?;
        registry.register(Box::new(mempool_v2_transactions.clone()))?;
        registry.register(Box::new(mempool_rejected_transactions.clone()))?;
        
        registry.register(Box::new(mining_hashrate_hps.clone()))?;
        registry.register(Box::new(mining_attempts_total.clone()))?;
        registry.register(Box::new(mining_blocks_found.clone()))?;
        registry.register(Box::new(mining_last_block_time_ms.clone()))?;
        
        registry.register(Box::new(transactions_submitted_total.clone()))?;
        registry.register(Box::new(transactions_confirmed_total.clone()))?;
        registry.register(Box::new(transaction_fees_avg.clone()))?;
        registry.register(Box::new(transaction_confirmation_time.clone()))?;
        
        registry.register(Box::new(node_uptime_seconds.clone()))?;
        registry.register(Box::new(memory_usage_bytes.clone()))?;
        registry.register(Box::new(database_size_bytes.clone()))?;
        
        Ok(Self {
            registry,
            block_height,
            blocks_total,
            block_processing_duration,
            block_size_bytes,
            peer_count,
            p2p_latency_ms,
            p2p_messages_received,
            p2p_messages_sent,
            sync_errors_total,
            mempool_size,
            mempool_v1_transactions,
            mempool_v2_transactions,
            mempool_rejected_transactions,
            mining_hashrate_hps,
            mining_attempts_total,
            mining_blocks_found,
            mining_last_block_time_ms,
            transactions_submitted_total,
            transactions_confirmed_total,
            transaction_fees_avg,
            transaction_confirmation_time,
            node_uptime_seconds,
            memory_usage_bytes,
            database_size_bytes,
        })
    }
    
    /// Met à jour les métriques avec l'état actuel du nœud
    ///
    /// Note: les unwrap() sur RwLock::read() sont intentionnels — un mutex poisonné
    /// signifie qu'un thread a paniqué en modifiant l'état, et la propagation est correcte.
    pub fn update_metrics(&self, state: &AppState, start_time: Instant) {
        // === MÉTRIQUES BLOCKCHAIN ===
        {
            let blockchain = state.blockchain.read().unwrap();
            self.block_height.set(blockchain.height() as f64);
            self.blocks_total.inc_by(blockchain.height());
        }
        
        // === MÉTRIQUES RÉSEAU ===
        {
            let peers = state.peers.read().unwrap();
            self.peer_count.set(peers.len() as f64);
        }
        
        // === MÉTRIQUES MEMPOOL ===
        {
            let mempool = state.mempool.read().unwrap();
            let v1_count = mempool.get_transactions(1000).len();
            let v2_count = mempool.get_v2_transactions(1000).len();
            let total_size = v1_count + v2_count;
            
            self.mempool_size.set(total_size as f64);
            self.mempool_v1_transactions.set(v1_count as f64);
            self.mempool_v2_transactions.set(v2_count as f64);
        }
        
        // === MÉTRIQUES MINING ===
        {
            let miner_stats = state.miner_stats.read().unwrap();
            self.mining_hashrate_hps.set(miner_stats.hashrate_hps as f64);
            if miner_stats.last_attempts > 0 {
                self.mining_attempts_total.inc_by(miner_stats.last_attempts);
            }
            if miner_stats.last_elapsed_ms > 0 {
                self.mining_last_block_time_ms.set(miner_stats.last_elapsed_ms as f64);
            }
        }
        
        // === MÉTRIQUES SYSTÈME ===
        let uptime = start_time.elapsed().as_secs();
        self.node_uptime_seconds.set(uptime as f64);
        
        // Utilisation mémoire (estimation basique)
        if let Ok(memory_info) = sys_info::mem_info() {
            let used_memory = (memory_info.total - memory_info.free) * 1024; // Convert to bytes
            self.memory_usage_bytes.set(used_memory as f64);
        }
    }
    
    /// Exporte les métriques au format Prometheus
    pub fn export_metrics(&self) -> Result<String, Box<dyn std::error::Error>> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
    
    /// Enregistre une latence P2P mesurée
    pub fn record_p2p_latency(&self, latency_ms: f64) {
        self.p2p_latency_ms.observe(latency_ms);
    }
    
    /// Enregistre un message P2P reçu
    pub fn record_p2p_message_received(&self) {
        self.p2p_messages_received.inc();
    }
    
    /// Enregistre un message P2P envoyé
    pub fn record_p2p_message_sent(&self) {
        self.p2p_messages_sent.inc();
    }
    
    /// Enregistre une erreur de synchronisation
    pub fn record_sync_error(&self) {
        self.sync_errors_total.inc();
    }
    
    /// Enregistre une transaction rejetée
    pub fn record_rejected_transaction(&self) {
        self.mempool_rejected_transactions.inc();
    }
    
    /// Enregistre une transaction soumise
    pub fn record_transaction_submitted(&self) {
        self.transactions_submitted_total.inc();
    }
    
    /// Enregistre une transaction confirmée
    pub fn record_transaction_confirmed(&self) {
        self.transactions_confirmed_total.inc();
    }
    
    /// Enregistre les frais d'une transaction
    pub fn record_transaction_fee(&self, fee: u64) {
        self.transaction_fees_avg.observe(fee as f64);
    }
    
    /// Enregistre le temps de traitement d'un bloc
    pub fn record_block_processing_time(&self, duration: Duration) {
        self.block_processing_duration.observe(duration.as_secs_f64());
    }
    
    /// Enregistre la taille d'un bloc
    pub fn record_block_size(&self, size_bytes: usize) {
        self.block_size_bytes.observe(size_bytes as f64);
    }
    
    /// Enregistre un bloc miné
    pub fn record_block_mined(&self) {
        self.mining_blocks_found.inc();
    }
}

/// Service de monitoring qui met à jour les métriques périodiquement
pub struct MonitoringService {
    metrics: Arc<TsnMetrics>,
    start_time: Instant,
}

impl MonitoringService {
    /// Crée un nouveau service de monitoring
    pub fn new(metrics: Arc<TsnMetrics>) -> Self {
        Self {
            metrics,
            start_time: Instant::now(),
        }
    }
    
    /// Lance le service de monitoring avec mise à jour périodique
    pub async fn start(&self, state: Arc<AppState>) {
        let mut interval = interval(Duration::from_secs(30)); // Mise à jour toutes les 30 secondes
        
        info!("Service de monitoring TSN démarré - mise à jour toutes les 30 secondes");
        
        loop {
            interval.tick().await;
            
            match std::panic::catch_unwind(|| {
                self.metrics.update_metrics(&state, self.start_time);
            }) {
                Ok(_) => {
                    // Mise à jour réussie
                }
                Err(e) => {
                    error!("Erreur lors de la mise à jour des métriques: {:?}", e);
                }
            }
        }
    }
}

/// Initialise le système de monitoring Prometheus
pub fn init_monitoring() -> Result<Arc<TsnMetrics>, Box<dyn std::error::Error>> {
    let metrics = TsnMetrics::new()?;
    info!("Système de monitoring Prometheus initialisé");
    Ok(Arc::new(metrics))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_metrics_creation() {
        let metrics = TsnMetrics::new().expect("Failed to create metrics");
        assert!(metrics.export_metrics().is_ok());
    }
    
    #[test]
    fn test_metrics_update() {
        let metrics = TsnMetrics::new().expect("Failed to create metrics");
        
        // Test des enregistrements de métriques
        metrics.record_p2p_latency(25.5);
        metrics.record_p2p_message_received();
        metrics.record_p2p_message_sent();
        metrics.record_transaction_submitted();
        metrics.record_transaction_fee(1000);
        metrics.record_block_mined();
        
        let exported = metrics.export_metrics().expect("Failed to export metrics");
        assert!(exported.contains("tsn_p2p_latency_milliseconds"));
        assert!(exported.contains("tsn_p2p_messages_received_total"));
        assert!(exported.contains("tsn_transactions_submitted_total"));
    }
}