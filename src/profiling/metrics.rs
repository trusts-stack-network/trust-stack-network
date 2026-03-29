//! Métriques Prometheus pour le profiling des opérations critiques
//!
//! Ce module définit les histogrammes et compteurs pour :
//! - Opérations cryptographiques (sign, verify, hash)
//! - Opérations base de données (read, write, scan)
//! - Sérialisation/désérialisation (serialize, deserialize)

use prometheus::{
    Histogram, HistogramVec, IntCounter, IntCounterVec,
    register_histogram, register_histogram_vec, 
    register_int_counter, register_int_counter_vec,
    opts, histogram_opts,
};
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Duration;

/// Métriques pour les opérations cryptographiques
pub struct CryptoMetrics {
    /// Histogramme des durées par opération
    pub duration: HistogramVec,
    /// Compteur total d'opérations
    pub total_count: IntCounterVec,
    /// Compteur d'erreurs
    pub error_count: IntCounterVec,
    /// Compteur d'opérations lentes (> 100ms)
    pub slow_count: IntCounterVec,
}

impl CryptoMetrics {
    /// Crée une nouvelle instance des métriques crypto
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_crypto_duration_seconds",
                    "Durée des opérations cryptographiques en secondes",
                    vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
                ),
                &["operation"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_operations_total",
                    "Nombre total d'opérations cryptographiques"
                ),
                &["operation"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_errors_total",
                    "Nombre d'erreurs lors des opérations cryptographiques"
                ),
                &["operation"]
            )?,
            
            slow_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_crypto_slow_operations_total",
                    "Nombre d'opérations cryptographiques lentes (> 100ms)"
                ),
                &["operation"]
            )?,
        })
    }
    
    /// Enregistre une opération réussie
    pub fn record_operation(&self, operation: &str, duration_secs: f64) {
        self.duration.with_label_values(&[operation]).observe(duration_secs);
        self.total_count.with_label_values(&[operation]).inc();
        
        if duration_secs > 0.1 {
            self.slow_count.with_label_values(&[operation]).inc();
        }
    }
    
    /// Enregistre une erreur
    pub fn record_error(&self, operation: &str) {
        self.error_count.with_label_values(&[operation]).inc();
    }
    
    /// Crée un snapshot des métriques actuelles
    pub fn snapshot(&self) -> CategorySnapshot {
        // Les valeurs sont collectées via Prometheus
        CategorySnapshot {
            category: "crypto",
            operations: vec![
                "sign", "verify", "hash", "batch_verify",
                "zk_proof_verify", "zk_proof_generate",
            ],
        }
    }
}

/// Métriques pour les opérations base de données
pub struct DatabaseMetrics {
    /// Histogramme des durées par opération
    pub duration: HistogramVec,
    /// Compteur total d'opérations
    pub total_count: IntCounterVec,
    /// Compteur d'erreurs
    pub error_count: IntCounterVec,
    /// Compteur d'opérations lentes
    pub slow_count: IntCounterVec,
    /// Taille des données lues/écrites
    pub bytes_transferred: HistogramVec,
}

impl DatabaseMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_db_duration_seconds",
                    "Durée des opérations base de données en secondes",
                    vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0]
                ),
                &["operation", "table"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_operations_total",
                    "Nombre total d'opérations base de données"
                ),
                &["operation", "table"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_errors_total",
                    "Nombre d'erreurs lors des opérations base de données"
                ),
                &["operation", "table"]
            )?,
            
            slow_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_db_slow_operations_total",
                    "Nombre d'opérations base de données lentes (> 50ms)"
                ),
                &["operation", "table"]
            )?,
            
            bytes_transferred: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_db_bytes_transferred",
                    "Nombre d'octets transférés lors des opérations DB",
                    vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0]
                ),
                &["operation", "table"]
            )?,
        })
    }
    
    /// Enregistre une opération réussie
    pub fn record_operation(&self, operation: &str, table: &str, duration_secs: f64) {
        self.duration
            .with_label_values(&[operation, table])
            .observe(duration_secs);
        self.total_count
            .with_label_values(&[operation, table])
            .inc();
        
        if duration_secs > 0.05 {
            self.slow_count
                .with_label_values(&[operation, table])
                .inc();
        }
    }
    
    /// Enregistre une opération avec taille des données
    pub fn record_operation_with_size(
        &self, 
        operation: &str, 
        table: &str, 
        duration_secs: f64,
        bytes: usize
    ) {
        self.record_operation(operation, table, duration_secs);
        self.bytes_transferred
            .with_label_values(&[operation, table])
            .observe(bytes as f64);
    }
    
    /// Enregistre une erreur
    pub fn record_error(&self, operation: &str, table: &str) {
        self.error_count.with_label_values(&[operation, table]).inc();
    }
    
    /// Crée un snapshot des métriques
    pub fn snapshot(&self) -> CategorySnapshot {
        CategorySnapshot {
            category: "database",
            operations: vec![
                "read", "write", "scan", "delete", "batch_write",
            ],
        }
    }
}

/// Métriques pour la sérialisation/désérialisation
pub struct SerdeMetrics {
    /// Histogramme des durées
    pub duration: HistogramVec,
    /// Compteur total d'opérations
    pub total_count: IntCounterVec,
    /// Taille des données sérialisées/désérialisées
    pub bytes_processed: HistogramVec,
    /// Compteur d'erreurs
    pub error_count: IntCounterVec,
}

impl SerdeMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            duration: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_serde_duration_seconds",
                    "Durée des opérations de sérialisation en secondes",
                    vec![0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
                ),
                &["operation", "type"]
            )?,
            
            total_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_serde_operations_total",
                    "Nombre total d'opérations de sérialisation"
                ),
                &["operation", "type"]
            )?,
            
            bytes_processed: register_histogram_vec!(
                histogram_opts!(
                    "tsn_profiling_serde_bytes_processed",
                    "Nombre d'octets traités lors de la sérialisation",
                    vec![64.0, 256.0, 1024.0, 4096.0, 16384.0, 65536.0, 262144.0, 1048576.0, 4194304.0]
                ),
                &["operation", "type"]
            )?,
            
            error_count: register_int_counter_vec!(
                opts!(
                    "tsn_profiling_serde_errors_total",
                    "Nombre d'erreurs lors des opérations de sérialisation"
                ),
                &["operation", "type"]
            )?,
        })
    }
    
    /// Enregistre une opération de sérialisation
    pub fn record_operation(
        &self, 
        operation: &str, 
        type_name: &str, 
        duration_secs: f64,
        bytes: usize
    ) {
        self.duration
            .with_label_values(&[operation, type_name])
            .observe(duration_secs);
        self.total_count
            .with_label_values(&[operation, type_name])
            .inc();
        self.bytes_processed
            .with_label_values(&[operation, type_name])
            .observe(bytes as f64);
    }
    
    /// Enregistre une erreur
    pub fn record_error(&self, operation: &str, type_name: &str) {
        self.error_count.with_label_values(&[operation, type_name]).inc();
    }
    
    /// Crée un snapshot des métriques
    pub fn snapshot(&self) -> CategorySnapshot {
        CategorySnapshot {
            category: "serialization",
            operations: vec![
                "serialize", "deserialize",
            ],
        }
    }
}

/// Snapshot d'une catégorie de métriques
#[derive(Debug, Clone, serde::Serialize)]
pub struct CategorySnapshot {
    pub category: &'static str,
    pub operations: Vec<&'static str>,
}

// === Instances globales ===

pub static CRYPTO_METRICS: Lazy<CryptoMetrics> = Lazy::new(|| {
    CryptoMetrics::new().expect("INIT: échec métriques crypto Prometheus — noms dupliqués?")
});

pub static DB_METRICS: Lazy<DatabaseMetrics> = Lazy::new(|| {
    DatabaseMetrics::new().expect("INIT: échec métriques DB Prometheus — noms dupliqués?")
});

pub static SERDE_METRICS: Lazy<SerdeMetrics> = Lazy::new(|| {
    SerdeMetrics::new().expect("INIT: échec métriques serde Prometheus — noms dupliqués?")
});

/// Guard pour mesurer automatiquement la durée
pub struct ProfilingGuard {
    histogram: Option<Histogram>,
    start: std::time::Instant,
}

impl ProfilingGuard {
    /// Crée un nouveau guard pour un histogramme
    pub fn new(histogram: Histogram) -> Self {
        Self {
            histogram: Some(histogram),
            start: std::time::Instant::now(),
        }
    }
    
    /// Crée un guard vide (no-op)
    pub fn noop() -> Self {
        Self {
            histogram: None,
            start: std::time::Instant::now(),
        }
    }
}

impl Drop for ProfilingGuard {
    fn drop(&mut self) {
        if let Some(h) = self.histogram.take() {
            h.observe(self.start.elapsed().as_secs_f64());
        }
    }
}

/// Enregistre une valeur dans un histogramme
pub fn record_histogram(histogram: &Histogram, duration: Duration) {
    histogram.observe(duration.as_secs_f64());
}

/// Crée un guard de profiling et démarre le timer
pub fn profile_duration(histogram: &Histogram) -> ProfilingGuard {
    ProfilingGuard::new(histogram.clone())
}

/// Macro pour mesurer la durée d'une expression
#[macro_export]
macro_rules! profile {
    ($metrics:expr, $operation:expr, $body:expr) => {{
        let _timer = $metrics.duration.with_label_values(&[$operation]).start_timer();
        let result = $body;
        result
    }};
}

/// Macro pour mesurer avec gestion d'erreur
#[macro_export]
macro_rules! profile_result {
    ($metrics:expr, $operation:expr, $body:expr) => {{
        let timer = $metrics.duration.with_label_values(&[$operation]).start_timer();
        let result = $body;
        timer.observe_duration();
        
        if result.is_err() {
            $metrics.error_count.with_label_values(&[$operation]).inc();
        }
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_crypto_metrics() {
        CRYPTO_METRICS.record_operation("test", 0.001);
        CRYPTO_METRICS.record_error("test");
        
        let snapshot = CRYPTO_METRICS.snapshot();
        assert_eq!(snapshot.category, "crypto");
    }
    
    #[test]
    fn test_db_metrics() {
        DB_METRICS.record_operation("read", "blocks", 0.001);
        DB_METRICS.record_operation_with_size("write", "accounts", 0.002, 1024);
        
        let snapshot = DB_METRICS.snapshot();
        assert_eq!(snapshot.category, "database");
    }
    
    #[test]
    fn test_serde_metrics() {
        SERDE_METRICS.record_operation("serialize", "Block", 0.0001, 512);
        
        let snapshot = SERDE_METRICS.snapshot();
        assert_eq!(snapshot.category, "serialization");
    }
}