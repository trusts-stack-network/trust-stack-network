//! Système de health checks multi-niveaux pour Trust Stack Network
//!
//! Ce module fournit un monitoring complet de la santé du nœud TSN avec:
//! - Health checks périodiques pour tous les modules (storage, network, consensus, crypto)
//! - Métriques de latence et disponibilité
//! - Alertes automatiques en cas de dégradation
//! - Endpoint HTTP /health pour le monitoring externe

pub mod checks;
pub mod aggregator;
pub mod reporter;
pub mod endpoint;
pub mod types;

pub use types::{
    HealthStatus, HealthCheck, HealthCheckResult, HealthReport,
    ComponentHealth, SystemHealth, HealthCheckConfig, HealthSeverity,
};
pub use checks::{
    StorageHealthCheck, NetworkHealthCheck, ConsensusHealthCheck,
    CryptoHealthCheck, MempoolHealthCheck, SyncHealthCheck,
};
pub use aggregator::HealthAggregator;
pub use reporter::{HealthReporter, AlertChannel};
pub use endpoint::HealthEndpoint;

use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;
use tracing::{info, error};

/// Service principal de health checking
pub struct HealthCheckService {
    config: HealthCheckConfig,
    aggregator: Arc<HealthAggregator>,
    reporter: Arc<HealthReporter>,
    endpoint: Option<HealthEndpoint>,
    is_running: Arc<RwLock<bool>>,
}

impl HealthCheckService {
    /// Crée un nouveau service de health checks
    pub fn new(config: HealthCheckConfig) -> Self {
        let aggregator = Arc::new(HealthAggregator::new(config.clone()));
        let reporter = Arc::new(HealthReporter::new(config.alert_channels.clone()));
        
        let endpoint = if config.enable_endpoint {
            Some(HealthEndpoint::new(
                config.endpoint_bind.clone(),
                config.endpoint_port,
                aggregator.clone(),
            ))
        } else {
            None
        };
        
        Self {
            config,
            aggregator,
            reporter,
            endpoint,
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Démarre le service de health checks
    pub async fn start(&self) -> Result<(), HealthCheckError> {
        let mut running = self.is_running.write().await;
        if *running {
            return Ok(());
        }
        
        info!("🩺 Démarrage du service de health checks");
        
        // Démarrer l'endpoint HTTP si activé
        if let Some(endpoint) = &self.endpoint {
            endpoint.start().await?;
        }
        
        // Démarrer la boucle de health checks périodiques
        self.start_health_check_loop().await;
        
        *running = true;
        info!("✅ Service de health checks démarré");
        
        Ok(())
    }
    
    /// Arrête le service
    pub async fn stop(&self) {
        let mut running = self.is_running.write().await;
        *running = false;
        
        if let Some(endpoint) = &self.endpoint {
            endpoint.stop().await;
        }
        
        info!("🛑 Service de health checks arrêté");
    }
    
    /// Vérifie si le service est en cours d'exécution
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Obtient l'agrégateur de santé
    pub fn aggregator(&self) -> Arc<HealthAggregator> {
        self.aggregator.clone()
    }
    
    /// Effectue un health check immédiat de tous les composants
    pub async fn check_now(&self) -> HealthReport {
        self.aggregator.run_all_checks().await
    }
    
    /// Démarre la boucle périodique de health checks
    async fn start_health_check_loop(&self) {
        let aggregator = self.aggregator.clone();
        let reporter = self.reporter.clone();
        let interval_duration = self.config.check_interval;
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            
            loop {
                interval.tick().await;
                
                if !*is_running.read().await {
                    break;
                }
                
                // Exécuter tous les health checks
                let report = aggregator.run_all_checks().await;
                
                // Envoyer les alertes si nécessaire
                if report.has_critical_issues() {
                    if let Err(e) = reporter.send_alert(&report).await {
                        error!("Erreur lors de l'envoi des alertes: {}", e);
                    }
                }
                
                // Log du statut
                if report.overall_status != HealthStatus::Healthy {
                    info!(
                        "Health check status: {:?} ({} issues)",
                        report.overall_status,
                        report.issues_count()
                    );
                }
            }
        });
    }
}

/// Erreurs du service de health checks
#[derive(Debug, thiserror::Error)]
pub enum HealthCheckError {
    #[error("Service déjà en cours d'exécution")]
    AlreadyRunning,
    
    #[error("Erreur IO: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Erreur de configuration: {0}")]
    Config(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_health_service_creation() {
        let config = HealthCheckConfig::default();
        let service = HealthCheckService::new(config);
        
        assert!(!service.is_running().await);
    }
}