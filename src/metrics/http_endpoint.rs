//! Endpoint HTTP pour exposer les métriques Prometheus
//!
//! Ce module fournit un serveur HTTP dédié aux métriques,
//! séparé de l'API principale pour des raisons de sécurité.

use crate::metrics::collect_metrics;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, error, warn};

/// Configuration du serveur de métriques
#[derive(Debug, Clone)]
pub struct MetricsServerConfig {
    /// Port d'écoute (défaut: 9090)
    pub port: u16,
    /// Interface d'écoute (défaut: 127.0.0.1 pour sécurité)
    pub bind_address: String,
    /// Activer CORS (défaut: false)
    pub enable_cors: bool,
}

impl Default for MetricsServerConfig {
    fn default() -> Self {
        let port = std::env::var("METRICS_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(9090);
        Self {
            port,
            bind_address: "127.0.0.1".to_string(),
            enable_cors: false,
        }
    }
}

/// Paramètres de requête pour l'endpoint /metrics
#[derive(Deserialize)]
struct MetricsQuery {
    /// Format de sortie (prometheus, json)
    #[serde(default = "default_format")]
    format: String,
}

fn default_format() -> String {
    "prometheus".to_string()
}

/// Serveur HTTP pour les métriques Prometheus
pub struct MetricsServer {
    config: MetricsServerConfig,
}

impl MetricsServer {
    /// Crée un nouveau serveur de métriques
    pub fn new(config: MetricsServerConfig) -> Self {
        Self { config }
    }
    
    /// Démarre le serveur de métriques
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let app = self.create_router();
        
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port);
        let listener = TcpListener::bind(&bind_addr).await?;
        
        info!(
            bind_address = %bind_addr,
            "Serveur de métriques TSN démarré"
        );
        
        axum::serve(listener, app).await?;
        
        Ok(())
    }
    
    /// Crée le routeur Axum avec tous les endpoints
    fn create_router(&self) -> Router {
        let mut router = Router::new()
            .route("/metrics", get(metrics_handler))
            .route("/health", get(health_handler))
            .route("/ready", get(readiness_handler));
        
        // Ajouter CORS si activé
        if self.config.enable_cors {
            router = router.layer(CorsLayer::permissive());
        }
        
        router
    }
}

/// Handler principal pour l'endpoint /metrics
async fn metrics_handler(Query(params): Query<MetricsQuery>) -> Response {
    match params.format.as_str() {
        "prometheus" => prometheus_metrics_handler().await,
        "json" => json_metrics_handler().await,
        _ => (
            StatusCode::BAD_REQUEST,
            "Format non supporté. Utilisez 'prometheus' ou 'json'"
        ).into_response(),
    }
}

/// Handler pour les métriques au format Prometheus
async fn prometheus_metrics_handler() -> Response {
    match collect_metrics() {
        Ok(metrics) => (
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics
        ).into_response(),
        Err(e) => {
            error!(error = %e, "Erreur lors de la collecte des métriques");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur lors de la collecte des métriques"
            ).into_response()
        }
    }
}

/// Handler pour les métriques au format JSON
async fn json_metrics_handler() -> Response {
    match collect_metrics_as_json().await {
        Ok(json) => (
            StatusCode::OK,
            [("content-type", "application/json")],
            json
        ).into_response(),
        Err(e) => {
            error!(error = %e, "Erreur lors de la collecte des métriques JSON");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur lors de la collecte des métriques JSON"
            ).into_response()
        }
    }
}

/// Collecte les métriques et les convertit en JSON
async fn collect_metrics_as_json() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Collecte des métriques principales
    let mut metrics: HashMap<&str, i64> = HashMap::new();

    // Métriques de validation de blocs
    metrics.insert("blocks_validated_total",
        crate::metrics::CONSENSUS_METRICS.blocks_validated_total.get() as i64);
    metrics.insert("blocks_rejected_total",
        crate::metrics::CONSENSUS_METRICS.blocks_rejected_total.get() as i64);
    metrics.insert("blocks_validating_current",
        crate::metrics::CONSENSUS_METRICS.blocks_validating_current.get());

    // Métriques de chaîne
    metrics.insert("chain_height",
        crate::metrics::CONSENSUS_METRICS.chain_height.get());
    metrics.insert("chain_reorgs_total",
        crate::metrics::CONSENSUS_METRICS.chain_reorgs_total.get() as i64);
    metrics.insert("forks_detected_total",
        crate::metrics::CONSENSUS_METRICS.forks_detected_total.get() as i64);
    metrics.insert("orphan_blocks_count",
        crate::metrics::CONSENSUS_METRICS.orphan_blocks_count.get());

    // Métriques PoW
    metrics.insert("pow_validation_failures",
        crate::metrics::CONSENSUS_METRICS.pow_validation_failures.get() as i64);

    // Métriques critiques pour le debug
    metrics.insert("invalid_commitment_root_errors",
        crate::metrics::CONSENSUS_METRICS.invalid_commitment_root_errors.get() as i64);
    metrics.insert("zk_proofs_validated_total",
        crate::metrics::CONSENSUS_METRICS.zk_proofs_validated_total.get() as i64);

    // Métriques de performance
    metrics.insert("mempool_size",
        crate::metrics::CONSENSUS_METRICS.mempool_size.get());
    
    let json_response = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "metrics": metrics,
        "status": "ok"
    });
    
    Ok(serde_json::to_string_pretty(&json_response)?)
}

/// Handler pour le health check
async fn health_handler() -> Response {
    let health_status = serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "tsn-metrics"
    });
    
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        serde_json::to_string(&health_status).unwrap()
    ).into_response()
}

/// Handler pour le readiness check
async fn readiness_handler() -> Response {
    // Vérifier que les métriques sont collectables
    match collect_metrics() {
        Ok(_) => {
            let ready_status = serde_json::json!({
                "status": "ready",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "checks": {
                    "metrics_collection": "ok"
                }
            });
            
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                serde_json::to_string(&ready_status).unwrap()
            ).into_response()
        }
        Err(e) => {
            warn!(error = %e, "Metrics collection failed in readiness check");
            
            let not_ready_status = serde_json::json!({
                "status": "not_ready",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "checks": {
                    "metrics_collection": "failed"
                },
                "error": e.to_string()
            });
            
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [("content-type", "application/json")],
                serde_json::to_string(&not_ready_status).unwrap()
            ).into_response()
        }
    }
}

/// Démarre le serveur de métriques en arrière-plan
pub async fn start_metrics_server(
    config: MetricsServerConfig
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error + Send + Sync>> {
    let server = MetricsServer::new(config);
    
    let handle = tokio::spawn(async move {
        if let Err(e) = server.start().await {
            error!(error = %e, "Erreur du serveur de métriques");
        }
    });
    
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    
    #[tokio::test]
    async fn test_metrics_endpoint() {
        let config = MetricsServerConfig::default();
        let server = MetricsServer::new(config);
        let app = server.create_router();
        
        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_health_endpoint() {
        let config = MetricsServerConfig::default();
        let server = MetricsServer::new(config);
        let app = server.create_router();
        
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_json_format() {
        let config = MetricsServerConfig::default();
        let server = MetricsServer::new(config);
        let app = server.create_router();
        
        let request = Request::builder()
            .uri("/metrics?format=json")
            .body(Body::empty())
            .unwrap();
        
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}