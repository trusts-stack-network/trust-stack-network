//! Module de telemetry structurée pour TSN
//!
//! Ce module fournit des utilitaires de logging et de tracing pour toute
//! l'application TSN. Il centralise la configuration du subscriber et fournit
//! des spans prédéfinis pour les opérations critiques.
//!
//! # Usage
//!
//! ```rust
//! use tsn::telemetry::{init_tracing, crypto_span, network_span};
//! use tracing::{info, instrument};
//!
//! // Initialiser le tracing au démarrage
//! init_tracing("info");
//!
//! // Utiliser un span prédéfini
//! let _span = crypto_span("signature_validation");
//! info!(target: "tsn::crypto", "Validation démarrée");
//! ```

use std::time::Duration;
use tracing::{span, Level, Span};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};

/// Initialise le système de tracing avec la configuration TSN.
///
/// # Arguments
/// * `default_level` - Niveau de log par défaut (ex: "info", "debug")
///
/// # Exemple
/// ```rust
/// init_tracing("tsn=info,network=debug");
/// ```
pub fn init_tracing(default_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_span_events(FmtSpan::CLOSE)
                .with_timer(fmt::time::UtcTime::rfc_3339()),
        )
        .with(filter)
        .init();
}

/// Crée un span pour les opérations cryptographiques critiques.
///
/// # Arguments
/// * `operation` - Nom de l'opération (ex: "signature_validation", "proof_generation")
pub fn crypto_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "crypto_operation",
        operation = operation,
        category = "cryptography",
        sensitivity = "high"
    )
}

/// Crée un span pour les opérations réseau.
///
/// # Arguments
/// * `operation` - Nom de l'opération (ex: "sync", "mempool_relay")
pub fn network_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "network_operation",
        operation = operation,
        category = "network",
        sensitivity = "medium"
    )
}

/// Crée un span pour les opérations de consensus.
///
/// # Arguments
/// * `operation` - Nom de l'opération (ex: "block_validation", "fork_choice")
pub fn consensus_span(operation: &str) -> Span {
    span!(
        Level::INFO,
        "consensus_operation",
        operation = operation,
        category = "consensus",
        sensitivity = "high"
    )
}

/// Crée un span pour les opérations de stockage.
///
/// # Arguments
/// * `operation` - Nom de l'opération (ex: "block_write", "state_read")
pub fn storage_span(operation: &str) -> Span {
    span!(
        Level::TRACE,
        "storage_operation",
        operation = operation,
        category = "storage",
        sensitivity = "low"
    )
}

/// Crée un span pour les opérations de wallet.
///
/// # Arguments
/// * `operation` - Nom de l'opération (ex: "transaction_create", "note_scan")
pub fn wallet_span(operation: &str) -> Span {
    span!(
        Level::DEBUG,
        "wallet_operation",
        operation = operation,
        category = "wallet",
        sensitivity = "high"
    )
}

/// Instrumente une fonction pour le tracing avec des attributs standard.
///
/// Cette macro ajoute automatiquement des attributs comme le module, la ligne,
/// et le temps d'exécution.
#[macro_export]
macro_rules! trace_fn {
    ($level:expr, $name:expr) => {
        let _span = tracing::span!($level, $name, module = module_path!(), line = line!());
        let _enter = _span.enter();
    };
}

/// Log une métrique de performance avec contexte.
///
/// # Arguments
/// * `name` - Nom de la métrique
/// * `value` - Valeur (en millisecondes généralement)
/// * `context` - Contexte additionnel
pub fn log_metric(name: &str, value: u64, context: &str) {
    tracing::info!(
        target: "tsn::metrics",
        metric = name,
        value_ms = value,
        context = context,
        "Performance metric"
    );
}

/// Log un événement de sécurité avec niveau de criticité.
///
/// # Arguments
/// * `level` - Niveau de criticité (warn, error)
/// * `event_type` - Type d'événement
/// * `description` - Description détaillée
/// * `source` - Source de l'événement
pub fn log_security_event(level: Level, event_type: &str, description: &str, source: &str) {
    match level {
        Level::ERROR => {
            tracing::error!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
        Level::WARN => {
            tracing::warn!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
        _ => {
            tracing::info!(
                target: "tsn::security",
                event_type = event_type,
                source = source,
                "Security event: {}",
                description
            );
        }
    }
}

/// Structure pour mesurer le temps d'exécution d'une opération.
///
/// Utilise le pattern RAII pour mesurer automatiquement la durée.
pub struct Timer {
    name: String,
    start: std::time::Instant,
    context: String,
}

impl Timer {
    /// Crée un nouveau timer.
    ///
    /// # Arguments
    /// * `name` - Nom de l'opération mesurée
    /// * `context` - Contexte additionnel
    pub fn new(name: &str, context: &str) -> Self {
        Self {
            name: name.to_string(),
            start: std::time::Instant::now(),
            context: context.to_string(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        log_metric(&self.name, elapsed.as_millis() as u64, &self.context);
    }
}

/// Extension trait pour instrumenter les résultats avec du logging.
pub trait InstrumentResult<T, E> {
    /// Log le résultat avec le niveau approprié.
    fn instrument(self, operation: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> InstrumentResult<T, E> for Result<T, E> {
    fn instrument(self, operation: &str) -> Result<T, E> {
        match &self {
            Ok(_) => {
                tracing::debug!(target: "tsn::operations", operation = operation, "Success");
            }
            Err(e) => {
                tracing::error!(
                    target: "tsn::operations",
                    operation = operation,
                    error = %e,
                    "Operation failed"
                );
            }
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_span_creation() {
        let span = crypto_span("test_operation");
        assert_eq!(span.metadata().unwrap().name(), "crypto_operation");
    }

    #[test]
    fn test_timer_creation() {
        let timer = Timer::new("test_op", "test_context");
        // Le timer sera drop à la fin du test
        drop(timer);
    }
}
