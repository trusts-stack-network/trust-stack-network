//! Système de logging structuré avec rotation pour TSN
//!
//! Ce module fournit un système de logging unifié avec:
//! - Support JSON pour une ingestion facile par les outils de log aggregation
//! - Rotation automatique des fichiers par taille ou par date
//! - Niveaux de log configurables par module
//! - Intégration avec tracing pour les spans et traces distribuées
//!
//! # Usage
//!
//! ```rust
//! use tsn::logging::{init_logging, LogConfig, LogRotation, LoggingHandle};
//!
//! let config = LogConfig::builder()
//!     .json_output(true)
//!     .rotation(LogRotation::Daily)
//!     .max_files(7)
//!     .build();
//!
//! let handle = init_logging(config).expect("Failed to initialize logging");
//! // Pour arrêter proprement:
//! // handle.shutdown();
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use tracing::Level;
use tracing_subscriber::{
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

mod appender;
mod config;
mod json_layer;
mod rotation;

pub use appender::{RotatingFileAppender, RotationPolicy};
pub use config::{LogConfig, LogConfigBuilder, LogOutput, LogRotation};
pub use json_layer::JsonLayer;
pub use rotation::{LogStats, RotationManager};

/// Erreurs du système de logging
#[derive(Error, Debug)]
pub enum LoggingError {
    #[error("Failed to initialize file appender: {0}")]
    FileAppenderError(String),
    
    #[error("Failed to create log directory: {0}")]
    DirectoryCreationError(#[from] std::io::Error),
    
    #[error("Invalid log level: {0}")]
    InvalidLogLevel(String),
    
    #[error("Failed to initialize subscriber: {0}")]
    SubscriberInitError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Logging already initialized")]
    AlreadyInitialized,
    
    #[error("Invalid module log directive '{module}={level}': {source}")]
    InvalidModuleDirective {
        module: String,
        level: String,
        source: String,
    },
}

/// Type résultat pour les opérations de logging
pub type Result<T> = std::result::Result<T, LoggingError>;

/// Handle pour contrôler le système de logging
/// 
/// Cette structure encapsule les ressources nécessaires pour gérer
/// le cycle de vie du système de logging, notamment l'arrêt propre
/// du gestionnaire de rotation.
#[derive(Debug, Clone)]
pub struct LoggingHandle {
    /// Token d'annulation pour le gestionnaire de rotation
    rotation_cancel_token: Option<Arc<CancellationToken>>,
}

impl LoggingHandle {
    /// Crée un nouveau handle sans gestionnaire de rotation
    fn new() -> Self {
        Self {
            rotation_cancel_token: None,
        }
    }

    /// Crée un nouveau handle avec un token d'annulation pour la rotation
    fn with_rotation_token(token: CancellationToken) -> Self {
        Self {
            rotation_cancel_token: Some(Arc::new(token)),
        }
    }

    /// Arrête proprement le gestionnaire de rotation
    /// 
    /// Cette méthode signale au gestionnaire de rotation qu'il doit
    /// s'arrêter. Elle est sans effet si la rotation n'est pas activée.
    /// 
    /// # Exemple
    /// 
    /// ```rust
    /// use tsn::logging::{init_logging, LogConfig};
    /// 
    /// async fn example() {
    ///     let config = LogConfig::builder().build();
    ///     let handle = init_logging(config).unwrap();
    ///     
    ///     // ... utilisation du logging ...
    ///     
    ///     handle.shutdown();
    /// }
    /// ```
    pub fn shutdown(&self) {
        if let Some(token) = &self.rotation_cancel_token {
            token.cancel();
            tracing::info!(target: "tsn::logging", "Rotation manager shutdown requested");
        }
    }

    /// Vérifie si le gestionnaire de rotation est actif
    pub fn has_rotation(&self) -> bool {
        self.rotation_cancel_token.is_some()
    }
}

/// Initialise le système de logging avec la configuration fournie.
///
/// Cette fonction configure le subscriber tracing avec:
/// - Un layer console (optionnel)
/// - Un layer fichier avec rotation (optionnel)
/// - Un layer JSON pour la production (optionnel)
/// - Un filtre d'environnement pour contrôler les niveaux
///
/// # Arguments
/// * `config` - Configuration du logging
///
/// # Retourne
/// Un `LoggingHandle` permettant de contrôler le cycle de vie du logging.
///
/// # Exemple
///
/// ```rust
/// use tsn::logging::{init_logging, LogConfig, LogRotation};
///
/// let config = LogConfig::builder()
///     .log_dir("./logs")
///     .file_name("tsn")
///     .rotation(LogRotation::Daily)
///     .max_files(7)
///     .console_output(true)
///     .json_output(true)
///     .build();
///
/// let handle = init_logging(config).unwrap();
/// ```
pub fn init_logging(config: LogConfig) -> Result<LoggingHandle> {
    // Créer le répertoire de logs si nécessaire
    if !config.log_dir.exists() {
        std::fs::create_dir_all(&config.log_dir)?;
    }

    // Construire le filtre d'environnement
    let filter = build_env_filter(&config)?;

    // Initialiser le subscriber avec les layers configurés
    let subscriber = tracing_subscriber::registry().with(filter);

    // Ajouter le layer console si activé
    let subscriber = if config.console_output {
        let console_layer = fmt::layer()
            .with_target(true)
            .with_thread_ids(config.show_thread_ids)
            .with_thread_names(config.show_thread_names)
            .with_span_events(FmtSpan::CLOSE)
            .with_timer(fmt::time::UtcTime::rfc_3339())
            .with_ansi(config.use_ansi_colors);
        
        subscriber.with(console_layer)
    } else {
        subscriber.with(None)
    };

    // Ajouter le layer fichier avec rotation
    let subscriber = if config.file_output {
        let file_appender = RotatingFileAppender::new(
            config.log_dir.clone(),
            config.file_name.clone(),
            config.rotation.clone(),
            config.max_file_size,
        )?;
        
        let file_layer = if config.json_output {
            // Layer JSON pour la production
            JsonLayer::new(file_appender).boxed()
        } else {
            // Layer texte formaté pour le développement
            fmt::layer()
                .with_writer(Arc::new(file_appender))
                .with_target(true)
                .with_thread_ids(config.show_thread_ids)
                .with_thread_names(config.show_thread_names)
                .with_span_events(FmtSpan::CLOSE)
                .with_timer(fmt::time::UtcTime::rfc_3339())
                .with_ansi(false)
                .boxed()
        };
        
        subscriber.with(file_layer)
    } else {
        subscriber.with(None)
    };

    // Initialiser le subscriber
    subscriber.init();

    let mut handle = LoggingHandle::new();

    // Configurer le gestionnaire de rotation si nécessaire
    if config.file_output && config.rotation != LogRotation::Never {
        let rotation_manager = RotationManager::new(config.clone())?;
        
        // Créer un token d'annulation pour pouvoir arrêter proprement
        let cancel_token = CancellationToken::new();
        handle = LoggingHandle::with_rotation_token(cancel_token.clone());
        
        // Démarrer la tâche de rotation en arrière-plan
        let _handle = tokio::spawn(async move {
            rotation_manager.run(cancel_token).await;
        });
    }

    tracing::info!(
        target: "tsn::logging",
        log_dir = %config.log_dir.display(),
        rotation = ?config.rotation,
        json_output = config.json_output,
        "Logging system initialized"
    );

    Ok(handle)
}

/// Arrête proprement le gestionnaire de rotation
/// 
/// # Déprécié
/// Cette fonction est dépréciée. Utilisez `LoggingHandle::shutdown()` à la place.
/// Elle est conservée temporairement pour la compatibilité ascendante.
#[deprecated(since = "0.2.0", note = "Utilisez LoggingHandle::shutdown() à la place")]
pub fn shutdown_rotation() {
    // Cette fonction ne fait plus rien car le token n'est plus global
    // Les utilisateurs doivent migrer vers LoggingHandle::shutdown()
    tracing::warn!(
        target: "tsn::logging",
        "shutdown_rotation() est dépréciée. Utilisez LoggingHandle::shutdown()"
    );
}

/// Construit le filtre d'environnement à partir de la configuration.
/// 
/// # Errors
/// Retourne une erreur si une directive de module est invalide.
fn build_env_filter(config: &LogConfig) -> Result<EnvFilter> {
    // Essayer d'abord la variable d'environnement RUST_LOG
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|e| {
            // Si RUST_LOG n'est pas définie ou invalide, logger l'erreur et utiliser default_level
            tracing::warn!(
                target: "tsn::logging",
                error = %e,
                "RUST_LOG invalide ou non définie, utilisation du niveau par défaut"
            );
            EnvFilter::try_new(&config.default_level)
                .unwrap_or_else(|e| {
                    tracing::error!(
                        target: "tsn::logging",
                        error = %e,
                        default_level = %config.default_level,
                        "Niveau de log par défaut invalide, fallback sur 'info'"
                    );
                    EnvFilter::new("info")
                })
        });

    // Ajouter les directives de niveau spécifiques aux modules
    let mut filter = filter;
    for (module, level) in &config.module_levels {
        let directive_str = format!("{}={}", module, level);
        match directive_str.parse::<tracing_subscriber::filter::Directive>() {
            Ok(directive) => {
                filter = filter.add_directive(directive);
            }
            Err(e) => {
                // Propager l'erreur avec contexte au lieu de silencer
                return Err(LoggingError::InvalidModuleDirective {
                    module: module.clone(),
                    level: level.clone(),
                    source: e.to_string(),
                });
            }
        }
    }

    Ok(filter)
}

/// Récupère le répertoire de logs par défaut
pub fn default_log_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tsn")
        .join("logs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_config_builder() {
        let config = LogConfig::builder()
            .log_dir("/tmp/test")
            .file_name("test")
            .console_output(true)
            .build();
        
        assert_eq!(config.log_dir, PathBuf::from("/tmp/test"));
        assert_eq!(config.file_name, "test");
        assert!(config.console_output);
    }

    #[test]
    fn test_default_log_dir() {
        let dir = default_log_dir();
        assert!(dir.to_string_lossy().contains("tsn"));
        assert!(dir.to_string_lossy().contains("logs"));
    }

    #[test]
    fn test_logging_handle_new() {
        let handle = LoggingHandle::new();
        assert!(!handle.has_rotation());
    }

    #[test]
    fn test_logging_handle_with_rotation() {
        let token = CancellationToken::new();
        let handle = LoggingHandle::with_rotation_token(token);
        assert!(handle.has_rotation());
    }

    #[test]
    fn test_invalid_module_directive_error() {
        use std::collections::HashMap;
        
        let mut module_levels = HashMap::new();
        // Niveau invalide: "invalid_level" n'est pas un niveau de log valide
        module_levels.insert("tsn::crypto".to_string(), "invalid_level".to_string());
        
        let config = LogConfig {
            log_dir: PathBuf::from("/tmp/test"),
            file_name: "test".to_string(),
            rotation: LogRotation::Never,
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            console_output: false,
            file_output: false,
            json_output: false,
            default_level: "info".to_string(),
            module_levels,
            show_thread_ids: false,
            show_thread_names: false,
            use_ansi_colors: true,
        };
        
        let result = build_env_filter(&config);
        assert!(result.is_err());
        
        match result {
            Err(LoggingError::InvalidModuleDirective { module, level, .. }) => {
                assert_eq!(module, "tsn::crypto");
                assert_eq!(level, "invalid_level");
            }
            _ => panic!("Expected InvalidModuleDirective error"),
        }
    }

    #[test]
    fn test_valid_module_directives() {
        use std::collections::HashMap;
        
        let mut module_levels = HashMap::new();
        module_levels.insert("tsn::crypto".to_string(), "debug".to_string());
        module_levels.insert("tsn::network".to_string(), "warn".to_string());
        
        let config = LogConfig {
            log_dir: PathBuf::from("/tmp/test"),
            file_name: "test".to_string(),
            rotation: LogRotation::Never,
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            console_output: false,
            file_output: false,
            json_output: false,
            default_level: "info".to_string(),
            module_levels,
            show_thread_ids: false,
            show_thread_names: false,
            use_ansi_colors: true,
        };
        
        let result = build_env_filter(&config);
        assert!(result.is_ok(), "Valid directives should not fail: {:?}", result.err());
    }
}
