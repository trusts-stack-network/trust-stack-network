//! Dev CLI - Outils de développement et simulation pour TSN
//!
//! Ce module fournit des outils pour tester la robustesse du réseau TSN
//! sous des conditions adversariales.

pub mod simulators;

use std::time::Duration;

/// Configuration globale pour les outils de développement
#[derive(Debug, Clone)]
pub struct DevConfig {
    /// Activer les simulateurs réseau
    pub enable_network_simulators: bool,
    /// Niveau de log pour les simulations
    pub log_level: tracing::Level,
    /// Timeout par défaut pour les opérations de test
    pub default_timeout: Duration,
}

impl Default for DevConfig {
    fn default() -> Self {
        Self {
            enable_network_simulators: true,
            log_level: tracing::Level::INFO,
            default_timeout: Duration::from_secs(30),
        }
    }
}

/// Initialise le module dev_cli avec la configuration donnée
pub fn init(config: DevConfig) {
    tracing::info!("Initialisation du module dev_cli");
    
    if config.enable_network_simulators {
        tracing::info!("Simulateurs réseau activés");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DevConfig::default();
        assert!(config.enable_network_simulators);
    }
}
