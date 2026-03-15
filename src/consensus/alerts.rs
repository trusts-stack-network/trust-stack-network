use std::collections::VecDeque;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{warn, error, info};

/// Types d'alertes de consensus
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    /// Temps inter-blocs anormalement élevé
    HighBlockTime {
        current: Duration,
        threshold: Duration,
    },
    /// Taux d'orphelins trop élevé
    HighOrphanRate {
        current: f64,
        threshold: f64,
    },
    /// Hashrate en chute libre
    HashrateDropped {
        current: f64,
        previous: f64,
        drop_percentage: f64,
    },
    /// Difficulté instable
    DifficultyInstability {
        variance: f64,
        threshold: f64,
    },
    /// Fork détecté
    ForkDetected {
        fork_length: u64,
        common_ancestor: String,
    },
    /// Stagnation de la blockchain
    ChainStagnation {
        last_block_time: Duration,
        threshold: Duration,
    },
    /// Attaque potentielle (51%)
    PotentialAttack {
        suspicious_hashrate: f64,
        network_hashrate: f64,
    },
}

/// Niveau de sévérité d'une alerte
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
    Emergency,
}

/// Structure d'une alerte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub timestamp: Instant,
    pub message: String,
    pub resolved: bool,
}

impl Alert {
    pub fn new(alert_type: AlertType, severity: AlertSeverity, message: String) -> Self {
        let id = format!("{:?}_{}", alert_type, chrono::Utc::now().timestamp_nanos());
        Self {
            id,
            alert_type,
            severity,
            timestamp: Instant::now(),
            message,
            resolved: false,
        }
    }

    pub fn resolve(&mut self) {
        self.resolved = true;
    }
}

/// Configuration des seuils d'alerte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    /// Seuil de temps inter-blocs (secondes)
    pub max_block_time: Duration,
    /// Seuil de taux d'orphelins (pourcentage)
    pub max_orphan_rate: f64,
    /// Seuil de chute de hashrate (pourcentage)
    pub max_hashrate_drop: f64,
    /// Seuil de variance de difficulté
    pub max_difficulty_variance: f64,
    /// Seuil de stagnation de la chaîne
    pub max_stagnation_time: Duration,
    /// Seuil d'attaque potentielle (pourcentage du hashrate total)
    pub attack_threshold: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_block_time: Duration::from_secs(300), // 5 minutes
            max_orphan_rate: 5.0, // 5%
            max_hashrate_drop: 30.0, // 30%
            max_difficulty_variance: 0.2, // 20%
            max_stagnation_time: Duration::from_secs(600), // 10 minutes
            attack_threshold: 45.0, // 45% du hashrate
        }
    }
}

/// Gestionnaire d'alertes de consensus
pub struct ConsensusAlertManager {
    thresholds: AlertThresholds,
    active_alerts: Vec<Alert>,
    alert_history: VecDeque<Alert>,
    alert_sender: mpsc::UnboundedSender<Alert>,
    max_history_size: usize,
    
    // Métriques pour détection d'anomalies
    block_times: VecDeque<Duration>,
    hashrates: VecDeque<f64>,
    difficulties: VecDeque<f64>,
    last_block_time: Option<Instant>,
}

impl ConsensusAlertManager {
    pub fn new(
        thresholds: AlertThresholds,
        alert_sender: mpsc::UnboundedSender<Alert>,
    ) -> Self {
        Self {
            thresholds,
            active_alerts: Vec::new(),
            alert_history: VecDeque::new(),
            alert_sender,
            max_history_size: 1000,
            block_times: VecDeque::new(),
            hashrates: VecDeque::new(),
            difficulties: VecDeque::new(),
            last_block_time: None,
        }
    }

    /// Met à jour les métriques et vérifie les alertes
    pub fn update_metrics(&mut self, 
        block_time: Duration, 
        hashrate: f64, 
        difficulty: f64,
        orphan_rate: f64,
    ) {
        // Mise à jour des métriques
        self.block_times.push_back(block_time);
        self.hashrates.push_back(hashrate);
        self.difficulties.push_back(difficulty);
        self.last_block_time = Some(Instant::now());

        // Limite la taille des buffers
        if self.block_times.len() > 100 {
            self.block_times.pop_front();
        }
        if self.hashrates.len() > 100 {
            self.hashrates.pop_front();
        }
        if self.difficulties.len() > 100 {
            self.difficulties.pop_front();
        }

        // Vérification des alertes
        self.check_block_time_alert(block_time);
        self.check_orphan_rate_alert(orphan_rate);
        self.check_hashrate_alert(hashrate);
        self.check_difficulty_stability();
        self.check_chain_stagnation();
    }

    /// Vérifie les alertes de temps inter-blocs
    fn check_block_time_alert(&mut self, block_time: Duration) {
        if block_time > self.thresholds.max_block_time {
            let alert = Alert::new(
                AlertType::HighBlockTime {
                    current: block_time,
                    threshold: self.thresholds.max_block_time,
                },
                AlertSeverity::Warning,
                format!(
                    "Temps inter-blocs élevé: {:?} (seuil: {:?})",
                    block_time, self.thresholds.max_block_time
                ),
            );
            self.emit_alert(alert);
        }
    }

    /// Vérifie les alertes de taux d'orphelins
    fn check_orphan_rate_alert(&mut self, orphan_rate: f64) {
        if orphan_rate > self.thresholds.max_orphan_rate {
            let severity = if orphan_rate > self.thresholds.max_orphan_rate * 2.0 {
                AlertSeverity::Critical
            } else {
                AlertSeverity::Warning
            };

            let alert = Alert::new(
                AlertType::HighOrphanRate {
                    current: orphan_rate,
                    threshold: self.thresholds.max_orphan_rate,
                },
                severity,
                format!(
                    "Taux d'orphelins élevé: {:.2}% (seuil: {:.2}%)",
                    orphan_rate, self.thresholds.max_orphan_rate
                ),
            );
            self.emit_alert(alert);
        }
    }

    /// Vérifie les alertes de hashrate
    fn check_hashrate_alert(&mut self, current_hashrate: f64) {
        if self.hashrates.len() >= 2 {
            let previous_hashrate = self.hashrates[self.hashrates.len() - 2];
            let drop_percentage = ((previous_hashrate - current_hashrate) / previous_hashrate) * 100.0;

            if drop_percentage > self.thresholds.max_hashrate_drop {
                let severity = if drop_percentage > self.thresholds.max_hashrate_drop * 2.0 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                };

                let alert = Alert::new(
                    AlertType::HashrateDropped {
                        current: current_hashrate,
                        previous: previous_hashrate,
                        drop_percentage,
                    },
                    severity,
                    format!(
                        "Chute du hashrate: {:.2}% (de {:.2} à {:.2})",
                        drop_percentage, previous_hashrate, current_hashrate
                    ),
                );
                self.emit_alert(alert);
            }

            // Détection d'attaque potentielle
            let total_network_hashrate = self.estimate_network_hashrate();
            if current_hashrate > total_network_hashrate * (self.thresholds.attack_threshold / 100.0) {
                let alert = Alert::new(
                    AlertType::PotentialAttack {
                        suspicious_hashrate: current_hashrate,
                        network_hashrate: total_network_hashrate,
                    },
                    AlertSeverity::Emergency,
                    format!(
                        "Attaque potentielle détectée: hashrate suspect {:.2} vs réseau {:.2}",
                        current_hashrate, total_network_hashrate
                    ),
                );
                self.emit_alert(alert);
            }
        }
    }

    /// Vérifie la stabilité de la difficulté
    fn check_difficulty_stability(&mut self) {
        if self.difficulties.len() >= 10 {
            let recent_difficulties: Vec<f64> = self.difficulties.iter()
                .rev()
                .take(10)
                .cloned()
                .collect();

            let mean = recent_difficulties.iter().sum::<f64>() / recent_difficulties.len() as f64;
            let variance = recent_difficulties.iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>() / recent_difficulties.len() as f64;
            let coefficient_variation = variance.sqrt() / mean;

            if coefficient_variation > self.thresholds.max_difficulty_variance {
                let alert = Alert::new(
                    AlertType::DifficultyInstability {
                        variance: coefficient_variation,
                        threshold: self.thresholds.max_difficulty_variance,
                    },
                    AlertSeverity::Warning,
                    format!(
                        "Instabilité de difficulté détectée: CV={:.3} (seuil: {:.3})",
                        coefficient_variation, self.thresholds.max_difficulty_variance
                    ),
                );
                self.emit_alert(alert);
            }
        }
    }

    /// Vérifie la stagnation de la chaîne
    fn check_chain_stagnation(&mut self) {
        if let Some(last_time) = self.last_block_time {
            let elapsed = last_time.elapsed();
            if elapsed > self.thresholds.max_stagnation_time {
                let severity = if elapsed > self.thresholds.max_stagnation_time * 2 {
                    AlertSeverity::Critical
                } else {
                    AlertSeverity::Warning
                };

                let alert = Alert::new(
                    AlertType::ChainStagnation {
                        last_block_time: elapsed,
                        threshold: self.thresholds.max_stagnation_time,
                    },
                    severity,
                    format!(
                        "Stagnation de la chaîne: {:?} depuis le dernier bloc (seuil: {:?})",
                        elapsed, self.thresholds.max_stagnation_time
                    ),
                );
                self.emit_alert(alert);
            }
        }
    }

    /// Estime le hashrate total du réseau
    fn estimate_network_hashrate(&self) -> f64 {
        if self.hashrates.is_empty() {
            return 0.0;
        }

        // Moyenne mobile sur les 20 dernières mesures
        let recent_count = std::cmp::min(20, self.hashrates.len());
        self.hashrates.iter()
            .rev()
            .take(recent_count)
            .sum::<f64>() / recent_count as f64
    }

    /// Émet une alerte
    fn emit_alert(&mut self, alert: Alert) {
        // Évite les doublons d'alertes actives
        if !self.active_alerts.iter().any(|a| 
            std::mem::discriminant(&a.alert_type) == std::mem::discriminant(&alert.alert_type)
        ) {
            match alert.severity {
                AlertSeverity::Info => info!("🔵 {}", alert.message),
                AlertSeverity::Warning => warn!("🟡 {}", alert.message),
                AlertSeverity::Critical => error!("🟠 {}", alert.message),
                AlertSeverity::Emergency => error!("🔴 URGENCE: {}", alert.message),
            }

            // Envoie l'alerte via le canal
            if let Err(e) = self.alert_sender.send(alert.clone()) {
                error!("Erreur envoi alerte: {}", e);
            }

            self.active_alerts.push(alert.clone());
            self.add_to_history(alert);
        }
    }

    /// Ajoute une alerte à l'historique
    fn add_to_history(&mut self, alert: Alert) {
        self.alert_history.push_back(alert);
        if self.alert_history.len() > self.max_history_size {
            self.alert_history.pop_front();
        }
    }

    /// Résout une alerte active
    pub fn resolve_alert(&mut self, alert_id: &str) {
        if let Some(alert) = self.active_alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.resolve();
            info!("✅ Alerte résolue: {}", alert.message);
        }
        self.active_alerts.retain(|a| !a.resolved);
    }

    /// Retourne les alertes actives
    pub fn get_active_alerts(&self) -> &[Alert] {
        &self.active_alerts
    }

    /// Retourne l'historique des alertes
    pub fn get_alert_history(&self) -> &VecDeque<Alert> {
        &self.alert_history
    }

    /// Nettoie les alertes résolues anciennes
    pub fn cleanup_resolved_alerts(&mut self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.active_alerts.retain(|alert| {
            !alert.resolved || alert.timestamp > cutoff
        });
    }

    /// Retourne les statistiques d'alertes
    pub fn get_alert_stats(&self) -> AlertStats {
        let total_alerts = self.alert_history.len();
        let active_count = self.active_alerts.len();
        
        let severity_counts = self.alert_history.iter()
            .fold([0; 4], |mut acc, alert| {
                match alert.severity {
                    AlertSeverity::Info => acc[0] += 1,
                    AlertSeverity::Warning => acc[1] += 1,
                    AlertSeverity::Critical => acc[2] += 1,
                    AlertSeverity::Emergency => acc[3] += 1,
                }
                acc
            });

        AlertStats {
            total_alerts,
            active_count,
            info_count: severity_counts[0],
            warning_count: severity_counts[1],
            critical_count: severity_counts[2],
            emergency_count: severity_counts[3],
        }
    }
}

/// Statistiques des alertes
#[derive(Debug, Serialize, Deserialize)]
pub struct AlertStats {
    pub total_alerts: usize,
    pub active_count: usize,
    pub info_count: usize,
    pub warning_count: usize,
    pub critical_count: usize,
    pub emergency_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_alert_manager_creation() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let thresholds = AlertThresholds::default();
        let manager = ConsensusAlertManager::new(thresholds, tx);
        
        assert_eq!(manager.active_alerts.len(), 0);
        assert_eq!(manager.alert_history.len(), 0);
    }

    #[tokio::test]
    async fn test_block_time_alert() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let thresholds = AlertThresholds::default();
        let mut manager = ConsensusAlertManager::new(thresholds, tx);
        
        // Temps de bloc normal - pas d'alerte
        manager.update_metrics(Duration::from_secs(60), 1000.0, 100.0, 2.0);
        assert!(rx.try_recv().is_err());
        
        // Temps de bloc élevé - alerte
        manager.update_metrics(Duration::from_secs(400), 1000.0, 100.0, 2.0);
        let alert = rx.try_recv().unwrap();
        assert!(matches!(alert.alert_type, AlertType::HighBlockTime { .. }));
    }

    #[tokio::test]
    async fn test_orphan_rate_alert() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let thresholds = AlertThresholds::default();
        let mut manager = ConsensusAlertManager::new(thresholds, tx);
        
        // Taux d'orphelins élevé
        manager.update_metrics(Duration::from_secs(60), 1000.0, 100.0, 8.0);
        let alert = rx.try_recv().unwrap();
        assert!(matches!(alert.alert_type, AlertType::HighOrphanRate { .. }));
    }

    #[tokio::test]
    async fn test_hashrate_drop_alert() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let thresholds = AlertThresholds::default();
        let mut manager = ConsensusAlertManager::new(thresholds, tx);
        
        // Premier point de données
        manager.update_metrics(Duration::from_secs(60), 1000.0, 100.0, 2.0);
        
        // Chute importante du hashrate
        manager.update_metrics(Duration::from_secs(60), 600.0, 100.0, 2.0);
        let alert = rx.try_recv().unwrap();
        assert!(matches!(alert.alert_type, AlertType::HashrateDropped { .. }));
    }
}