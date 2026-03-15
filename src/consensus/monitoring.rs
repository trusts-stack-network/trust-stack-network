use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tokio::time::interval;
use tracing::{info, warn, error};

use crate::consensus::metrics::{ConsensusMetrics, BlockMetrics, MiningMetrics, NetworkMetrics};
use crate::consensus::alerts::{ConsensusAlertManager, Alert, AlertThresholds};

/// Point de données temporel pour les métriques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: u64,
    pub value: f64,
}

/// Série temporelle de métriques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    pub name: String,
    pub points: VecDeque<TimeSeriesPoint>,
    pub max_points: usize,
}

impl TimeSeries {
    pub fn new(name: String, max_points: usize) -> Self {
        Self {
            name,
            points: VecDeque::new(),
            max_points,
        }
    }

    pub fn add_point(&mut self, value: f64) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.points.push_back(TimeSeriesPoint { timestamp, value });
        
        if self.points.len() > self.max_points {
            self.points.pop_front();
        }
    }

    pub fn get_latest(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }

    pub fn get_average(&self, duration: Duration) -> Option<f64> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - duration.as_secs();

        let recent_points: Vec<f64> = self.points
            .iter()
            .filter(|p| p.timestamp >= cutoff)
            .map(|p| p.value)
            .collect();

        if recent_points.is_empty() {
            None
        } else {
            Some(recent_points.iter().sum::<f64>() / recent_points.len() as f64)
        }
    }

    pub fn get_trend(&self, duration: Duration) -> Option<f64> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - duration.as_secs();

        let recent_points: Vec<&TimeSeriesPoint> = self.points
            .iter()
            .filter(|p| p.timestamp >= cutoff)
            .collect();

        if recent_points.len() < 2 {
            return None;
        }

        // Calcul de la pente (régression linéaire simple)
        let n = recent_points.len() as f64;
        let sum_x: f64 = recent_points.iter().map(|p| p.timestamp as f64).sum();
        let sum_y: f64 = recent_points.iter().map(|p| p.value).sum();
        let sum_xy: f64 = recent_points.iter().map(|p| p.timestamp as f64 * p.value).sum();
        let sum_x2: f64 = recent_points.iter().map(|p| (p.timestamp as f64).powi(2)).sum();

        let slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x.powi(2));
        Some(slope)
    }
}

/// Dashboard de monitoring en temps réel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusDashboard {
    pub block_height: u64,
    pub block_time_avg: f64,
    pub difficulty: f64,
    pub hashrate: f64,
    pub orphan_rate: f64,
    pub mempool_size: usize,
    pub peer_count: usize,
    pub sync_status: String,
    pub last_update: u64,
    
    // Tendances (sur 1h)
    pub block_time_trend: Option<f64>,
    pub difficulty_trend: Option<f64>,
    pub hashrate_trend: Option<f64>,
    
    // Alertes actives
    pub active_alerts: Vec<Alert>,
    pub alert_count_by_severity: HashMap<String, usize>,
}

/// Configuration du monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub update_interval: Duration,
    pub retention_period: Duration,
    pub max_time_series_points: usize,
    pub dashboard_refresh_rate: Duration,
    pub export_metrics: bool,
    pub export_interval: Duration,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            update_interval: Duration::from_secs(30),
            retention_period: Duration::from_secs(24 * 3600), // 24h
            max_time_series_points: 2880, // 24h à 30s d'intervalle
            dashboard_refresh_rate: Duration::from_secs(5),
            export_metrics: true,
            export_interval: Duration::from_secs(60),
        }
    }
}

/// Système de monitoring du consensus
pub struct ConsensusMonitor {
    config: MonitoringConfig,
    metrics: Arc<RwLock<ConsensusMetrics>>,
    alert_manager: Arc<RwLock<ConsensusAlertManager>>,
    
    // Séries temporelles
    time_series: Arc<RwLock<HashMap<String, TimeSeries>>>,
    
    // Dashboard
    dashboard: Arc<RwLock<ConsensusDashboard>>,
    
    // Canaux de communication
    alert_receiver: mpsc::UnboundedReceiver<Alert>,
    shutdown_sender: mpsc::Sender<()>,
    shutdown_receiver: mpsc::Receiver<()>,
}

impl ConsensusMonitor {
    pub fn new(
        config: MonitoringConfig,
        metrics: Arc<RwLock<ConsensusMetrics>>,
        alert_thresholds: AlertThresholds,
    ) -> Self {
        let (alert_sender, alert_receiver) = mpsc::unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        
        let alert_manager = Arc::new(RwLock::new(
            ConsensusAlertManager::new(alert_thresholds, alert_sender)
        ));

        let time_series = Arc::new(RwLock::new(HashMap::new()));
        let dashboard = Arc::new(RwLock::new(ConsensusDashboard {
            block_height: 0,
            block_time_avg: 0.0,
            difficulty: 0.0,
            hashrate: 0.0,
            orphan_rate: 0.0,
            mempool_size: 0,
            peer_count: 0,
            sync_status: "Unknown".to_string(),
            last_update: 0,
            block_time_trend: None,
            difficulty_trend: None,
            hashrate_trend: None,
            active_alerts: Vec::new(),
            alert_count_by_severity: HashMap::new(),
        }));

        Self {
            config,
            metrics,
            alert_manager,
            time_series,
            dashboard,
            alert_receiver,
            shutdown_sender,
            shutdown_receiver,
        }
    }

    /// Démarre le système de monitoring
    pub async fn start(&mut self) {
        info!("🔍 Démarrage du monitoring du consensus");

        // Initialise les séries temporelles
        self.initialize_time_series().await;

        // Lance les tâches de monitoring
        let metrics_task = self.start_metrics_collection();
        let dashboard_task = self.start_dashboard_updates();
        let alert_task = self.start_alert_processing();
        let export_task = self.start_metrics_export();

        // Attend l'arrêt
        tokio::select! {
            _ = metrics_task => warn!("Tâche de collecte de métriques terminée"),
            _ = dashboard_task => warn!("Tâche de mise à jour du dashboard terminée"),
            _ = alert_task => warn!("Tâche de traitement des alertes terminée"),
            _ = export_task => warn!("Tâche d'export des métriques terminée"),
            _ = self.shutdown_receiver.recv() => info!("Arrêt du monitoring demandé"),
        }

        info!("🔍 Monitoring du consensus arrêté");
    }

    /// Arrête le système de monitoring
    pub async fn stop(&self) {
        if let Err(e) = self.shutdown_sender.send(()).await {
            error!("Erreur lors de l'arrêt du monitoring: {}", e);
        }
    }

    /// Initialise les séries temporelles
    async fn initialize_time_series(&self) {
        let mut series = self.time_series.write().await;
        let max_points = self.config.max_time_series_points;

        series.insert("block_time".to_string(), TimeSeries::new("block_time".to_string(), max_points));
        series.insert("difficulty".to_string(), TimeSeries::new("difficulty".to_string(), max_points));
        series.insert("hashrate".to_string(), TimeSeries::new("hashrate".to_string(), max_points));
        series.insert("orphan_rate".to_string(), TimeSeries::new("orphan_rate".to_string(), max_points));
        series.insert("mempool_size".to_string(), TimeSeries::new("mempool_size".to_string(), max_points));
        series.insert("peer_count".to_string(), TimeSeries::new("peer_count".to_string(), max_points));
        series.insert("block_height".to_string(), TimeSeries::new("block_height".to_string(), max_points));
    }

    /// Lance la collecte de métriques
    async fn start_metrics_collection(&self) {
        let mut interval = interval(self.config.update_interval);
        let metrics = Arc::clone(&self.metrics);
        let alert_manager = Arc::clone(&self.alert_manager);
        let time_series = Arc::clone(&self.time_series);

        tokio::spawn(async move {
            loop {
                interval.tick().await;

                // Collecte les métriques actuelles
                let current_metrics = metrics.read().await;
                let block_metrics = &current_metrics.block_metrics;
                let mining_metrics = &current_metrics.mining_metrics;
                let network_metrics = &current_metrics.network_metrics;

                // Met à jour les séries temporelles
                {
                    let mut series = time_series.write().await;
                    
                    if let Some(ts) = series.get_mut("block_time") {
                        ts.add_point(block_metrics.average_block_time.as_secs_f64());
                    }
                    if let Some(ts) = series.get_mut("difficulty") {
                        ts.add_point(mining_metrics.current_difficulty);
                    }
                    if let Some(ts) = series.get_mut("hashrate") {
                        ts.add_point(mining_metrics.network_hashrate);
                    }
                    if let Some(ts) = series.get_mut("orphan_rate") {
                        ts.add_point(block_metrics.orphan_rate);
                    }
                    if let Some(ts) = series.get_mut("mempool_size") {
                        ts.add_point(network_metrics.mempool_size as f64);
                    }
                    if let Some(ts) = series.get_mut("peer_count") {
                        ts.add_point(network_metrics.peer_count as f64);
                    }
                    if let Some(ts) = series.get_mut("block_height") {
                        ts.add_point(block_metrics.current_height as f64);
                    }
                }

                // Met à jour le gestionnaire d'alertes
                {
                    let mut manager = alert_manager.write().await;
                    manager.update_metrics(
                        block_metrics.average_block_time,
                        mining_metrics.network_hashrate,
                        mining_metrics.current_difficulty,
                        block_metrics.orphan_rate,
                    );
                }

                drop(current_metrics);
            }
        })
    }

    /// Lance les mises à jour du dashboard
    async fn start_dashboard_updates(&self) {
        let mut interval = interval(self.config.dashboard_refresh_rate);
        let metrics = Arc::clone(&self.metrics);
        let alert_manager = Arc::clone(&self.alert_manager);
        let time_series = Arc::clone(&self.time_series);
        let dashboard = Arc::clone(&self.dashboard);

        tokio::spawn(async move {
            loop {
                interval.tick().await;

                // Met à jour le dashboard
                {
                    let current_metrics = metrics.read().await;
                    let manager = alert_manager.read().await;
                    let series = time_series.read().await;
                    let mut dash = dashboard.write().await;

                    // Métriques actuelles
                    dash.block_height = current_metrics.block_metrics.current_height;
                    dash.block_time_avg = current_metrics.block_metrics.average_block_time.as_secs_f64();
                    dash.difficulty = current_metrics.mining_metrics.current_difficulty;
                    dash.hashrate = current_metrics.mining_metrics.network_hashrate;
                    dash.orphan_rate = current_metrics.block_metrics.orphan_rate;
                    dash.mempool_size = current_metrics.network_metrics.mempool_size;
                    dash.peer_count = current_metrics.network_metrics.peer_count;
                    dash.sync_status = current_metrics.network_metrics.sync_status.clone();
                    dash.last_update = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();

                    // Tendances
                    let trend_duration = Duration::from_secs(3600); // 1h
                    if let Some(ts) = series.get("block_time") {
                        dash.block_time_trend = ts.get_trend(trend_duration);
                    }
                    if let Some(ts) = series.get("difficulty") {
                        dash.difficulty_trend = ts.get_trend(trend_duration);
                    }
                    if let Some(ts) = series.get("hashrate") {
                        dash.hashrate_trend = ts.get_trend(trend_duration);
                    }

                    // Alertes
                    dash.active_alerts = manager.get_active_alerts().to_vec();
                    
                    let stats = manager.get_alert_stats();
                    dash.alert_count_by_severity.clear();
                    dash.alert_count_by_severity.insert("info".to_string(), stats.info_count);
                    dash.alert_count_by_severity.insert("warning".to_string(), stats.warning_count);
                    dash.alert_count_by_severity.insert("critical".to_string(), stats.critical_count);
                    dash.alert_count_by_severity.insert("emergency".to_string(), stats.emergency_count);
                }
            }
        })
    }

    /// Lance le traitement des alertes
    async fn start_alert_processing(&mut self) {
        tokio::spawn(async move {
            while let Some(alert) = self.alert_receiver.recv().await {
                info!("📢 Nouvelle alerte: {} - {}", alert.severity, alert.message);
                
                // Ici on pourrait ajouter:
                // - Envoi de notifications (email, Slack, Discord)
                // - Webhooks
                // - Intégration avec des systèmes de monitoring externes
                // - Actions automatiques de mitigation
            }
        })
    }

    /// Lance l'export des métriques
    async fn start_metrics_export(&self) {
        if !self.config.export_metrics {
            return;
        }

        let mut interval = interval(self.config.export_interval);
        let time_series = Arc::clone(&self.time_series);
        let dashboard = Arc::clone(&self.dashboard);

        tokio::spawn(async move {
            loop {
                interval.tick().await;

                // Export des métriques (format Prometheus/OpenMetrics)
                let series = time_series.read().await;
                let dash = dashboard.read().await;

                let mut prometheus_output = String::new();
                
                // Métriques actuelles
                prometheus_output.push_str(&format!(
                    "# HELP tsn_block_height Current block height\n\
                     # TYPE tsn_block_height gauge\n\
                     tsn_block_height {}\n\n",
                    dash.block_height
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_block_time_seconds Average block time in seconds\n\
                     # TYPE tsn_block_time_seconds gauge\n\
                     tsn_block_time_seconds {}\n\n",
                    dash.block_time_avg
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_difficulty Current mining difficulty\n\
                     # TYPE tsn_difficulty gauge\n\
                     tsn_difficulty {}\n\n",
                    dash.difficulty
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_hashrate_total Network hashrate\n\
                     # TYPE tsn_hashrate_total gauge\n\
                     tsn_hashrate_total {}\n\n",
                    dash.hashrate
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_orphan_rate_percent Orphan block rate percentage\n\
                     # TYPE tsn_orphan_rate_percent gauge\n\
                     tsn_orphan_rate_percent {}\n\n",
                    dash.orphan_rate
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_mempool_size Number of transactions in mempool\n\
                     # TYPE tsn_mempool_size gauge\n\
                     tsn_mempool_size {}\n\n",
                    dash.mempool_size
                ));

                prometheus_output.push_str(&format!(
                    "# HELP tsn_peer_count Number of connected peers\n\
                     # TYPE tsn_peer_count gauge\n\
                     tsn_peer_count {}\n\n",
                    dash.peer_count
                ));

                // Alertes par sévérité
                for (severity, count) in &dash.alert_count_by_severity {
                    prometheus_output.push_str(&format!(
                        "# HELP tsn_alerts_total Number of alerts by severity\n\
                         # TYPE tsn_alerts_total counter\n\
                         tsn_alerts_total{{severity=\"{}\"}} {}\n\n",
                        severity, count
                    ));
                }

                // Sauvegarde dans un fichier (pour scraping par Prometheus)
                if let Err(e) = tokio::fs::write("/tmp/tsn_metrics.prom", prometheus_output).await {
                    error!("Erreur export métriques Prometheus: {}", e);
                }

                drop(series);
                drop(dash);
            }
        })
    }

    /// Retourne le dashboard actuel
    pub async fn get_dashboard(&self) -> ConsensusDashboard {
        self.dashboard.read().await.clone()
    }

    /// Retourne une série temporelle spécifique
    pub async fn get_time_series(&self, name: &str) -> Option<TimeSeries> {
        self.time_series.read().await.get(name).cloned()
    }

    /// Retourne toutes les séries temporelles
    pub async fn get_all_time_series(&self) -> HashMap<String, TimeSeries> {
        self.time_series.read().await.clone()
    }

    /// Retourne les alertes actives
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        self.alert_manager.read().await.get_active_alerts().to_vec()
    }

    /// Résout une alerte
    pub async fn resolve_alert(&self, alert_id: &str) {
        self.alert_manager.write().await.resolve_alert(alert_id);
    }

    /// Retourne les statistiques de santé du système
    pub async fn get_health_status(&self) -> HealthStatus {
        let dashboard = self.get_dashboard().await;
        let alerts = self.get_active_alerts().await;

        let critical_alerts = alerts.iter()
            .filter(|a| matches!(a.severity, crate::consensus::alerts::AlertSeverity::Critical | crate::consensus::alerts::AlertSeverity::Emergency))
            .count();

        let status = if critical_alerts > 0 {
            "critical"
        } else if !alerts.is_empty() {
            "warning"
        } else {
            "healthy"
        };

        HealthStatus {
            status: status.to_string(),
            block_height: dashboard.block_height,
            sync_status: dashboard.sync_status,
            peer_count: dashboard.peer_count,
            active_alerts: alerts.len(),
            critical_alerts,
            last_block_time: dashboard.block_time_avg,
            uptime: dashboard.last_update,
        }
    }
}

/// Statut de santé du système
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: String,
    pub block_height: u64,
    pub sync_status: String,
    pub peer_count: usize,
    pub active_alerts: usize,
    pub critical_alerts: usize,
    pub last_block_time: f64,
    pub uptime: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::alerts::AlertThresholds;

    #[tokio::test]
    async fn test_time_series_creation() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        ts.add_point(1.0);
        ts.add_point(2.0);
        ts.add_point(3.0);

        assert_eq!(ts.points.len(), 3);
        assert_eq!(ts.get_latest(), Some(3.0));
    }

    #[tokio::test]
    async fn test_time_series_average() {
        let mut ts = TimeSeries::new("test".to_string(), 100);
        ts.add_point(1.0);
        ts.add_point(2.0);
        ts.add_point(3.0);

        let avg = ts.get_average(Duration::from_secs(3600)).unwrap();
        assert_eq!(avg, 2.0);
    }

    #[tokio::test]
    async fn test_monitor_creation() {
        let config = MonitoringConfig::default();
        let metrics = Arc::new(RwLock::new(ConsensusMetrics::new()));
        let thresholds = AlertThresholds::default();
        
        let monitor = ConsensusMonitor::new(config, metrics, thresholds);
        let dashboard = monitor.get_dashboard().await;
        
        assert_eq!(dashboard.block_height, 0);
        assert_eq!(dashboard.active_alerts.len(), 0);
    }
}