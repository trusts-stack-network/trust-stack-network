//! Gestionnaire de rotation des fichiers de log
//!
//! Ce module fournit un gestionnaire asynchrone qui surveille
//! et nettoie les anciens fichiers de log selon la politique configurée.

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use super::{LogConfig, LoggingError, Result};

/// Gestionnaire de rotation des fichiers de log
pub struct RotationManager {
    /// Configuration du logging
    config: LogConfig,
    /// Intervalle de vérification
    check_interval: Duration,
    /// Pattern de fichiers à surveiller
    file_pattern: String,
}

impl RotationManager {
    /// Crée un nouveau gestionnaire de rotation
    pub fn new(config: LogConfig) -> Result<Self> {
        let file_pattern = config.file_pattern();
        
        Ok(RotationManager {
            config,
            check_interval: Duration::from_secs(300), // 5 minutes par défaut
            file_pattern,
        })
    }

    /// Définit l'intervalle de vérification
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Démarre le gestionnaire de rotation avec support d'annulation
    /// 
    /// Cette méthode doit être appelée dans un contexte tokio.
/// Elle s'arrête proprement lorsque le token d'annulation est déclenché.
    pub async fn run(self, cancel_token: tokio_util::sync::CancellationToken) {
        info!(
            "Démarrage du gestionnaire de rotation: intervalle={:?}, max_files={}",
            self.check_interval,
            self.config.max_files
        );

        let mut ticker = interval(self.check_interval);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.cleanup_old_logs().await {
                        error!("Erreur lors du nettoyage des anciens logs: {}", e);
                    }
                }
                _ = cancel_token.cancelled() => {
                    info!("Arrêt du gestionnaire de rotation");
                    break;
                }
            }
        }
    }

    /// Nettoie les anciens fichiers de log
    async fn cleanup_old_logs(&self) -> Result<()> {
        if self.config.max_files == 0 {
            return Ok(());
        }

        let log_dir = &self.config.log_dir;
        
        if !log_dir.exists() {
            return Ok(());
        }

        // Lister tous les fichiers de log avec gestion d'erreur explicite
        let mut log_files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        
        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            // Vérifier si c'est un fichier de log
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                // Vérifier le pattern
                if file_name_str.starts_with(&self.config.file_name)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                // Gestion explicite de modified() - si erreur, utiliser UNIX_EPOCH
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                log_files.push((modified_time, path));
                            }
                        }
                        Err(e) => {
                            warn!("Impossible de lire les métadonnées de {:?}: {}", path, e);
                            // Continuer avec les autres fichiers
                        }
                    }
                }
            }
        }

        // Trier par date de modification (du plus récent au plus ancien)
        log_files.sort_by(|a, b| b.0.cmp(&a.0));

        // Supprimer les fichiers excédentaires
        if log_files.len() > self.config.max_files {
            let files_to_remove = &log_files[self.config.max_files..];
            
            for (_, file_path) in files_to_remove {
                debug!("Suppression du fichier de log ancien: {:?}", file_path);
                
                match tokio::fs::remove_file(file_path).await {
                    Ok(_) => {
                        info!("Fichier de log supprimé: {:?}", file_path);
                    }
                    Err(e) => {
                        warn!("Impossible de supprimer {:?}: {}", file_path, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Obtient la liste des fichiers de log actuels
    pub fn list_log_files(&self) -> Result<Vec<PathBuf>> {
        let log_dir = &self.config.log_dir;
        
        if !log_dir.exists() {
            return Ok(Vec::new());
        }

        let mut log_files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        
        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                if file_name_str.starts_with(&self.config.file_name)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                log_files.push((modified_time, path));
                            }
                        }
                        Err(e) => {
                            warn!("Impossible de lire les métadonnées de {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Trier par date de modification (du plus récent au plus ancien)
        log_files.sort_by(|a, b| b.0.cmp(&a.0));
        
        Ok(log_files.into_iter().map(|(_, path)| path).collect())
    }

    /// Calcule l'espace disque utilisé par les logs
    pub fn calculate_log_size(&self) -> Result<u64> {
        let files = self.list_log_files()?;
        let mut total_size: u64 = 0;

        for file in files {
            if let Ok(metadata) = std::fs::metadata(&file) {
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }

    /// Force la rotation immédiate
    pub async fn force_rotation(&self) -> Result<()> {
        info!("Rotation forcée des fichiers de log");
        self.cleanup_old_logs().await
    }
}

/// Statistiques sur les fichiers de log
#[derive(Debug, Clone)]
pub struct LogStats {
    /// Nombre de fichiers
    pub file_count: usize,
    /// Taille totale en octets
    pub total_size: u64,
    /// Taille moyenne par fichier
    pub average_size: u64,
    /// Fichier le plus récent
    pub newest_file: Option<PathBuf>,
    /// Fichier le plus ancien
    pub oldest_file: Option<PathBuf>,
}

impl LogStats {
    /// Calcule les statistiques pour un répertoire de logs
    pub fn calculate(log_dir: &Path, file_prefix: &str) -> Result<Self> {
        let mut files: Vec<(std::time::SystemTime, PathBuf, u64)> = Vec::new();
        
        if !log_dir.exists() {
            return Ok(LogStats {
                file_count: 0,
                total_size: 0,
                average_size: 0,
                newest_file: None,
                oldest_file: None,
            });
        }

        let entries = std::fs::read_dir(log_dir).map_err(|e| {
            LoggingError::DirectoryCreationError(e)
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                LoggingError::FileAppenderError(e.to_string())
            })?;

            let path = entry.path();
            
            if let Some(file_name) = path.file_name() {
                let file_name_str = file_name.to_string_lossy();
                
                if file_name_str.starts_with(file_prefix)
                    && file_name_str.ends_with(".log")
                {
                    match entry.metadata() {
                        Ok(metadata) => {
                            if metadata.is_file() {
                                let modified_time = metadata.modified()
                                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                                let size = metadata.len();
                                files.push((modified_time, path, size));
                            }
                        }
                        Err(e) => {
                            warn!("Impossible de lire les métadonnées de {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        let file_count = files.len();
        let total_size: u64 = files.iter().map(|(_, _, size)| size).sum();
        let average_size = if file_count > 0 {
            total_size / file_count as u64
        } else {
            0
        };

        // Trier par date (du plus récent au plus ancien)
        files.sort_by(|a, b| b.0.cmp(&a.0));

        let newest_file = files.first().map(|(_, p, _)| p.clone());
        let oldest_file = files.last().map(|(_, p, _)| p.clone());

        Ok(LogStats {
            file_count,
            total_size,
            average_size,
            newest_file,
            oldest_file,
        })
    }

    /// Formate la taille totale en unités lisibles
    pub fn format_total_size(&self) -> String {
        format_bytes(self.total_size)
    }

    /// Formate la taille moyenne en unités lisibles
    pub fn format_average_size(&self) -> String {
        format_bytes(self.average_size)
    }
}

/// Formate une taille en octets en unités lisibles
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0.00 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1536), "1.50 KB");
    }

    #[tokio::test]
    async fn test_rotation_manager() {
        let temp_dir = TempDir::new().unwrap();
        let config = LogConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_name: "test".to_string(),
            max_files: 2,
            ..Default::default()
        };

        let manager = RotationManager::new(config.clone()).unwrap();

        // Créer quelques fichiers de log
        for i in 0..5 {
            let file_path = temp_dir.path().join(format!("test_{}.log", i));
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "Log content {}").unwrap();
            // Petite pause pour différencier les timestamps
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Vérifier qu'on a 5 fichiers
        let files = manager.list_log_files().unwrap();
        assert_eq!(files.len(), 5);

        // Nettoyer
        manager.cleanup_old_logs().await.unwrap();

        // Vérifier qu'il ne reste que 2 fichiers
        let files = manager.list_log_files().unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_log_stats() {
        let temp_dir = TempDir::new().unwrap();
        
        // Créer quelques fichiers
        for i in 0..3 {
            let file_path = temp_dir.path().join(format!("test_{}.log", i));
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "Content").unwrap();
        }

        let stats = LogStats::calculate(temp_dir.path(), "test").unwrap();
        assert_eq!(stats.file_count, 3);
        assert!(stats.total_size > 0);
        assert!(stats.average_size > 0);
        assert!(stats.newest_file.is_some());
        assert!(stats.oldest_file.is_some());
    }
}
