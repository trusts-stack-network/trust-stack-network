//! Appender de fichier avec rotation
//!
//! Ce module fournit un appender de fichier qui supporte la rotation
//! automatique basée sur la taille ou la date.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use super::{LogRotation, LoggingError, Result};

/// Politique de rotation pour l'appender
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    /// Pas de rotation
    Never,
    /// Rotation basée sur la taille (en octets)
    Size(u64),
    /// Rotation quotidienne
    Daily,
    /// Rotation hebdomadaire
    Weekly,
}

impl From<LogRotation> for RotationPolicy {
    fn from(rotation: LogRotation) -> Self {
        match rotation {
            LogRotation::Never => RotationPolicy::Never,
            LogRotation::Daily => RotationPolicy::Daily,
            LogRotation::Weekly => RotationPolicy::Weekly,
            LogRotation::Monthly => RotationPolicy::Weekly, // Simplifié
            LogRotation::Size(bytes) => RotationPolicy::Size(bytes),
        }
    }
}

/// Appender de fichier avec support de rotation
pub struct RotatingFileAppender {
    /// Répertoire des logs
    log_dir: PathBuf,
    /// Nom de base du fichier
    file_name: String,
    /// Politique de rotation
    rotation: RotationPolicy,
    /// Taille maximale du fichier
    max_size: u64,
    /// État interne protégé par mutex
    state: Mutex<AppenderState>,
}

struct AppenderState {
    /// Fichier actuellement ouvert
    current_file: Option<std::fs::File>,
    /// Chemin du fichier actuel
    current_path: PathBuf,
    /// Taille actuelle du fichier
    current_size: u64,
    /// Date du dernier changement de fichier (pour rotation temporelle)
    last_rotation: chrono::DateTime<chrono::Utc>,
}

impl RotatingFileAppender {
    /// Crée un nouvel appender avec rotation
    pub fn new(
        log_dir: PathBuf,
        file_name: String,
        rotation: LogRotation,
        max_size: u64,
    ) -> Result<Self> {
        // Créer le répertoire si nécessaire
        if !log_dir.exists() {
            std::fs::create_dir_all(&log_dir).map_err(|e| {
                LoggingError::DirectoryCreationError(e)
            })?;
        }

        let rotation_policy = rotation.into();
        let current_path = Self::generate_file_path(&log_dir, &file_name, rotation_policy);
        
        // Ouvrir ou créer le fichier
        let (file, current_size) = Self::open_or_create_file(&current_path)?;

        let state = AppenderState {
            current_file: Some(file),
            current_path,
            current_size,
            last_rotation: chrono::Utc::now(),
        };

        Ok(RotatingFileAppender {
            log_dir,
            file_name,
            rotation: rotation_policy,
            max_size,
            state: Mutex::new(state),
        })
    }

    /// Génère le chemin du fichier de log en fonction de la politique
    fn generate_file_path(
        log_dir: &Path,
        file_name: &str,
        rotation: RotationPolicy,
    ) -> PathBuf {
        let timestamp = match rotation {
            RotationPolicy::Never => String::new(),
            RotationPolicy::Size(_) => {
                // Pour la rotation par taille, on utilise un timestamp précis
                chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string()
            }
            RotationPolicy::Daily => {
                chrono::Utc::now().format("%Y-%m-%d").to_string()
            }
            RotationPolicy::Weekly => {
                let now = chrono::Utc::now();
                let iso_week = now.iso_week();
                format!("{}-W{:02}", now.year(), iso_week.week())
            }
        };

        if timestamp.is_empty() {
            log_dir.join(format!("{}.log", file_name))
        } else {
            log_dir.join(format!("{}_{}.log", file_name, timestamp))
        }
    }

    /// Ouvre un fichier existant ou en crée un nouveau
    fn open_or_create_file(path: &Path) -> Result<(std::fs::File, u64)> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LoggingError::FileAppenderError(e.to_string()))?;

        let metadata = file.metadata().map_err(|e| {
            LoggingError::FileAppenderError(e.to_string())
        })?;
        
        Ok((file, metadata.len()))
    }

    /// Vérifie si une rotation est nécessaire
    fn should_rotate(&self,
        state: &AppenderState,
    ) -> bool {
        match self.rotation {
            RotationPolicy::Never => false,
            RotationPolicy::Size(max_size) => {
                state.current_size >= max_size
            }
            RotationPolicy::Daily => {
                let now = chrono::Utc::now();
                now.date_naive() != state.last_rotation.date_naive()
            }
            RotationPolicy::Weekly => {
                let now = chrono::Utc::now();
                now.iso_week() != state.last_rotation.iso_week()
            }
        }
    }

    /// Effectue la rotation du fichier
    fn rotate(&self, state: &mut AppenderState) -> Result<()> {
        // Fermer le fichier actuel
        if let Some(file) = state.current_file.take() {
            drop(file);
        }

        // Générer le nouveau chemin
        let new_path = Self::generate_file_path(&self.log_dir,
            &self.file_name,
            self.rotation,
        );

        // Ouvrir le nouveau fichier
        let (file, size) = Self::open_or_create_file(&new_path)?;

        state.current_file = Some(file);
        state.current_path = new_path;
        state.current_size = size;
        state.last_rotation = chrono::Utc::now();

        Ok(())
    }

    /// Obtient le chemin du fichier actuel
    pub fn current_path(&self) -> PathBuf {
        let state = self.state.lock().unwrap();
        state.current_path.clone()
    }

    /// Obtient la taille actuelle du fichier
    pub fn current_size(&self) -> u64 {
        let state = self.state.lock().unwrap();
        state.current_size
    }
}

impl Write for RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        // Vérifier si rotation nécessaire
        if self.should_rotate(&state) {
            self.rotate(&mut state).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;
        }

        // Écrire dans le fichier
        if let Some(ref mut file) = state.current_file {
            let written = file.write(buf)?;
            state.current_size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for writing",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        if let Some(ref mut file) = state.current_file {
            file.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for flushing",
            ))
        }
    }
}

impl Write for &RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        // Vérifier si rotation nécessaire
        if self.should_rotate(&state) {
            self.rotate(&mut state).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, e.to_string())
            })?;
        }

        // Écrire dans le fichier
        if let Some(ref mut file) = state.current_file {
            let written = file.write(buf)?;
            state.current_size += written as u64;
            Ok(written)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for writing",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "Failed to lock appender state")
        })?;

        if let Some(ref mut file) = state.current_file {
            file.flush()
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "No file open for flushing",
            ))
        }
    }
}

impl std::fmt::Debug for RotatingFileAppender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotatingFileAppender")
            .field("log_dir", &self.log_dir)
            .field("file_name", &self.file_name)
            .field("rotation", &self.rotation)
            .field("max_size", &self.max_size)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_appender_creation() {
        let temp_dir = TempDir::new().unwrap();
        let appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Never,
            1024,
        ).unwrap();

        assert!(appender.current_path().exists());
    }

    #[test]
    fn test_appender_write() {
        let temp_dir = TempDir::new().unwrap();
        let mut appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Never,
            1024,
        ).unwrap();

        let data = b"Hello, World!\n";
        let written = appender.write(data).unwrap();
        assert_eq!(written, data.len());

        appender.flush().unwrap();
        
        // Vérifier que le fichier contient les données
        let content = std::fs::read_to_string(appender.current_path()).unwrap();
        assert_eq!(content, "Hello, World!\n");
    }

    #[test]
    fn test_rotation_by_size() {
        let temp_dir = TempDir::new().unwrap();
        let mut appender = RotatingFileAppender::new(
            temp_dir.path().to_path_buf(),
            String::from("test"),
            LogRotation::Size(10), // Rotation après 10 octets
            10,
        ).unwrap();

        let initial_path = appender.current_path();
        
        // Écrire assez de données pour déclencher la rotation
        appender.write(b"0123456789").unwrap(); // 10 octets
        appender.write(b"trigger").unwrap(); // Déclenche rotation

        // Le fichier devrait avoir changé
        assert_ne!(appender.current_path(), initial_path);
    }

    #[test]
    fn test_generate_file_path() {
        let temp_dir = PathBuf::from("/tmp/logs");
        
        let path = RotatingFileAppender::generate_file_path(
            &temp_dir,
            "app",
            RotationPolicy::Never,
        );
        assert_eq!(path, PathBuf::from("/tmp/logs/app.log"));

        let path = RotatingFileAppender::generate_file_path(
            &temp_dir,
            "app",
            RotationPolicy::Daily,
        );
        assert!(path.to_string_lossy().contains("app_"));
        assert!(path.to_string_lossy().ends_with(".log"));
    }
}
