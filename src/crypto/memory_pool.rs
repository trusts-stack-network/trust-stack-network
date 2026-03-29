//! Pool de mémoire optimisé pour les validations cryptographiques
//!
//! Gère des buffers réutilisables pour éviter les allocations répétées
//! dans les hot paths de validation de signatures et preuves ZK.
//!
//! Basé sur des techniques de memory pooling pour réduire la pression
//! sur l'allocateur et améliorer les performances des validations crypto.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use std::fmt;

/// Taille par défaut des buffers dans le pool (32KB)
pub const DEFAULT_BUFFER_SIZE: usize = 32 * 1024;

/// Nombre maximum de buffers dans le pool
pub const MAX_POOL_SIZE: usize = 128;

/// Durée de vie maximale d'un buffer dans le pool (5 minutes)
pub const MAX_BUFFER_AGE: Duration = Duration::from_secs(300);

/// Buffer poolé avec métadonnées de gestion
#[derive(Debug)]
pub struct PooledBuffer {
    data: Vec<u8>,
    created_at: Instant,
    last_used: Instant,
    usage_count: u64,
}

impl PooledBuffer {
    /// Crée un nouveau buffer poolé
    fn new(size: usize) -> Self {
        let now = Instant::now();
        Self {
            data: vec![0u8; size],
            created_at: now,
            last_used: now,
            usage_count: 0,
        }
    }

    /// Retourne une référence mutable aux données
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.last_used = Instant::now();
        self.usage_count += 1;
        &mut self.data
    }

    /// Retourne une référence aux données
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Retourne la taille du buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Vérifie si le buffer est vide
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Efface le contenu du buffer (sécurité)
    pub fn clear(&mut self) {
        // Effacement sécurisé des données sensibles
        for byte in &mut self.data {
            *byte = 0;
        }
        self.last_used = Instant::now();
    }

    /// Vérifie si le buffer est trop ancien
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > MAX_BUFFER_AGE
    }

    /// Retourne les statistiques d'utilisation
    pub fn usage_stats(&self) -> (Duration, u64) {
        (self.created_at.elapsed(), self.usage_count)
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Effacement sécurisé lors de la destruction
        self.clear();
    }
}

/// Pool de buffers pour optimiser les allocations mémoire
pub struct MemoryPool {
    buffers: VecDeque<PooledBuffer>,
    buffer_size: usize,
    max_size: usize,
    stats: PoolStats,
}

#[derive(Debug, Default)]
struct PoolStats {
    total_allocations: u64,
    cache_hits: u64,
    cache_misses: u64,
    expired_buffers: u64,
}

impl MemoryPool {
    /// Crée un nouveau pool de mémoire
    pub fn new(buffer_size: usize, max_size: usize) -> Self {
        Self {
            buffers: VecDeque::with_capacity(max_size),
            buffer_size,
            max_size,
            stats: PoolStats::default(),
        }
    }

    /// Obtient un buffer du pool ou en crée un nouveau
    pub fn get_buffer(&mut self) -> PooledBuffer {
        self.stats.total_allocations += 1;

        // Nettoie les buffers expirés
        self.cleanup_expired();

        // Essaie de réutiliser un buffer existant
        if let Some(mut buffer) = self.buffers.pop_front() {
            buffer.clear(); // Sécurité : efface les données précédentes
            self.stats.cache_hits += 1;
            buffer
        } else {
            // Crée un nouveau buffer
            self.stats.cache_misses += 1;
            PooledBuffer::new(self.buffer_size)
        }
    }

    /// Retourne un buffer au pool
    pub fn return_buffer(&mut self, buffer: PooledBuffer) {
        if self.buffers.len() < self.max_size && !buffer.is_expired() {
            self.buffers.push_back(buffer);
        }
        // Sinon le buffer sera détruit automatiquement
    }

    /// Nettoie les buffers expirés
    fn cleanup_expired(&mut self) {
        let initial_len = self.buffers.len();
        self.buffers.retain(|buffer| !buffer.is_expired());
        let removed = initial_len - self.buffers.len();
        self.stats.expired_buffers += removed as u64;
    }

    /// Retourne les statistiques du pool
    pub fn stats(&self) -> PoolStatsSummary {
        PoolStatsSummary {
            total_allocations: self.stats.total_allocations,
            cache_hits: self.stats.cache_hits,
            cache_misses: self.stats.cache_misses,
            expired_buffers: self.stats.expired_buffers,
            current_pool_size: self.buffers.len(),
            max_pool_size: self.max_size,
            buffer_size: self.buffer_size,
            hit_rate: if self.stats.total_allocations > 0 {
                (self.stats.cache_hits as f64 / self.stats.total_allocations as f64) * 100.0
            } else {
                0.0
            },
        }
    }

    /// Vide complètement le pool
    pub fn clear(&mut self) {
        self.buffers.clear();
    }
}

/// Résumé des statistiques du pool
#[derive(Debug, Clone)]
pub struct PoolStatsSummary {
    pub total_allocations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub expired_buffers: u64,
    pub current_pool_size: usize,
    pub max_pool_size: usize,
    pub buffer_size: usize,
    pub hit_rate: f64,
}

impl fmt::Display for PoolStatsSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryPool Stats: {} allocs, {:.1}% hit rate, {}/{} buffers, {}KB each",
            self.total_allocations,
            self.hit_rate,
            self.current_pool_size,
            self.max_pool_size,
            self.buffer_size / 1024
        )
    }
}

/// Gestionnaire global de pools de mémoire thread-safe
pub struct MemoryPoolManager {
    signature_pool: Arc<Mutex<MemoryPool>>,
    proof_pool: Arc<Mutex<MemoryPool>>,
    hash_pool: Arc<Mutex<MemoryPool>>,
    stats: Arc<RwLock<GlobalStats>>,
}

#[derive(Debug, Default)]
struct GlobalStats {
    signature_validations: u64,
    proof_validations: u64,
    hash_operations: u64,
    total_memory_saved: u64, // Estimation en bytes
}

impl MemoryPoolManager {
    /// Crée un nouveau gestionnaire de pools
    pub fn new() -> Self {
        Self {
            signature_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE, MAX_POOL_SIZE))),
            proof_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE * 4, MAX_POOL_SIZE / 2))),
            hash_pool: Arc::new(Mutex::new(MemoryPool::new(DEFAULT_BUFFER_SIZE / 4, MAX_POOL_SIZE * 2))),
            stats: Arc::new(RwLock::new(GlobalStats::default())),
        }
    }

    /// Obtient un buffer pour la validation de signatures
    pub fn get_signature_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.signature_validations += 1;
            stats.total_memory_saved += DEFAULT_BUFFER_SIZE as u64;
        }
        
        Ok(buffer)
    }

    /// Retourne un buffer de signature au pool
    pub fn return_signature_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Obtient un buffer pour la validation de preuves ZK
    pub fn get_proof_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.proof_validations += 1;
            stats.total_memory_saved += (DEFAULT_BUFFER_SIZE * 4) as u64;
        }
        
        Ok(buffer)
    }

    /// Retourne un buffer de preuve au pool
    pub fn return_proof_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Obtient un buffer pour les opérations de hash
    pub fn get_hash_buffer(&self) -> Result<PooledBuffer, String> {
        let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
        let buffer = pool.get_buffer();
        
        if let Ok(mut stats) = self.stats.write() {
            stats.hash_operations += 1;
            stats.total_memory_saved += (DEFAULT_BUFFER_SIZE / 4) as u64;
        }
        
        Ok(buffer)
    }

    /// Retourne un buffer de hash au pool
    pub fn return_hash_buffer(&self, buffer: PooledBuffer) -> Result<(), String> {
        let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
        pool.return_buffer(buffer);
        Ok(())
    }

    /// Retourne un résumé des statistiques globales
    pub fn summary(&self) -> Result<MemoryPoolSummary, String> {
        let sig_stats = {
            let pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let proof_stats = {
            let pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let hash_stats = {
            let pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.stats()
        };
        
        let global_stats = self.stats.read().map_err(|_| "Stats lock failed")?.clone();
        
        Ok(MemoryPoolSummary {
            signature_pool: sig_stats,
            proof_pool: proof_stats,
            hash_pool: hash_stats,
            total_operations: global_stats.signature_validations + global_stats.proof_validations + global_stats.hash_operations,
            estimated_memory_saved_mb: global_stats.total_memory_saved as f64 / (1024.0 * 1024.0),
        })
    }

    /// Nettoie tous les pools
    pub fn cleanup(&self) -> Result<(), String> {
        {
            let mut pool = self.signature_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        {
            let mut pool = self.proof_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        {
            let mut pool = self.hash_pool.lock().map_err(|_| "Pool lock failed")?;
            pool.clear();
        }
        Ok(())
    }
}

impl Default for MemoryPoolManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Résumé complet des pools de mémoire
#[derive(Debug, Clone)]
pub struct MemoryPoolSummary {
    pub signature_pool: PoolStatsSummary,
    pub proof_pool: PoolStatsSummary,
    pub hash_pool: PoolStatsSummary,
    pub total_operations: u64,
    pub estimated_memory_saved_mb: f64,
}

impl fmt::Display for MemoryPoolSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== Memory Pool Manager Summary ===")?;
        writeln!(f, "Signature Pool: {}", self.signature_pool)?;
        writeln!(f, "Proof Pool: {}", self.proof_pool)?;
        writeln!(f, "Hash Pool: {}", self.hash_pool)?;
        writeln!(f, "Total Operations: {}", self.total_operations)?;
        writeln!(f, "Estimated Memory Saved: {:.2} MB", self.estimated_memory_saved_mb)?;
        Ok(())
    }
}

// Instance globale du gestionnaire de pools
lazy_static::lazy_static! {
    static ref GLOBAL_POOL_MANAGER: MemoryPoolManager = MemoryPoolManager::new();
}

/// Accès à l'instance globale du gestionnaire de pools
pub fn global_pool_manager() -> &'static MemoryPoolManager {
    &GLOBAL_POOL_MANAGER
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_pooled_buffer_basic() {
        let mut buffer = PooledBuffer::new(1024);
        assert_eq!(buffer.len(), 1024);
        assert!(!buffer.is_empty());
        
        let data = buffer.as_mut_slice();
        data[0] = 42;
        assert_eq!(buffer.as_slice()[0], 42);
        
        buffer.clear();
        assert_eq!(buffer.as_slice()[0], 0);
    }

    #[test]
    fn test_memory_pool_reuse() {
        let mut pool = MemoryPool::new(1024, 10);
        
        // Obtient un buffer
        let buffer1 = pool.get_buffer();
        assert_eq!(buffer1.len(), 1024);
        
        // Le retourne au pool
        pool.return_buffer(buffer1);
        
        // Obtient un nouveau buffer (devrait être réutilisé)
        let buffer2 = pool.get_buffer();
        assert_eq!(buffer2.len(), 1024);
        
        let stats = pool.stats();
        assert_eq!(stats.total_allocations, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
    }

    #[test]
    fn test_pool_manager_thread_safety() {
        let manager = MemoryPoolManager::new();
        let manager_arc = Arc::new(manager);
        
        let mut handles = vec![];
        
        // Lance plusieurs threads qui utilisent les pools
        for _ in 0..4 {
            let manager_clone = Arc::clone(&manager_arc);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    if let Ok(buffer) = manager_clone.get_signature_buffer() {
                        // Simule une utilisation
                        thread::sleep(Duration::from_millis(1));
                        let _ = manager_clone.return_signature_buffer(buffer);
                    }
                }
            });
            handles.push(handle);
        }
        
        // Attend que tous les threads terminent
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Vérifie les statistiques
        let summary = manager_arc.summary().unwrap();
        assert!(summary.total_operations > 0);
    }

    #[test]
    fn test_buffer_expiration() {
        let mut pool = MemoryPool::new(1024, 10);
        
        // Crée un buffer avec un âge artificiel
        let mut buffer = PooledBuffer::new(1024);
        buffer.created_at = Instant::now() - Duration::from_secs(400); // Plus ancien que MAX_BUFFER_AGE
        
        pool.return_buffer(buffer);
        
        // Force le nettoyage
        pool.cleanup_expired();
        
        let stats = pool.stats();
        assert_eq!(stats.expired_buffers, 1);
        assert_eq!(stats.current_pool_size, 0);
    }
}