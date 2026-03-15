//! Instrumentation des opérations critiques pour profiling
//!
//! Ce module fournit des wrappers pratiques pour profiler :
//! - Opérations cryptographiques (sign, verify, hash)
//! - Opérations base de données (read, write, scan)
//! - Sérialisation/désérialisation

use super::metrics::{CRYPTO_METRICS, DB_METRICS, SERDE_METRICS};
use super::{OperationCategory, OperationTimer};
use std::time::Instant;

// ============================================================================
// Opérations Cryptographiques
// ============================================================================

/// Profile une opération de signature ML-DSA-65
/// 
/// # Exemple
/// ```rust,ignore
/// let signature = profile_crypto_sign("transaction", || {
///     sign_transaction(&tx, keypair)
/// });
/// ```
pub fn profile_crypto_sign<T, F>(context: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("sign", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "sign",
        context = %context,
        duration_ms = %duration.as_millis(),
        "Signature crypto profilée"
    );
    
    result
}

/// Profile une opération de vérification de signature
pub fn profile_crypto_verify<T, F>(context: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "verify",
        context = %context,
        duration_ms = %duration.as_millis(),
        "Vérification crypto profilée"
    );
    
    result
}

/// Profile une opération de vérification batch
pub fn profile_crypto_batch_verify<T, F>(batch_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("batch_verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "batch_verify",
        batch_size = %batch_size,
        duration_ms = %duration.as_millis(),
        "Vérification batch profilée"
    );
    
    result
}

/// Profile une opération de hachage
pub fn profile_crypto_hash<T, F>(algorithm: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("hash", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "hash",
        algorithm = %algorithm,
        duration_ms = %duration.as_millis(),
        "Hachage profilé"
    );
    
    result
}

/// Profile une opération de génération de preuve ZK
pub fn profile_zk_proof_generate<T, F>(proof_type: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("zk_proof_generate", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "zk_proof_generate",
        proof_type = %proof_type,
        duration_ms = %duration.as_millis(),
        "Génération de preuve ZK profilée"
    );
    
    result
}

/// Profile une opération de vérification de preuve ZK
pub fn profile_zk_proof_verify<T, F>(proof_type: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("zk_proof_verify", OperationCategory::Crypto);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "zk_proof_verify",
        proof_type = %proof_type,
        duration_ms = %duration.as_millis(),
        "Vérification de preuve ZK profilée"
    );
    
    result
}

/// Wrapper générique pour les opérations crypto
pub fn profile_crypto_op<T, F>(operation: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Crypto);
    f()
}

// ============================================================================
// Opérations Base de Données
// ============================================================================

/// Profile une opération de lecture DB
pub fn profile_db_read<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    DB_METRICS.record_operation("read", table, duration.as_secs_f64());
    
    tracing::trace!(
        operation = "db_read",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Lecture DB profilée"
    );
    
    result
}

/// Profile une opération d'écriture DB
pub fn profile_db_write<T, F>(table: &str, data_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    DB_METRICS.record_operation_with_size("write", table, duration.as_secs_f64(), data_size);
    
    tracing::trace!(
        operation = "db_write",
        table = %table,
        data_size = %data_size,
        duration_ms = %duration.as_millis(),
        "Écriture DB profilée"
    );
    
    result
}

/// Profile une opération de scan DB (itération)
pub fn profile_db_scan<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("scan", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "db_scan",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Scan DB profilé"
    );
    
    result
}

/// Profile une opération de suppression DB
pub fn profile_db_delete<T, F>(table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("delete", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::trace!(
        operation = "db_delete",
        table = %table,
        duration_ms = %duration.as_millis(),
        "Suppression DB profilée"
    );
    
    result
}

/// Profile une opération batch DB
pub fn profile_db_batch_write<T, F>(table: &str, item_count: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new("batch_write", OperationCategory::Database);
    let result = f();
    let duration = timer.stop();
    
    tracing::debug!(
        operation = "db_batch_write",
        table = %table,
        item_count = %item_count,
        duration_ms = %duration.as_millis(),
        "Écriture batch DB profilée"
    );
    
    result
}

/// Wrapper générique pour les opérations DB
pub fn profile_db_op<T, F>(operation: &str, table: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Database);
    f()
}

// ============================================================================
// Opérations de Sérialisation
// ============================================================================

/// Profile une opération de sérialisation
pub fn profile_serde_serialize<T, F>(type_name: &str, f: F) -> (T, usize)
where
    F: FnOnce() -> (T, usize),
{
    let start = Instant::now();
    let (result, bytes) = f();
    let duration = start.elapsed();
    
    SERDE_METRICS.record_operation("serialize", type_name, duration.as_secs_f64(), bytes);
    
    tracing::trace!(
        operation = "serialize",
        type_name = %type_name,
        bytes = %bytes,
        duration_ms = %duration.as_millis(),
        "Sérialisation profilée"
    );
    
    (result, bytes)
}

/// Profile une opération de désérialisation
pub fn profile_serde_deserialize<T, F>(type_name: &str, data_size: usize, f: F) -> T
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    SERDE_METRICS.record_operation("deserialize", type_name, duration.as_secs_f64(), data_size);
    
    tracing::trace!(
        operation = "deserialize",
        type_name = %type_name,
        data_size = %data_size,
        duration_ms = %duration.as_millis(),
        "Désérialisation profilée"
    );
    
    result
}

/// Wrapper générique pour les opérations de sérialisation
pub fn profile_serde_op<T, F>(operation: &str, type_name: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let timer = OperationTimer::new(operation, OperationCategory::Serialization);
    f()
}

// ============================================================================
// Versions Async
// ============================================================================

/// Profile une opération crypto async
pub async fn profile_crypto_op_async<T, F>(operation: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Crypto);
    let result = f.await;
    timer.stop();
    result
}

/// Profile une opération DB async
pub async fn profile_db_op_async<T, F>(operation: &str, table: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Database);
    let result = f.await;
    timer.stop();
    result
}

/// Profile une opération de sérialisation async
pub async fn profile_serde_op_async<T, F>(operation: &str, type_name: &str, f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let timer = OperationTimer::new(operation, OperationCategory::Serialization);
    let result = f.await;
    timer.stop();
    result
}

// ============================================================================
// Fonctions utilitaires pour les types spécifiques TSN
// ============================================================================

/// Profile la sérialisation d'un bloc
pub fn profile_block_serialize<F>(f: F) -> Vec<u8>
where
    F: FnOnce() -> Vec<u8>,
{
    let (result, bytes) = profile_serde_serialize("ShieldedBlock", || {
        let data = f();
        let len = data.len();
        (data, len)
    });
    result
}

/// Profile la désérialisation d'un bloc
pub fn profile_block_deserialize<T, F>(data: &[u8], f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_serde_deserialize("ShieldedBlock", data.len(), f)
}

/// Profile la sérialisation d'une transaction
pub fn profile_tx_serialize<F>(f: F) -> Vec<u8>
where
    F: FnOnce() -> Vec<u8>,
{
    let (result, _) = profile_serde_serialize("ShieldedTransaction", || {
        let data = f();
        let len = data.len();
        (data, len)
    });
    result
}

/// Profile la désérialisation d'une transaction
pub fn profile_tx_deserialize<T, F>(data: &[u8], f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_serde_deserialize("ShieldedTransaction", data.len(), f)
}

/// Profile la vérification d'une transaction complète
pub fn profile_tx_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_crypto_verify("transaction", f)
}

/// Profile la vérification d'un spend proof
pub fn profile_spend_proof_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_zk_proof_verify("spend", f)
}

/// Profile la vérification d'un output proof
pub fn profile_output_proof_verify<T, F>(f: F) -> T
where
    F: FnOnce() -> T,
{
    profile_zk_proof_verify("output", f)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_profile_crypto_op() {
        let result = profile_crypto_op("test", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            42
        });
        assert_eq!(result, 42);
    }
    
    #[test]
    fn test_profile_db_op() {
        let result = profile_db_op("read", "blocks", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            "data"
        });
        assert_eq!(result, "data");
    }
    
    #[test]
    fn test_profile_serde_op() {
        let result = profile_serde_op("serialize", "Block", || {
            std::thread::sleep(std::time::Duration::from_millis(1));
            vec![1u8, 2, 3]
        });
        assert_eq!(result, vec![1, 2, 3]);
    }
}