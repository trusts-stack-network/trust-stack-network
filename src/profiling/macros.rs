//! Macros pour le profiling des opérations critiques
//!
//! Ce module fournit des macros pratiques pour instrumenter le code
//! sans ajouter de boilerplate. Les macros sont désactivables via
//! la feature flag `profiling`.
//!
//! ## Exemples d'utilisation
//!
//! ```rust,ignore
//! use tsn::profiling::{profile, profile_crypto, profile_db};
//!
//! // Profiler une fonction entière
//! fn process_block(block: &Block) -> Result<BlockHash, Error> {
//!     profile!("process_block", || {
//!         // ... logique de traitement
//!         Ok(block.hash())
//!     })
//! }
//!
//! // Profiler une opération crypto spécifique
//! let sig = profile_crypto!("sign", || {
//!     sign_message(msg, keypair)
//! });
//!
//! // Profiler une requête DB
//! let block = profile_db!("read", "blocks", || {
//!     db.get_block(&hash)
//! });
//! ```

/// Profile une opération générique avec catégorie et nom
///
/// # Exemples
///
/// ```rust,ignore
/// let result = profile!("crypto", "sign", || {
///     sign_message(message, keypair)
/// });
/// ```
#[macro_export]
macro_rules! profile {
    ($category:expr, $name:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($name, $category);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Profile une opération cryptographique
///
/// # Exemples
///
/// ```rust,ignore
/// let signature = profile_crypto!("sign", || {
///     sign_transaction(&tx, keypair)
/// });
/// ```
#[macro_export]
macro_rules! profile_crypto {
    ($operation:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Crypto);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Profile une opération de base de données
///
/// # Exemples
///
/// ```rust,ignore
/// let block = profile_db!("read", "blocks", || {
///     db.load_block(&hash)
/// });
/// ```
#[macro_export]
macro_rules! profile_db {
    ($operation:expr, $table:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Database);
        let result = $body;
        let duration = timer.stop();
        
        // Enregistrer avec la table spécifiée
        $crate::profiling::DB_METRICS.record_operation(
            $operation,
            $table,
            duration.as_secs_f64()
        );
        
        result
    }};
}

/// Profile une opération de sérialisation
///
/// # Exemples
///
/// ```rust,ignore
/// let bytes = profile_serde!("serialize", "Block", || {
///     block.to_bytes()
/// });
/// ```
#[macro_export]
macro_rules! profile_serde {
    ($operation:expr, $type_name:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Serialization);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Profile une opération réseau
///
/// # Exemples
///
/// ```rust,ignore
/// let response = profile_network!("send_block", || {
///     peer.send(&block).await
/// });
/// ```
#[macro_export]
macro_rules! profile_network {
    ($operation:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Network);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Profile une opération de consensus
///
/// # Exemples
///
/// ```rust,ignore
/// let valid = profile_consensus!("validate", || {
///     validate_block(&block)
/// });
/// ```
#[macro_export]
macro_rules! profile_consensus {
    ($operation:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Consensus);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Profile une fonction async
///
/// # Exemples
///
/// ```rust,ignore
/// let result = profile_async!("crypto", "verify", async {
///     verify_signature(&sig, &msg).await
/// }).await;
/// ```
#[macro_export]
macro_rules! profile_async {
    ($category:expr, $name:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        async move {
            let timer = OperationTimer::new($name, $category);
            let result = $body.await;
            timer.stop();
            result
        }
    }};
}

/// Profile une opération crypto async
///
/// # Exemples
///
/// ```rust,ignore
/// let result = profile_crypto_async!("batch_verify", async {
///     batch_verify_signatures(&sigs).await
/// }).await;
/// ```
#[macro_export]
macro_rules! profile_crypto_async {
    ($operation:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        async move {
            let timer = OperationTimer::new($operation, OperationCategory::Crypto);
            let result = $body.await;
            timer.stop();
            result
        }
    }};
}

/// Profile une opération DB async
///
/// # Exemples
///
/// ```rust,ignore
/// let block = profile_db_async!("read", "blocks", async {
///     db.get_block(&hash).await
/// }).await;
/// ```
#[macro_export]
macro_rules! profile_db_async {
    ($operation:expr, $table:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        async move {
            let timer = OperationTimer::new($operation, OperationCategory::Database);
            let result = $body.await;
            let duration = timer.stop();
            
            $crate::profiling::DB_METRICS.record_operation(
                $operation,
                $table,
                duration.as_secs_f64()
            );
            
            result
        }
    }};
}

/// Crée un timer de profiling qui s'arrête automatiquement à la fin du scope
///
/// # Exemples
///
/// ```rust,ignore
/// {
///     let _timer = profile_scope!("crypto", "hash");
///     // ... opération à profiler
/// } // Le timer s'arrête ici automatiquement
/// ```
#[macro_export]
macro_rules! profile_scope {
    ($category:expr, $name:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        OperationTimer::new($name, $category)
    }};
}

/// Crée un timer de profiling pour les opérations crypto
///
/// # Exemples
///
/// ```rust,ignore
/// {
///     let _timer = profile_crypto_scope!("sign");
///     let sig = sign_message(msg, keypair);
/// } // Le timer s'arrête ici
/// ```
#[macro_export]
macro_rules! profile_crypto_scope {
    ($operation:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        OperationTimer::new($operation, OperationCategory::Crypto)
    }};
}

/// Crée un timer de profiling pour les opérations DB
///
/// # Exemples
///
/// ```rust,ignore
/// {
///     let _timer = profile_db_scope!("read", "blocks");
///     let block = db.get_block(&hash);
/// } // Le timer s'arrête ici
/// ```
#[macro_export]
macro_rules! profile_db_scope {
    ($operation:expr, $table:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        // Note: la table n'est pas utilisée dans le timer de base
        // mais peut être étendue si nécessaire
        OperationTimer::new($operation, OperationCategory::Database)
    }};
}

/// Profile une fonction entière avec instrumentation automatique
///
/// Cette macro ajoute du profiling au début et à la fin de la fonction.
///
/// # Exemples
///
/// ```rust,ignore
/// #[profile_fn]
/// fn process_transaction(tx: &Transaction) -> Result<(), Error> {
///     // ... logique
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! profile_fn {
    ($name:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($name, OperationCategory::Crypto);
        let result = $body;
        timer.stop();
        result
    }};
}

/// Version conditionnelle du profiling (désactivable en release)
///
/// Cette macro ne profile que si la feature `profiling` est activée
/// ou si le mode debug est utilisé.
#[macro_export]
macro_rules! profile_debug {
    ($category:expr, $name:expr, $body:expr) => {{
        #[cfg(any(feature = "profiling", debug_assertions))]
        {
            use $crate::profiling::{OperationCategory, OperationTimer};
            let timer = OperationTimer::new($name, $category);
            let result = $body;
            timer.stop();
            result
        }
        #[cfg(not(any(feature = "profiling", debug_assertions)))]
        {
            $body
        }
    }};
}

/// Mesure le temps d'exécution sans enregistrer de métriques
///
/// Utile pour les benchmarks rapides ou le debugging.
///
/// # Exemples
///
/// ```rust,ignore
/// let (result, duration) = time_op!(|| {
///     expensive_computation()
/// });
/// println!("Durée: {:?}", duration);
/// ```
#[macro_export]
macro_rules! time_op {
    ($body:expr) => {{
        let start = std::time::Instant::now();
        let result = $body;
        let duration = start.elapsed();
        (result, duration)
    }};
}

/// Mesure le temps d'exécution async sans enregistrer de métriques
///
/// # Exemples
///
/// ```rust,ignore
/// let (result, duration) = time_op_async!(async {
///     async_computation().await
/// }).await;
/// ```
#[macro_export]
macro_rules! time_op_async {
    ($body:expr) => {{
        async move {
            let start = std::time::Instant::now();
            let result = $body.await;
            let duration = start.elapsed();
            (result, duration)
        }
    }};
}

/// Enregistre une métrique personnalisée
///
/// # Exemples
///
/// ```rust,ignore
/// record_metric!("custom", "my_operation", 0.5);
/// ```
#[macro_export]
macro_rules! record_metric {
    ($category:expr, $name:expr, $duration:expr) => {{
        use $crate::profiling::record_histogram;
        record_histogram($category, $name, $duration);
    }};
}

/// Profile une opération avec gestion d'erreur
///
/// Enregistre une métrique d'erreur si l'opération échoue.
///
/// # Exemples
///
/// ```rust,ignore
/// let result = profile_result!("crypto", "verify", || {
///     verify_signature(&sig, &msg)
/// });
/// ```
#[macro_export]
macro_rules! profile_result {
    ($category:expr, $name:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($name, $category);
        let result = $body;
        
        match &result {
            Ok(_) => {}
            Err(_) => {
                // Enregistrer l'erreur dans les métriques
                match $category {
                    OperationCategory::Crypto => {
                        $crate::profiling::CRYPTO_METRICS.record_error($name);
                    }
                    OperationCategory::Database => {
                        $crate::profiling::DB_METRICS.record_error($name, "unknown");
                    }
                    _ => {}
                }
            }
        }
        
        timer.stop();
        result
    }};
}

/// Profile une opération crypto avec gestion d'erreur
#[macro_export]
macro_rules! profile_crypto_result {
    ($operation:expr, $body:expr) => {{
        $crate::profile_result!(OperationCategory::Crypto, $operation, $body)
    }};
}

/// Profile une opération DB avec gestion d'erreur
#[macro_export]
macro_rules! profile_db_result {
    ($operation:expr, $table:expr, $body:expr) => {{
        use $crate::profiling::{OperationCategory, OperationTimer};
        let timer = OperationTimer::new($operation, OperationCategory::Database);
        let result = $body;
        
        if result.is_err() {
            $crate::profiling::DB_METRICS.record_error($operation, $table);
        }
        
        timer.stop();
        result
    }};
}

// ============================================================================
// Ré-export des macros pour usage interne
// ============================================================================

pub use crate::profile;
pub use crate::profile_crypto;
pub use crate::profile_db;
pub use crate::profile_serde;
pub use crate::profile_network;
pub use crate::profile_consensus;
pub use crate::profile_async;
pub use crate::profile_crypto_async;
pub use crate::profile_db_async;
pub use crate::profile_scope;
pub use crate::profile_crypto_scope;
pub use crate::profile_db_scope;
pub use crate::profile_fn;
pub use crate::profile_debug;
pub use crate::time_op;
pub use crate::time_op_async;
pub use crate::record_metric;
pub use crate::profile_result;
pub use crate::profile_crypto_result;
pub use crate::profile_db_result;
