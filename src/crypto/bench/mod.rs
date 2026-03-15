//! Benchmarks pour les circuits ZK de TSN
//! 
//! Ce module fournit des benchmarks comparatifs entre:
//! - Plonky2 STARKs (système ZK principal de TSN, post-quantique)
//! - Legacy Groth16 (via arkworks, pour référence)
//! 
//! Contexte de sécurité:
//! - Tous les benchmarks utilisent des paramètres 128-bit security
//! - Les benchmarks sont conçus pour être reproductibles
//! 
//! Usage:
//! ```bash
//! cargo test --lib crypto::bench
//! ```

// Modules de benchmarks
pub mod halo2_commitment_bench;
pub mod plonky2_bench;
pub mod memory_bench;
pub mod halo2_plonky2_comparison;

// Re-exports pour utilisation externe
pub use halo2_commitment_bench::{BenchmarkResult, BenchmarkRunner, run_all_benchmarks};
pub use plonky2_bench::run_plonky2_benchmarks;
pub use memory_bench::run_memory_benchmarks;
pub use halo2_plonky2_comparison::run_comparison;

/// Exécute la suite complète de benchmarks
/// 
/// Cette fonction est le point d'entrée principal pour tous les benchmarks ZK.
/// Elle mesure:
/// - Temps de génération de preuve
/// - Temps de vérification
/// - Consommation mémoire
/// - Scaling avec la taille du circuit
/// 
/// # Returns
/// Une liste de tous les résultats de benchmarks
/// 
/// # Example
/// ```
/// use tsn::crypto::bench::run_full_benchmark_suite;
/// 
/// let results = run_full_benchmark_suite();
/// for result in results {
///     println!("{}: {:?}", result.name, result.avg_time);
/// }
/// ```
pub fn run_full_benchmark_suite() -> Vec<BenchmarkResult> {
    let mut all_results = Vec::new();
    
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║     TSN ZK CIRCUITS FULL BENCHMARK SUITE                       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();
    
    // Benchmarks Plonky2
    all_results.extend(run_plonky2_benchmarks());
    
    // Benchmarks mémoire
    all_results.extend(run_memory_benchmarks());
    
    // Comparaison
    let _ = run_comparison();
    
    println!();
    println!("Benchmark suite completed.");
    
    all_results
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_full_suite() {
        // Test que la suite complète s'exécute sans paniquer
        let results = run_full_benchmark_suite();
        assert!(!results.is_empty());
    }
}
