//! Benchmarks de consommation mémoire pour les systèmes ZK de TSN
//! 
//! Mesure la consommation mémoire pendant:
//! - Génération de preuve
//! - Vérification de preuve
//! 
//! Contexte de sécurité:
//! - La consommation mémoire doit être O(n) où n = taille du circuit
//! - Pas de fuites mémoire pendant les opérations répétées
//! - Zeroize des secrets après usage

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use std::time::{Duration, Instant};

/// Type aliases pour Plonky2
type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Estimateur de mémoire simple
/// 
/// Note: Une implémentation complète nécessiterait jemalloc ou similar
/// pour des statistiques précises d'allocation.
pub struct MemoryEstimator {
    baseline: usize,
}

impl MemoryEstimator {
    pub fn new() -> Self {
        Self {
            baseline: Self::current_usage(),
        }
    }
    
    /// Retourne l'utilisation mémoire actuelle en KB
    /// 
    /// Sur Linux, lit /proc/self/status pour VmRSS
    fn current_usage() -> usize {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            if let Ok(status) = fs::read_to_string("/proc/self/status") {
                for line in status.lines() {
                    if line.starts_with("VmRSS:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            if let Ok(kb) = parts[1].parse::<usize>() {
                                return kb;
                            }
                        }
                    }
                }
            }
        }
        0 // Fallback
    }
    
    /// Mesure la mémoire utilisée pendant l'exécution d'une fonction
    pub fn measure<T>(&self, f: impl FnOnce() -> T) -> (T, usize) {
        let before = Self::current_usage();
        let result = f();
        let after = Self::current_usage();
        
        // Soustrait la baseline pour obtenir la mémoire réellement utilisée
        let used = if after > self.baseline {
            after.saturating_sub(self.baseline)
        } else {
            after.saturating_sub(before)
        };
        
        (result, used)
    }
}

/// Circuit simple pour benchmark mémoire
fn build_memory_test_circuit() -> plonky2::plonk::circuit_data::CircuitData<F, C, D> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Crée plusieurs gates pour simuler un circuit réaliste
    let num_gates = 1000;
    
    let mut prev = builder.add_virtual_target();
    builder.register_public_input(prev);
    
    for i in 1..num_gates {
        let next = builder.add_virtual_target();
        // Simple opération: next = prev + i
        let i_const = builder.constant(F::from_canonical_usize(i));
        let sum = builder.add(prev, i_const);
        builder.connect(sum, next);
        prev = next;
    }
    
    builder.build::<C>()
}

/// Benchmark: Consommation mémoire Plonky2 génération
pub fn bench_plonky2_memory_generation() -> crate::crypto::bench::halo2_commitment_bench::BenchmarkResult {
    use crate::crypto::bench::halo2_commitment_bench::{BenchmarkResult, BenchmarkRunner};
    
    let circuit_data = build_memory_test_circuit();
    let estimator = MemoryEstimator::new();
    
    let mut times = Vec::new();
    let mut memory_usages = Vec::new();
    
    for _ in 0..10 {
        let mut pw = PartialWitness::new();
        let initial = circuit_data.prover_only.public_inputs[0];
        pw.set_target(initial, F::from_canonical_u64(42));
        
        let start = Instant::now();
        let (_, mem_used) = estimator.measure(|| {
            let proof = circuit_data.prove(pw).expect("proof generation failed");
            std::hint::black_box(proof);
        });
        let elapsed = start.elapsed();
        
        times.push(elapsed);
        memory_usages.push(mem_used);
    }
    
    let avg_memory = if !memory_usages.is_empty() {
        memory_usages.iter().sum::<usize>() / memory_usages.len()
    } else {
        0
    };
    
    BenchmarkResult::new(
        "Plonky2 memory generation",
        times,
        Some(avg_memory),
    )
}

/// Benchmark: Consommation mémoire Plonky2 vérification
pub fn bench_plonky2_memory_verification() -> crate::crypto::bench::halo2_commitment_bench::BenchmarkResult {
    use crate::crypto::bench::halo2_commitment_bench::{BenchmarkResult, BenchmarkRunner};
    
    let circuit_data = build_memory_test_circuit();
    let verifier_data = circuit_data.verifier_data();
    
    // Génère une preuve une fois
    let mut pw = PartialWitness::new();
    let initial = circuit_data.prover_only.public_inputs[0];
    pw.set_target(initial, F::from_canonical_u64(42));
    let proof = circuit_data.prove(pw).expect("proof generation failed");
    
    let estimator = MemoryEstimator::new();
    let mut times = Vec::new();
    let mut memory_usages = Vec::new();
    
    for _ in 0..10 {
        let start = Instant::now();
        let (_, mem_used) = estimator.measure(|| {
            let _ = verifier_data.verify(proof.clone());
        });
        let elapsed = start.elapsed();
        
        times.push(elapsed);
        memory_usages.push(mem_used);
    }
    
    let avg_memory = if !memory_usages.is_empty() {
        memory_usages.iter().sum::<usize>() / memory_usages.len()
    } else {
        0
    };
    
    BenchmarkResult::new(
        "Plonky2 memory verification",
        times,
        Some(avg_memory),
    )
}

/// Exécute tous les benchmarks mémoire
pub fn run_memory_benchmarks() -> Vec<crate::crypto::bench::halo2_commitment_bench::BenchmarkResult> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║           TSN MEMORY BENCHMARKS                                 ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
    println!();
    
    let mut results = Vec::new();
    
    results.push(bench_plonky2_memory_generation());
    results.push(bench_plonky2_memory_verification());
    
    // Affiche les résultats
    for result in &results {
        result.print();
    }
    
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_memory_estimator() {
        let estimator = MemoryEstimator::new();
        let (_, mem) = estimator.measure(|| {
            let vec: Vec<u8> = vec![0; 1024 * 1024]; // 1MB
            std::hint::black_box(vec);
        });
        
        // La mémoire devrait être > 0 sur Linux
        #[cfg(target_os = "linux")]
        assert!(mem > 0, "Memory usage should be detectable on Linux");
    }
    
    #[test]
    fn test_build_memory_circuit() {
        let circuit_data = build_memory_test_circuit();
        assert!(!circuit_data.verifier_only.constants_sigmas_cap.0.is_empty());
    }
    
    #[test]
    fn test_memory_benchmarks() {
        let results = run_memory_benchmarks();
        assert!(!results.is_empty());
    }
}
