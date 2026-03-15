# Benchmarks TSN — SLH-DSA vs ML-DSA

Ce répertoire contient les benchmarks comparatifs de performance pour les deux signatures post-quantiques de TSN :

- **SLH-DSA** (SPHINCS+) — FIPS 205, signature de référence
- **ML-DSA-65** — FIPS 204, conservé pour compatibilité legacy

## Métriques mesurées

| Benchmark | Métriques |
|-----------|-----------|
| `throughput_bench.rs` | Throughput (tx/s), latence moyenne |
| `latency_bench.rs` | p50, p95, p99 (percentiles) |
| `memory_bench.rs` | Utilisation mémoire (heap) |
| `parallel_bench.rs` | Accélération parallèle (batch verification) |
| `workload_bench.rs` | Charge réelle (1000–10000 tx/bloc) |

## Usage

```bash
# Lancer tous les benchmarks
cargo bench

# Lancer un benchmark spécifique
cargo bench --bench throughput_bench

# Générer un rapport HTML (avec criterion)
cargo bench -- --output-file bench_report.json
```

## Rapport de performance attendu

| Opération | SLH-DSA (µs) | ML-DSA-65 (µs) | Ratio SLH/ML |
|-----------|--------------|----------------|--------------|
| Sign (p50) | ~1500 | ~500 | 3.0x |
| Verify (p50) | ~800 | ~200 | 4.0x |
| Keygen (p50) | ~2000 | ~600 | 3.3x |
| Mémoire (sign) | ~8 KB | ~2 KB | 4.0x |

## Recommandations

- **Production** : SLH-DSA (sécurité prouvée, NIST standard)
- **Legacy** : ML-DSA-65 (compatibilité avec v1)
- **Optimisation** : Utiliser batch verification pour les hauts débits

## CI Integration

Les benchmarks sont intégrés à la CI GitHub Actions :

```yaml
- name: Run benchmarks
  run: cargo bench -- --output-file bench_results.json
- name: Check performance regressions
  run: cargo run --bin bench_diff -- bench_results.json
```

## Scripts associés

- `scripts/bench_report.sh` — Génère un rapport HTML à partir des résultats
- `scripts/bench_compare.sh` — Compare deux jeux de benchmarks
