#!/bin/bash
# ============================================================================
# Script d'exécution des benchmarks de performance TSN
# ============================================================================
# Usage: ./scripts/run_benchmarks.sh [options]
# Options:
#   --consensus    : Exécute uniquement les benchmarks de consensus
#   --crypto       : Exécute uniquement les benchmarks cryptographiques
#   --network      : Exécute uniquement les benchmarks réseau
#   --all          : Exécute tous les benchmarks (défaut)
#   --save         : Sauvegarde les résultats dans benches/results/
#   --compare      : Compare avec les résultats précédents
#   --help         : Affiche l'aide
# ============================================================================

set -euo pipefail

# Couleurs pour l'affichage
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Répertoire du projet
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly RESULTS_DIR="${PROJECT_ROOT}/benches/results"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Flags par défaut
RUN_CONSENSUS=false
RUN_CRYPTO=false
RUN_NETWORK=false
RUN_ALL=true
SAVE_RESULTS=false
COMPARE=false

# ============================================================================
# Fonctions utilitaires
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_help() {
    cat << EOF
TSN Benchmark Runner

Usage: $0 [options]

Options:
  --consensus    Exécute uniquement les benchmarks de consensus
  --crypto       Exécute uniquement les benchmarks cryptographiques
  --network      Exécute uniquement les benchmarks réseau
  --all          Exécute tous les benchmarks (défaut)
  --save         Sauvegarde les résultats dans benches/results/
  --compare      Compare avec les résultats précédents
  --help         Affiche cette aide

Exemples:
  $0 --consensus --save          # Benchmark consensus + sauvegarde
  $0 --crypto --compare          # Benchmark crypto + comparaison
  $0 --all                       # Tous les benchmarks

EOF
}

# ============================================================================
# Parsing des arguments
# ============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --consensus)
                RUN_CONSENSUS=true
                RUN_ALL=false
                shift
                ;;
            --crypto)
                RUN_CRYPTO=true
                RUN_ALL=false
                shift
                ;;
            --network)
                RUN_NETWORK=true
                RUN_ALL=false
                shift
                ;;
            --all)
                RUN_ALL=true
                shift
                ;;
            --save)
                SAVE_RESULTS=true
                shift
                ;;
            --compare)
                COMPARE=true
                shift
                ;;
            --help)
                print_help
                exit 0
                ;;
            *)
                log_error "Option inconnue: $1"
                print_help
                exit 1
                ;;
        esac
    done
}

# ============================================================================
# Vérification des prérequis
# ============================================================================

check_prerequisites() {
    log_info "Vérification des prérequis..."
    
    if ! command -v cargo &> /dev/null; then
        log_error "cargo n'est pas installé"
        exit 1
    fi
    
    if ! cargo bench --help &> /dev/null; then
        log_error "cargo-criterion n'est pas installé"
        log_info "Installation: cargo install cargo-criterion"
        exit 1
    fi
    
    log_success "Prérequis OK"
}

# ============================================================================
# Préparation du répertoire de résultats
# ============================================================================

prepare_results_dir() {
    if [[ "$SAVE_RESULTS" == true ]]; then
        mkdir -p "${RESULTS_DIR}"
        log_info "Résultats sauvegardés dans: ${RESULTS_DIR}"
    fi
}

# ============================================================================
# Exécution des benchmarks
# ============================================================================

run_benchmark() {
    local bench_name=$1
    local bench_filter=$2
    
    log_info "Exécution des benchmarks: ${bench_name}"
    
    local cargo_args=("--bench" "$bench_name")
    
    if [[ -n "$bench_filter" ]]; then
        cargo_args+=("--" "$bench_filter")
    fi
    
    if [[ "$SAVE_RESULTS" == true ]]; then
        local result_file="${RESULTS_DIR}/${bench_name}_${TIMESTAMP}.json"
        cargo_args+=("--" "--noplot" "--save-baseline" "${TIMESTAMP}")
        CARGO_TARGET_DIR="${PROJECT_ROOT}/target/bench" \
            cargo bench "${cargo_args[@]}" 2>&1 | tee "${result_file}.log"
    else
        CARGO_TARGET_DIR="${PROJECT_ROOT}/target/bench" \
            cargo bench "${cargo_args[@]}"
    fi
    
    log_success "Benchmark ${bench_name} terminé"
}

run_consensus_benchmarks() {
    log_info "=== Benchmarks de Consensus ==="
    run_benchmark "consensus_bench" ""
}

run_crypto_benchmarks() {
    log_info "=== Benchmarks Cryptographiques ==="
    
    # SLH-DSA benchmarks
    if [[ -f "${PROJECT_ROOT}/benches/slh_dsa_bench.rs" ]]; then
        run_benchmark "slh_dsa_bench" ""
    fi
    
    # Halo2 vs Plonky2 comparison
    if [[ -f "${PROJECT_ROOT}/benches/halo2_plonky2_comparison.rs" ]]; then
        run_benchmark "halo2_plonky2_comparison" ""
    fi
    
    # Timing benchmarks
    if [[ -f "${PROJECT_ROOT}/benches/timing_bench.rs" ]]; then
        run_benchmark "timing_bench" ""
    fi
}

run_network_benchmarks() {
    log_info "=== Benchmarks Réseau ==="
    
    # Latency benchmarks
    if [[ -f "${PROJECT_ROOT}/benches/latency_bench.rs" ]]; then
        run_benchmark "latency_bench" ""
    fi
    
    # Throughput benchmarks
    if [[ -f "${PROJECT_ROOT}/benches/throughput_bench.rs" ]]; then
        run_benchmark "throughput_bench" ""
    fi
}

# ============================================================================
# Comparaison des résultats
# ============================================================================

compare_results() {
    if [[ "$COMPARE" != true ]]; then
        return
    fi
    
    log_info "=== Comparaison des résultats ==="
    
    local baselines
    baselines=$(ls -1 "${PROJECT_ROOT}/target/criterion" 2>/dev/null | head -5 || true)
    
    if [[ -z "$baselines" ]]; then
        log_warning "Aucun baseline trouvé pour comparaison"
        return
    fi
    
    log_info "Baselines disponibles:"
    echo "$baselines"
    
    # Générer un rapport de comparaison
    local compare_report="${RESULTS_DIR}/comparison_${TIMESTAMP}.md"
    cat > "$compare_report" << EOF
# Rapport de Comparaison des Benchmarks

Date: $(date)

## Baselines comparées
\`\`\`
$baselines
\`\`\`

## Analyse

Pour une analyse détaillée, utiliser:
\`\`\`bash
cargo bench -- --baseline <ancien> --load-baseline <nouveau>
\`\`\`

EOF
    
    log_success "Rapport de comparaison généré: ${compare_report}"
}

# ============================================================================
# Génération du rapport final
# ============================================================================

generate_report() {
    if [[ "$SAVE_RESULTS" != true ]]; then
        return
    fi
    
    log_info "=== Génération du rapport final ==="
    
    local report_file="${RESULTS_DIR}/report_${TIMESTAMP}.md"
    
    cat > "$report_file" << EOF
# Rapport de Benchmarks TSN

**Date:** $(date)
**Commit:** $(git rev-parse --short HEAD 2>/dev/null || echo "N/A")
**Branche:** $(git branch --show-current 2>/dev/null || echo "N/A")

## Résumé

Ce rapport contient les résultats des benchmarks de performance pour Trust Stack Network.

## Benchmarks exécutés

EOF
    
    if [[ "$RUN_CONSENSUS" == true ]] || [[ "$RUN_ALL" == true ]]; then
        echo "- ✅ Consensus (PoW, validation de blocs)" >> "$report_file"
    fi
    
    if [[ "$RUN_CRYPTO" == true ]] || [[ "$RUN_ALL" == true ]]; then
        echo "- ✅ Cryptographie (SLH-DSA, Halo2)" >> "$report_file"
    fi
    
    if [[ "$RUN_NETWORK" == true ]] || [[ "$RUN_ALL" == true ]]; then
        echo "- ✅ Réseau (latence, throughput)" >> "$report_file"
    fi
    
    cat >> "$report_file" << EOF

## Fichiers de résultats

\`\`\`
$(ls -la "${RESULTS_DIR}"/*.json 2>/dev/null || echo "Aucun fichier JSON")
\`\`\`

## Notes

- Les benchmarks sont exécutés avec \`cargo bench\`
- Les résultats sont stockés dans \`target/criterion/\`
- Utiliser \`cargo install cargo-criterion\` pour de meilleures visualisations

## Prochaines étapes

1. Analyser les résultats pour identifier les bottlenecks
2. Comparer avec les baselines précédentes
3. Optimiser les fonctions critiques identifiées

EOF
    
    log_success "Rapport généré: ${report_file}"
}

# ============================================================================
# Fonction principale
# ============================================================================

main() {
    log_info "TSN Benchmark Runner"
    log_info "===================="
    
    parse_args "$@"
    check_prerequisites
    prepare_results_dir
    
    cd "$PROJECT_ROOT"
    
    if [[ "$RUN_ALL" == true ]] || [[ "$RUN_CONSENSUS" == true ]]; then
        run_consensus_benchmarks
    fi
    
    if [[ "$RUN_ALL" == true ]] || [[ "$RUN_CRYPTO" == true ]]; then
        run_crypto_benchmarks
    fi
    
    if [[ "$RUN_ALL" == true ]] || [[ "$RUN_NETWORK" == true ]]; then
        run_network_benchmarks
    fi
    
    compare_results
    generate_report
    
    log_success "Tous les benchmarks terminés avec succès!"
    
    if [[ "$SAVE_RESULTS" == true ]]; then
        log_info "Résultats disponibles dans: ${RESULTS_DIR}"
    fi
}

# ============================================================================
# Point d'entrée
# ============================================================================

main "$@"
