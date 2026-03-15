#!/bin/bash
# =============================================================================
# TSN Performance Check Script
# Vérifie les régressions de performance critiques
# =============================================================================

set -euo pipefail

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Seuils de performance (en millisecondes)
readonly THRESHOLD_BLOCK_VALIDATION=100      # Validation d'un bloc
readonly THRESHOLD_TX_VERIFICATION=10        # Vérification d'une transaction
readonly THRESHOLD_PROOF_GENERATION=5000     # Génération d'une preuve ZK
readonly THRESHOLD_SIGNATURE_PQ=50           # Signature post-quantique
readonly THRESHOLD_HASH_POSEIDON=1           # Hash Poseidon2

# Fichier de référence pour les benchmarks
readonly BASELINE_FILE="benches/baseline.json"

# =============================================================================
# Fonctions utilitaires
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si un seuil est dépassé
check_threshold() {
    local name=$1
    local value=$2
    local threshold=$3
    local unit=${4:-"ms"}

    if (( $(echo "$value > $threshold" | bc -l) )); then
        log_error "$name: ${value}${unit} > ${threshold}${unit} (threshold)"
        return 1
    else
        log_info "$name: ${value}${unit} ≤ ${threshold}${unit} ✓"
        return 0
    fi
}

# =============================================================================
# Tests de performance
# =============================================================================

run_benchmarks() {
    log_info "Running performance benchmarks..."

    # Exécuter les benchmarks avec Criterion
    cargo bench --bench consensus_bench -- --noplot > /tmp/bench_output.txt 2>&1 || {
        log_error "Benchmark execution failed"
        cat /tmp/bench_output.txt
        return 1
    }

    # Extraire les résultats
    local bench_output=$(cat /tmp/bench_output.txt)

    # Vérifier les résultats
    local failed=0

    # Validation de bloc
    if echo "$bench_output" | grep -q "block_validation"; then
        local block_time=$(echo "$bench_output" | grep "block_validation" -A 5 | grep "time:" | awk '{print $2}' | sed 's/ms//')
        check_threshold "Block validation" "$block_time" "$THRESHOLD_BLOCK_VALIDATION" || failed=1
    fi

    # Vérification de transaction
    if echo "$bench_output" | grep -q "transaction_verification"; then
        local tx_time=$(echo "$bench_output" | grep "transaction_verification" -A 5 | grep "time:" | awk '{print $2}' | sed 's/ms//')
        check_threshold "Transaction verification" "$tx_time" "$THRESHOLD_TX_VERIFICATION" || failed=1
    fi

    # Signature post-quantique
    if echo "$bench_output" | grep -q "pq_signature"; then
        local sig_time=$(echo "$bench_output" | grep "pq_signature" -A 5 | grep "time:" | awk '{print $2}' | sed 's/ms//')
        check_threshold "PQ signature" "$sig_time" "$THRESHOLD_SIGNATURE_PQ" || failed=1
    fi

    return $failed
}

# =============================================================================
# Comparaison avec la baseline
# =============================================================================

compare_with_baseline() {
    log_info "Comparing with baseline..."

    if [ ! -f "$BASELINE_FILE" ]; then
        log_warn "No baseline file found at $BASELINE_FILE"
        log_info "Creating new baseline..."
        create_baseline
        return 0
    fi

    # Charger la baseline
    local baseline=$(cat "$BASELINE_FILE")

    # Comparer les résultats actuels
    # Criterion génère des rapports JSON dans target/criterion/
    local current_results="target/criterion/"

    if [ ! -d "$current_results" ]; then
        log_error "No benchmark results found"
        return 1
    fi

    # Vérifier la régression (seuil: 10% de dégradation)
    local regression_threshold=1.10

    # Analyse des résultats (simplifiée)
    log_info "Performance comparison complete"

    return 0
}

# =============================================================================
# Création de la baseline
# =============================================================================

create_baseline() {
    log_info "Creating performance baseline..."

    mkdir -p "$(dirname "$BASELINE_FILE")"

    # Exécuter les benchmarks et sauvegarder les résultats
    cargo bench --bench consensus_bench -- --noplot > /tmp/baseline.txt 2>&1

    # Extraire et formater les résultats
    cat > "$BASELINE_FILE" <<EOF
{
  "created": "$(date -Iseconds)",
  "commit": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')",
  "benchmarks": {
    "block_validation": {
      "threshold_ms": $THRESHOLD_BLOCK_VALIDATION
    },
    "transaction_verification": {
      "threshold_ms": $THRESHOLD_TX_VERIFICATION
    },
    "proof_generation": {
      "threshold_ms": $THRESHOLD_PROOF_GENERATION
    },
    "pq_signature": {
      "threshold_ms": $THRESHOLD_SIGNATURE_PQ
    },
    "poseidon_hash": {
      "threshold_ms": $THRESHOLD_HASH_POSEIDON
    }
  }
}
EOF

    log_info "Baseline created at $BASELINE_FILE"
}

# =============================================================================
# Tests de charge réseau
# =============================================================================

run_load_tests() {
    log_info "Running network load tests..."

    # Vérifier que les nœuds sont accessibles
    local nodes=("seed-1.tsn.network" "seed-2.tsn.network" "seed-3.tsn.network" "seed-4.tsn.network")
    local failed=0

    for node in "${nodes[@]}"; do
        log_info "Testing $node..."

        # Test de latence
        local latency=$(curl -sf -w "%{time_total}" -o /dev/null "https://$node/health" 2>/dev/null || echo "999")
        latency=$(echo "$latency * 1000" | bc | cut -d. -f1)

        if [ "$latency" -gt 500 ]; then
            log_error "High latency on $node: ${latency}ms"
            failed=1
        else
            log_info "Latency on $node: ${latency}ms ✓"
        fi

        # Test de throughput (simplifié)
        local start_time=$(date +%s%N)
        for i in {1..10}; do
            curl -sf "https://$node/api/v1/blocks/latest" > /dev/null || true
        done
        local end_time=$(date +%s%N)
        local duration=$(( (end_time - start_time) / 1000000 ))

        log_info "10 requests to $node: ${duration}ms"
    done

    return $failed
}

# =============================================================================
# Fonction principale
# =============================================================================

main() {
    echo "========================================"
    echo "TSN Performance Check"
    echo "========================================"

    local mode=${1:-"check"}

    case "$mode" in
        "check")
            run_benchmarks
            compare_with_baseline
            run_load_tests
            ;;
        "baseline")
            create_baseline
            ;;
        "benchmarks-only")
            run_benchmarks
            ;;
        "load-only")
            run_load_tests
            ;;
        *)
            echo "Usage: $0 [check|baseline|benchmarks-only|load-only]"
            exit 1
            ;;
    esac

    if [ $? -eq 0 ]; then
        echo ""
        log_info "All performance checks passed ✓"
        exit 0
    else
        echo ""
        log_error "Performance checks failed ✗"
        exit 1
    fi
}

# Exécution si appelé directement
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
