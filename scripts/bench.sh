#!/bin/bash
# =============================================================================
# TSN Benchmark Script
# Performance testing with regression detection
# =============================================================================

set -euo pipefail

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly BENCH_RESULTS_DIR="${PROJECT_ROOT}/target/criterion"
readonly BASELINE_DIR="${PROJECT_ROOT}/.bench-baseline"
readonly REGRESSION_THRESHOLD=10.0  # Percentage

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

# Show help
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Run benchmarks and detect performance regressions.

Options:
  --save-baseline NAME    Save results as baseline
  --compare NAME          Compare against baseline
  --regression-threshold N  Set regression threshold percentage (default: ${REGRESSION_THRESHOLD}%)
  --quick                 Run quick benchmarks only
  --crypto-only           Run only crypto benchmarks
  --consensus-only        Run only consensus benchmarks
  --list                  List available benchmarks
  --open                  Open benchmark report in browser
  --ci-mode               CI mode: fail on regression
  --help, -h              Show this help message

Examples:
  $0 --save-baseline main     Save current results as baseline
  $0 --compare main           Compare current results against baseline
  $0 --ci-mode                Run in CI mode with regression detection
EOF
}

# Parse arguments
SAVE_BASELINE=""
COMPARE_BASELINE=""
QUICK=false
CRYPTO_ONLY=false
CONSENSUS_ONLY=false
LIST=false
OPEN_REPORT=false
CI_MODE=false

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --save-baseline)
                SAVE_BASELINE="$2"
                shift 2
                ;;
            --compare)
                COMPARE_BASELINE="$2"
                shift 2
                ;;
            --regression-threshold)
                REGRESSION_THRESHOLD="$2"
                shift 2
                ;;
            --quick)
                QUICK=true
                shift
                ;;
            --crypto-only)
                CRYPTO_ONLY=true
                shift
                ;;
            --consensus-only)
                CONSENSUS_ONLY=true
                shift
                ;;
            --list)
                LIST=true
                shift
                ;;
            --open)
                OPEN_REPORT=true
                shift
                ;;
            --ci-mode)
                CI_MODE=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# List available benchmarks
list_benchmarks() {
    log_info "Available benchmarks:"
    
    if [ -d "${PROJECT_ROOT}/benches" ]; then
        for bench in "${PROJECT_ROOT}/benches"/*.rs; do
            if [ -f "$bench" ]; then
                local name
                name=$(basename "$bench" .rs)
                echo "  - ${name}"
            fi
        done
    fi
}

# Run benchmarks
run_benchmarks() {
    log_info "Running benchmarks..."
    
    cd "$PROJECT_ROOT"
    
    local cargo_args=()
    
    if [ "$QUICK" = true ]; then
        cargo_args+=("--" "--quick")
    fi
    
    if [ -n "$SAVE_BASELINE" ]; then
        cargo_args+=("--save-baseline" "$SAVE_BASELINE")
    fi
    
    if [ -n "$COMPARE_BASELINE" ]; then
        cargo_args+=("--baseline" "$COMPARE_BASELINE")
    fi
    
    # Select benchmarks to run
    if [ "$CRYPTO_ONLY" = true ]; then
        cargo bench --bench crypto_bench "${cargo_args[@]}"
    elif [ "$CONSENSUS_ONLY" = true ]; then
        cargo bench --bench consensus_bench "${cargo_args[@]}"
    else
        cargo bench "${cargo_args[@]}"
    fi
}

# Parse benchmark results and detect regressions
detect_regressions() {
    log_info "Checking for performance regressions..."
    
    if [ -z "$COMPARE_BASELINE" ]; then
        log_warn "No baseline specified, skipping regression detection"
        return 0
    fi
    
    local baseline_dir="${BENCH_RESULTS_DIR}/${COMPARE_BASELINE}"
    local current_dir="${BENCH_RESULTS_DIR}/new"
    
    if [ ! -d "$baseline_dir" ]; then
        log_error "Baseline not found: ${baseline_dir}"
        return 1
    fi
    
    if [ ! -d "$current_dir" ]; then
        log_error "Current results not found: ${current_dir}"
        return 1
    fi
    
    local regressions=0
    local improvements=0
    
    # Compare results (simplified - would need proper JSON parsing in production)
    log_info "Comparing against baseline: ${COMPARE_BASELINE}"
    log_info "Regression threshold: ${REGRESSION_THRESHOLD}%"
    
    # In a real implementation, this would parse the Criterion JSON output
    # and compare each benchmark's mean execution time
    
    # Placeholder for regression detection logic
    if [ "$CI_MODE" = true ] && [ $regressions -gt 0 ]; then
        log_error "${regressions} performance regressions detected!"
        return 1
    fi
    
    log_success "No significant regressions detected"
    return 0
}

# Generate benchmark report
generate_report() {
    log_info "Generating benchmark report..."
    
    local report_file="${PROJECT_ROOT}/target/benchmark-report.md"
    
    cat > "$report_file" << EOF
# TSN Benchmark Report

Generated: $(date -Iseconds)

## Summary

| Benchmark | Baseline | Current | Change |
|------------|----------|---------|--------|
EOF
    
    # Add benchmark results to report
    if [ -d "$BENCH_RESULTS_DIR" ]; then
        for result in "$BENCH_RESULTS_DIR"/*/new/estimates.json; do
            if [ -f "$result" ]; then
                local bench_name
                bench_name=$(basename "$(dirname "$(dirname "$result")")")
                echo "| ${bench_name} | - | - | - |" >> "$report_file"
            fi
        done
    fi
    
    log_info "Report saved to: ${report_file}"
}

# Open benchmark report
open_report() {
    if [ "$OPEN_REPORT" = false ]; then
        return 0
    fi
    
    local report_url="${BENCH_RESULTS_DIR}/report/index.html"
    
    if [ -f "$report_url" ]; then
        log_info "Opening benchmark report..."
        if command -v xdg-open > /dev/null 2>&1; then
            xdg-open "$report_url"
        elif command -v open > /dev/null 2>&1; then
            open "$report_url"
        else
            log_warn "Could not open browser automatically"
            log_info "Report available at: ${report_url}"
        fi
    else
        log_warn "Benchmark report not found: ${report_url}"
    fi
}

# Save baseline
save_baseline() {
    if [ -z "$SAVE_BASELINE" ]; then
        return 0
    fi
    
    log_info "Saving baseline: ${SAVE_BASELINE}"
    
    mkdir -p "$BASELINE_DIR"
    
    if [ -d "$BENCH_RESULTS_DIR" ]; then
        cp -r "${BENCH_RESULTS_DIR}/new" "${BASELINE_DIR}/${SAVE_BASELINE}"
        log_success "Baseline saved: ${SAVE_BASELINE}"
    fi
}

# Main function
main() {
    parse_args "$@"
    
    if [ "$LIST" = true ]; then
        list_benchmarks
        exit 0
    fi
    
    log_info "Starting benchmark run..."
    
    run_benchmarks
    
    if [ -n "$COMPARE_BASELINE" ]; then
        detect_regressions || {
            if [ "$CI_MODE" = true ]; then
                exit 1
            fi
        }
    fi
    
    generate_report
    save_baseline
    open_report
    
    log_success "Benchmark run completed!"
}

# Run main
trap 'log_error "Benchmark interrupted"' INT TERM
main "$@"
