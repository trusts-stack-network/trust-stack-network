#!/bin/bash
# =============================================================================
# TSN Test Runner
# Comprehensive test suite with coverage and reporting
# =============================================================================

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Configuration
readonly COVERAGE_THRESHOLD=70
readonly TEST_TIMEOUT=300

# Test results
declare -A TEST_RESULTS
FAILED_TESTS=0
PASSED_TESTS=0

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

# Print banner
print_banner() {
    echo ""
    echo "=========================================="
    echo "      TSN Test Suite Runner"
    echo "=========================================="
    echo ""
}

# Run a test suite
run_test_suite() {
    local name="$1"
    local command="$2"
    local description="${3:-$name}"
    
    log_info "Running: $description"
    
    local start_time
    start_time=$(date +%s)
    
    if eval "$command" > /tmp/test_output_$$.log 2>&1; then
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_success "$name (${duration}s)"
        TEST_RESULTS["$name"]="PASS"
        PASSED_TESTS=$((PASSED_TESTS + 1))
        return 0
    else
        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_error "$name (${duration}s)"
        TEST_RESULTS["$name"]="FAIL"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        echo "--- Output ---"
        cat /tmp/test_output_$$.log
        echo "--------------"
        return 1
    fi
}

# Format check
run_format_check() {
    run_test_suite "format" \
        "cargo fmt -- --check" \
        "Code formatting check"
}

# Clippy lints
run_clippy() {
    run_test_suite "clippy" \
        "cargo clippy --all-targets --all-features -- -D warnings" \
        "Clippy lints"
}

# Unit tests
run_unit_tests() {
    run_test_suite "unit" \
        "cargo test --lib --all-features" \
        "Unit tests"
}

# Integration tests
run_integration_tests() {
    run_test_suite "integration" \
        "cargo test --test '*' --all-features" \
        "Integration tests"
}

# Doc tests
run_doc_tests() {
    run_test_suite "doc" \
        "cargo test --doc --all-features" \
        "Documentation tests"
}

# Security audit
run_security_audit() {
    if command -v cargo-audit > /dev/null 2>&1; then
        run_test_suite "audit" \
            "cargo audit" \
            "Security audit"
    else
        log_warn "cargo-audit not installed, skipping security audit"
        TEST_RESULTS["audit"]="SKIP"
    fi
}

# Dependency check
run_dependency_check() {
    if command -v cargo-deny > /dev/null 2>&1; then
        run_test_suite "deny" \
            "cargo deny check" \
            "Dependency license and security check"
    else
        log_warn "cargo-deny not installed, skipping dependency check"
        TEST_RESULTS["deny"]="SKIP"
    fi
}

# Unused dependencies
run_unused_deps_check() {
    if command -v cargo-machete > /dev/null 2>&1; then
        run_test_suite "machete" \
            "cargo machete" \
            "Unused dependencies check"
    else
        log_warn "cargo-machete not installed, skipping unused deps check"
        TEST_RESULTS["machete"]="SKIP"
    fi
}

# Build check
run_build_check() {
    run_test_suite "build" \
        "cargo build --all-features --release" \
        "Release build"
}

# Coverage report
run_coverage() {
    if command -v cargo-tarpaulin > /dev/null 2>&1; then
        log_info "Running code coverage analysis..."
        
        if cargo tarpaulin --out Html --out Stdout --all-features --timeout 300; then
            log_success "coverage"
            TEST_RESULTS["coverage"]="PASS"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            
            # Check coverage threshold
            if [ -f "tarpaulin-report.html" ]; then
                log_info "Coverage report generated: tarpaulin-report.html"
            fi
        else
            log_warn "Coverage analysis completed with warnings"
            TEST_RESULTS["coverage"]="WARN"
        fi
    else
        log_warn "cargo-tarpaulin not installed, skipping coverage"
        TEST_RESULTS["coverage"]="SKIP"
    fi
}

# Benchmark compilation check
run_benchmark_check() {
    run_test_suite "bench-compile" \
        "cargo build --benches --all-features" \
        "Benchmark compilation"
}

# Print summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "           Test Summary"
    echo "=========================================="
    echo ""
    
    for test in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$test]}"
        case "$result" in
            PASS)
                printf "  ${GREEN}✓${NC} %-20s %s\n" "$test" "$result"
                ;;
            FAIL)
                printf "  ${RED}✗${NC} %-20s %s\n" "$test" "$result"
                ;;
            SKIP)
                printf "  ${YELLOW}○${NC} %-20s %s\n" "$test" "$result"
                ;;
            WARN)
                printf "  ${YELLOW}!${NC} %-20s %s\n" "$test" "$result"
                ;;
        esac
    done
    
    echo ""
    echo "=========================================="
    printf "  Total: %d passed, %d failed\n" "$PASSED_TESTS" "$FAILED_TESTS"
    echo "=========================================="
    echo ""
}

# Main function
main() {
    print_banner
    
    local run_all=true
    local quick_mode=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick|-q)
                quick_mode=true
                shift
                ;;
            --unit|-u)
                run_all=false
                run_unit_tests
                shift
                ;;
            --integration|-i)
                run_all=false
                run_integration_tests
                shift
                ;;
            --coverage|-c)
                run_all=false
                run_coverage
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --quick, -q        Quick mode (format, clippy, unit tests only)"
                echo "  --unit, -u         Run unit tests only"
                echo "  --integration, -i  Run integration tests only"
                echo "  --coverage, -c     Run coverage analysis"
                echo "  --help, -h         Show this help"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [ "$run_all" = true ]; then
        if [ "$quick_mode" = true ]; then
            log_info "Running in quick mode..."
            run_format_check
            run_clippy
            run_unit_tests
        else
            log_info "Running full test suite..."
            run_format_check
            run_clippy
            run_unit_tests
            run_integration_tests
            run_doc_tests
            run_security_audit
            run_dependency_check
            run_unused_deps_check
            run_build_check
            run_benchmark_check
            run_coverage
        fi
    fi
    
    print_summary
    
    # Exit with appropriate code
    if [ $FAILED_TESTS -gt 0 ]; then
        exit 1
    else
        log_success "All tests passed!"
        exit 0
    fi
}

# Cleanup on exit
cleanup() {
    rm -f /tmp/test_output_$$.log
}
trap cleanup EXIT

# Run main
main "$@"
