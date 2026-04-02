#!/bin/bash
# =============================================================================
# TSN Node Health Check Script
# Performs comprehensive health checks on TSN nodes
# =============================================================================

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/tsn-health-check.log"
readonly API_PORT="${TSN_API_PORT:-8080}"
readonly P2P_PORT="${TSN_P2P_PORT:-30303}"
readonly METRICS_PORT="${TSN_METRICS_PORT:-9090}"

# Thresholds
readonly DISK_WARNING_THRESHOLD=80
readonly DISK_CRITICAL_THRESHOLD=90
readonly MEMORY_WARNING_THRESHOLD=80
readonly MEMORY_CRITICAL_THRESHOLD=90
readonly LOAD_WARNING_THRESHOLD=4.0
readonly LOAD_CRITICAL_THRESHOLD=8.0

# Exit codes
readonly EXIT_OK=0
readonly EXIT_WARNING=1
readonly EXIT_CRITICAL=2
readonly EXIT_UNKNOWN=3

# State
OVERALL_STATUS=$EXIT_OK
CHECKS_PASSED=0
CHECKS_FAILED=0

# =============================================================================
# Logging Functions
# =============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" 2>/dev/null || true
}

info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; echo -e "${YELLOW}⚠️  $*${NC}"; }
error() { log "ERROR" "$@"; echo -e "${RED}❌ $*${NC}"; }
success() { log "SUCCESS" "$@"; echo -e "${GREEN}✅ $*${NC}"; }

# =============================================================================
# Utility Functions
# =============================================================================

check_command() {
    command -v "$1" > /dev/null 2>&1
}

http_get() {
    local url="$1"
    local timeout="${2:-5}"
    curl -s -o /dev/null -w "%{http_code}" --max-time "$timeout" "$url" 2>/dev/null || echo "000"
}

# =============================================================================
# Health Check Functions
# =============================================================================

check_system_resources() {
    info "Checking system resources..."
    
    # Check disk usage
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    
    if [[ "$disk_usage" -ge "$DISK_CRITICAL_THRESHOLD" ]]; then
        error "Disk usage critical: ${disk_usage}%"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    elif [[ "$disk_usage" -ge "$DISK_WARNING_THRESHOLD" ]]; then
        warn "Disk usage high: ${disk_usage}%"
        [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
        ((CHECKS_FAILED++)) || true
    else
        success "Disk usage OK: ${disk_usage}%"
        ((CHECKS_PASSED++)) || true
    fi
    
    # Check memory usage
    local memory_usage
    memory_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
    
    if [[ "$memory_usage" -ge "$MEMORY_CRITICAL_THRESHOLD" ]]; then
        error "Memory usage critical: ${memory_usage}%"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    elif [[ "$memory_usage" -ge "$MEMORY_WARNING_THRESHOLD" ]]; then
        warn "Memory usage high: ${memory_usage}%"
        [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
        ((CHECKS_FAILED++)) || true
    else
        success "Memory usage OK: ${memory_usage}%"
        ((CHECKS_PASSED++)) || true
    fi
    
    # Check load average
    local load_avg
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    if (( $(echo "$load_avg > $LOAD_CRITICAL_THRESHOLD" | bc -l) )); then
        error "Load average critical: $load_avg"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    elif (( $(echo "$load_avg > $LOAD_WARNING_THRESHOLD" | bc -l) )); then
        warn "Load average high: $load_avg"
        [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
        ((CHECKS_FAILED++)) || true
    else
        success "Load average OK: $load_avg"
        ((CHECKS_PASSED++)) || true
    fi
}

check_tsn_service() {
    info "Checking TSN service status..."
    
    if check_command systemctl; then
        if systemctl is-active --quiet tsn-node 2>/dev/null; then
            success "TSN service is running"
            ((CHECKS_PASSED++)) || true
        else
            error "TSN service is not running"
            OVERALL_STATUS=$EXIT_CRITICAL
            ((CHECKS_FAILED++)) || true
        fi
    else
        # Check if process is running
        if pgrep -f "tsn-node" > /dev/null 2>&1; then
            success "TSN process is running"
            ((CHECKS_PASSED++)) || true
        else
            error "TSN process is not running"
            OVERALL_STATUS=$EXIT_CRITICAL
            ((CHECKS_FAILED++)) || true
        fi
    fi
}

check_api_endpoint() {
    info "Checking API endpoint..."
    
    local http_code
    http_code=$(http_get "http://localhost:${API_PORT}/health")
    
    if [[ "$http_code" == "200" ]]; then
        success "API health endpoint OK (HTTP $http_code)"
        ((CHECKS_PASSED++)) || true
    else
        error "API health endpoint failed (HTTP $http_code)"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    fi
}

check_p2p_connectivity() {
    info "Checking P2P connectivity..."
    
    # Check if P2P port is listening
    if check_command ss; then
        if ss -tlnp | grep -q ":${P2P_PORT}"; then
            success "P2P port ${P2P_PORT} is listening"
            ((CHECKS_PASSED++)) || true
        else
            error "P2P port ${P2P_PORT} is not listening"
            OVERALL_STATUS=$EXIT_CRITICAL
            ((CHECKS_FAILED++)) || true
        fi
    elif check_command netstat; then
        if netstat -tlnp 2>/dev/null | grep -q ":${P2P_PORT}"; then
            success "P2P port ${P2P_PORT} is listening"
            ((CHECKS_PASSED++)) || true
        else
            error "P2P port ${P2P_PORT} is not listening"
            OVERALL_STATUS=$EXIT_CRITICAL
            ((CHECKS_FAILED++)) || true
        fi
    else
        warn "Cannot check P2P port (ss/netstat not available)"
    fi
}

check_blockchain_sync() {
    info "Checking blockchain sync status..."
    
    local http_code
    http_code=$(http_get "http://localhost:${API_PORT}/api/v1/sync/status")
    
    if [[ "$http_code" == "200" ]]; then
        # Try to get sync status
        local sync_response
        sync_response=$(curl -s --max-time 5 "http://localhost:${API_PORT}/api/v1/sync/status" 2>/dev/null || echo "{}")
        
        # Check if fully synced (simplified check)
        if echo "$sync_response" | grep -q '"synced":true' 2>/dev/null; then
            success "Blockchain is fully synced"
            ((CHECKS_PASSED++)) || true
        else
            warn "Blockchain sync in progress"
            [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
            ((CHECKS_FAILED++)) || true
        fi
    else
        error "Cannot check sync status (HTTP $http_code)"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    fi
}

check_metrics_endpoint() {
    info "Checking metrics endpoint..."
    
    local http_code
    http_code=$(http_get "http://localhost:${METRICS_PORT}/metrics")
    
    if [[ "$http_code" == "200" ]]; then
        success "Metrics endpoint OK (HTTP $http_code)"
        ((CHECKS_PASSED++)) || true
    else
        warn "Metrics endpoint not available (HTTP $http_code)"
        [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
        ((CHECKS_FAILED++)) || true
    fi
}

check_log_errors() {
    info "Checking for recent errors in logs..."
    
    local error_count
    error_count=$(journalctl -u tsn-node --since "1 hour ago" --no-pager 2>/dev/null | grep -c "ERROR" || echo "0")
    
    if [[ "$error_count" -eq 0 ]]; then
        success "No errors in last hour"
        ((CHECKS_PASSED++)) || true
    elif [[ "$error_count" -lt 10 ]]; then
        warn "Found $error_count errors in last hour"
        [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
        ((CHECKS_FAILED++)) || true
    else
        error "Found $error_count errors in last hour"
        OVERALL_STATUS=$EXIT_CRITICAL
        ((CHECKS_FAILED++)) || true
    fi
}

check_network_time() {
    info "Checking network time synchronization..."
    
    if check_command timedatectl; then
        if timedatectl status | grep -q "NTP synchronized: yes"; then
            success "NTP synchronized"
            ((CHECKS_PASSED++)) || true
        else
            warn "NTP not synchronized"
            [[ $OVERALL_STATUS -lt $EXIT_WARNING ]] && OVERALL_STATUS=$EXIT_WARNING
            ((CHECKS_FAILED++)) || true
        fi
    else
        warn "Cannot check NTP status"
    fi
}

# =============================================================================
# Main Function
# =============================================================================

main() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           TSN Node Health Check                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    info "Starting health check at $(date)"
    
    # Run all checks
    check_system_resources
    check_tsn_service
    check_api_endpoint
    check_p2p_connectivity
    check_blockchain_sync
    check_metrics_endpoint
    check_log_errors
    check_network_time
    
    # Summary
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo "Health Check Summary:"
    echo "  Checks passed: $CHECKS_PASSED"
    echo "  Checks failed: $CHECKS_FAILED"
    echo ""
    
    case $OVERALL_STATUS in
        $EXIT_OK)
            success "Overall status: HEALTHY"
            ;;
        $EXIT_WARNING)
            warn "Overall status: WARNING"
            ;;
        $EXIT_CRITICAL)
            error "Overall status: CRITICAL"
            ;;
        *)
            echo -e "${YELLOW}Overall status: UNKNOWN${NC}"
            OVERALL_STATUS=$EXIT_UNKNOWN
            ;;
    esac
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    
    info "Health check completed with status $OVERALL_STATUS"
    
    exit $OVERALL_STATUS
}

# =============================================================================
# Script Entry Point
# =============================================================================

# Create log directory if needed
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Run main function
main "$@"
