#!/bin/bash
# Script de monitoring continu des nœuds TSN
# Trust Stack Network DevOps Automation
# Author: Yuki.T Release & DevOps Engineer

set -euo pipefail

# ===== CONFIGURATION =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration des nœuds
declare -A NODES=(
    ["node1"]="node1.tsn.network:8080"
    ["node2"]="node2.tsn.network:8080"
    ["node3"]="node3.tsn.network:8080"
    ["node4"]="node4.tsn.network:8080"
    ["node5"]="node5.tsn.network:8080"
)

# Configuration monitoring
MONITOR_INTERVAL="${MONITOR_INTERVAL:-30}"  # secondes
ALERT_THRESHOLD_CPU="${ALERT_THRESHOLD_CPU:-80}"  # %
ALERT_THRESHOLD_MEMORY="${ALERT_THRESHOLD_MEMORY:-85}"  # %
ALERT_THRESHOLD_DISK="${ALERT_THRESHOLD_DISK:-90}"  # %
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-10}"  # secondes
MAX_CONSECUTIVE_FAILURES="${MAX_CONSECUTIVE_FAILURES:-3}"

# Fichiers de state
STATE_DIR="${PROJECT_ROOT}/logs/monitoring"
ALERTS_LOG="${STATE_DIR}/alerts.log"
METRICS_LOG="${STATE_DIR}/metrics.log"
STATUS_FILE="${STATE_DIR}/status.json"

# Webhooks et notifications
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
EMAIL_ALERTS="${EMAIL_ALERTS:-false}"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ===== FONCTIONS UTILITAIRES =====
log() {
    local level="$1"
    shift
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $*" | tee -a "$ALERTS_LOG"
}

info() {
    log "INFO" "$@"
    echo -e "${BLUE}ℹ${NC} $*"
}

warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}⚠${NC} $*"
}

error() {
    log "ERROR" "$@"
    echo -e "${RED}✗${NC} $*"
}

success() {
    log "INFO" "$@"
    echo -e "${GREEN}✓${NC} $*"
}

# ===== INITIALISATION =====
init_monitoring() {
    info "Initialisation du monitoring TSN..."
    
    # Création des répertoires
    mkdir -p "$STATE_DIR"
    
    # Initialisation des fichiers de log
    touch "$ALERTS_LOG" "$METRICS_LOG"
    
    # Initialisation du status
    if [[ ! -f "$STATUS_FILE" ]]; then
        echo '{}' > "$STATUS_FILE"
    fi
    
    # Vérification des dépendances
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd n'est pas installé"
            exit 1
        fi
    done
    
    success "Monitoring initialisé"
}

# ===== VÉRIFICATIONS SANTÉ =====
check_node_health() {
    local node_name="$1"
    local node_url="$2"
    local health_data
    
    # Test de connectivité de base
    if ! curl -s --max-time "$HEALTH_CHECK_TIMEOUT" "http://$node_url/health" > /dev/null; then
        return 1
    fi
    
    # Récupération des données de santé
    health_data=$(curl -s --max-time "$HEALTH_CHECK_TIMEOUT" "http://$node_url/health" | jq -r '.' 2>/dev/null || echo '{}')
    
    # Vérification des champs critiques
    local status
    status=$(echo "$health_data" | jq -r '.status // "unknown"')
    
    if [[ "$status" != "healthy" && "$status" != "ok" ]]; then
        return 1
    fi
    
    echo "$health_data"
    return 0
}

# ===== MÉTRIQUES SYSTÈME =====
get_node_metrics() {
    local node_name="$1"
    local node_url="$2"
    local metrics_url="http://${node_url%:*}:9090/metrics"
    
    # Récupération des métriques Prometheus
    local metrics_data
    if ! metrics_data=$(curl -s --max-time "$HEALTH_CHECK_TIMEOUT" "$metrics_url" 2>/dev/null); then
        echo "{}"
        return 1
    fi
    
    # Parsing des métriques importantes
    local cpu_usage memory_usage disk_usage block_height peer_count
    
    cpu_usage=$(echo "$metrics_data" | grep "^process_cpu_seconds_total" | tail -1 | awk '{print $2}' || echo "0")
    memory_usage=$(echo "$metrics_data" | grep "^process_resident_memory_bytes" | tail -1 | awk '{print $2}' || echo "0")
    disk_usage=$(echo "$metrics_data" | grep "^tsn_storage_disk_usage_bytes" | tail -1 | awk '{print $2}' || echo "0")
    block_height=$(echo "$metrics_data" | grep "^tsn_blockchain_height" | tail -1 | awk '{print $2}' || echo "0")
    peer_count=$(echo "$metrics_data" | grep "^tsn_network_peers_connected" | tail -1 | awk '{print $2}' || echo "0")
    
    # Conversion en format JSON
    jq -n \
        --arg cpu "$cpu_usage" \
        --arg memory "$memory_usage" \
        --arg disk "$disk_usage" \
        --arg height "$block_height" \
        --arg peers "$peer_count" \
        '{
            cpu_usage: ($cpu | tonumber),
            memory_usage: ($memory | tonumber),
            disk_usage: ($disk | tonumber),
            block_height: ($height | tonumber),
            peer_count: ($peers | tonumber),
            timestamp: now
        }'
}

# ===== DÉTECTION D'ANOMALIES =====
detect_anomalies() {
    local node_name="$1"
    local health_data="$2"
    local metrics_data="$3"
    local anomalies=()
    
    # Vérification CPU
    local cpu_percent
    cpu_percent=$(echo "$metrics_data" | jq -r '.cpu_usage // 0')
    if (( $(echo "$cpu_percent > $ALERT_THRESHOLD_CPU" | bc -l) )); then
        anomalies+=("CPU élevé: ${cpu_percent}%")
    fi
    
    # Vérification mémoire
    local memory_mb
    memory_mb=$(echo "$metrics_data" | jq -r '.memory_usage // 0 | . / 1024 / 1024')
    local memory_percent
    memory_percent=$(echo "$memory_mb / 4096 * 100" | bc -l)  # Assumant 4GB de RAM
    if (( $(echo "$memory_percent > $ALERT_THRESHOLD_MEMORY" | bc -l) )); then
        anomalies+=("Mémoire élevée: ${memory_percent}%")
    fi
    
    # Vérification peers
    local peer_count
    peer_count=$(echo "$metrics_data" | jq -r '.peer_count // 0')
    if (( peer_count < 2 )); then
        anomalies+=("Peu de peers connectés: $peer_count")
    fi
    
    # Vérification synchronisation
    local block_height
    block_height=$(echo "$metrics_data" | jq -r '.block_height // 0')
    local expected_height
    expected_height=$(get_network_height)
    local height_diff
    height_diff=$((expected_height - block_height))
    
    if (( height_diff > 10 )); then
        anomalies+=("Désynchronisé: $height_diff blocs de retard")
    fi
    
    # Retourner les anomalies
    if [[ ${#anomalies[@]} -gt 0 ]]; then
        printf '%s\n' "${anomalies[@]}"
        return 1
    fi
    
    return 0
}

# ===== HAUTEUR RÉSEAU =====
get_network_height() {
    local max_height=0
    
    for node_url in "${NODES[@]}"; do
        local height
        if height=$(curl -s --max-time 5 "http://$node_url/api/v1/blocks/latest" | jq -r '.height // 0' 2>/dev/null); then
            if (( height > max_height )); then
                max_height=$height
            fi
        fi
    done
    
    echo "$max_height"
}

# ===== NOTIFICATIONS =====
send_alert() {
    local severity="$1"
    local node_name="$2"
    local message="$3"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    # Log local
    log "$severity" "[$node_name] $message"
    
    # Discord webhook
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        local color
        case "$severity" in
            "CRITICAL") color="16711680";;  # Rouge
            "WARNING") color="16776960";;   # Jaune
            *) color="65280";;              # Vert
        esac
        
        curl -s -H "Content-Type: application/json" \
            -d "{
                \"embeds\": [{
                    \"title\": \"TSN Alert - $severity\",
                    \"description\": \"**Nœud:** $node_name\\n**Message:** $message\",
                    \"color\": $color,
                    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
                }]
            }" \
            "$DISCORD_WEBHOOK" > /dev/null || true
    fi
    
    # Slack webhook
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        local emoji
        case "$severity" in
            "CRITICAL") emoji=":red_circle:";;
            "WARNING") emoji=":warning:";;
            *) emoji=":white_check_mark:";;
        esac
        
        curl -s -H "Content-Type: application/json" \
            -d "{
                \"text\": \"$emoji TSN Alert - $severity\",
                \"attachments\": [{
                    \"color\": \"$(case $severity in CRITICAL) echo danger;; WARNING) echo warning;; *) echo good;; esac)\",
                    \"fields\": [
                        {\"title\": \"Nœud\", \"value\": \"$node_name\", \"short\": true},
                        {\"title\": \"Message\", \"value\": \"$message\", \"short\": false}
                    ],
                    \"ts\": $(date +%s)
                }]
            }" \
            "$SLACK_WEBHOOK" > /dev/null || true
    fi
}

# ===== MONITORING PRINCIPAL =====
monitor_node() {
    local node_name="$1"
    local node_url="$2"
    local current_status
    
    # État précédent
    local previous_status
    previous_status=$(jq -r ".\"$node_name\".status // \"unknown\"" "$STATUS_FILE" 2>/dev/null || echo "unknown")
    local failure_count
    failure_count=$(jq -r ".\"$node_name\".consecutive_failures // 0" "$STATUS_FILE" 2>/dev/null || echo "0")
    
    # Vérification de santé
    local health_data
    if health_data=$(check_node_health "$node_name" "$node_url"); then
        # Nœud en bonne santé
        current_status="healthy"
        
        # Récupération des métriques
        local metrics_data
        metrics_data=$(get_node_metrics "$node_name" "$node_url")
        
        # Détection d'anomalies
        local anomalies
        if anomalies=$(detect_anomalies "$node_name" "$health_data" "$metrics_data"); then
            # Pas d'anomalies
            if [[ "$previous_status" != "healthy" ]]; then
                send_alert "INFO" "$node_name" "Nœud récupéré et fonctionne normalement"
            fi
            failure_count=0
        else
            # Anomalies détectées
            send_alert "WARNING" "$node_name" "Anomalies détectées: $anomalies"
            current_status="warning"
        fi
        
        # Log des métriques
        echo "$(date '+%Y-%m-%d %H:%M:%S') [$node_name] $metrics_data" >> "$METRICS_LOG"
        
    else
        # Nœud défaillant
        current_status="failed"
        failure_count=$((failure_count + 1))
        
        if [[ $failure_count -ge $MAX_CONSECUTIVE_FAILURES ]]; then
            if [[ "$previous_status" != "failed" ]]; then
                send_alert "CRITICAL" "$node_name" "Nœud défaillant après $failure_count tentatives"
            fi
        else
            send_alert "WARNING" "$node_name" "Échec de connexion ($failure_count/$MAX_CONSECUTIVE_FAILURES)"
        fi
        
        health_data="{}"
        metrics_data="{}"
    fi
    
    # Mise à jour du status
    local updated_status
    updated_status=$(jq \
        --arg node "$node_name" \
        --arg status "$current_status" \
        --arg failures "$failure_count" \
        --argjson health "$health_data" \
        --argjson metrics "$metrics_data" \
        ".\"$node\" = {
            status: $status,
            consecutive_failures: ($failures | tonumber),
            last_check: now,
            health_data: $health,
            metrics: $metrics
        }" \
        "$STATUS_FILE")
    
    echo "$updated_status" > "$STATUS_FILE"
    
    # Affichage status
    case "$current_status" in
        "healthy")
            success "$node_name: Sain"
            ;;
        "warning")
            warn "$node_name: Anomalies détectées"
            ;;
        "failed")
            error "$node_name: Défaillant ($failure_count échecs)"
            ;;
    esac
}

# ===== RAPPORT DE STATUS =====
generate_report() {
    local report_file="${STATE_DIR}/report_$(date +%Y%m%d_%H%M%S).json"
    
    # Statistiques globales
    local total_nodes=${#NODES[@]}
    local healthy_nodes
    healthy_nodes=$(jq '[.[] | select(.status == "healthy")] | length' "$STATUS_FILE")
    local warning_nodes
    warning_nodes=$(jq '[.[] | select(.status == "warning")] | length' "$STATUS_FILE")
    local failed_nodes
    failed_nodes=$(jq '[.[] | select(.status == "failed")] | length' "$STATUS_FILE")
    
    # Génération du rapport
    jq -n \
        --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg total "$total_nodes" \
        --arg healthy "$healthy_nodes" \
        --arg warning "$warning_nodes" \
        --arg failed "$failed_nodes" \
        --slurpfile nodes "$STATUS_FILE" \
        '{
            timestamp: $timestamp,
            summary: {
                total_nodes: ($total | tonumber),
                healthy_nodes: ($healthy | tonumber),
                warning_nodes: ($warning | tonumber),
                failed_nodes: ($failed | tonumber),
                health_percentage: (($healthy | tonumber) / ($total | tonumber) * 100)
            },
            nodes: $nodes[0]
        }' > "$report_file"
    
    info "Rapport généré: $report_file"
    
    # Affichage du résumé
    echo ""
    echo "=== RÉSUMÉ MONITORING TSN ==="
    echo "Total nœuds: $total_nodes"
    echo "Sains: $healthy_nodes"
    echo "Avertissements: $warning_nodes"
    echo "Défaillants: $failed_nodes"
    echo "Santé globale: $(echo "scale=1; $healthy_nodes * 100 / $total_nodes" | bc)%"
    echo ""
}

# ===== BOUCLE PRINCIPALE =====
monitoring_loop() {
    info "Démarrage du monitoring continu (intervalle: ${MONITOR_INTERVAL}s)"
    
    local iteration=0
    
    while true; do
        iteration=$((iteration + 1))
        info "=== Itération $iteration ==="
        
        # Monitoring de chaque nœud
        for node_name in "${!NODES[@]}"; do
            monitor_node "$node_name" "${NODES[$node_name]}"
        done
        
        # Génération de rapport périodique (toutes les 10 itérations)
        if (( iteration % 10 == 0 )); then
            generate_report
        fi
        
        # Attente avant prochaine itération
        sleep "$MONITOR_INTERVAL"
    done
}

# ===== FONCTIONS DE CONTRÔLE =====
show_status() {
    if [[ ! -f "$STATUS_FILE" ]]; then
        error "Aucun fichier de status trouvé. Lancez d'abord le monitoring."
        exit 1
    fi
    
    echo "=== STATUS ACTUEL DES NŒUDS TSN ==="
    jq -r '
        to_entries[] | 
        "Nœud: \(.key)
         Status: \(.value.status)
         Dernière vérification: \(.value.last_check | strftime("%Y-%m-%d %H:%M:%S"))
         Échecs consécutifs: \(.value.consecutive_failures)
         Hauteur bloc: \(.value.metrics.block_height // "N/A")
         Peers: \(.value.metrics.peer_count // "N/A")
         ---"
    ' "$STATUS_FILE"
}

# ===== AIDE =====
show_help() {
    cat << EOF
Monitoring des nœuds TSN

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    start       Démarrer le monitoring continu (défaut)
    status      Afficher le status actuel
    report      Générer un rapport
    test        Tester la connectivité une fois
    help        Afficher cette aide

OPTIONS:
    --interval SECONDS      Intervalle de monitoring (défaut: 30)
    --cpu-threshold PERCENT Seuil d'alerte CPU (défaut: 80)
    --mem-threshold PERCENT Seuil d'alerte mémoire (défaut: 85)
    --max-failures COUNT    Échecs max avant alerte critique (défaut: 3)

VARIABLES D'ENVIRONNEMENT:
    DISCORD_WEBHOOK         URL webhook Discord pour alertes
    SLACK_WEBHOOK          URL webhook Slack pour alertes
    EMAIL_ALERTS           Activer alertes email (true/false)

EXEMPLES:
    $0                      # Monitoring continu
    $0 status               # Afficher status
    $0 --interval 60        # Monitoring toutes les minutes
    $0 test                 # Test unique

FICHIERS:
    logs/monitoring/alerts.log      # Log des alertes
    logs/monitoring/metrics.log     # Log des métriques
    logs/monitoring/status.json     # Status actuel
EOF
}

# ===== FONCTION PRINCIPALE =====
main() {
    local command="start"
    
    # Parsing des arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|status|report|test|help)
                command="$1"
                shift
                ;;
            --interval)
                MONITOR_INTERVAL="$2"
                shift 2
                ;;
            --cpu-threshold)
                ALERT_THRESHOLD_CPU="$2"
                shift 2
                ;;
            --mem-threshold)
                ALERT_THRESHOLD_MEMORY="$2"
                shift 2
                ;;
            --max-failures)
                MAX_CONSECUTIVE_FAILURES="$2"
                shift 2
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                error "Option inconnue: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Initialisation
    init_monitoring
    
    # Exécution de la commande
    case "$command" in
        "start")
            monitoring_loop
            ;;
        "status")
            show_status
            ;;
        "report")
            generate_report
            ;;
        "test")
            for node_name in "${!NODES[@]}"; do
                monitor_node "$node_name" "${NODES[$node_name]}"
            done
            generate_report
            ;;
        "help")
            show_help
            ;;
        *)
            error "Commande inconnue: $command"
            exit 1
            ;;
    esac
}

# Trap pour cleanup
trap 'echo "Monitoring interrompu"; exit 130' INT TERM

# Point d'entrée
main "$@"