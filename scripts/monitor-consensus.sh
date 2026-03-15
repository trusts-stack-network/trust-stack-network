#!/bin/bash
set -euo pipefail

# =============================================================================
# Script de monitoring du consensus TSN
# =============================================================================
# Ce script surveille les métriques de performance du consensus et alerte
# en cas de problèmes détectés, notamment le bug "Invalid commitment root".
#
# Usage:
#   ./scripts/monitor-consensus.sh [OPTIONS]
#
# Options:
#   --metrics-url URL    URL du serveur de métriques (défaut: http://localhost:9090)
#   --interval SECONDS   Intervalle de vérification (défaut: 30)
#   --alert-webhook URL  Webhook pour les alertes (optionnel)
#   --log-file FILE      Fichier de log (défaut: /tmp/tsn-monitor.log)
#   --daemon             Lancer en mode daemon
#   --help               Afficher cette aide
#
# Auteur: Yuki.T (Release & DevOps Engineer)
# =============================================================================

# Configuration par défaut
METRICS_URL="${TSN_METRICS_URL:-http://localhost:9090}"
CHECK_INTERVAL="${TSN_MONITOR_INTERVAL:-30}"
ALERT_WEBHOOK="${TSN_ALERT_WEBHOOK:-}"
LOG_FILE="${TSN_MONITOR_LOG:-/tmp/tsn-monitor.log}"
DAEMON_MODE=false

# Seuils d'alerte
BLOCK_VALIDATION_FAILURE_THRESHOLD=5
COMMITMENT_ROOT_ERROR_THRESHOLD=3
CHAIN_REORG_DEPTH_THRESHOLD=6
MEMPOOL_SIZE_THRESHOLD=1000
BLOCK_INTERVAL_THRESHOLD=300  # 5 minutes

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction d'aide
show_help() {
    cat << EOF
Script de monitoring du consensus TSN

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --metrics-url URL      URL du serveur de métriques (défaut: $METRICS_URL)
    --interval SECONDS     Intervalle de vérification (défaut: $CHECK_INTERVAL)
    --alert-webhook URL    Webhook pour les alertes
    --log-file FILE        Fichier de log (défaut: $LOG_FILE)
    --daemon               Lancer en mode daemon
    --help                 Afficher cette aide

EXEMPLES:
    # Vérification unique
    $0

    # Monitoring continu avec alertes
    $0 --daemon --alert-webhook https://hooks.slack.com/...

    # Monitoring avec intervalle personnalisé
    $0 --interval 60 --daemon

MÉTRIQUES SURVEILLÉES:
    - Erreurs de validation de blocs
    - Erreurs "Invalid commitment root"
    - Réorganisations de chaîne profondes
    - Taille excessive du mempool
    - Intervalles entre blocs anormaux
    - Performance générale du consensus

EOF
}

# Parsing des arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --metrics-url)
            METRICS_URL="$2"
            shift 2
            ;;
        --interval)
            CHECK_INTERVAL="$2"
            shift 2
            ;;
        --alert-webhook)
            ALERT_WEBHOOK="$2"
            shift 2
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --daemon)
            DAEMON_MODE=true
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            echo "Option inconnue: $1"
            show_help
            exit 1
            ;;
    esac
done

# Fonction de logging
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "$@"
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_warn() {
    log "WARN" "$@"
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    log "ERROR" "$@"
    echo -e "${RED}[ERROR]${NC} $*"
}

log_success() {
    log "SUCCESS" "$@"
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

# Fonction pour envoyer une alerte
send_alert() {
    local severity=$1
    local title=$2
    local message=$3
    
    if [[ -n "$ALERT_WEBHOOK" ]]; then
        local payload=$(cat << EOF
{
    "text": "🚨 TSN Consensus Alert",
    "attachments": [
        {
            "color": "$([[ $severity == "critical" ]] && echo "danger" || echo "warning")",
            "title": "$title",
            "text": "$message",
            "footer": "TSN Monitoring",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        if curl -s -X POST -H "Content-Type: application/json" \
           -d "$payload" "$ALERT_WEBHOOK" > /dev/null; then
            log_info "Alerte envoyée: $title"
        else
            log_error "Échec envoi alerte: $title"
        fi
    fi
}

# Fonction pour récupérer une métrique
get_metric() {
    local metric_name=$1
    local value=$(curl -s "$METRICS_URL/metrics?format=json" | \
                  jq -r ".metrics.${metric_name} // 0" 2>/dev/null)
    
    if [[ "$value" == "null" || -z "$value" ]]; then
        echo "0"
    else
        echo "$value"
    fi
}

# Fonction pour vérifier la connectivité
check_metrics_server() {
    if ! curl -s --max-time 5 "$METRICS_URL/health" > /dev/null; then
        log_error "Impossible de contacter le serveur de métriques: $METRICS_URL"
        return 1
    fi
    return 0
}

# Fonction principale de vérification
check_consensus_health() {
    log_info "Début vérification santé consensus..."
    
    # Vérifier la connectivité
    if ! check_metrics_server; then
        send_alert "critical" "Serveur de métriques inaccessible" \
                   "Le serveur de métriques TSN à $METRICS_URL est inaccessible"
        return 1
    fi
    
    local alerts_count=0
    
    # 1. Vérifier les erreurs de validation de blocs
    local blocks_rejected=$(get_metric "blocks_rejected_total")
    local blocks_validated=$(get_metric "blocks_validated_total")
    
    if [[ $blocks_validated -gt 0 ]]; then
        local rejection_rate=$((blocks_rejected * 100 / (blocks_validated + blocks_rejected)))
        if [[ $rejection_rate -gt $BLOCK_VALIDATION_FAILURE_THRESHOLD ]]; then
            log_warn "Taux de rejet de blocs élevé: ${rejection_rate}%"
            send_alert "warning" "Taux de rejet de blocs élevé" \
                       "Taux de rejet: ${rejection_rate}% (seuil: ${BLOCK_VALIDATION_FAILURE_THRESHOLD}%)"
            ((alerts_count++))
        fi
    fi
    
    # 2. Vérifier les erreurs "Invalid commitment root"
    local commitment_errors=$(get_metric "invalid_commitment_root_errors")
    if [[ $commitment_errors -gt $COMMITMENT_ROOT_ERROR_THRESHOLD ]]; then
        log_error "Erreurs 'Invalid commitment root' détectées: $commitment_errors"
        send_alert "critical" "Bug Invalid Commitment Root" \
                   "Nombre d'erreurs: $commitment_errors (seuil: $COMMITMENT_ROOT_ERROR_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 3. Vérifier les réorganisations de chaîne
    local last_reorg_depth=$(get_metric "last_reorg_depth")
    if [[ $last_reorg_depth -gt $CHAIN_REORG_DEPTH_THRESHOLD ]]; then
        log_warn "Réorganisation de chaîne profonde détectée: $last_reorg_depth blocs"
        send_alert "warning" "Réorganisation de chaîne profonde" \
                   "Profondeur: $last_reorg_depth blocs (seuil: $CHAIN_REORG_DEPTH_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 4. Vérifier la taille du mempool
    local mempool_size=$(get_metric "mempool_size")
    if [[ $mempool_size -gt $MEMPOOL_SIZE_THRESHOLD ]]; then
        log_warn "Mempool surchargé: $mempool_size transactions"
        send_alert "warning" "Mempool surchargé" \
                   "Taille: $mempool_size transactions (seuil: $MEMPOOL_SIZE_THRESHOLD)"
        ((alerts_count++))
    fi
    
    # 5. Afficher un résumé des métriques importantes
    local chain_height=$(get_metric "chain_height")
    local forks_detected=$(get_metric "forks_detected_total")
    local orphan_blocks=$(get_metric "orphan_blocks_count")
    local zk_proofs_validated=$(get_metric "zk_proofs_validated_total")
    
    log_info "=== Résumé des métriques ==="
    log_info "Hauteur de chaîne: $chain_height"
    log_info "Blocs validés: $blocks_validated"
    log_info "Blocs rejetés: $blocks_rejected"
    log_info "Erreurs commitment root: $commitment_errors"
    log_info "Forks détectés: $forks_detected"
    log_info "Blocs orphelins: $orphan_blocks"
    log_info "Preuves ZK validées: $zk_proofs_validated"
    log_info "Taille mempool: $mempool_size"
    log_info "============================"
    
    if [[ $alerts_count -eq 0 ]]; then
        log_success "Consensus en bonne santé - aucune alerte"
    else
        log_warn "Consensus: $alerts_count alerte(s) détectée(s)"
    fi
    
    return $alerts_count
}

# Fonction pour le mode daemon
run_daemon() {
    log_info "Démarrage du monitoring en mode daemon (intervalle: ${CHECK_INTERVAL}s)"
    
    # Créer un fichier PID
    local pid_file="/tmp/tsn-monitor.pid"
    echo $$ > "$pid_file"
    
    # Gestionnaire de signal pour arrêt propre
    trap 'log_info "Arrêt du monitoring daemon"; rm -f "$pid_file"; exit 0' SIGTERM SIGINT
    
    while true; do
        check_consensus_health
        sleep "$CHECK_INTERVAL"
    done
}

# Point d'entrée principal
main() {
    log_info "Démarrage du monitoring TSN Consensus"
    log_info "URL métriques: $METRICS_URL"
    log_info "Fichier log: $LOG_FILE"
    
    # Créer le répertoire de log si nécessaire
    mkdir -p "$(dirname "$LOG_FILE")"
    
    if [[ "$DAEMON_MODE" == "true" ]]; then
        run_daemon
    else
        check_consensus_health
        exit $?
    fi
}

# Vérifications préalables
if ! command -v curl &> /dev/null; then
    log_error "curl n'est pas installé"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    log_error "jq n'est pas installé"
    exit 1
fi

# Lancer le script principal
main "$@"