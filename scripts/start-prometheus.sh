#!/bin/bash
set -euo pipefail

# Script de démarrage Prometheus pour TSN
# Gère la génération de config, validation et démarrage

SCRIPT_DIR="$(dirname "$0")"
CONFIG_FILE="$SCRIPT_DIR/prometheus-consensus.yml"
ALERTS_FILE="$SCRIPT_DIR/consensus_alerts.yml"
DATA_DIR="$SCRIPT_DIR/../data/prometheus"
PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
PROMETHEUS_VERSION=${PROMETHEUS_VERSION:-"2.47.2"}

echo "🚀 Démarrage de Prometheus pour TSN"
echo "   Config: $CONFIG_FILE"
echo "   Alerts: $ALERTS_FILE"
echo "   Data: $DATA_DIR"
echo "   Port: $PROMETHEUS_PORT"

# Vérifier si Prometheus est installé
if ! command -v prometheus &> /dev/null; then
    echo "❌ Prometheus non trouvé. Installation automatique..."
    
    # Détecter l'architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) PROM_ARCH="amd64" ;;
        aarch64|arm64) PROM_ARCH="arm64" ;;
        *) echo "❌ Architecture non supportée: $ARCH"; exit 1 ;;
    esac
    
    # Télécharger et installer Prometheus
    PROM_URL="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/prometheus-${PROMETHEUS_VERSION}.linux-${PROM_ARCH}.tar.gz"
    TEMP_DIR=$(mktemp -d)
    
    echo "📥 Téléchargement de Prometheus $PROMETHEUS_VERSION pour $PROM_ARCH..."
    curl -L "$PROM_URL" | tar -xz -C "$TEMP_DIR" --strip-components=1
    
    # Installer dans /usr/local/bin
    sudo mv "$TEMP_DIR/prometheus" /usr/local/bin/
    sudo mv "$TEMP_DIR/promtool" /usr/local/bin/
    sudo chmod +x /usr/local/bin/prometheus /usr/local/bin/promtool
    
    rm -rf "$TEMP_DIR"
    echo "✅ Prometheus installé avec succès"
fi

# Générer la configuration si elle n'existe pas ou si forcé
if [[ ! -f "$CONFIG_FILE" ]] || [[ "${FORCE_REGEN:-false}" == "true" ]]; then
    echo "🔧 Génération de la configuration Prometheus..."
    "$SCRIPT_DIR/generate-prometheus-config.sh" "$CONFIG_FILE"
fi

# Vérifier que les fichiers de configuration existent
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Fichier de configuration manquant: $CONFIG_FILE"
    exit 1
fi

if [[ ! -f "$ALERTS_FILE" ]]; then
    echo "❌ Fichier d'alertes manquant: $ALERTS_FILE"
    exit 1
fi

# Valider la configuration avec promtool
echo "🔍 Validation de la configuration..."
if ! promtool check config "$CONFIG_FILE"; then
    echo "❌ Configuration Prometheus invalide"
    exit 1
fi

if ! promtool check rules "$ALERTS_FILE"; then
    echo "❌ Règles d'alerte invalides"
    exit 1
fi

echo "✅ Configuration validée"

# Créer le répertoire de données
mkdir -p "$DATA_DIR"

# Vérifier si Prometheus est déjà en cours d'exécution
if pgrep -f "prometheus.*$PROMETHEUS_PORT" > /dev/null; then
    echo "⚠️  Prometheus semble déjà en cours d'exécution sur le port $PROMETHEUS_PORT"
    echo "   Arrêt de l'instance existante..."
    pkill -f "prometheus.*$PROMETHEUS_PORT" || true
    sleep 2
fi

# Démarrer Prometheus
echo "🎯 Démarrage de Prometheus..."
prometheus \
    --config.file="$CONFIG_FILE" \
    --storage.tsdb.path="$DATA_DIR" \
    --web.listen-address="0.0.0.0:$PROMETHEUS_PORT" \
    --web.console.libraries=/usr/local/share/prometheus/console_libraries \
    --web.console.templates=/usr/local/share/prometheus/consoles \
    --storage.tsdb.retention.time=30d \
    --storage.tsdb.retention.size=10GB \
    --web.enable-lifecycle \
    --web.enable-admin-api \
    --log.level=info \
    --log.format=logfmt &

PROMETHEUS_PID=$!
echo "✅ Prometheus démarré (PID: $PROMETHEUS_PID)"
echo ""
echo "📊 Interface web disponible sur:"
echo "   http://localhost:$PROMETHEUS_PORT"
echo ""
echo "🎯 Targets configurés:"
echo "   http://localhost:$PROMETHEUS_PORT/targets"
echo ""
echo "📈 Métriques de consensus TSN:"
echo "   http://localhost:$PROMETHEUS_PORT/graph?g0.expr=tsn_consensus_blocks_processed_total"
echo ""
echo "🔍 Pour surveiller les logs:"
echo "   tail -f $DATA_DIR/prometheus.log"
echo ""
echo "⏹️  Pour arrêter Prometheus:"
echo "   kill $PROMETHEUS_PID"

# Attendre quelques secondes et vérifier que Prometheus démarre correctement
sleep 3
if ! kill -0 $PROMETHEUS_PID 2>/dev/null; then
    echo "❌ Prometheus n'a pas pu démarrer correctement"
    exit 1
fi

echo "🎉 Prometheus opérationnel !"

# Garder le script en vie si lancé en mode interactif
if [[ "${PROMETHEUS_DAEMON:-false}" == "false" ]]; then
    echo ""
    echo "Appuyez sur Ctrl+C pour arrêter Prometheus..."
    trap "echo '🛑 Arrêt de Prometheus...'; kill $PROMETHEUS_PID; exit 0" INT
    wait $PROMETHEUS_PID
fi