#!/bin/bash
set -euo pipefail

# Générateur de configuration Prometheus pour TSN
# Usage: ./scripts/generate-prometheus-config.sh [output_file] [nodes_file]

OUTPUT_FILE=${1:-"scripts/prometheus-consensus.yml"}
NODES_FILE=${2:-"scripts/tsn-nodes.txt"}
SCRIPT_DIR="$(dirname "$0")"

echo "🔧 Génération de la configuration Prometheus pour TSN"
echo "   Output: $OUTPUT_FILE"
echo "   Nodes: $NODES_FILE"

# Créer le fichier de nœuds par défaut s'il n'existe pas
if [[ ! -f "$NODES_FILE" ]]; then
    echo "📝 Création du fichier de nœuds par défaut: $NODES_FILE"
    cat > "$NODES_FILE" << 'EOF'
# Liste des nœuds TSN (format: hostname:port ou ip:port)
# Un nœud par ligne, lignes vides et # ignorées
localhost:9944
127.0.0.1:9944
EOF
fi

# Lire les nœuds depuis le fichier
echo "📖 Lecture des nœuds depuis $NODES_FILE"
NODES=()
while IFS= read -r line; do
    # Ignorer les lignes vides et commentaires
    if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
        NODES+=("$line")
    fi
done < "$NODES_FILE"

if [[ ${#NODES[@]} -eq 0 ]]; then
    echo "❌ Aucun nœud trouvé dans $NODES_FILE"
    exit 1
fi

echo "✅ ${#NODES[@]} nœuds détectés: ${NODES[*]}"

# Générer la configuration Prometheus
echo "🏗️  Génération de la configuration..."
cat > "$OUTPUT_FILE" << 'EOF'
# Configuration Prometheus pour métriques de consensus TSN
# Générée automatiquement - NE PAS MODIFIER MANUELLEMENT
# Utilisez scripts/generate-prometheus-config.sh pour régénérer

global:
  scrape_interval: 5s      # Fréquence élevée pour consensus
  evaluation_interval: 5s  # Évaluation des règles
  external_labels:
    cluster: 'tsn-mainnet'
    environment: 'production'
    generated_at: 'TIMESTAMP_PLACEHOLDER'

# Configuration des règles d'alerte
rule_files:
  - "consensus_alerts.yml"

# Configuration de scraping
scrape_configs:
  # Nœuds TSN - métriques de consensus
  - job_name: 'tsn-consensus'
    scrape_interval: 2s  # Très fréquent pour consensus
    scrape_timeout: 10s
    metrics_path: '/metrics'
    static_configs:
      - targets:
EOF

# Ajouter les targets de consensus
for node in "${NODES[@]}"; do
    echo "          - '$node'" >> "$OUTPUT_FILE"
done

cat >> "$OUTPUT_FILE" << 'EOF'
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
      - source_labels: [__address__]
        regex: '([^:]+):(.*)'
        target_label: node_name
        replacement: '${1}'
      - source_labels: [__address__]
        regex: '([^:]+):(.*)'
        target_label: node_port
        replacement: '${2}'

  # Métriques système des nœuds (Node Exporter)
  - job_name: 'tsn-system'
    scrape_interval: 10s
    scrape_timeout: 5s
    static_configs:
      - targets:
EOF

# Ajouter les targets système (port 9100 pour node_exporter)
for node in "${NODES[@]}"; do
    # Remplacer le port par 9100 pour node_exporter
    system_node=$(echo "$node" | sed 's/:[0-9]*$/:9100/')
    echo "          - '$system_node'" >> "$OUTPUT_FILE"
done

cat >> "$OUTPUT_FILE" << 'EOF'

  # Métriques réseau et P2P
  - job_name: 'tsn-network'
    scrape_interval: 5s
    scrape_timeout: 10s
    metrics_path: '/network/metrics'
    static_configs:
      - targets:
EOF

# Ajouter les targets réseau
for node in "${NODES[@]}"; do
    echo "          - '$node'" >> "$OUTPUT_FILE"
done

cat >> "$OUTPUT_FILE" << 'EOF'

  # Auto-discovery via file_sd (optionnel)
  - job_name: 'tsn-discovery'
    scrape_interval: 10s
    file_sd_configs:
      - files:
          - 'tsn-targets-*.json'
        refresh_interval: 30s

# Configuration d'alerting (optionnel)
alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - 'localhost:9093'  # Alertmanager local
EOF

# Remplacer le timestamp
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
sed -i "s/TIMESTAMP_PLACEHOLDER/$TIMESTAMP/" "$OUTPUT_FILE"

echo "✅ Configuration générée: $OUTPUT_FILE"
echo "📊 Targets configurés:"
echo "   - Consensus: ${#NODES[@]} nœuds"
echo "   - Système: ${#NODES[@]} nœuds (port 9100)"
echo "   - Réseau: ${#NODES[@]} nœuds"
echo ""
echo "🚀 Pour démarrer Prometheus:"
echo "   ./scripts/start-prometheus.sh"
echo ""
echo "📈 Interface web:"
echo "   http://localhost:9090"