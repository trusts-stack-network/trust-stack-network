#!/bin/bash
# =============================================================================
# TSN Node Setup Script
# Idempotent deployment script for TSN nodes
# =============================================================================

set -euo pipefail

# Configuration
readonly TSN_VERSION="${TSN_VERSION:-latest}"
readonly TSN_NETWORK="${TSN_NETWORK:-mainnet}"
readonly TSN_DATA_DIR="${TSN_DATA_DIR:-/opt/tsn/data}"
readonly TSN_CONFIG_DIR="${TSN_CONFIG_DIR:-/opt/tsn/config}"
readonly TSN_LOG_DIR="${TSN_LOG_DIR:-/var/log/tsn}"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# Vérifications système
# =============================================================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_system() {
    log_info "Checking system requirements..."

    # Vérifier la mémoire (minimum 4GB)
    local mem_gb=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$mem_gb" -lt 4 ]; then
        log_warn "System has less than 4GB RAM ($mem_gb GB). Performance may be degraded."
    fi

    # Vérifier l'espace disque (minimum 50GB)
    local disk_gb=$(df -BG "$TSN_DATA_DIR" 2>/dev/null | awk 'NR==2{print $4}' | sed 's/G//') || disk_gb=0
    if [ "$disk_gb" -lt 50 ]; then
        log_warn "Less than 50GB free space available ($disk_gb GB)."
    fi

    log_info "System requirements checked ✓"
}

# =============================================================================
# Installation des dépendances
# =============================================================================

install_dependencies() {
    log_info "Installing system dependencies..."

    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y --no-install-recommends \
            ca-certificates \
            curl \
            jq \
            supervisor \
            logrotate \
            ufw
    elif command -v yum >/dev/null 2>&1; then
        yum update -y
        yum install -y \
            ca-certificates \
            curl \
            jq \
            supervisor \
            logrotate \
            firewalld
    else
        log_error "Unsupported package manager"
        exit 1
    fi

    log_info "Dependencies installed ✓"
}

# =============================================================================
# Création des répertoires
# =============================================================================

setup_directories() {
    log_info "Setting up directories..."

    # Créer les répertoires
    mkdir -p "$TSN_DATA_DIR" "$TSN_CONFIG_DIR" "$TSN_LOG_DIR"

    # Créer l'utilisateur tsn s'il n'existe pas
    if ! id -u tsn >/dev/null 2>&1; then
        useradd -r -s /bin/false -d "$TSN_DATA_DIR" tsn
    fi

    # Permissions
    chown -R tsn:tsn "$TSN_DATA_DIR" "$TSN_CONFIG_DIR"
    chmod 755 "$TSN_DATA_DIR" "$TSN_CONFIG_DIR"

    log_info "Directories configured ✓"
}

# =============================================================================
# Configuration du nœud
# =============================================================================

setup_config() {
    log_info "Setting up node configuration..."

    local config_file="$TSN_CONFIG_DIR/node.toml"

    # Générer la configuration si elle n'existe pas
    if [ ! -f "$config_file" ]; then
        cat > "$config_file" <<EOF
# TSN Node Configuration
# Generated: $(date -Iseconds)

[network]
network = "$TSN_NETWORK"
bind_address = "0.0.0.0:30303"
api_address = "0.0.0.0:8080"

# Bootstrap nodes
bootstrap_nodes = [
    "/dns4/seed-1.tsn.network/tcp/30303/p2p/12D3KooW...",
    "/dns4/seed-2.tsn.network/tcp/30303/p2p/12D3KooW...",
    "/dns4/seed-3.tsn.network/tcp/30303/p2p/12D3KooW...",
    "/dns4/seed-4.tsn.network/tcp/30303/p2p/12D3KooW..."
]

[consensus]
enabled = true
min_peers = 5
max_peers = 50

[storage]
data_dir = "$TSN_DATA_DIR"
cache_size_mb = 512

[logging]
level = "info"
file = "$TSN_LOG_DIR/tsn.log"
max_size_mb = 100
max_files = 5

[metrics]
enabled = true
address = "0.0.0.0:9090"
EOF

        chown tsn:tsn "$config_file"
        chmod 640 "$config_file"
    fi

    log_info "Configuration created ✓"
}

# =============================================================================
# Installation du binaire
# =============================================================================

install_binary() {
    log_info "Installing TSN binary..."

    local install_dir="/opt/tsn/bin"
    mkdir -p "$install_dir"

    if [ "$TSN_VERSION" = "latest" ]; then
        # Télécharger la dernière release
        local release_url="https://github.com/truststack/tsn/releases/latest/download/tsn-linux-x86_64"
        curl -fsSL -o "$install_dir/tsn" "$release_url" || {
            log_error "Failed to download TSN binary"
            exit 1
        }
    else
        # Télécharger une version spécifique
        local release_url="https://github.com/truststack/tsn/releases/download/v$TSN_VERSION/tsn-linux-x86_64"
        curl -fsSL -o "$install_dir/tsn" "$release_url" || {
            log_error "Failed to download TSN binary v$TSN_VERSION"
            exit 1
        }
    fi

    chmod +x "$install_dir/tsn"
    chown -R tsn:tsn "$install_dir"

    # Créer un lien symbolique
    ln -sf "$install_dir/tsn" /usr/local/bin/tsn

    log_info "Binary installed ✓"
}

# =============================================================================
# Configuration du service systemd
# =============================================================================

setup_systemd() {
    log_info "Setting up systemd service..."

    cat > /etc/systemd/system/tsn-node.service <<'EOF'
[Unit]
Description=TSN Node
After=network.target

[Service]
Type=simple
User=tsn
Group=tsn
WorkingDirectory=/opt/tsn
ExecStart=/opt/tsn/bin/tsn --config /opt/tsn/config/node.toml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=tsn-node

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/tsn/data /var/log/tsn
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable tsn-node

    log_info "Systemd service configured ✓"
}

# =============================================================================
# Configuration du firewall
# =============================================================================

setup_firewall() {
    log_info "Configuring firewall..."

    if command -v ufw >/dev/null 2>&1; then
        # UFW
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 8080/tcp comment 'TSN API'
        ufw allow 30303/tcp comment 'TSN P2P'
        ufw allow 30303/udp comment 'TSN P2P UDP'
        ufw allow 9090/tcp comment 'TSN Metrics'
        ufw --force enable
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # firewalld
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --permanent --add-port=30303/tcp
        firewall-cmd --permanent --add-port=30303/udp
        firewall-cmd --permanent --add-port=9090/tcp
        firewall-cmd --reload
    fi

    log_info "Firewall configured ✓"
}

# =============================================================================
# Configuration de logrotate
# =============================================================================

setup_logrotate() {
    log_info "Setting up log rotation..."

    cat > /etc/logrotate.d/tsn <<EOF
$TSN_LOG_DIR/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0644 tsn tsn
    sharedscripts
    postrotate
        /bin/kill -HUP \$(cat /var/run/rsyslogd.pid 2> /dev/null) 2> /dev/null || true
    endscript
}
EOF

    log_info "Log rotation configured ✓"
}

# =============================================================================
# Vérification de l'installation
# =============================================================================

verify_installation() {
    log_info "Verifying installation..."

    # Vérifier le binaire
    if [ ! -x "/opt/tsn/bin/tsn" ]; then
        log_error "Binary not found or not executable"
        exit 1
    fi

    # Vérifier la configuration
    if [ ! -f "$TSN_CONFIG_DIR/node.toml" ]; then
        log_error "Configuration file not found"
        exit 1
    fi

    # Vérifier le service
    if ! systemctl is-enabled tsn-node >/dev/null 2>&1; then
        log_error "Service not enabled"
        exit 1
    fi

    log_info "Installation verified ✓"
}

# =============================================================================
# Fonction principale
# =============================================================================

main() {
    echo "========================================"
    echo "TSN Node Setup"
    echo "========================================"
    echo ""

    check_root
    check_system
    install_dependencies
    setup_directories
    setup_config
    install_binary
    setup_systemd
    setup_firewall
    setup_logrotate
    verify_installation

    echo ""
    echo "========================================"
    log_info "TSN node setup complete!"
    echo ""
    echo "To start the node:"
    echo "  sudo systemctl start tsn-node"
    echo ""
    echo "To check status:"
    echo "  sudo systemctl status tsn-node"
    echo "  sudo journalctl -u tsn-node -f"
    echo ""
    echo "Configuration: $TSN_CONFIG_DIR/node.toml"
    echo "Data directory: $TSN_DATA_DIR"
    echo "Logs: $TSN_LOG_DIR"
    echo "========================================"
}

# Gestion des arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            TSN_VERSION="$2"
            shift 2
            ;;
        --network)
            TSN_NETWORK="$2"
            shift 2
            ;;
        --data-dir)
            TSN_DATA_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --version VERSION    TSN version to install (default: latest)"
            echo "  --network NETWORK    Network to join (default: mainnet)"
            echo "  --data-dir PATH      Data directory (default: /opt/tsn/data)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

main
