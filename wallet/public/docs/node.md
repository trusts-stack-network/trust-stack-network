# 🏗️ Guide Déploiement Node TSN

Guide complet pour installer, configurer et déployer un nœud Trust Stack Network.

## 📋 Prérequis

### Matériel recommandé

| Composant | Minimum | Recommandé | Optimal |
|-----------|---------|------------|---------|
| **CPU** | 2 cores 2.0 GHz | 4 cores 3.0 GHz | 8+ cores 3.5+ GHz |
| **RAM** | 4 GB | 8 GB | 16+ GB |
| **Stockage** | 20 GB SSD | 100 GB NVMe | 500+ GB NVMe |
| **Réseau** | 10 Mbps | 100 Mbps | 1 Gbps |

### Logiciels requis

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential curl git

# Installation Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup default stable
```

## 🚀 Installation rapide

### 1. Cloner et compiler

```bash
# Cloner le repository
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn

# Compiler en mode release (optimisé)
cargo build --release

# Vérifier l'installation
./target/release/tsn --version
```

### 2. Configuration de base

```bash
# Créer le répertoire de données
mkdir -p ~/.tsn/data

# Générer la configuration par défaut
./target/release/tsn node --help
```

## 🎯 Types de nœuds

TSN propose 4 types de nœuds selon vos besoins :

### 🔵 Light Node (Usage personnel)

**Pour** : Portefeuilles, applications légères
**Ressources** : Minimales (2 GB RAM, 10 GB disque)

```bash
# Démarrer un light node
./target/release/tsn node --role light --port 8333

# Avec répertoire de données custom
./target/release/tsn node --role light \
    --data-dir ~/.tsn/light \
    --port 8334
```

**Fonctionnalités** :
- ✅ Synchronisation des headers de blocs seulement
- ✅ Vérification des preuves ZK reçues
- ✅ Envoi/réception de transactions
- ❌ Pas de minage
- ❌ Ne stocke pas la blockchain complète

### ⛏️ Miner Node (Mining + revenue)

**Pour** : Mineurs cherchant des récompenses
**Ressources** : Moyennes (8 GB RAM, 100 GB disque)

```bash
# Créer un wallet pour les récompenses
./target/release/tsn new-wallet --output miner-wallet.json

# Démarrer le mining (4 threads)
./target/release/tsn node --role miner \
    --mine miner-wallet.json \
    --jobs 4 \
    --port 8333
```

**Fonctionnalités** :
- ✅ Synchronisation complète de la blockchain
- ✅ Minage de nouveaux blocs
- ✅ Récompenses de bloc (50 TSN actuellement)
- ✅ Validation des transactions
- ✅ Relais des blocs vers autres nœuds

### 🌐 Relay Node (Infrastructure réseau)

**Pour** : Soutenir le réseau, relais robuste
**Ressources** : Élevées (16 GB RAM, 500 GB disque)

```bash
# Node relay avec URL publique
./target/release/tsn node --role relay \
    --port 8333 \
    --public-url https://relay.mondomaine.com \
    --data-dir /opt/tsn/data
```

**Fonctionnalités** :
- ✅ Stockage complet de la blockchain
- ✅ Pas de minage (focus sur la stabilité)
- ✅ Relais haute performance
- ✅ Point d'entrée pour autres nœuds
- ✅ APIs REST complètes

### 🔬 Prover Node (Vérification maximale)

**Pour** : Auditeurs, recherche, vérification complète
**Ressources** : Maximales (32 GB RAM, 1 TB disque)

```bash
# Node prover avec vérification complète
./target/release/tsn node --role prover \
    --full-verify \
    --port 8333 \
    --data-dir /opt/tsn/prover-data
```

**Fonctionnalités** :
- ✅ Vérification complète des preuves ZK depuis genèse
- ✅ Validation cryptographique maximum
- ✅ APIs étendues pour audit
- ✅ Métriques détaillées
- ⚠️ Très intensif en CPU/RAM

## ⚙️ Configuration avancée

### Variables d'environnement

```bash
# Configuration par env vars
export TSN_PORT=8333
export TSN_DATA_DIR=/opt/tsn/data
export TSN_LOG_LEVEL=info
export TSN_PEERS="peer1.example.com:8333,peer2.example.com:8333"

# Démarrer avec config env
./target/release/tsn node
```

### Fichier de configuration

Créer `~/.tsn/config.toml` :

```toml
[network]
port = 8333
peers = [
    "seed1.tsnchain.com:8333",
    "seed2.tsnchain.com:8333"
]
max_peers = 50

[mining]
enabled = true
wallet_file = "wallet.json"
threads = 4
simd_mode = "neon"  # Sur ARM64

[storage]
data_dir = "/opt/tsn/data"
cache_size_mb = 1024

[logging]
level = "info"
file = "/var/log/tsn.log"

[faucet]
enabled = false
wallet_file = "faucet-wallet.json"
daily_limit = 50
```

### Optimisations performance

```bash
# Mode SIMD sur ARM64 (Raspberry Pi, M1/M2)
./target/release/tsn node --mine wallet.json --simd neon

# Fast sync (sync rapide depuis snapshot)
./target/release/tsn node --fast-sync

# Plus de threads mining
./target/release/tsn node --mine wallet.json --jobs 8

# Désactiver les seeds (node isolé)
./target/release/tsn node --no-seeds --force-mine
```

## 🔧 Gestion du service

### Systemd (Linux)

Créer `/etc/systemd/system/tsn.service` :

```ini
[Unit]
Description=TSN Node
After=network.target

[Service]
Type=simple
User=tsn
WorkingDirectory=/opt/tsn
ExecStart=/opt/tsn/target/release/tsn node --role miner --mine /opt/tsn/wallet.json
Restart=on-failure
RestartSec=10
Environment=TSN_DATA_DIR=/opt/tsn/data
Environment=TSN_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Activer et démarrer
sudo systemctl enable tsn
sudo systemctl start tsn
sudo systemctl status tsn

# Logs
sudo journalctl -u tsn -f
```

### Docker

```dockerfile
# Dockerfile
FROM rust:1.75-slim as builder

WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tsn /usr/local/bin/
EXPOSE 8333
CMD ["tsn", "node", "--role", "relay"]
```

```bash
# Build et run
docker build -t tsn:latest .
docker run -d \
    -p 8333:8333 \
    -v tsn-data:/root/.tsn \
    --name tsn-node \
    tsn:latest
```

## 📊 Monitoring

### Health check

```bash
# Vérifier l'état du node
curl http://localhost:8333/health

# Informations blockchain
curl http://localhost:8333/chain/info

# Statistiques mining
curl http://localhost:8333/mining/stats
```

### Métriques importantes

```bash
# Hauteur de la blockchain locale
curl http://localhost:8333/chain/height

# Nombre de peers connectés
curl http://localhost:8333/network/peers

# Hashrate mining
curl http://localhost:8333/mining/hashrate

# Usage mémoire
curl http://localhost:8333/system/memory
```

## 🚨 Troubleshooting

### Problèmes courants

**Sync lente** :
```bash
# Utiliser fast sync
./target/release/tsn node --fast-sync

# Vérifier les peers
curl http://localhost:8333/network/peers
```

**Pas de connexion peers** :
```bash
# Ajouter peers manuellement
./target/release/tsn node --peer seed1.tsnchain.com:8333

# Debug réseau
./target/release/tsn node --log-level debug
```

**Mining ne démarre pas** :
```bash
# Solo mining pour test
./target/release/tsn node --force-mine --mine wallet.json

# Vérifier le wallet
./target/release/tsn balance --wallet wallet.json
```

## 🔐 Sécurité

### Pare-feu

```bash
# Ubuntu/Debian ufw
sudo ufw allow 8333/tcp
sudo ufw enable

# CentOS/RHEL firewalld
sudo firewall-cmd --add-port=8333/tcp --permanent
sudo firewall-cmd --reload
```

### Backup du wallet

```bash
# Backup automatique quotidien
echo "0 2 * * * cp /opt/tsn/wallet.json /opt/tsn/backups/wallet-$(date +\%Y\%m\%d).json" | crontab -
```

### SSL/TLS (nginx)

```nginx
server {
    listen 443 ssl;
    server_name node.mondomaine.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8333;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## 🌐 Déploiement production

### VPS Cloud

**Configuration recommandée** :
- 4 vCPU, 8 GB RAM, 100 GB SSD
- Ubuntu 22.04 LTS
- Ports 8333 (TSN), 22 (SSH), 80/443 (HTTP/S)

**Providers testés** :
- DigitalOcean (Droplet Premium Intel)
- AWS (t3.large)
- Hetzner Cloud (CX31)

### Haute disponibilité

```bash
# Load balancer avec HAProxy
backend tsn_nodes
    balance roundrobin
    server node1 10.0.1.10:8333 check
    server node2 10.0.1.11:8333 check
    server node3 10.0.1.12:8333 check
```

---

*Guide Node TSN v0.4.0 • Mis à jour Mars 2026*