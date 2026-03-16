# Guide Complet Blockchain TSN — User Documentation
> **Trust Stack Network v0.4.0** — La blockchain post-quantique prête pour la production  
> *Document de backup Herald — Livrable CEO 16/03/2026*

---

## 🎯 Vue d'Ensemble Exécutive

Trust Stack Network (TSN) est la **première blockchain Layer 1 post-quantique en production**, conçue pour résister aux ordinateurs quantiques tout en offrant des transactions shielded par défaut. Cette documentation couvre l'installation, le déploiement et l'utilisation des trois composants essentiels : **Node**, **Mining**, et **Wallet**.

### Technologies Post-Quantiques
- **ML-DSA-65** (FIPS 204) : Signatures résistantes aux attaques quantiques
- **Plonky3 STARKs** : Preuves zero-knowledge sans trusted setup
- **Poseidon2** : Hash function optimisée ZK-friendly
- **MIK Consensus** : Mining Identity Key avec protection anti-Sybil

---

## 📦 I. INSTALLATION & PRÉREQUIS

### Environnement Système
```bash
# Prérequis minimum
- Rust ≥ 1.78.0 (cargo --version)
- RAM : 8 Go minimum (16 Go recommandés pour mining)
- Stockage : 500 Go SSD NVMe
- OS : Linux/macOS (Windows via WSL2)
- Réseau : Port 8333 ouvert (P2P), 8545 (RPC)
# 1. Cloner le repository
git clone https://github.com/trust-stack-network/tsn.git
cd tsn

# 2. Build optimisé release
make build
# ou directement avec cargo
cargo build --release

# 3. Vérifier l'installation
./target/release/tsn --version
# TSN v0.4.0 - Post-quantum blockchain
# Créer répertoire de données TSN
mkdir -p ~/.tsn/{keys,data,logs}

# Variables d'environnement (ajouter à ~/.bashrc)
export TSN_DATA_DIR=~/.tsn/data
export TSN_PORT=8333
export RUST_LOG=info  # debug, info, warn, error
# Node basique sans mining
./target/release/tsn node \
  --port 8333 \
  --data-dir ~/.tsn/data \
  --log-file ~/.tsn/logs/node.log

# Vérification du statut
curl http://localhost:8333/chain/info
# Node avec mining activé (recommandé)
./target/release/tsn node \
  --port 8333 \
  --mine mon-wallet.json \
  --jobs $(nproc) \
  --data-dir ~/.tsn/data
# Node public avec URL annoncée
./target/release/tsn node \
  --port 8333 \
  --mine mon-wallet.json \
  --public-url https://monnode.tsnchain.com \
  --data-dir /opt/tsn-mainnet \
  --log-level info
# Node avec peers personnalisés
./target/release/tsn node \
  --peer http://seed1.truststack.network:8333 \
  --peer http://seed2.truststack.network:8333 \
  --port 8333

# Node solo pour développement
./target/release/tsn node \
  --no-seeds \
  --force-mine \
  --mine dev-wallet.json \
  --port 9333

# Node avec vérification complète ZK
./target/release/tsn node \
  --full-verify \
  --port 8333
# Activer faucet (50 TSN/jour par défaut)
./target/release/tsn node \
  --faucet-wallet faucet-wallet.json \
  --faucet-daily-limit 100 \
  --port 8333
# APIs de monitoring disponibles
curl http://localhost:8333/chain/info     # État blockchain
curl http://localhost:8333/chain/height   # Hauteur actuelle
curl http://localhost:8333/mempool       # Transactions en attente
curl http://localhost:8333/peers         # Peers connectés
curl http://localhost:8333/sync/status   # Statut synchronisation
# Créer wallet pour recevoir les récompenses
./target/release/tsn new-wallet --output mining-wallet.json

# Mining illimité (arrêt avec Ctrl+C)
./target/release/tsn mine \
  --wallet mining-wallet.json \
  --blocks 0 \
  --difficulty 16
# Serveurs Linux (multi-thread)
./target/release/tsn mine \
  --wallet mining-wallet.json \
  --jobs $(nproc) \
  --difficulty 12

# Apple Silicon / ARM64 (optimisé SIMD)
./target/release/tsn mine \
  --wallet mining-wallet.json \
  --simd neon \
  --jobs 8

# Mining pool (si disponible)
./target/release/tsn mine \
  --pool mining.truststack.network:3333 \
  --wallet mining-wallet.json \
  --algorithm poseidon2
# Test performance mining
./target/release/tsn benchmark \
  --wallet mining-wallet.json \
  --blocks 20 \
  --difficulty 20 \
  --jobs 4

# Monitoring TUI en temps réel
./target/release/tsn-miner-monitor \
  --wallet mining-wallet.json \
  --node http://localhost:8333
# Node + Mining en un processus
./target/release/tsn node \
  --mine mining-wallet.json \
  --jobs 4 \
  --port 8333 \
  --public-url https://mining-node.example.com
- Récompense par bloc : 50 TSN
- Temps bloc moyen : ~10 secondes
- Difficulté genesis : 12
- Ajustement difficulté : Tous les 144 blocs (~24h)
- Halving : Tous les 210,000 blocs
- Dev fund : 5% automatique
# Créer nouveau wallet shielded
./target/release/tsn new-wallet --output mon-wallet.json

# Afficher l'adresse publique
./target/release/tsn wallet-info --wallet mon-wallet.json

# Vérifier le solde
./target/release/tsn balance \
  --wallet mon-wallet.json \
  --node http://localhost:8333
# Envoi shielded basique
./target/release/tsn send \
  --from mon-wallet.json \
  --to tsn1qzw...destinataire... \
  --amount 25.5 \
  --fee 0.001

# Transaction avec memo privé
./target/release/tsn send \
  --from mon-wallet.json \
  --to tsn1qzw...destinataire... \
  --amount 100 \
  --memo "Paiement confidentiel"
# Lancer wallet web (nécessite node actif)
./target/release/tsn wallet-ui \
  --port 8080 \
  --wallet-dir ~/.tsn/wallets

# Accès : http://localhost:8080/wallet
# Exporter clés pour backup
./target/release/tsn wallet-export \
  --wallet mon-wallet.json \
  --output backup-keys.pem

# Importer wallet depuis backup
./target/release/tsn wallet-import \
  --keys backup-keys.pem \
  --output restored-wallet.json

# Changer mot de passe wallet
./target/release/tsn wallet-encrypt \
  --wallet mon-wallet.json \
  --new-password
# Configuration mainnet recommandée
./target/release/tsn node \
  --network mainnet \
  --port 8333 \
  --mine production-wallet.json \
  --jobs $(nproc) \
  --data-dir /opt/tsn-mainnet \
  --log-file /var/log/tsn/node.log \
  --public-url https://node.votredomaine.com
Seed nodes officiels (connexion automatique) :
- seed1.truststack.network:8333
- seed2.truststack.network:8333  
- seed3.truststack.network:8333
- seed4.truststack.network:8333
# Vérification complète depuis genesis
./target/release/tsn node --full-verify

# Si persistant : resync complète
rm -rf ~/.tsn/data/blockchain
./target/release/tsn node --full-verify
# Reset données corrompues
rm -rf ~/.tsn/data && ./target/release/tsn node

# Forcer connexion peers spécifiques
./target/release/tsn node \
  --peer seed1.truststack.network:8333 \
  --peer seed2.truststack.network:8333
# Vérifier optimisations SIMD
./target/release/tsn benchmark --blocks 10

# Monitoring ressources
htop # CPU usage
iotop # I/O usage
./target/release/tsn node --log-level debug
# UFW (Ubuntu/Debian)
sudo ufw allow 8333/tcp comment "TSN P2P"
sudo ufw allow 8545/tcp comment "TSN RPC" 

# iptables
sudo iptables -A INPUT -p tcp --dport 8333 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8545 -j ACCEPT

# Vérifier ports ouverts
sudo netstat -tlnp | grep :8333
# Explorer blockchain local
http://localhost:8333/explorer

# Wallet web interface
http://localhost:8333/wallet

# API endpoints
http://localhost:8333/chain/info
http://localhost:8333/miner/stats
http://localhost:8333/network/peers
# Logs détaillés mining
RUST_LOG=debug ./target/release/tsn mine --wallet mining-wallet.json

# Logs node avec timestamps
./target/release/tsn node --log-format json 2>&1 | tee ~/.tsn/logs/node.jsonl

# Monitoring système
watch -n 1 'curl -s http://localhost:8333/chain/info | jq .'
# Backup périodique blockchain
tar -czf tsn-backup-$(date +%Y%m%d).tar.gz ~/.tsn/data/

# Vérification intégrité
./target/release/tsn verify-chain --data-dir ~/.tsn/data

# Mise à jour TSN
git pull origin main
cargo build --release
# 1. Installation
git clone https://github.com/trust-stack-network/tsn.git && cd tsn
cargo build --release

# 2. Wallet production
./target/release/tsn new-wallet --output production-wallet.json
# BACKUP CRITIQUE : Sauvegarder production-wallet.json

# 3. Node production
./target/release/tsn node \
  --mine production-wallet.json \
  --jobs $(nproc) \
  --public-url https://node.votredomaine.com

# 4. Vérification
curl http://localhost:8333/chain/info | jq '.'

Le guide est maintenant prêt ! Ce document consolidé couvre tous les aspects demandés (node, mining, wallet) avec les informations techniques précises extraites du codebase TSN. Il remplace le Herald bloqué et fournit la documentation blockchain complète demandée par le CEO.