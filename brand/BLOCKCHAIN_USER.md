# Guide Utilisateur Blockchain TSN
*Trust Stack Network - Blockchain Post-Quantique*

## 🚀 Démarrage Rapide

Trust Stack Network (TSN) est une blockchain post-quantique utilisant la cryptographie SLH-DSA et les preuves zero-knowledge. Ce guide vous accompagne pour déployer un node, miner et gérer votre wallet.

## 📦 Installation

```bash
# Cloner le repository
git clone https://github.com/trust-stack-network/tsn.git
cd tsn

# Build en mode release
make build

# Ou directement avec cargo
cargo build --release
```

Le binaire sera disponible dans `target/release/tsn`.

## 🔐 1. Configuration Wallet

### Créer un nouveau wallet
```bash
# Générer un nouveau wallet shielded
tsn new-wallet -o mon-wallet.json

# Ou avec un nom personnalisé
tsn new-wallet --output mes-cles.json
```

### Vérifier le solde
```bash
# Vérifier le solde (scan blockchain)
tsn balance -w mon-wallet.json -n http://localhost:8333

# Avec un node distant
tsn balance --wallet mon-wallet.json --node http://seed1.truststack.network:8333
```

**Important :** Le wallet TSN utilise la cryptographie post-quantique SLH-DSA-SHA2-128s. Sauvegardez précieusement votre fichier wallet.json !

## ⛏️ 2. Mining

### Mining simple (local)
```bash
# Miner 10 blocs avec difficulté 16
tsn mine -w mon-wallet.json -b 10 -d 16

# Mining illimité (jusqu'à interruption)
tsn mine --wallet mon-wallet.json --blocks 0 --difficulty 12
```

### Mining optimisé
```bash
# Mining multi-thread (4 threads)
tsn mine -w mon-wallet.json -j 4 -d 16

# Avec SIMD NEON (ARM64 uniquement)
tsn mine --wallet mon-wallet.json --jobs 4 --simd neon
```

### Benchmark mining
```bash
# Test performance (20 blocs, difficulté 20)
tsn benchmark -w mon-wallet.json -b 20 -d 20 -j 4
```

## 🌐 3. Déployer un Node TSN

### Node complet (avec mining)
```bash
# Node sur port 8333 avec mining activé
tsn node --port 8333 --mine mon-wallet.json --jobs 2

# Node avec peers personnalisés
tsn node -p 8333 --peer http://peer1.example.com:8333 --peer http://peer2.example.com:8333
```

### Node de validation seulement
```bash
# Node sans mining (validation uniquement)
tsn node --port 8333

# Node avec répertoire de données personnalisé
tsn node -p 8333 --data-dir /opt/tsn-data
```

### Configuration avancée
```bash
# Node public avec URL annoncée
tsn node --port 8333 --public-url https://mon-node.example.com

# Node solo (sans seeds) pour tests
tsn node --port 8333 --no-seeds --force-mine --mine mon-wallet.json

# Node avec vérification complète (depuis genesis)
tsn node --port 8333 --full-verify
```

### Node avec faucet
```bash
# Activer le faucet (50 TSN/jour par défaut)
tsn node --port 8333 --faucet-wallet faucet-wallet.json

# Faucet avec limite personnalisée (100 TSN/jour)
tsn node --port 8333 --faucet-wallet faucet-wallet.json --faucet-daily-limit 100
```

## 🔧 4. Commandes CLI Essentielles

### Variables d'environnement
```bash
# Port du node (défaut: 8333)
export TSN_PORT=8333

# Répertoire de données
export TSN_DATA_DIR=/opt/tsn-data

# Niveau de log
export RUST_LOG=info  # debug, info, warn, error
```

### Monitoring et debug
```bash
# Monitoring TUI du mining
tsn-miner-monitor -w mon-wallet.json -n http://localhost:8333

# Logs détaillés
RUST_LOG=debug tsn node --port 8333
```

### APIs et endpoints
Une fois le node démarré, les endpoints suivants sont disponibles :

```
http://localhost:8333/chain/info    - Infos blockchain
http://localhost:8333/chain/height  - Hauteur actuelle
http://localhost:8333/blocks/:hash  - Détails d'un bloc
http://localhost:8333/mempool      - Transactions en attente
```

## ⚡ Configuration Optimisée

### Configuration réseau mainnet
```bash
# Node mainnet avec configuration recommandée
tsn node \
  --port 8333 \
  --mine mon-wallet.json \
  --jobs $(nproc) \
  --public-url https://mon-node.tsnchain.com \
  --data-dir /opt/tsn-mainnet
```

### Seeds mainnet (configuration par défaut)
```
- seed1.truststack.network:8333
- seed2.truststack.network:8333
- seed3.truststack.network:8333
```

## 🛡️ Sécurité Post-Quantique

TSN intègre nativement :
- **SLH-DSA** (FIPS 205) : Signatures post-quantiques
- **Plonky2 STARKs** : Preuves zero-knowledge quantum-safe
- **Poseidon2** : Hash résistant aux attaques quantiques

Vos transactions et wallets sont protégés contre les futures attaques d'ordinateurs quantiques.

## 🎯 Paramètres Réseau

```
Réseau: tsn-mainnet
Difficulté genesis: 12
Récompense bloc: 50 TSN (50,000,000,000 base units)
Décimales: 9 (1 TSN = 10^9 base units)
Activation Poseidon2: Height 1100
```

## ❗ Notes Importantes

- **Sauvegarde wallet** : Le fichier wallet.json contient vos clés privées
- **Sync réseau** : Le premier démarrage nécessite une sync avec les peers
- **Ports firewall** : Ouvrez le port 8333 (ou celui configuré) pour les connexions P2P
- **ARM64 SIMD** : Le flag `--simd neon` accélère le mining sur processeurs ARM

---

🔗 **Support** : [GitHub Issues](https://github.com/trust-stack-network/tsn/issues) | 💬 **Discord** : [TSN Community](https://discord.gg/tsnchain)