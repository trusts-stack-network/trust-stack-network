# Guide TSN — Trust Stack Network 🛡️

> **La blockchain post-quantique simple à utiliser**

Les ordinateurs quantiques menacent toute la crypto actuelle. TSN vous protège dès maintenant avec une cryptographie résistante aux attaques quantiques + confidentialité native. Ce guide vous accompagne en 5 minutes.

---

## ⚡ Installation Rapide

```bash
# Compiler TSN
git clone https://github.com/Trust-Stack-Network/TSN.git && cd TSN
cargo build --release

# Vos outils TSN
./target/release/tsn                 # CLI principal
./target/release/tsn-miner-monitor   # Interface monitoring
```

---

## 🏗️ Déployer Votre Node

### Node Basique (Observer)
```bash
# Synchronise la blockchain TSN
./target/release/tsn node

# Avec port personnalisé
./target/release/tsn node --port 9333
```

### Node Mineur (Recommandé)
```bash
# Créer d'abord votre wallet
./target/release/tsn new-wallet

# Lancer mining avec 4 threads
./target/release/tsn node --mine wallet.json --jobs 4

# ARM/Apple Silicon optimisé
./target/release/tsn node --mine wallet.json --jobs 8 --simd neon
```

### Variables Environnement
```bash
export TSN_PORT=8333         # Port d'écoute
export TSN_DATA_DIR=~/.tsn   # Données blockchain
```

---

## ⛏️ Mining TSN

### Modes de Mining
```bash
# Mining standalone - 100 blocs
./target/release/tsn mine --wallet wallet.json --blocks 100

# Mining continu (Ctrl+C pour arrêter)
./target/release/tsn mine --wallet wallet.json --blocks 0 --jobs 8

# Test performance
./target/release/tsn benchmark --wallet wallet.json --blocks 20
```

### Interface Monitoring
```bash
# TUI avec stats temps réel
./target/release/tsn-miner-monitor --wallet wallet.json

# Affiche : hashrate, gains, blocs minés, état réseau
```

### Optimisation Performance
```bash
# ARM/Apple Silicon
./target/release/tsn mine --wallet wallet.json --simd neon --jobs 8

# Serveurs x86-64
./target/release/tsn mine --wallet wallet.json --jobs $(nproc)
```

**💡 Le sync gate TSN pause automatiquement le mining si votre node est en retard sur le réseau.**

---

## 💼 Wallet TSN

### Gestion Wallet
```bash
# Nouveau wallet
./target/release/tsn new-wallet --output mon-wallet.json

# Vérifier solde
./target/release/tsn balance --wallet mon-wallet.json

# Node distant
./target/release/tsn balance --node http://node.tsnchain.com:8333
```

### Structure Wallet
Le fichier `wallet.json` contient :
- **spending_key** : Clé privée ML-DSA-65 (FIPS 204) post-quantique
- **viewing_key** : Décryptage des notes privées (32 bytes)
- **address** : Adresse publique (hash Poseidon2)

⚠️ **SAUVEGARDEZ votre wallet.json ! Perte = perte définitive de vos TSN.**

---

## 🖥️ API & Commandes Essentielles

### API REST Node
```bash
# État blockchain
curl http://localhost:8333/chain/info

# Explorer web
open http://localhost:8333/explorer

# Wallet web interface
open http://localhost:8333/wallet

# Bloc spécifique
curl http://localhost:8333/block/height/100

# Stats mining (si mineur)
curl http://localhost:8333/miner/stats
```

### Network & Debug
```bash
# Mode debug
RUST_LOG=debug ./target/release/tsn node

# Node privé avec peers custom
./target/release/tsn node --no-seeds --peer http://peer.example.com:8333

# Vérification ZK complète
./target/release/tsn node --full-verify
```

---

## 🔧 Résolution Problèmes

### Erreurs Communes

**Node ne sync pas :**
```bash
curl http://seed1.tsnchain.com:9333/chain/info
rm -rf ./data && ./target/release/tsn node
```

**"Invalid commitment root" :**
```bash
./target/release/tsn node --full-verify
```

**Clés ZK manquantes :**
```bash
cd circuits/ && npm run compile:all && npm run setup:spend && npm run setup:output
```

**Mining lent :**
```bash
# Monitoring temps réel
./target/release/tsn-miner-monitor --wallet wallet.json

# ARM/Apple Silicon
./target/release/tsn mine --simd neon --jobs 8
```

---

## 🌐 Infos Réseau

### Mainnet TSN
- **Seed Nodes :** `seed1.tsnchain.com:9333`, `seed2.tsnchain.com:9333`
- **Récompense bloc :** 50 TSN
- **Temps bloc :** ~10 secondes
- **Frais dev :** 5% automatique

### Cryptographie Post-Quantique
- **Signatures :** ML-DSA-65 (FIPS 204) — résistant quantique
- **Preuves V2 :** Plonky2 STARKs — quantum-safe
- **Legacy V1 :** Groth16 BN254 — sera deprecated

---

## 🔒 Sécurité

### Backup Critique
```bash
# Sauvegarder wallet
cp wallet.json ~/backup/wallet-$(date +%Y%m%d).json
sha256sum wallet.json > wallet.json.sha256

# Firewall node
sudo ufw allow 8333/tcp
```

### Vérification
```bash
# Hash binaire
sha256sum target/release/tsn
```

---

**🚀 Prêt à miner sur la blockchain post-quantique !**

**Support :** [GitHub](https://github.com/Trust-Stack-Network/TSN) | [Discord](https://discord.gg/tsn) | [Documentation](https://tsnchain.com/docs)

*TSN = ML-DSA-65 + Plonky2 STARKs = 100% résistant quantique*