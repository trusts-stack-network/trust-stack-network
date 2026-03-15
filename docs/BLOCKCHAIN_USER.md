# Guide Utilisateur TSN (Trust Stack Network)

Guide pratique pour déployer un nœud, miner et utiliser le wallet TSN.

## 🔧 Installation rapide

### Compilation depuis les sources
```bash
git clone https://github.com/nicmusic/tsn.git
cd tsn
cargo build --release
```

Le binaire sera disponible dans `target/release/tsn` ou `bin/tsn`.

---

## 🏗️ Déployer un Node TSN

### Node Basic (Observer)

```bash
# Synchronise automatiquement avec le testnet
./target/release/tsn node

# Port personnalisé + répertoire data
./target/release/tsn node --port 8333 --data-dir /var/lib/tsn
```

### Node Mineur (Recommandé)

```bash
# Node mineur avec wallet + 4 threads
./target/release/tsn node --mine wallet.json --jobs 4

# ARM/Apple Silicon optimisé (NEON SIMD)
./target/release/tsn node --mine wallet.json --jobs 8 --simd neon

# Node public avec URL externe
./target/release/tsn node --mine wallet.json --public-url https://monnode.com
```

### Configuration Environnement

```bash
export TSN_PORT=8333                    # Port P2P/API (défaut: 8333)
export TSN_DATA_DIR=/opt/tsn/data       # Données blockchain
export RUST_LOG=info                   # Niveau de log
```

### Options Avancées

```bash
# Node avec faucet intégré (testnet)
./target/release/tsn node --faucet-wallet faucet.json --faucet-daily-limit 50

# Vérification ZK complète (sécurité maximale)
./target/release/tsn node --full-verify

# Mining forcé sans sync (dev/solo uniquement)
./target/release/tsn node --mine wallet.json --force-mine

# Réseau privé avec peers personnalisés
./target/release/tsn node --no-seeds --peer https://peer1.example.com --peer https://peer2.example.com

# Synchronisation rapide (snapshot au lieu de replay)
./target/release/tsn node --fast-sync
```

---

## ⛏️ Minage TSN

### Commandes de Base

```bash
# Créer un wallet first
./target/release/tsn new-wallet --output wallet.json

# Minage continu (Ctrl+C pour arrêter)
./target/release/tsn mine --wallet wallet.json --blocks 0 --jobs 8

# Test performance
./target/release/tsn benchmark --wallet wallet.json --blocks 20 --jobs 4
```

### Optimisations Performance

```bash
# ARM/Apple Silicon
./target/release/tsn mine --wallet wallet.json --simd neon --jobs 8

# Serveurs x86-64
./target/release/tsn mine --wallet wallet.json --jobs $(nproc)
```

**Récompenses :** 50 TSN par bloc • Temps cible : ~10s • Difficulté auto-ajustée

---

## 💼 Gestion Wallet

### Créer & Vérifier

```bash
# Nouveau wallet
./target/release/tsn new-wallet --output mon-wallet.json

# Vérifier solde (scanne la blockchain)
./target/release/tsn balance --wallet mon-wallet.json

# Interroger node distant
./target/release/tsn balance --node http://node.tsnchain.com:8333
```

### Structure Crypto Post-Quantique

Le `wallet.json` contient :
- **spending_key** : ML-DSA-65 (FIPS 204) post-quantique
- **viewing_key** : ChaCha20Poly1305 (32 bytes)
- **address** : Hash Poseidon2 quantum-safe

⚠️ **BACKUP OBLIGATOIRE** : `cp wallet.json ~/backup/wallet-$(date +%Y%m%d).json`

---

## 🖥️ API & Commandes Essentielles

### API REST du Node

```bash
# État sync + hauteur blockchain
curl http://localhost:8333/chain/info

# Bloc par numéro
curl http://localhost:8333/block/height/100

# Stats de mining
curl http://localhost:8333/miner/stats

# Interface web explorer
open http://localhost:8333/explorer

# Interface web wallet
open http://localhost:8333/wallet
```

### Faucet (si activé)

```bash
# Obtenir des TSN de test
curl -X POST http://localhost:8333/faucet \
  -H "Content-Type: application/json" \
  -d '{"recipient": "votre_adresse_hex"}'
```

### Debug & Monitoring

```bash
# Logs détaillés
RUST_LOG=debug ./target/release/tsn node

# Vérification intégrité complète
./target/release/tsn node --full-verify

# Performance mining
RUST_LOG=tsn::consensus=debug ./target/release/tsn mine --wallet wallet.json
```

---

## 🔧 Résolution Problèmes

### Node ne sync pas

```bash
# Test connectivité seed nodes
curl http://seed1.tsnchain.com:9333/chain/info

# Reset données & resync
rm -rf ~/.tsn && ./target/release/tsn node
```

### Erreur "Invalid commitment root"

```bash
# Forcer vérification ZK complète
./target/release/tsn node --full-verify
```

### Performance minage lente

```bash
# ARM : SIMD Neon
./target/release/tsn mine --simd neon --jobs 8

# x86 : tous les cores
./target/release/tsn mine --jobs $(nproc)
```

---

## 🌐 Infos Réseau

### Seed Nodes Mainnet
- `seed1.tsnchain.com:9333`
- `seed2.tsnchain.com:9333`
- `seed3.tsnchain.com:9333`

### Firewall
```bash
# Ouvrir port peers
sudo ufw allow 8333/tcp

# Restreindre API locale
sudo ufw allow from 127.0.0.1 to any port 8333
```

---

## 🔒 Technologies Crypto

**Post-Quantique Ready :**
- **ML-DSA-65** (FIPS 204) : Signatures résistantes quantique
- **Plonky2 STARKs** : Preuves ZK quantum-safe
- **Poseidon2** : Hash function post-quantique
- **ChaCha20Poly1305** : Chiffrement symétrique

**Legacy Support :**
- **Groth16 BN254** : Compatibilité V1 (sera deprecated)

---

**Support :** [GitHub](https://github.com/Trust-Stack-Network/TSN) • [Discord](https://discord.gg/tsn) • [Docs](https://tsnchain.com/docs)

**Mission :** Construire l'infrastructure de confiance pour l'ère post-quantique 🚀