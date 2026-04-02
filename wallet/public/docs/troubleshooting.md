# ⚡ Guide Troubleshooting TSN

Solutions aux problèmes courants rencontrés avec Trust Stack Network.

## 🚨 Problèmes de compilation

### Erreur : `failed to compile tsn`

**Symptômes :**
```bash
error: failed to compile `tsn v0.4.0`
Caused by: feature `generic_const_exprs` is incomplete
```

**Solutions :**

1. **Vérifier la version de Rust**
```bash
rustc --version
# Doit être >= 1.75.0

# Si nécessaire, mettre à jour
rustup update stable
rustup default stable
```

2. **Clean + rebuild complet**
```bash
cargo clean
cargo build --release
```

3. **Dépendances système manquantes**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential pkg-config libssl-dev

# macOS
brew install openssl
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl
```

### Erreur de linking : `cannot find -lpq`

**Solution :**
```bash
# Ubuntu/Debian
sudo apt install libpq-dev

# macOS
brew install postgresql
```

---

## 🔌 Problèmes de réseau

### Node ne se connecte pas aux peers

**Symptômes :**
```
[WARN] No peers connected after 30 seconds
[ERROR] Failed to sync with network
```

**Diagnostic :**
```bash
# Vérifier connectivité réseau
./target/release/tsn node --test-network

# Vérifier les ports (par défaut: 8333)
netstat -tuln | grep 8333
```

**Solutions :**

1. **Firewall/NAT**
```bash
# Ouvrir le port TSN (Ubuntu/ufw)
sudo ufw allow 8333

# Test de connectivité
telnet seed1.tsnchain.com 8333
```

2. **Configuration explicite des peers**
```bash
# Forcer les seed nodes
./target/release/tsn node \
  --peers seed1.tsnchain.com:8333,seed2.tsnchain.com:8333
```

3. **Réseau derrière proxy**
```bash
# Configuration SOCKS5
export ALL_PROXY=socks5://127.0.0.1:9050
./target/release/tsn node
```

### Erreur : "Invalid commitment root"

**Symptômes :**
```
[ERROR] Block validation failed: Invalid commitment root
[WARN] Rejecting block #1234 from peer
```

**Causes principales :**
- Désynchronisation avec le réseau principal
- Corruption de données locales
- Version obsolète du client

**Solutions :**

1. **Resync complète**
```bash
# Sauvegarder le wallet d'abord !
cp ~/.tsn/wallet.json ~/wallet-backup.json

# Nettoyer les données corrompues
rm -rf ~/.tsn/data/
./target/release/tsn node --resync
```

2. **Vérifier version client**
```bash
./target/release/tsn --version
# Si < v0.4.0, mettre à jour obligatoire
git pull origin main
cargo build --release
```

---

## ⛏️ Problèmes de mining

### Hashrate très faible

**Symptômes :**
```
[INFO] Mining hashrate: 12.3 H/s (expected: 500+ H/s)
```

**Optimisations :**

1. **Vérifier SIMD support**
```bash
# Linux : vérifier les flags CPU
cat /proc/cpuinfo | grep -E "(sse|avx|neon)"

# macOS : vérifier Apple Silicon
sysctl -n machdep.cpu.brand_string
```

2. **Optimiser les threads**
```bash
# Tester différentes configurations
./target/release/tsn mine --jobs 1    # Baseline
./target/release/tsn mine --jobs 4    # Standard
./target/release/tsn mine --jobs 8    # High-end

# Surveiller l'utilisation CPU
top -p $(pgrep tsn)
```

3. **Compilation optimisée**
```bash
# Build avec optimisations native
RUSTFLAGS="-C target-cpu=native" cargo build --release

# Pour Raspberry Pi (ARMv8)
RUSTFLAGS="-C target-cpu=cortex-a72" cargo build --release
```

### Mining rate = 0

**Diagnostic :**
```bash
# Vérifier wallet mineur
./target/release/tsn wallet info --file miner-wallet.json

# Tester le hashing
./target/release/tsn benchmark --poseidon --duration 10
```

**Solutions :**

1. **Wallet invalide**
```bash
# Recréer le wallet mineur
./target/release/tsn new-wallet --output new-miner.json
./target/release/tsn mine --wallet new-miner.json
```

2. **Node non synchronisé**
```bash
# Attendre sync complète avant mining
./target/release/tsn node --sync-only
# Une fois sync, relancer avec mining
./target/release/tsn node --mine miner-wallet.json
```

---

## 💼 Problèmes de wallet

### Erreur : "Insufficient funds"

**Diagnostic :**
```bash
# Vérifier balance
./target/release/tsn wallet balance --file my-wallet.json

# Vérifier historique transactions
./target/release/tsn wallet history --file my-wallet.json --limit 10
```

**Solutions :**

1. **Transaction en attente**
```bash
# Lister les transactions pending
./target/release/tsn wallet pending --file my-wallet.json

# Attendre confirmation (2-3 blocs)
./target/release/tsn node info | grep "Current height"
```

2. **Utiliser le faucet testnet**
```bash
# Récupérer l'adresse wallet
ADDR=$(./target/release/tsn wallet address --file my-wallet.json)

# Demander des TSN testnet
curl -X POST https://faucet.tsnchain.com/request \
  -H "Content-Type: application/json" \
  -d "{\"address\": \"$ADDR\"}"
```

### Wallet corrompu

**Symptômes :**
```
[ERROR] Failed to load wallet: Invalid key format
[ERROR] Wallet decryption failed
```

**Solutions :**

1. **Récupération depuis backup**
```bash
# Si backup disponible
cp ~/wallet-backup.json ~/.tsn/wallet.json

# Vérifier intégrité
./target/release/tsn wallet verify --file ~/.tsn/wallet.json
```

2. **Récupération depuis seed phrase**
```bash
# Restaurer depuis mnemonic
./target/release/tsn wallet recover \
  --mnemonic "word1 word2 ... word24" \
  --output recovered-wallet.json
```

---

## 🔧 Diagnostic système

### Vérification complète

```bash
#!/bin/bash
# Script de diagnostic TSN complet

echo "=== TSN System Diagnostic ==="

# 1. Version info
echo "[INFO] TSN Version:"
./target/release/tsn --version

# 2. Network connectivity
echo "[INFO] Network test:"
./target/release/tsn node --test-network --timeout 10

# 3. Crypto benchmarks
echo "[INFO] Performance test:"
./target/release/tsn benchmark --all --duration 5

# 4. Storage check
echo "[INFO] Database status:"
du -sh ~/.tsn/data/
./target/release/tsn node --verify-db --limit 100

# 5. Wallet status
echo "[INFO] Wallet verification:"
./target/release/tsn wallet verify --file ~/.tsn/wallet.json

echo "=== Diagnostic Complete ==="
```

### Logs de debug

```bash
# Activer logs détaillés
export RUST_LOG=debug
./target/release/tsn node 2>&1 | tee tsn-debug.log

# Filtrer par composant
export RUST_LOG=tsn::network=debug,tsn::consensus=info
./target/release/tsn node

# Analyser les erreurs
grep -i error tsn-debug.log | tail -20
```

### Monitoring performance

```bash
# CPU/RAM usage
watch -n 1 'ps aux | grep tsn'

# Network I/O
ss -tuln | grep :8333
netstat -i

# Disk I/O
iotop -p $(pgrep tsn)

# TSN-specific metrics
./target/release/tsn node info --json | jq
```

---

## 📊 Métriques de santé

### Indicateurs clés

| Métrique | Normal | Warning | Critical |
|----------|--------|---------|----------|
| **Sync lag** | < 5 blocs | 5-20 blocs | > 20 blocs |
| **Peers** | 8-32 | 3-7 | < 3 |
| **Memory** | < 500 MB | 500 MB - 2 GB | > 2 GB |
| **CPU usage** | < 50% | 50-80% | > 80% |
| **Mining rate** | > 100 H/s | 10-100 H/s | < 10 H/s |

### Monitoring automatisé

```bash
#!/bin/bash
# Script monitoring TSN

while true; do
  HEIGHT=$(./target/release/tsn node info | grep height | cut -d: -f2)
  PEERS=$(./target/release/tsn node peers | wc -l)
  MEM=$(ps aux | grep tsn | grep -v grep | awk '{print $6}')

  echo "[$(date)] Height: $HEIGHT | Peers: $PEERS | Memory: ${MEM}KB"

  sleep 30
done
```

---

## 🆘 Support d'urgence

### Contacts rapides

- **GitHub Issues** : [github.com/Trust-Stack-Network/tsn/issues](https://github.com/Trust-Stack-Network/tsn/issues)
- **Discord #support** : [discord.gg/truststack](https://discord.gg/truststack)
- **Email urgent** : support@tsnchain.com

### Informations à fournir

Quand vous reportez un bug, incluez toujours :

1. **Version TSN** : `./target/release/tsn --version`
2. **OS/Architecture** : `uname -a`
3. **Config Rust** : `rustc --version`
4. **Logs d'erreur** : Les 20 dernières lignes avec timestamps
5. **Commande exacte** qui génère l'erreur
6. **Hardware** : CPU, RAM, type de stockage

### Debug avancé

```bash
# Capture complète pour support
{
  echo "=== TSN Debug Report ==="
  date
  ./target/release/tsn --version
  uname -a
  rustc --version
  echo "=== Last errors ==="
  journalctl -u tsn --since "1 hour ago" --no-pager | tail -50
} > tsn-debug-report.txt
```

---

*Guide troubleshooting TSN v0.4.0 • Dernière mise à jour : Mars 2026*