# ⛏️ Guide Mining TSN

Guide complet pour miner efficacement sur Trust Stack Network et optimiser vos récompenses.

## 🎯 Comprendre le mining TSN

### Algorithme de consensus

TSN utilise un **Poseidon Proof-of-Work** post-quantique :
- **Hash function** : Poseidon2 (optimisé ZK-friendly)
- **Difficulté** : Auto-ajustée tous les 10 blocs (cible ~10 secondes)
- **Récompense actuelle** : 50 TSN par bloc
- **SIMD** : Support ARMv8 NEON pour Raspberry Pi et Apple Silicon

### Sécurité post-quantique

- **Signatures de bloc** : ML-DSA-65 (FIPS 204) — résistant quantique
- **Preuves ZK** : Plonky3 STARKs (quantum-safe)
- **Pas de vulnérabilité** aux futurs ordinateurs quantiques

---

## 🚀 Démarrage rapide

### 1. Créer un wallet mineur

```bash
# Nouveau wallet pour recevoir les récompenses
./target/release/tsn new-wallet --output miner-wallet.json

# Vérifier le wallet
cat miner-wallet.json
```

### 2. Mining solo (débutants)

```bash
# Démarrer le mining immédiatement (1 thread)
./target/release/tsn mine --wallet miner-wallet.json --jobs 1

# Mining avec 4 threads
./target/release/tsn mine --wallet miner-wallet.json --jobs 4

# Mining limité à 10 blocs (pour test)
./target/release/tsn mine --wallet miner-wallet.json --blocks 10 --jobs 2
```

### 3. Node mineur intégré (recommandé)

```bash
# Node + mining dans le même processus
./target/release/tsn node --mine miner-wallet.json --jobs 4

# Avec seed peers désactivés (test local)
./target/release/tsn node --mine miner-wallet.json --force-mine --jobs 8
```

---

## ⚙️ Configuration optimale

### Nombre de threads

| CPU Cores | Threads Mining | Threads Libres | Performance |
|-----------|----------------|----------------|-------------|
| 2 cores | 1 thread | 1 pour OS | 100% |
| 4 cores | 2-3 threads | 1-2 pour réseau | 180% |
| 8 cores | 4-6 threads | 2-4 pour sync/API | 400% |
| 16+ cores | 8-12 threads | 4+ pour infrastructure | 800%+ |

**Règle** : Gardez 1-2 cores libres pour la synchronisation réseau.

```bash
# CPU 8 cores : optimal avec 6 threads
./target/release/tsn node --mine wallet.json --jobs 6

# CPU 16 cores : optimal avec 12 threads
./target/release/tsn node --mine wallet.json --jobs 12
```

### Optimisations SIMD

**Sur ARM64** (Raspberry Pi, Apple M1/M2) :

```bash
# Activer NEON SIMD (2-3x plus rapide)
./target/release/tsn mine --wallet wallet.json --simd neon --jobs 4

# Node ARM64 optimisé
./target/release/tsn node --mine wallet.json --simd neon --jobs 6
```

**Vérification support** :
```bash
# Le CLI détecte automatiquement le support SIMD
./target/release/tsn mine --wallet wallet.json --simd neon
# → Erreur si NEON non supporté
```

### Benchmark de performance

```bash
# Test de performance (mine 20 blocs)
./target/release/tsn benchmark --wallet wallet.json --blocks 20 --jobs 4

# Test difficulté élevée
./target/release/tsn benchmark --wallet wallet.json --difficulty 22 --blocks 10

# Test SIMD vs standard
./target/release/tsn benchmark --wallet wallet.json --blocks 10 --jobs 4
./target/release/tsn benchmark --wallet wallet.json --blocks 10 --jobs 4 --simd neon
```

**Exemple output** :
```
Mining benchmark completed!
Blocks mined: 20
Total time: 45.7 seconds
Average time per block: 2.29 seconds
Estimated hashrate: 2.8 MH/s
```

---

## 📊 Monitoring et métriques

### APIs de monitoring

```bash
# Statistiques mining en temps réel
curl http://localhost:8333/miner/stats
```

**Réponse** :
```json
{
  "hashrate": 2800000,
  "blocks_mined": 15,
  "shares_submitted": 156,
  "mining_threads": 4,
  "simd_enabled": true,
  "uptime_seconds": 3600
}
```

### Métriques blockchain

```bash
# Info générale de la chaîne
curl http://localhost:8333/chain/info
```

**Réponse** :
```json
{
  "height": 1234,
  "latest_hash": "0x1a2b3c...",
  "difficulty": 18,
  "network": "testnet",
  "peers_connected": 5
}
```

### Vérifier les récompenses

```bash
# Solde du wallet mineur
./target/release/tsn balance --wallet miner-wallet.json

# Via node local
./target/release/tsn balance --wallet miner-wallet.json --node http://localhost:8333
```

---

## 💰 Économie du mining

### Structure des récompenses

| Bloc Height | Récompense | Halving |
|-------------|------------|---------|
| 0 - 210,000 | 50 TSN | — |
| 210,001 - 420,000 | 25 TSN | Première réduction |
| 420,001 - 630,000 | 12.5 TSN | Deuxième réduction |
| 630,001+ | 6.25 TSN | Continue tous les 210k blocs |

**Temps de halving estimé** : ~2 ans (210k blocs × 10 secondes)

### Calcul de rentabilité

**Variables** :
- Hashrate personnel : H (hashes/seconde)
- Hashrate réseau total : N (hashes/seconde)
- Récompense par bloc : R (50 TSN actuellement)
- Temps de bloc : T (10 secondes cible)

**Revenus quotidiens** = `(H / N) × R × (86400 / T)`

**Exemple** :
- Votre hashrate : 2.8 MH/s
- Réseau total : 50 MH/s
- Votre part : 2.8/50 = 5.6%
- Blocs par jour : 8640 (86400s / 10s)
- Vos blocs par jour : 8640 × 5.6% = ~484 blocs
- Revenus : 484 × 50 = **24,200 TSN/jour**

---

## 🔧 Mining avancé

### Configuration par fichier

Créer `~/.tsn/mining.toml` :

```toml
[mining]
# Wallet pour les récompenses
wallet_file = "/opt/tsn/miner-wallet.json"

# Performance
threads = 6
simd_mode = "neon"  # "neon" sur ARM64

# Seuils
min_difficulty = 16
max_difficulty = 24

# Monitoring
stats_interval_seconds = 30
log_level = "info"

[network]
# Mining pool (futur)
pool_url = "stratum+tcp://pool.tsnchain.com:4444"
pool_wallet = "tsn1abcd..."
```

### Mining en pool (roadmap)

⚠️ **Les pools de mining ne sont pas encore implémentées** dans TSN v0.4.0

**Prévision Q2 2026** :
- Protocole Stratum pour TSN
- Pools distribuées avec partage équitable
- Support multi-wallet dans une pool

### Scripts de surveillance

**Auto-restart en cas de crash** :

```bash
#!/bin/bash
# mining-watchdog.sh

WALLET="/opt/tsn/miner-wallet.json"
JOBS=6
LOG="/var/log/tsn-mining.log"

while true; do
    echo "$(date): Démarrage mining..." >> $LOG

    ./target/release/tsn node --mine $WALLET --jobs $JOBS 2>&1 | tee -a $LOG

    echo "$(date): Mining arrêté, redémarrage dans 10s..." >> $LOG
    sleep 10
done
```

**Monitoring Telegram** :

```bash
#!/bin/bash
# mining-monitor.sh

TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID"

STATS=$(curl -s http://localhost:8333/miner/stats)
HASHRATE=$(echo $STATS | jq -r '.hashrate')
BLOCKS=$(echo $STATS | jq -r '.blocks_mined')

MESSAGE="TSN Miner Update:
Hashrate: $(($HASHRATE / 1000000)) MH/s
Blocs minés: $BLOCKS
Status: Online ✅"

curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
     -d chat_id=$TELEGRAM_CHAT_ID \
     -d text="$MESSAGE"
```

---

## 🛠️ Troubleshooting mining

### Problèmes courants

**Mining ne démarre pas** :
```bash
# Vérifier le wallet
./target/release/tsn balance --wallet miner-wallet.json

# Test mining solo (sans réseau)
./target/release/tsn mine --wallet miner-wallet.json --blocks 1 --force-mine
```

**Hashrate faible** :
```bash
# Vérifier les threads actives
top -H -p $(pgrep tsn)

# Test benchmark
./target/release/tsn benchmark --wallet wallet.json --blocks 5

# Essayer avec SIMD (si ARM64)
./target/release/tsn benchmark --wallet wallet.json --blocks 5 --simd neon
```

**Blocs rejetés** :
```bash
# Vérifier la sync avec le réseau
curl http://localhost:8333/chain/info

# Log en mode debug
TSN_LOG_LEVEL=debug ./target/release/tsn node --mine wallet.json
```

**CPU overload** :
```bash
# Réduire les threads
./target/release/tsn node --mine wallet.json --jobs 2

# Surveiller l'utilisation
htop -t
```

### Optimisations système

**Linux** :
```bash
# Priorité temps réel pour le minage
sudo nice -n -10 ./target/release/tsn node --mine wallet.json --jobs 4

# Désactiver swap (SSD uniquement)
sudo swapoff -a

# Governor CPU en performance
sudo cpupower frequency-set -g performance
```

**macOS** :
```bash
# Température CPU
sudo powermetrics -n 1 | grep "CPU die temperature"

# Monitoring thermique
sudo powermetrics -s cpu_power -n 1
```

---

## 🏆 Meilleures pratiques

### Sécurité du wallet

```bash
# Backup automatique quotidien
echo "0 3 * * * cp /opt/tsn/miner-wallet.json /opt/tsn/backups/wallet-$(date +\%Y\%m\%d).json" | crontab -

# Permissions restrictives
chmod 600 miner-wallet.json
chown root:root miner-wallet.json
```

### Haute disponibilité

```bash
# Mining multi-nodes (répartition du risque)
# Node 1: 40% des threads
./target/release/tsn node --mine wallet1.json --jobs 4

# Node 2: 40% des threads
./target/release/tsn node --mine wallet2.json --jobs 4 --port 8334

# Node 3: 20% relay/backup
./target/release/tsn node --role relay --port 8335
```

### Rentabilité long terme

- **Démarrer maintenant** : Difficulté faible en phase testnet
- **Diversifier** : Ne pas mettre 100% sur un seul node
- **HODL** : Les TSN minés aujourd'hui vaudront plus sur mainnet
- **Infrastructure** : Investir dans NVME SSD et refroidissement

---

**📈 Le mining TSN est l'opportunité de sécuriser la première blockchain post-quantique tout en accumulant des récompenses avant le passage au mainnet !**

---

*Guide Mining TSN v0.4.0 • Mis à jour Mars 2026*