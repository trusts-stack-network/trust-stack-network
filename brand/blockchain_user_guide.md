# Guide Utilisateur TSN — La Blockchain Post-Quantique qui Protège Votre Futur

**Trust Stack Network** • Version 0.4.0 • La sécurité crypto d'aujourd'hui, protégée contre les ordinateurs quantiques de demain.

*Créée par une équipe IA pour sécuriser l'ère post-quantique — l'ironie est intentionnelle et puissante.*

---

## 🚀 Démarrage Rapide

### Installation
```bash
git clone https://github.com/Trust-Stack-Network/TSN.git && cd TSN
cargo build --release
```

### Votre Premier Wallet TSN
```bash
# Créer un wallet post-quantique sécurisé
./target/release/tsn new-wallet --output mon-wallet.json

# Vérifier le solde
./target/release/tsn balance --wallet mon-wallet.json
```

⚠️ **Votre wallet contient vos clés ML-DSA-65 post-quantiques. Sauvegardez-le !**

---

## 🏗️ Lancer Votre Node TSN

### Node Basique (Observer)
```bash
# Rejoint automatiquement le réseau TSN mainnet
./target/release/tsn node
```

### Node Mineur (Recommandé)
```bash
# Gagnez des TSN en sécurisant le réseau
./target/release/tsn node --mine mon-wallet.json --jobs 4

# Optimisé Apple Silicon/ARM
./target/release/tsn node --mine mon-wallet.json --simd neon --jobs 8
```

### Node Public
```bash
# Pour servir votre communauté
./target/release/tsn node --mine mon-wallet.json --public-url https://monnode.tsnchain.com
```

**Votre node devient automatiquement un maillon du réseau post-quantique mondial.**

---

## ⛏️ Minage TSN — Sécurisez le Futur

### Pourquoi Miner ?
- **50 TSN par bloc** minés
- **Protection quantique** native
- **~10 secondes** par bloc
- **Réseau décentralisé** global

### Commandes de Minage
```bash
# Minage continu (Ctrl+C pour arrêter)
./target/release/tsn mine --wallet mon-wallet.json --blocks 0

# Test de performance
./target/release/tsn benchmark --wallet mon-wallet.json --blocks 20

# Monitoring en temps réel
./target/release/tsn-miner-monitor --wallet mon-wallet.json
```

### Optimisations Par Plateforme
```bash
# ARM/Apple Silicon
./target/release/tsn mine --simd neon --jobs 8

# Serveurs Linux
./target/release/tsn mine --jobs $(nproc)
```

---

## 🖥️ Commandes Essentielles

### État du Réseau
```bash
# Info blockchain
curl http://localhost:8333/chain/info

# Statistiques de minage
curl http://localhost:8333/miner/stats
```

### Interfaces Web Intégrées
- **Explorer** : `http://localhost:8333/explorer`
- **Wallet** : `http://localhost:8333/wallet`
- **API** : `http://localhost:8333/chain/info`

### Configuration Avancée
```bash
# Variables d'environnement
export TSN_PORT=8333                    # Port d'écoute
export TSN_DATA_DIR=~/.tsn              # Données blockchain
export TSN_FULL_VERIFY=1               # Vérification ZK complète

# Node avec faucet public
./target/release/tsn node --faucet-wallet faucet.json --faucet-daily-limit 100

# Réseau privé (tests/développement)
./target/release/tsn node --no-seeds --force-mine
```

---

## 🔧 Dépannage Rapide

### Node Ne Synchronise Pas
```bash
rm -rf ./data && ./target/release/tsn node
```

### "Invalid Commitment Root" Error
```bash
./target/release/tsn node --full-verify
```

### Performance Lente
```bash
# Vérifiez vos optimisations SIMD et nombre de threads
./target/release/tsn benchmark --blocks 10
```

---

## 🌐 Le Réseau TSN

### Seed Nodes Mainnet
TSN se connecte automatiquement à un réseau de seed nodes distribués mondialement pour une décentralisation maximale.

### Architecture Post-Quantique
- **ML-DSA-65** (FIPS 204) : Signatures résistantes aux ordinateurs quantiques
- **Plonky2 STARKs** : Preuves zéro-knowledge quantum-safe
- **Poseidon2** : Fonction de hachage optimisée

### Économie
- **Récompense** : 50 TSN/bloc
- **Halving** : Tous les 210,000 blocs
- **Dev Fund** : 5% automatique
- **Temps bloc** : ~10 secondes

---

## 💡 Pourquoi TSN ?

**L'ordinateur quantique arrive.** IBM, Google et autres investissent des milliards. Quand il arrivera, Bitcoin, Ethereum et 99% des cryptos actuelles seront cassables en quelques heures.

**TSN est différent.** Construit avec les standards cryptographiques post-quantiques du NIST. Votre sécurité aujourd'hui, garantie demain.

**Une équipe IA autonome** a conçu TSN — une blockchain résistante aux quantum computers, par des IA, pour protéger l'humanité de l'obsolescence crypto.

---

## 🔗 Ressources

- **GitHub** : [Trust-Stack-Network/TSN](https://github.com/Trust-Stack-Network/TSN)
- **Discord** : [Communauté TSN](https://discord.gg/tsn)
- **Documentation** : [tsnchain.com/docs](https://tsnchain.com/docs)
- **Whitepaper** : Technical specs & cryptography analysis

**TSN : Trust Stack Network — Post-Quantum. Privacy-First. Future-Proof.**

*La blockchain qui survit aux ordinateurs quantiques.*