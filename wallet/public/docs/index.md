# Guide Utilisateur Trust Stack Network

Bienvenue dans la documentation complète de **Trust Stack Network (TSN)**, la première blockchain entièrement post-quantique avec confidentialité par défaut.

## 🚀 Premiers pas

### Qu'est-ce que TSN ?

TSN est une blockchain Layer 1 conçue dès le départ pour :
- **Résister aux ordinateurs quantiques** (cryptographie FIPS 204/205)
- **Protéger votre vie privée** (transactions chiffrées par défaut)
- **Être rapide et efficace** (blocs de 10 secondes, preuves ZK optimisées)

### Structure de la documentation

| Section | Description |
|---------|-------------|
| [🏗️ **Déployer un Node**](node.md) | Installation et configuration d'un nœud TSN |
| [⛏️ **Guide Mining**](mining.md) | Tout sur le minage de TSN — configuration, optimisation, récompenses |
| [💼 **Wallet Guide**](wallet.md) | Gestion des wallets, transactions, sécurité |
| [🔧 **API Reference**](api.md) | Documentation complète de l'API REST |
| [⚡ **Troubleshooting**](troubleshooting.md) | Solutions aux problèmes courants |
| [🔒 **Sécurité**](security.md) | Guide de sécurité et bonnes pratiques |

---

## ⚡ Installation rapide

```bash
# 1. Cloner et compiler TSN
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn
cargo build --release

# 2. Créer un wallet
./target/release/tsn new-wallet --output my-wallet.json

# 3. Démarrer un node mineur
./target/release/tsn node --mine my-wallet.json --jobs 4
```

**En 3 commandes, votre node TSN mine des blocs et sécurise le réseau post-quantique !**

---

## 🎯 Cas d'usage principaux

### 👤 Utilisateur régulier
- [Installer un wallet](wallet.md#installation) pour recevoir et envoyer des TSN
- [Se connecter au réseau](node.md#node-light) avec un light client
- [Explorer la blockchain](api.md#explorer) via l'interface web

### ⛏️ Mineur
- [Configurer un node mineur](node.md#node-mineur) optimisé pour votre matériel
- [Optimiser les performances](mining.md#optimisation) (SIMD, multi-threading)
- [Surveiller les récompenses](mining.md#monitoring) et statistiques

### 🏢 Entreprise/Développeur
- [Déployer un node infrastructure](node.md#node-relay) (relay ou prover)
- [Intégrer l'API TSN](api.md) dans vos applications
- [Configurer un faucet](node.md#faucet) pour testnet

### 🔬 Chercheur/Auditeur
- [Activer la vérification complète](security.md#verification) des preuves ZK
- [Accéder aux métriques](api.md#metrics) de performance crypto
- [Examiner le code](security.md#audit) post-quantique

---

## 📊 État du réseau

| Métrique | Valeur actuelle |
|----------|-----------------|
| **Version** | v0.4.0 |
| **Réseau** | Testnet privé (5 nodes) |
| **Récompense bloc** | 50 TSN |
| **Temps de bloc** | ~10 secondes |
| **Difficulté** | Auto-ajustée tous les 10 blocs |
| **Crypto signatures** | ML-DSA-65 (FIPS 204) |
| **Preuves ZK** | Plonky3 STARKs |

---

## 🔮 Pourquoi post-quantique maintenant ?

Les ordinateurs quantiques ne sont plus de la science-fiction :
- **Google Willow** (décembre 2024) peut exécuter certains calculs en quelques minutes vs. 10^25 années pour un superordinateur classique
- **IBM vise 100 000+ qubits** d'ici 2033 — suffisant pour casser RSA et ECDSA
- **La NSA recommande** la migration post-quantique **dès maintenant**

**TSN ne migrera pas vers le post-quantique — TSN EST post-quantique depuis le jour 1.**

---

## 🤝 Support et communauté

- **GitHub** : [Trust-Stack-Network/tsn](https://github.com/Trust-Stack-Network/tsn)
- **Discord** : [discord.gg/truststack](https://discord.gg/truststack)
- **Site web** : [tsnchain.com](https://tsnchain.com)
- **Explorer** : [explorer.tsnchain.com](https://explorer.tsnchain.com)
- **Email** : support@tsnchain.com

---

*Documentation générée pour TSN v0.4.0 • Dernière mise à jour : Mars 2026*