# 🚀 Premiers Pas avec TSN — Guide Débutant

**Nouveau dans l'univers blockchain ? Découvrez Trust Stack Network en 10 minutes !**

## 💡 TSN en 3 points clés

### 🛡️ Post-Quantique dès le départ
Contrairement à Bitcoin ou Ethereum qui devront migrer, **TSN résiste déjà aux ordinateurs quantiques**. Vos TSN seront sécurisés même quand Google ou IBM casseront les cryptos actuelles.

### 🔒 Confidentialité par défaut
Toutes vos transactions sont **privées automatiquement**. Pas besoin de coins spécialisés comme Monero — TSN intègre la confidentialité dans son ADN.

### ⚡ Rapide et efficace
**10 secondes par bloc**, frais minimaux (0.1 TSN), mining accessible même sur Raspberry Pi avec optimisations SIMD.

---

## 🎯 3 parcours selon votre profil

### 👤 **"Je veux juste essayer"** → Light Wallet
```bash
# 1. Télécharger et compiler (5 minutes)
git clone https://github.com/Trust-Stack-Network/tsn.git
cd tsn && cargo build --release

# 2. Créer votre wallet (30 secondes)
./target/release/tsn new-wallet --output my-wallet.json

# 3. Obtenir des TSN testnet (30 secondes)
./target/release/tsn faucet --wallet my-wallet.json

# ✅ Vous avez 50 TSN pour expérimenter !
./target/release/tsn balance --wallet my-wallet.json
```

### ⛏️ **"Je veux miner et gagner des TSN"** → Node Mineur
```bash
# Après les étapes ci-dessus :
# 4. Démarrer le mining (4 threads)
./target/release/tsn node --mine my-wallet.json --jobs 4

# ✅ Votre node mine et vous accumulez 50 TSN par bloc trouvé !
# Surveillez vos gains : curl http://localhost:8333/mining/stats
```

### 🏢 **"Je veux une infrastructure robuste"** → Node Relay
```bash
# Après compilation :
# 4. Node relay haute performance
./target/release/tsn node --role relay --port 8333 --public-url https://mon-domaine.com

# ✅ Votre node soutient le réseau TSN et expose des APIs !
```

---

## 🌟 Votre première transaction TSN

Une fois votre wallet créé et approvisionné :

```bash
# 1. Obtenir l'adresse d'un ami (format tsn1...)
# 2. Envoyer vos premiers TSN
./target/release/tsn send \
  --wallet my-wallet.json \
  --to tsn1abc123def456... \
  --amount 5.0 \
  --memo "Mon premier TSN !"

# 3. Transaction confirmée en ~10 secondes ⚡
```

**🎉 Félicitations ! Vous venez d'utiliser la première blockchain post-quantique au monde !**

---

## 🔗 Prochaines étapes

| Si vous voulez... | Consultez le guide... |
|-------------------|----------------------|
| Optimiser votre mining | [⛏️ Guide Mining](mining.md) |
| Sécuriser vos TSN | [💼 Guide Wallet](wallet.md) + [🔒 Sécurité](security.md) |
| Déployer en production | [🏗️ Guide Node](node.md) |
| Intégrer TSN dans une app | [🔧 API Reference](api.md) |
| Résoudre un problème | [⚡ Troubleshooting](troubleshooting.md) |

---

## ❓ Questions fréquentes

**Q: TSN va-t-il vraiment résister aux ordinateurs quantiques ?**
R: Oui ! TSN utilise ML-DSA-65 (FIPS 204) et SLH-DSA (FIPS 205), les standards post-quantiques officiels de la NSA/NIST. Bitcoin et Ethereum devront migrer — TSN est déjà prêt.

**Q: Combien je peux gagner en minant ?**
R: Actuellement 50 TSN par bloc (~10 secondes). Avec 4 threads sur CPU moderne, comptez 1-5 blocs par jour selon la difficulté réseau.

**Q: TSN est-il vraiment privé ?**
R: Oui, grâce aux preuves ZK Plonky3. Seuls l'expéditeur et destinataire connaissent les montants. Le réseau voit seulement qu'une transaction valide a eu lieu.

**Q: Je peux miner sur Raspberry Pi ?**
R: Absolument ! TSN supporte ARMv8 NEON SIMD. Un Raspberry Pi 4 peut miner efficacement grâce aux optimisations spécialisées.

---

## 🚀 Rejoindre la révolution post-quantique

**TSN n'est pas une blockchain de plus — c'est la blockchain qui survivra à l'ère quantique.**

Pendant que les autres projets paniquent face à l'arrivée des ordinateurs quantiques, vous êtes déjà protégé. Bienvenue dans le futur de la crypto !

---

🌐 **Communauté** : [Discord](https://discord.gg/truststack) • [GitHub](https://github.com/Trust-Stack-Network/tsn)
🔗 **Explorer** : [explorer.tsnchain.com](https://explorer.tsnchain.com)
📧 **Support** : support@tsnchain.com

*Guide Débutant TSN v0.4.0 • Mars 2026*