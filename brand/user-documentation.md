# Trust Stack Network - Documentation Utilisateur

## 🚀 Démarrage rapide

### Prérequis système
- **OS**: Linux (Ubuntu 20.04+ recommandé), macOS 11+, Windows 10+ (WSL2)
- **CPU**: 4 cœurs minimum, 8 cœurs recommandés
- **RAM**: 8GB minimum, 16GB recommandés
- **Stockage**: 100GB SSD minimum, 500GB recommandés
- **Réseau**: Connexion stable, 10 Mbps upload minimum

### Installation en 3 étapes

```bash
# 1. Télécharger la dernière version
curl -L https://github.com/truststack/tsn/releases/latest/download/tsn-linux-amd64 -o tsn
chmod +x tsn

# 2. Initialiser le node
./tsn init --network mainnet --data-dir ~/.tsn

# 3. Démarrer le node
./tsn start --config ~/.tsn/config.toml
# ~/.tsn/config.toml
[mining]
enabled = true
wallet_address = "tsn1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
threads = 4
stake_amount = 1000

[quantum_protection]
ml_dsa_level = 3
zk_stark_frequency = "every_block"
# Vérifier la synchronisation
./tsn status | grep "synced"

# Démarrer le mining
./tsn mining start --threads 4

# Vérifier les statistiques
./tsn mining stats
# Générer un nouveau wallet
./tsn wallet create --name mon_wallet --password-file password.txt

# Afficher l'adresse
./tsn wallet address --name mon_wallet
# Vérifier le solde
./tsn wallet balance --name mon_wallet

# Envoyer 100 TSN
./tsn wallet send \
  --from mon_wallet \
  --to tsn1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh \
  --amount 100 \
  --password-file password.txt
# Dernier bloc
./tsn explorer block --latest

# Transaction par hash
./tsn explorer tx --hash 0x1234...

# Adresse et soldes
./tsn explorer address --address tsn1qxy...
# Vérifier la résistance quantique
./tsn crypto verify-quantum-resistance

# Afficher les paramètres cryptographiques
./tsn crypto params
# Sync depuis zéro (sécurisé mais lent)
./tsn sync --mode full

# Snap sync (rapide, vérifie les signatures)
./tsn sync --mode snap --trusted-hash 0x1234...

# Vérifier la progression
./tsn sync --status
# Réparer la base de données
./tsn repair --validate-merkle

# Forcer la resync
./tsn sync --reset --mode snap
# Réduire la cache
echo "cache_size = 1024" >> ~/.tsn/config.toml

# Limiter les threads
./tsn start --threads 2
# Vérifier les ports
netstat -tulpn | grep 9944

# Firewall
sudo ufw allow 9944/tcp
# Logs en temps réel
tail -f ~/.tsn/logs/tsn.log

# Niveau de log
./tsn start --log-level debug

# Métriques
curl http://localhost:9945/metrics
# ~/.tsn/config.toml
[performance]
cache_size = 2048
threads = 8
db_cache = 512

[sync]
fast_sync = true
parallel_download = 16
# Tableau de bord web
./tsn dashboard --port 8080

# API Prometheus
curl http://localhost:9945/metrics | grep tsn_

# Statistiques détaillées
./tsn stats --detailed
# Vérifier les mises à jour
./tsn update --check

# Mettre à jour
./tsn update --apply
# Sauvegarder la config
cp ~/.tsn/config.toml ~/.tsn/config.toml.bak

# Télécharger la nouvelle version
wget https://github.com/truststack/tsn/releases/download/v2.0.0/tsn-linux-amd64

# Remplacer et redémarrer
sudo systemctl stop tsn
cp tsn-linux-amd64 /usr/local/bin/tsn
sudo systemctl start tsn
# Générer un rapport
./tsn bug-report > tsn-bug-report.txt

# Avec logs
./tsn bug-report --include-logs --last-hours 24