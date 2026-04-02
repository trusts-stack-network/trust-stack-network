# TSN CI/CD Pipeline

Ce répertoire contient les workflows GitHub Actions et configurations pour le pipeline CI/CD de Trust Stack Network (TSN).

## Workflows

### 1. CI (`ci.yml`)

Exécuté sur chaque push et pull request.

**Jobs:**
- `fmt`: Vérification du formatage avec rustfmt
- `clippy`: Analyse statique avec Clippy
- `test`: Tests unitaires et d'intégration
- `audit`: Audit de sécurité des dépendances
- `deny`: Vérification des licences et sources
- `build`: Compilation pour toutes les targets

**Déclencheurs:**
- Push sur `main` et `develop`
- Pull requests
- Workflow dispatch manuel

### 2. Release (`release.yml`)

Exécuté lors de la création d'un tag `v*`.

**Jobs:**
- `build`: Compilation cross-platform
- `test`: Tests complets
- `security`: Audit et vérifications de sécurité
- `release`: Création de la release GitHub avec artefacts
- `docker`: Build et push des images Docker

**Artefacts générés:**
- Binaires pour Linux x86_64, ARM64, RISC-V
- Images Docker multi-arch
- Checksums SHA256
- Documentation

### 3. Deploy (`deploy.yml`)

Déploiement automatique sur les nœuds TSN.

**Jobs:**
- `deploy-seed`: Déploiement sur les nœuds seed
- `deploy-nodes`: Déploiement sur les nœuds réguliers
- `verify`: Vérification post-déploiement
- `rollback`: Rollback automatique en cas d'échec

**Stratégie de déploiement:**
- Déploiement progressif (canary)
- Health checks automatiques
- Rollback automatique sur échec

## Configuration

### Secrets requis

Les secrets suivants doivent être configurés dans GitHub:

| Secret | Description |
|--------|-------------|
| `DOCKER_USERNAME` | Nom d'utilisateur Docker Hub |
| `DOCKER_PASSWORD` | Mot de passe Docker Hub |
| `DEPLOY_KEY_SEED_*` | Clés SSH pour les nœuds seed |
| `DEPLOY_KEY_NODE_*` | Clés SSH pour les nœuds réguliers |

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `CARGO_TERM_COLOR` | `always` | Couleurs dans les logs |
| `RUST_BACKTRACE` | `1` | Backtrace en cas d'erreur |

## Utilisation

### Déclencher manuellement le CI

```bash
gh workflow run ci.yml
```

### Créer une release

```bash
# Taguer la version
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# Le workflow release.yml se déclenche automatiquement
```

### Déployer manuellement

```bash
gh workflow run deploy.yml -f environment=staging
```

## Scripts associés

- `../scripts/setup-dev.sh`: Setup environnement de développement
- `../scripts/setup-node.sh`: Setup nœud TSN
- `../scripts/health-check.sh`: Vérification de santé
- `../scripts/perf-check.sh`: Tests de performance

## Docker

Le Dockerfile multi-stage permet de créer des images optimisées:

```bash
# Build
docker build -t tsn:latest .

# Run
docker run -p 8080:8080 -p 30303:30303 tsn:latest
```

## Makefile

Le Makefile à la racine fournit des commandes pratiques:

```bash
make help          # Afficher l'aide
make ci            # Exécuter tous les checks CI
make release-check # Vérifier la release
make docker-build  # Build Docker
```

## Dépannage

### Le CI échoue sur clippy

```bash
make clippy-fix    # Correction automatique
```

### Les tests sont lents

```bash
make test-lib      # Tests unitaires seulement
```

### Audit échoue

```bash
cargo audit        # Voir les détails
cargo update       # Mettre à jour les dépendances
```

## Contact

Pour toute question sur le pipeline CI/CD, contacter l'équipe DevOps.
