# Docker – Trust Stack Network

## Build

## Testnet local

## CI
Chaque PR déclenche :
- Build multi-arch
- Tests d'intégration via docker-compose
- Vérification taille image

## Release
Les tags `v*` poussent automatiquement une image signée sur `ghcr.io/trust-stack-network/tsn-node`.