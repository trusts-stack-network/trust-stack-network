#!/usr/bin/env bash
set -euo pipefail
# Lance un testnet local via docker-compose

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"

cd "$ROOT_DIR"

export TSN_VERSION=${TSN_VERSION:-0.4.0}
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1

# Arrêt propre si déjà en cours
docker-compose down --volumes --remove-orphans 2>/dev/null || true

# Build et up
docker-compose up --build -d

echo "⏳ Attente santé nœud…"
timeout 60 bash -c 'until curl -sf http://localhost:9933/health; do sleep 2; done' || {
  docker-compose logs tsn-node
  exit 1
}

echo "✅ Testnet local prêt :"
echo "   RPC HTTP : http://localhost:9933"
echo "   RPC WS   : ws://localhost:9944"
echo "   Explorer : http://localhost:3000"

echo "Pour arrêter : docker-compose down --volumes"