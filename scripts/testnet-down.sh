#!/usr/bin/env bash
set -euo pipefail

# Arrête le testnet local
# Usage: ./scripts/testnet-down.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

cd "$ROOT_DIR"
docker compose -f docker-compose.yml down --volumes
echo "Testnet TSN arrêté."