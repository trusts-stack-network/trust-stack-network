#!/usr/bin/env bash
set -euo pipefail

# Lance un testnet local via docker-compose
# Usage: ./scripts/testnet-up.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

cd "$ROOT_DIR"
docker compose -f docker-compose.yml up --detach
echo "Testnet TSN démarré :"
echo "  RPC   : http://localhost:9944"
echo "  WS    : ws://localhost:9944"
echo "  Explorer: http://localhost:3000"