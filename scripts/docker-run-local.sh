#!/usr/bin/env bash
set -euo pipefail

# Run local 2-node testnet via docker-compose
# Usage: ./scripts/docker-run-local.sh [up|down|logs]

CMD="${1:-up}"

case "$CMD" in
  up)
    docker compose -f docker-compose.yml up --build -d
    echo "Local testnet started. RPC ports: 9944/9945"
    ;;
  down)
    docker compose -f docker-compose.yml down -v
    ;;
  logs)
    docker compose -f docker-compose.yml logs -f
    ;;
  *)
    echo "Usage: $0 [up|down|logs]"
    exit 1
    ;;
esac