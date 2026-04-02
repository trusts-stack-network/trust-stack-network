#!/usr/bin/env bash
set -euo pipefail
# Lance un testnet local via docker-compose

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

export TSN_IMAGE="${TSN_IMAGE:-ghcr.io/truststack/tsn-node:latest}"

docker compose -f docker-compose.testnet.yml down --volumes || true
docker compose -f docker-compose.testnet.yml up --remove-orphans