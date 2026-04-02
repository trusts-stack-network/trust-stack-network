#!/usr/bin/env bash
set -euo pipefail

# check-image-size.sh - vérifie la taille de l'image Docker
# Usage: check-image-size.sh <tag> <max_size_mb>

TAG=${1:-tsn-node:testnet}
MAX_SIZE_MB=${2:-100} # 100MB par défaut

SIZE_BYTES=$(docker images --format "{{.Size}}" "$TAG" | awk '{print $1}')
SIZE_MB=$((SIZE_BYTES / 1024 / 1024))

if [[ $SIZE_MB -gt $MAX_SIZE_MB ]]; then
    echo "❌ Image trop grosse: ${SIZE_MB}MB > ${MAX_SIZE_MB}MB"
    exit 1
else
    echo "✅ Image OK: ${SIZE_MB}MB"
fi