#!/usr/bin/env bash
set -euo pipefail

IMAGE=${1:-truststack/tsn-node:latest}
MAX_MB=${2:-120}

SIZE=$(docker images --format "{{.Size}}" "$IMAGE" | sed 's/MB.*//')
if [ "$(echo "$SIZE > $MAX_MB" | bc -l)" -eq 1 ]; then
  echo "❌ Image trop grosse : $SIZE MB > $MAX_MB MB"
  exit 1
fi
echo "✅ Taille OK : $SIZE MB"
