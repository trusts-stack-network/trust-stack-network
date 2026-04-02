#!/usr/bin/env bash
set -euo pipefail
# Vérifie que l'image Docker reste < 100 MB
IMAGE=${1:-tsn:testnet}
SIZE_BYTES=$(docker images --format "{{.Size}}" "$IMAGE" | numfmt --from=iec)
MAX=104857600  # 100 MB
if (( SIZE_BYTES > MAX )); then
  echo "❌ Image trop grosse : $SIZE_BYTES > $MAX bytes"
  exit 1
fi
echo "✅ Taille image OK : $SIZE_BYTES bytes"