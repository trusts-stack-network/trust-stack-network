#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Vérifie que l'image finale reste < 50 MiB
# ------------------------------------------------------------
IMAGE=${1:-tsn-node:0.1.0}
MAX_SIZE_MB=${2:-50}

SIZE_BYTES=$(docker images --format "{{.Size}}" "${IMAGE}" | numfmt --from=iec)
MAX_BYTES=$((MAX_SIZE_MB * 1024 * 1024))

if [ "$SIZE_BYTES" -gt "$MAX_BYTES" ]; then
  echo "❌ Image trop grosse : ${SIZE_BYTES} bytes > ${MAX_BYTES}"
  exit 1
fi

echo "✅ Taille image OK : ${SIZE_BYTES} bytes"