#!/usr/bin/env bash
set -euo pipefail

# Vérifie que l'image finale ne dépasse pas 50 MiB
LIMIT_MB=50
SIZE_BYTES=$(docker images tsn-node --format "{{.Size}}" | head -1 | awk '{print $1}')
SIZE_MB=$(numfmt --from=iec "$SIZE_BYTES" | awk '{print int($1/1024/1024)}')

if (( SIZE_MB > LIMIT_MB )); then
  echo "❌ Image size $SIZE_MB MiB exceeds limit $LIMIT_MB MiB"
  exit 1
fi
echo "✅ Image size $SIZE_MB MiB under limit"