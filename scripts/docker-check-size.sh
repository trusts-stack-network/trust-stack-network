#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_TAG="${1:-tsn:testnet}"
MAX_SIZE_MB="${2:-150}"

size_bytes=$(docker images --format "{{.Size}}" "$IMAGE_TAG")
size_mb=$(numfmt --from=iec <<<"${size_bytes%??}")

if (( size_mb > MAX_SIZE_MB * 1024 * 1024 )); then
  echo "::error::Image $IMAGE_TAG = ${size_mb}MB > ${MAX_SIZE_MB}MB"
  exit 1
fi

echo "✅ Image size ${size_mb}MB ≤ ${MAX_SIZE_MB}MB"