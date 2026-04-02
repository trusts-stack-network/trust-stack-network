#!/usr/bin/env bash
set -euo pipefail
# ------------------------------------------------------------
# Build local Docker image (multi-arch) + size check
# ------------------------------------------------------------
IMAGE=tsn-node:local
PLATFORM="${PLATFORM:-linux/amd64}"

echo "Building $IMAGE for $PLATFORM…"
docker buildx build \
  --platform "$PLATFORM" \
  --tag "$IMAGE" \
  --load \
  --target runtime \
  .

SIZE=$(docker images -f reference="$IMAGE" --format "{{.Size}}")
echo "Built $IMAGE size = $SIZE"

# Fail if image > 50 MiB
MAX_MB=50
SIZE_MB=$(docker images -f reference="$IMAGE" --format "{{.Size}}" | awk '{print $1}' | numfmt --from=iec --to-unit=M)
if (( SIZE_MB > MAX_MB )); then
  echo "❌ Image trop grosse : ${SIZE_MB}M > ${MAX_MB}M"
  exit 1
fi
echo "✅ Taille image OK"