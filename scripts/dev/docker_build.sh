#!/usr/bin/env bash
set -euo pipefail
# Build local rapide – sans push
IMAGE="tsn-node:local"
docker buildx build \
  --platform linux/amd64 \
  --tag "$IMAGE" \
  --load \
  .
echo "✅ Image construite : $IMAGE"
docker images "$IMAGE" --format "table {{.Repository}}:{{.Tag}} {{.Size}}"