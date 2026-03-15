#!/usr/bin/env bash
set -euo pipefail

# Build local reproductible – Yuki.T
PLATFORM="${1:-linux/amd64}"
TAG="${2:-tsn:local}"

docker buildx build \
  --platform "$PLATFORM" \
  --tag "$TAG" \
  --load \
  --progress=plain \
  .

echo "✅ Image construite : $TAG"