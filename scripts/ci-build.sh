#!/usr/bin/env bash
set -euo pipefail

# Script idempotent pour build & test rapides en CI
TARGETS="${TARGETS:-x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu}"
RUST_VERSION="${RUST_VERSION:-1.78.0}"

docker buildx create --use --name tsn-multi || true

for target in $TARGETS; do
  tag="tsn:${GITHUB_SHA:0:7}-${target//\./-}"
  docker buildx build \
    --platform "linux/amd64,linux/arm64" \
    --build-arg RUST_VERSION="$RUST_VERSION" \
    --target runtime \
    --tag "$tag" \
    --push \
    .
  # Test rapide : healthcheck
  docker run --rm -d --name tsn-smoke "$tag"
  sleep 5
  docker exec tsn-smoke wget -qO- http://localhost:9944/health
  docker stop tsn-smoke
done