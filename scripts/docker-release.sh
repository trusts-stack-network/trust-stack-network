#!/usr/bin/env bash
set -euo pipefail

# Script idempotent pour release Docker + signature
IMAGE="ghcr.io/truststacknetwork/tsn"
VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2)
TAG="${IMAGE}:${VERSION}"

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag "${TAG}" \
  --tag "${IMAGE}:latest" \
  --push \
  .

# Génération checksums
docker pull "${TAG}"
DIGEST=$(docker inspect "${TAG}" --format='{{index .RepoDigests 0}}')
echo "Digest: ${DIGEST}" > release-docker.txt

cosign sign --yes "${TAG}"
echo "Image signée et poussée : ${TAG}"