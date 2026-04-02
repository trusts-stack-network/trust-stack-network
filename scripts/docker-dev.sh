#!/usr/bin/env bash
set -euo pipefail

# Build local rapide sans cache multi-plateforme
docker buildx build \
  --load \
  --tag tsn:local \
  --file Dockerfile \
  .

echo "Image locale tsn:local construite. Lancer avec :"
echo "  docker run --rm -it tsn:local"