#!/usr/bin/env bash
set -euo pipefail

# Lance un nœud temporaire pour tests
docker run --rm -it \
  --name tsn-test \
  -p 9944:9944 \
  -p 30333:30333 \
  tsn:local "$@"