#!/usr/bin/env bash
set -euo pipefail

# Lance un nœud TSN en local (data dans ./data)
mkdir -p data
docker run --rm -it \
  --name tsn-local \
  -p 9944:9944 \
  -p 30303:30303 \
  -v "$(pwd)/data:/app/data" \
  tsn:latest \
  --base-path /app/data \
  --rpc-external --ws-external --rpc-cors all