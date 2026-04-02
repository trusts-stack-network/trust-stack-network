#!/usr/bin/env bash
set -euo pipefail
# Stats rapides sur l'image produite
IMAGE=${1:-ghcr.io/trust-stack/tsn:latest}

docker pull -q "${IMAGE}"
SIZE=$(docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}" | grep "${IMAGE}" | awk '{print $2}' || echo "N/A")
echo "Image size : ${SIZE}"

docker run --rm --entrypoint /usr/local/bin/tsn "${IMAGE}" --version