#!/usr/bin/env bash
set -euo pipefail
# Smoke test rapide du container

IMAGE=${1:-"tsn:local"}
CONTAINER_NAME="tsn-smoke-$$"

cleanup() {
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "🔍 Smoke test de l'image $IMAGE"

docker run -d --name "$CONTAINER_NAME" "$IMAGE" --help >/dev/null
sleep 2
docker logs "$CONTAINER_NAME" | grep -q "Trust Stack Network" || {
    echo "❌ Le binaire ne s'est pas lancé correctement"
    exit 1
}
echo "✅ Container OK"