#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Test rapide de l'image Docker locale
# ------------------------------------------------------------
IMAGE=${1:-tsn-node:0.1.0}

echo "==> Démarrage conteneur pour tests"
docker run --rm -d --name tsn-test -p 3030:3030 "${IMAGE}"

cleanup() {
  docker stop tsn-test || true
}
trap cleanup EXIT

echo "==> Attente health-check"
for i in {1..30}; do
  if curl -sf http://localhost:3030/health >/dev/null; then
    echo "✅ Health OK"
    exit 0
  fi
  sleep 2
done

echo "❌ Health-check échoué"
exit 1