#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR/.."

echo "🧪 Test du testnet local TSN..."

for i in {0..1}; do
  PORT=$((8080 + i))
  URL="http://localhost:$PORT/health"
  echo "Attente santé nœud $i sur $URL..."
  for retry in {1..30}; do
    if curl -sf "$URL" > /dev/null; then
      echo "✅ Nœud $i prêt"
      break
    fi
    sleep 2
  done
done

echo "Vérification consensus..."
HEIGHT=$(curl -sf http://localhost:8080/block/height)
if [[ -z "$HEIGHT" || "$HEIGHT" -eq 0 ]]; then
  echo "❌ Hauteur de bloc invalide : $HEIGHT"
  exit 1
fi

echo "Test TX..."
RESPONSE=$(curl -sf http://localhost:8080/tx/submit \
  -H "Content-Type: application/json" \
  -d '{"from":"0x123","to":"0x456","value":42}')
if [[ "$RESPONSE" != *"tx_hash"* ]]; then
  echo "❌ Échec soumission TX : $RESPONSE"
  exit 1
fi

echo "✅ Testnet local OK"