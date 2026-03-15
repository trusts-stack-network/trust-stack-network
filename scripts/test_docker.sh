#!/usr/bin/env bash
set -euo pipefail

# Tests rapides dans le container
echo "🔍 Vérification binaire…"
/usr/local/bin/tsn --version

echo "🔍 Vérification genesis…"
test -f /etc/tsn/genesis.json

echo "🔍 Vérification user…"
test "$(id -u)" = "10000"

echo "✅ Container OK"