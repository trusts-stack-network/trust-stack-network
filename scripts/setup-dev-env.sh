#!/usr/bin/env bash
set -euo pipefail

# Script idempotent pour préparer l’environnement développeur local
# Usage: ./scripts/setup-dev-env.sh

# Vérification des outils
command -v docker >/dev/null 2>&1 || { echo "Docker requis"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "Rust requis"; exit 1; }

# Installation des outils manquants
if ! command -v cargo-audit &>/dev/null; then
    cargo install --locked cargo-audit
fi
if ! command -v cargo-deny &>/dev/null; then
    cargo install --locked cargo-deny
fi
if ! command -v cargo-outdated &>/dev/null; then
    cargo install --locked cargo-outdated
fi

# Pré-commit hook
HOOK=.git/hooks/pre-commit
cat > "$HOOK" <<'EOF'
#!/bin/bash
set -euo pipefail
cargo fmt --check
cargo clippy -- -D warnings
cargo test --locked
cargo audit
EOF
chmod +x "$HOOK"

echo "✅ Environnement développeur prêt"