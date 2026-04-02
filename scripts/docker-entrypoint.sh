#!/usr/bin/env bash
set -euo pipefail

# Initialise le répertoire de données
mkdir -p "${TSN_DATA_DIR}"

# Génère un node-key aléatoire s'il n'existe pas
if [[ ! -f "${TSN_DATA_DIR}/node-key" ]]; then
  openssl rand -hex 32 > "${TSN_DATA_DIR}/node-key"
  chmod 600 "${TSN_DATA_DIR}/node-key"
fi

# Remplace les variables d'env dans le config.toml (gomplate ou envsubst)
if command -v envsubst >/dev/null 2>&1; then
  envsubst < "${TSN_CONFIG_FILE}.tpl" > "${TSN_CONFIG_FILE}"
fi

# Lance le nœud
exec /usr/local/bin/tsn-node \
  --base-path "${TSN_DATA_DIR}" \
  --config "${TSN_CONFIG_FILE}" \
  "$@"