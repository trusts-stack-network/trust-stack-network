#!/usr/bin/env bash
set -euo pipefail

# Génération idempotente des configs toml pour testnet local

NODES=${1:-3}
DIR=$(cd "$(dirname "$0")" && pwd)

for i in $(seq 0 $((NODES - 1))); do
  mkdir -p "${DIR}/node${i}"
  cat >"${DIR}/node${i}/config.toml" <<EOF
# TSN testnet node${i}
network = "testnet"
p2p_port = 30303
rpc_port = 9944
data_dir = "/data/db"

[consensus]
pow = true
mine = true

[rpc]
cors = ["*"]
interfaces = ["0.0.0.0"]
EOF
done