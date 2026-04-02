#!/bin/bash
set -euo pipefail

# Génération des checksums
docker build -t tsn-node .
docker save tsn-node -o tsn-node.tar
sha256sum tsn-node.tar > tsn-node.sha256