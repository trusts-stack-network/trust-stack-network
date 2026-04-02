#!/bin/bash
set -euo pipefail

# Déployer le noeud TSN
docker run -d -p 8080:8080 mytsn