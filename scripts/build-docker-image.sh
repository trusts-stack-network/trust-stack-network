#!/bin/bash
set -euo pipefail

# Construit l'image Docker
docker build -t tsn-node .