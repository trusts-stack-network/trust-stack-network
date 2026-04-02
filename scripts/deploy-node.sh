#!/bin/bash
set -euo pipefail

# Construction de l'image Docker
docker build -t tsn-node .

# Lancement du conteneur
docker run -d --name tsn-node -p 8080:8080 tsn-node