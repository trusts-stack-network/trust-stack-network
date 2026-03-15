#!/bin/bash
set -euo pipefail

# Déployer l'image Docker sur un serveur distant
ssh user@host "docker pull ${{ secrets.DOCKER_USERNAME }}/tsn:latest"
ssh user@host "docker run -d -p 8080:8080 ${{ secrets.DOCKER_USERNAME }}/tsn:latest"