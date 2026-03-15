#!/bin/bash
set -euo pipefail

# Installation des dépendances
sudo apt-get update
sudo apt-get install -y docker.io docker-compose

# Configuration de Docker
sudo systemctl start docker
sudo systemctl enable docker

# Création du répertoire de données
mkdir -p data