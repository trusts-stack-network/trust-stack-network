#!/bin/bash
set -euo pipefail

# Installer les dépendances
sudo apt update
sudo apt install -y docker.io git

# Configurer Docker
sudo systemctl start docker
sudo systemctl enable docker

# Cloner le dépôt Git
git clone https://github.com/mytsn/tsn.git
cd tsn

# Construire l'image Docker
docker build -t mytsn .

# Exécuter le conteneur
docker run -p 8080:8080 mytsn