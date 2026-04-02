# syntax=docker/dockerfile:1.6
# Image pour l'explorateur de blocs TSN
FROM node:20-slim AS builder

WORKDIR /app

# Copie des fichiers de dépendances
COPY wallet/package.json wallet/package-lock.json ./

# Installation des dépendances
RUN npm ci --only=production

# Copie du code source
COPY wallet ./

# Build de l'application
RUN npm run build

# Runtime minimal
FROM nginx:alpine

# Copie des fichiers buildés
COPY --from=builder /app/dist /usr/share/nginx/html

# Copie de la configuration nginx
COPY docker/nginx.conf /etc/nginx/nginx.conf

EXPOSE 3000

CMD ["nginx", "-g", "daemon off;"]