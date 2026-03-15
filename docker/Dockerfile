# syntax=docker/dockerfile:1.7
# Build reproductible pour nœud TSN
# Versions fixées pour la reproductibilité
ARG GO_VERSION=1.22.3
ARG ALPINE_VERSION=3.19
ARG BUILDER_IMAGE=golang:${GO_VERSION}-alpine${ALPINE_VERSION}
ARG RUNTIME_IMAGE=alpine:${ALPINE_VERSION}

# ============================================================================
# Étape 1: Builder
# ============================================================================
FROM ${BUILDER_IMAGE} AS builder

# Métadonnées de build
ARG GIT_COMMIT
ARG GIT_VERSION
ARG BUILD_DATE
ARG TSN_VERSION=v1.2.0

# Variables d'environnement pour build reproductible
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    GO111MODULE=on \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org

WORKDIR /build

# Installation des dépendances système (versions fixées)
RUN apk add --no-cache --virtual .build-deps \
    git=2.43.0-r0 \
    make=4.4.1-r2 \
    gcc=13.2.1_git20231014-r0 \
    musl-dev=1.2.4_git20230717-r4 \
    linux-headers=6.5-r0 \
    ca-certificates=20240226-r0 \
    && update-ca-certificates

# Copie des fichiers de dépendances pour le cache layer
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# Copie du source
COPY . .

# Build du binaire avec flags reproductibles
# -ldflags pour build statique et informations de version
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "\
    -s -w \
    -extldflags '-static' \
    -X github.com/tsn-network/node/version.Version=${TSN_VERSION} \
    -X github.com/tsn-network/node/version.Commit=${GIT_COMMIT} \
    -X github.com/tsn-network/node/version.BuildDate=${BUILD_DATE} \
    " -o /build/bin/tsnd ./cmd/tsnd

# Vérification du binaire
RUN /build/bin/tsnd version --long && \
    file /build/bin/tsnd && \
    ls -la /build/bin/tsnd

# ============================================================================
# Étape 2: Test runner (optionnel, pour CI)
# ============================================================================
FROM builder AS tester

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test -v -race -coverprofile=coverage.out ./... && \
    go tool cover -html=coverage.out -o coverage.html

# ============================================================================
# Étape 3: Runtime minimal
# ============================================================================
FROM ${RUNTIME_IMAGE} AS runtime

# Arguments pour le runtime
ARG UID=1000
ARG GID=1000
ARG USER=tsn
ARG TSN_VERSION
ARG GIT_COMMIT

# Labels OCI standard
LABEL org.opencontainers.image.title="TSN Node" \
      org.opencontainers.image.description="Nœud Time-Sensitive Network" \
      org.opencontainers.image.version="${TSN_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.source="https://github.com/tsn-network/node" \
      org.opencontainers.image.licenses="MIT"

# Installation des dépendances runtime minimales
RUN apk add --no-cache \
    ca-certificates=20240226-r0 \
    tzdata=2024a-r0 \
    curl=8.5.0-r0 \
    jq=1.7.1-r0 \
    && rm -rf /var/cache/apk/* /tmp/*

# Création utilisateur non-root
RUN addgroup -g ${GID} ${USER} && \
    adduser -u ${UID} -G ${USER} -D -s /bin/sh ${USER}

# Création des répertoires de données
RUN mkdir -p /data/tsn/config /data/tsn/data /logs && \
    chown -R ${USER}:${USER} /data /logs

# Copie du binaire depuis le builder
COPY --from=builder --chown=${USER}:${USER} /build/bin/tsnd /usr/local/bin/tsnd

# Vérification santé
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD tsnd status --node http://localhost:26657 2>&1 | jq -e '.sync_info.catching_up == false' || exit 1

# Permissions et sécurité
RUN chmod 755 /usr/local/bin/tsnd && \
    chmod 644 /etc/ssl/cert.pem

USER ${USER}

# Exposition des ports
# 26656: P2P
# 26657: RPC
# 1317: API REST
# 9090: gRPC
# 26660: Prometheus metrics
EXPOSE 26656 26657 1317 9090 26660

# Volumes pour persistance
VOLUME ["/data/tsn"]

# Configuration par défaut
ENV TSN_HOME=/data/tsn \
    TSN_MONIKER="tsn-node" \
    TSN_CHAIN_ID="tsn-testnet-1" \
    TSN_RPC_LADDR="tcp://0.0.0.0:26657" \
    TSN_P2P_LADDR="tcp://0.0.0.0:26656" \
    TSN_GRPC_ADDRESS="0.0.0.0:9090" \
    TSN_API_ADDRESS="tcp://0.0.0.0:1317"

ENTRYPOINT ["/usr/local/bin/tsnd"]
CMD ["start", "--home", "/data/tsn"]