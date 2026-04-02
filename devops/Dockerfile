# syntax=docker/dockerfile:1.7
# Build reproductible pour nœud TSN (Rust)
# Versions fixées pour la reproductibilité
ARG RUST_VERSION=1.75
ARG ALPINE_VERSION=3.19
ARG BUILDER_IMAGE=rust:${RUST_VERSION}-alpine${ALPINE_VERSION}
ARG RUNTIME_IMAGE=alpine:${ALPINE_VERSION}

# ============================================================================
# Étape 1: Builder
# ============================================================================
FROM ${BUILDER_IMAGE} AS builder

# Métadonnées de build
ARG GIT_COMMIT
ARG GIT_VERSION
ARG BUILD_DATE
ARG TSN_VERSION=v0.1.0

# Variables d'environnement pour build reproductible
ENV RUSTFLAGS="-C target-feature=-crt-static" \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0 \
    RUST_BACKTRACE=1

WORKDIR /build

# Installation des dépendances système (versions fixées)
RUN apk add --no-cache --virtual .build-deps \
    git=2.43.0-r0 \
    make=4.4.1-r2 \
    gcc=13.2.1_git20231014-r0 \
    musl-dev=1.2.4_git20230717-r4 \
    linux-headers=6.5-r0 \
    ca-certificates=20240226-r0 \
    pkgconfig=2.1.1-r0 \
    && update-ca-certificates

# Copie des fichiers de dépendances pour le cache layer
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Download et compilation des dépendances
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release && \
    rm src/main.rs

# Copie du code source
COPY src/ src/
COPY fuzz/ fuzz/

# Build du binaire avec flags optimisés
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin tsn && \
    cp target/release/tsn /build/tsn

# Vérification du binaire
RUN /build/tsn --help && \
    file /build/tsn && \
    ls -la /build/tsn && \
    ldd /build/tsn || true

# ============================================================================
# Étape 2: Test runner (optionnel, pour CI)
# ============================================================================
FROM builder AS tester

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo test --release

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
      org.opencontainers.image.description="Trust Stack Network - Post-Quantum Blockchain Node" \
      org.opencontainers.image.version="${TSN_VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.source="https://github.com/tsn-network/tsn" \
      org.opencontainers.image.licenses="MIT"

# Installation des dépendances runtime minimales
RUN apk add --no-cache \
    ca-certificates=20240226-r0 \
    tzdata=2024a-r0 \
    curl=8.5.0-r0 \
    jq=1.7.1-r0 \
    libgcc=13.2.1_git20231014-r0 \
    && rm -rf /var/cache/apk/* /tmp/*

# Création utilisateur non-root
RUN addgroup -g ${GID} ${USER} && \
    adduser -u ${UID} -G ${USER} -D -s /bin/sh ${USER}

# Création des répertoires de données
RUN mkdir -p /data/tsn/{config,blocks,state,logs} && \
    chown -R ${USER}:${USER} /data

# Copie du binaire depuis le builder
COPY --from=builder --chown=${USER}:${USER} /build/tsn /usr/local/bin/tsn

# Configuration par défaut
COPY --chown=${USER}:${USER} devops/config/node.toml /data/tsn/config/node.toml

# Vérification sanité
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Permissions et sécurité
RUN chmod 755 /usr/local/bin/tsn && \
    chmod 644 /etc/ssl/cert.pem

USER ${USER}

# Exposition des ports
# 8080: API HTTP
# 9000: P2P Network
# 9001: RPC
# 9090: Prometheus metrics
EXPOSE 8080 9000 9001 9090

# Volumes pour persistance
VOLUME ["/data/tsn"]

# Configuration par défaut
ENV TSN_HOME=/data/tsn \
    TSN_CONFIG=/data/tsn/config/node.toml \
    TSN_HTTP_BIND="0.0.0.0:8080" \
    TSN_P2P_BIND="0.0.0.0:9000" \
    TSN_RPC_BIND="0.0.0.0:9001" \
    TSN_METRICS_BIND="0.0.0.0:9090" \
    RUST_LOG="info,tsn=debug"

ENTRYPOINT ["/usr/local/bin/tsn"]
CMD ["--config", "/data/tsn/config/node.toml"]