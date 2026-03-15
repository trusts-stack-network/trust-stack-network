# =============================================================================
# TSN (Trust Stack Network) - Dockerfile multi-stage
# =============================================================================
# Build reproductible avec versions fixées des dépendances
# =============================================================================

# -----------------------------------------------------------------------------
# STAGE 1: Builder
# Image avec tous les outils de compilation
# -----------------------------------------------------------------------------
FROM rust:1.75-slim-bookworm AS builder

# Versions fixées des outils
ARG CARGO_AUDIT_VERSION=0.18.3
ARG CARGO_DENY_VERSION=0.14.11
ARG CARGO_TARPAULIN_VERSION=0.27.3

# Installation des dépendances système
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libclang-dev \
    clang \
    cmake \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Création d'un utilisateur non-root pour le build
RUN useradd -m -u 1000 -s /bin/bash builder

# Configuration du répertoire de travail
WORKDIR /build

# Copie des fichiers de dépendances en premier (pour le cache)
COPY --chown=builder:builder Cargo.toml Cargo.lock ./
COPY --chown=builder:builder .cargo/ ./.cargo/

# Pré-compilation des dépendances (cache layer)
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -rf src

# Copie du code source
COPY --chown=builder:builder . .

# Build de l'application en mode release
RUN cargo build --release --locked

# Vérification du binaire
RUN ls -la target/release/tsn && \
    file target/release/tsn && \
    ldd target/release/tsn || true

# -----------------------------------------------------------------------------
# STAGE 2: Runtime
# Image minimale pour l'exécution
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# Installation des dépendances runtime minimales
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Création de l'utilisateur tsn
RUN groupadd -r tsn && useradd -r -g tsn -s /bin/false tsn

# Création des répertoires nécessaires
RUN mkdir -p /opt/tsn/data /opt/tsn/config /opt/tsn/logs && \
    chown -R tsn:tsn /opt/tsn

# Copie du binaire depuis le builder
COPY --from=builder /build/target/release/tsn /opt/tsn/bin/tsn

# Configuration des permissions
RUN chmod +x /opt/tsn/bin/tsn && \
    chown tsn:tsn /opt/tsn/bin/tsn

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

# Exposition des ports
EXPOSE 8080 30303

# Utilisateur non-root
USER tsn

# Répertoire de travail
WORKDIR /opt/tsn

# Point d'entrée
ENTRYPOINT ["/opt/tsn/bin/tsn"]

# Commande par défaut
CMD ["--config", "/opt/tsn/config/node.toml"]

# -----------------------------------------------------------------------------
# STAGE 3: Development (optionnel)
# Image avec outils de développement
# -----------------------------------------------------------------------------
FROM builder AS dev

# Installation des outils de développement
RUN cargo install cargo-watch cargo-audit@=${CARGO_AUDIT_VERSION} \
    cargo-deny@=${CARGO_DENY_VERSION} \
    cargo-tarpaulin@=${CARGO_TARPAULIN_VERSION}

# Configuration pour le développement
ENV RUST_BACKTRACE=1
ENV RUST_LOG=debug

WORKDIR /build

CMD ["cargo", "watch", "-x", "run"]

# -----------------------------------------------------------------------------
# STAGE 4: Distroless (optionnel, plus sécurisé)
# Image minimale sans shell
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12 AS distroless

# Copie du binaire
COPY --from=builder /build/target/release/tsn /tsn

# Copie des certificats CA
COPY --from=runtime /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Configuration
ENV RUST_LOG=info

# Health check (note: distroless n'a pas curl, utiliser une alternative)
# HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
#     CMD ["/tsn", "--version"] || exit 1

EXPOSE 8080 30303

USER nonroot:nonroot

ENTRYPOINT ["/tsn"]
