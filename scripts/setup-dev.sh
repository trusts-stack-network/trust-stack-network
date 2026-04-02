#!/bin/bash
# =============================================================================
# TSN Development Environment Setup Script
# Idempotent setup script for new developers
# =============================================================================

set -euo pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Versions requises
readonly REQUIRED_RUST_VERSION="1.75.0"
readonly REQUIRED_CARGO_VERSION="1.75.0"

# =============================================================================
# Logging
# =============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# =============================================================================
# Vérifications système
# =============================================================================

check_os() {
    log_step "Checking operating system..."

    case "$(uname -s)" in
        Linux*)     OS=Linux;;
        Darwin*)    OS=Mac;;
        CYGWIN*|MINGW*|MSYS*) OS=Windows;;
        *)          OS="UNKNOWN";;
    esac

    log_info "Detected OS: $OS"
}

check_dependencies() {
    log_step "Checking system dependencies..."

    local missing=()

    # Liste des dépendances requises
    local deps=("curl" "git" "make" "pkg-config" "openssl")

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done

    if [ ${#missing[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Please install them:"
        case "$OS" in
            Linux)
                if command -v apt-get >/dev/null 2>&1; then
                    echo "  sudo apt-get update && sudo apt-get install -y ${missing[*]}"
                elif command -v yum >/dev/null 2>&1; then
                    echo "  sudo yum install -y ${missing[*]}"
                elif command -v pacman >/dev/null 2>&1; then
                    echo "  sudo pacman -S ${missing[*]}"
                fi
                ;;
            Mac)
                echo "  brew install ${missing[*]}"
                ;;
        esac
        exit 1
    fi

    log_info "All system dependencies present ✓"
}

# =============================================================================
# Installation de Rust
# =============================================================================

install_rust() {
    log_step "Checking Rust installation..."

    if command -v rustc >/dev/null 2>&1; then
        local current_version=$(rustc --version | awk '{print $2}')
        log_info "Rust found: $current_version"

        # Vérifier la version minimale
        if [ "$(printf '%s\n' "$REQUIRED_RUST_VERSION" "$current_version" | sort -V | head -n1)" != "$REQUIRED_RUST_VERSION" ]; then
            log_warn "Rust version $current_version is older than required $REQUIRED_RUST_VERSION"
            log_info "Updating Rust..."
            rustup update
        else
            log_info "Rust version is sufficient ✓"
        fi
    else
        log_info "Rust not found. Installing..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$REQUIRED_RUST_VERSION"
        source "$HOME/.cargo/env"
    fi

    # Vérifier que cargo est disponible
    if ! command -v cargo >/dev/null 2>&1; then
        log_error "Cargo not found after installation"
        exit 1
    fi

    log_info "Rust/Cargo ready ✓"
}

install_rust_components() {
    log_step "Installing Rust components..."

    # Composants essentiels
    rustup component add rustfmt clippy

    # Toolchains additionnelles pour cross-compilation
    rustup target add x86_64-unknown-linux-musl
    rustup target add aarch64-unknown-linux-gnu

    log_info "Rust components installed ✓"
}

# =============================================================================
# Installation des outils Cargo
# =============================================================================

install_cargo_tools() {
    log_step "Installing Cargo tools..."

    # Liste des outils avec versions fixées
    declare -A tools=(
        ["cargo-audit"]="0.18.3"
        ["cargo-deny"]="0.14.11"
        ["cargo-tarpaulin"]="0.27.3"
        ["cargo-outdated"]="0.14.0"
        ["cargo-tree"]="0.29.0"
    )

    for tool in "${!tools[@]}"; do
        local version="${tools[$tool]}"
        log_info "Installing $tool@$version..."

        if cargo install --list | grep -q "^$tool v$version"; then
            log_info "$tool@$version already installed ✓"
        else
            cargo install "$tool@$version" || {
                log_warn "Failed to install $tool, continuing..."
            }
        fi
    done

    log_info "Cargo tools installed ✓"
}

# =============================================================================
# Configuration du projet
# =============================================================================

setup_project() {
    log_step "Setting up project..."

    # Vérifier que nous sommes dans le bon répertoire
    if [ ! -f "Cargo.toml" ]; then
        log_error "Cargo.toml not found. Please run this script from the project root."
        exit 1
    fi

    # Créer les répertoires nécessaires
    mkdir -p data logs config

    # Rendre les scripts exécutables
    chmod +x scripts/*.sh 2>/dev/null || true

    log_info "Project directories created ✓"
}

# =============================================================================
# Vérification du build
# =============================================================================

verify_build() {
    log_step "Verifying build..."

    # Check du formatage
    log_info "Checking formatting..."
    cargo fmt -- --check || {
        log_warn "Code formatting issues found. Run 'cargo fmt' to fix."
    }

    # Clippy
    log_info "Running clippy..."
    cargo clippy --all-targets --all-features -- -D warnings 2>&1 || {
        log_warn "Clippy found issues. Please review."
    }

    # Build de test
    log_info "Running test build..."
    cargo check --all-targets || {
        log_error "Build failed. Please check the errors above."
        exit 1
    }

    log_info "Build verification complete ✓"
}

# =============================================================================
# Configuration Git
# =============================================================================

setup_git() {
    log_step "Setting up Git hooks..."

    # Hook pre-commit
    cat > .git/hooks/pre-commit <<'EOF'
#!/bin/bash
# Pre-commit hook for TSN

set -e

echo "Running pre-commit checks..."

# Format check
cargo fmt -- --check || {
    echo "❌ Formatting check failed. Run 'cargo fmt' to fix."
    exit 1
}

# Clippy check
cargo clippy --all-targets --all-features -- -D warnings || {
    echo "❌ Clippy check failed."
    exit 1
}

# Tests rapides
cargo test --lib --quiet || {
    echo "❌ Tests failed."
    exit 1
}

echo "✅ Pre-commit checks passed"
EOF

    chmod +x .git/hooks/pre-commit
    log_info "Git hooks configured ✓"
}

# =============================================================================
# Message de bienvenue
# =============================================================================

print_welcome() {
    echo ""
    echo "========================================"
    echo "  TSN Development Environment Ready!"
    echo "========================================"
    echo ""
    echo "Available commands:"
    echo "  cargo build          - Build the project"
    echo "  cargo test           - Run tests"
    echo "  cargo bench          - Run benchmarks"
    echo "  cargo fmt            - Format code"
    echo "  cargo clippy         - Run linter"
    echo "  cargo audit          - Check for security advisories"
    echo "  cargo deny check     - Check licenses and advisories"
    echo ""
    echo "Scripts:"
    echo "  ./scripts/perf-check.sh    - Check performance"
    echo "  ./scripts/setup-node.sh    - Setup a TSN node"
    echo ""
    echo "Documentation:"
    echo "  README.md              - Project overview"
    echo "  CONTRIBUTING.md        - Contribution guidelines"
    echo ""
}

# =============================================================================
# Fonction principale
# =============================================================================

main() {
    echo "========================================"
    echo "TSN Development Environment Setup"
    echo "========================================"
    echo ""

    check_os
    check_dependencies
    install_rust
    install_rust_components
    install_cargo_tools
    setup_project
    verify_build
    setup_git

    print_welcome

    log_info "Setup complete! You're ready to contribute to TSN."
}

# Exécution
main "$@"
