# =============================================================================
# TSN (Trust Stack Network) - Makefile
# Development and deployment automation
# =============================================================================

.PHONY: all build test check fmt clippy audit deny clean help
.PHONY: setup dev-install docker-build docker-run
.PHONY: bench bench-save bench-compare
.PHONY: deploy deploy-staging deploy-production rollback

# Default target
all: check test

# =============================================================================
# Development
# =============================================================================

## Setup development environment
setup:
	@echo "Setting up TSN development environment..."
	@./scripts/setup-dev.sh

## Install development dependencies
dev-install:
	@echo "Installing development tools..."
	@rustup component add rustfmt clippy
	@cargo install cargo-audit cargo-deny cargo-tarpaulin
	@cargo install cargo-criterion

## Build the project
build:
	@echo "Building TSN..."
	@cargo build --release

## Build with all features
build-all:
	@echo "Building TSN with all features..."
	@cargo build --release --all-features

# =============================================================================
# Testing
# =============================================================================

## Run all tests
test:
	@echo "Running all tests..."
	@./scripts/run-tests.sh

## Run quick tests only
test-quick:
	@echo "Running quick tests..."
	@./scripts/run-tests.sh --quick

## Run unit tests only
test-unit:
	@echo "Running unit tests..."
	@cargo test --lib

## Run integration tests only
test-integration:
	@echo "Running integration tests..."
	@cargo test --test '*'

## Run crypto tests only
test-crypto:
	@echo "Running crypto tests..."
	@cargo test crypto -- --nocapture

## Run consensus tests only
test-consensus:
	@echo "Running consensus tests..."
	@cargo test consensus -- --nocapture

## Generate test coverage report
coverage:
	@echo "Generating test coverage report..."
	@cargo tarpaulin --out Html --out Stdout

# =============================================================================
# Code Quality
# =============================================================================

## Run all checks (fmt, clippy, audit, deny)
check: fmt clippy audit deny

## Format code
fmt:
	@echo "Formatting code..."
	@cargo fmt

## Check formatting
fmt-check:
	@echo "Checking code formatting..."
	@cargo fmt -- --check

## Run clippy
clippy:
	@echo "Running clippy..."
	@cargo clippy --all-targets --all-features -- -D warnings

## Run security audit
audit:
	@echo "Running security audit..."
	@cargo audit

## Check dependencies with cargo-deny
deny:
	@echo "Checking dependencies..."
	@cargo deny check

# =============================================================================
# Benchmarks
# =============================================================================

## Run all benchmarks
bench:
	@echo "Running benchmarks..."
	@./scripts/bench.sh

## Save current results as baseline
bench-save:
	@echo "Saving benchmark baseline..."
	@./scripts/bench.sh --save-baseline main

## Compare against baseline
bench-compare:
	@echo "Comparing benchmarks..."
	@./scripts/bench.sh --compare main --ci-mode

## Run quick benchmarks
bench-quick:
	@echo "Running quick benchmarks..."
	@./scripts/bench.sh --quick

## Run crypto benchmarks only
bench-crypto:
	@echo "Running crypto benchmarks..."
	@./scripts/bench.sh --crypto-only

## Run consensus benchmarks only
bench-consensus:
	@echo "Running consensus benchmarks..."
	@./scripts/bench.sh --consensus-only

## List available benchmarks
bench-list:
	@echo "Available benchmarks:"
	@./scripts/bench.sh --list

## Open benchmark report
bench-report:
	@echo "Opening benchmark report..."
	@./scripts/bench.sh --open

# =============================================================================
# Docker
# =============================================================================

## Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t tsn:latest -f Dockerfile --target runtime .

## Build Docker image with cache
docker-build-cache:
	@echo "Building Docker image with cache..."
	@docker build -t tsn:latest -f Dockerfile --target runtime \
		--cache-from type=local,src=/tmp/.buildx-cache \
		--cache-to type=local,dest=/tmp/.buildx-cache .

## Run Docker container
docker-run:
	@echo "Running TSN in Docker..."
	@docker run -it --rm \
		-p 8080:8080 \
		-p 30303:30303 \
		-v tsn-data:/data/tsn \
		tsn:latest node --data-dir /data/tsn

## Run Docker container in dev mode
docker-dev:
	@echo "Running TSN in Docker (dev mode)..."
	@docker run -it --rm \
		-p 8080:8080 \
		-p 30303:30303 \
		-v "$(PWD):/workspace" \
		--entrypoint /bin/bash \
		tsn:builder

# =============================================================================
# Deployment
# =============================================================================

## Deploy to staging
deploy-staging:
	@echo "Deploying to staging..."
	@./scripts/deploy.sh --build staging

## Deploy to production
deploy-production:
	@echo "Deploying to production..."
	@./scripts/deploy.sh --build production

## Rollback staging
rollback-staging:
	@echo "Rolling back staging..."
	@./scripts/deploy.sh --rollback staging

## Rollback production
rollback-production:
	@echo "Rolling back production..."
	@./scripts/deploy.sh --rollback production

# Generic deploy target (requires ENV environment variable)
deploy:
ifndef ENV
	$(error ENV is not set. Use: make deploy ENV=staging)
endif
	@echo "Deploying to $(ENV)..."
	@./scripts/deploy.sh --build $(ENV)

# =============================================================================
# CI/CD
# =============================================================================

## Run CI checks locally
ci: fmt-check clippy test audit deny
	@echo "All CI checks passed!"

## Run full CI pipeline locally
ci-full: clean setup ci bench-compare
	@echo "Full CI pipeline completed!"

# =============================================================================
# Maintenance
# =============================================================================

## Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@cargo clean
	@rm -rf target/
	@rm -rf .bench-baseline/
	@rm -rf .rollback/

## Update dependencies
update:
	@echo "Updating dependencies..."
	@cargo update

## Check for outdated dependencies
outdated:
	@echo "Checking for outdated dependencies..."
	@cargo outdated -R

## Generate documentation
docs:
	@echo "Generating documentation..."
	@cargo doc --no-deps --open

# =============================================================================
# Help
# =============================================================================

## Show this help message
help:
	@echo "TSN (Trust Stack Network) - Available Commands"
	@echo ""
	@echo "Development:"
	@echo "  make setup          Setup development environment"
	@echo "  make dev-install    Install development tools"
	@echo "  make build          Build the project"
	@echo "  make build-all      Build with all features"
	@echo ""
	@echo "Testing:"
	@echo "  make test           Run all tests"
	@echo "  make test-quick     Run quick tests only"
	@echo "  make test-unit      Run unit tests only"
	@echo "  make test-crypto    Run crypto tests only"
	@echo "  make coverage       Generate test coverage report"
	@echo ""
	@echo "Code Quality:"
	@echo "  make check          Run all checks"
	@echo "  make fmt            Format code"
	@echo "  make clippy         Run clippy"
	@echo "  make audit          Run security audit"
	@echo "  make deny           Check dependencies"
	@echo ""
	@echo "Benchmarks:"
	@echo "  make bench          Run all benchmarks"
	@echo "  make bench-save     Save baseline"
	@echo "  make bench-compare  Compare against baseline"
	@echo "  make bench-crypto   Run crypto benchmarks"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-run     Run Docker container"
	@echo ""
	@echo "Deployment:"
	@echo "  make deploy-staging     Deploy to staging"
	@echo "  make deploy-production  Deploy to production"
	@echo "  make rollback-staging   Rollback staging"
	@echo ""
	@echo "CI/CD:"
	@echo "  make ci             Run CI checks locally"
	@echo "  make ci-full        Run full CI pipeline"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean          Clean build artifacts"
	@echo "  make update         Update dependencies"
	@echo "  make docs           Generate documentation"
