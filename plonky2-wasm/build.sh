#!/bin/bash
# Build script for the WASM prover
#
# Prerequisites:
#   cargo install wasm-pack
#   rustup target add wasm32-unknown-unknown
#
# Usage:
#   ./build.sh          # Build for web (default)
#   ./build.sh bundler  # Build for bundlers (webpack, etc.)
#   ./build.sh nodejs   # Build for Node.js

set -e

TARGET="${1:-web}"

echo "Building tsn-plonky2-wasm for target: $TARGET"
echo "================================================"

# Ensure we're using nightly (required by plonky2)
if ! rustup run nightly rustc --version > /dev/null 2>&1; then
    echo "Error: Nightly Rust is required. Install with: rustup install nightly"
    exit 1
fi

# Build with wasm-pack
wasm-pack build --target "$TARGET" --release

echo ""
echo "Build complete!"
echo "Output in: pkg/"
echo ""
echo "To use in a web project:"
echo "  1. Copy pkg/ to your project"
echo "  2. Import in JavaScript:"
echo "     import init, { WasmProver } from './pkg/tsn_plonky2_wasm.js';"
echo "     await init();"
echo "     const prover = new WasmProver();"
