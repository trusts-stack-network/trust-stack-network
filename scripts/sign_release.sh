#!/bin/bash
# Signs a release tarball with the Ed25519 private key.
#
# Usage: ./scripts/sign_release.sh <tarball>
# Output: prints the hex-encoded Ed25519 signature to stdout.
#
# Requirements:
#   - Python 3 with the 'cryptography' package (pip install cryptography)
#   - Private key at /opt/tsn/keys/release_signing.key (PEM format)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_FILE="${SCRIPT_DIR}/../keys/release_signing.key"

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tarball>" >&2
    exit 1
fi

TARBALL="$1"

if [ ! -f "$TARBALL" ]; then
    echo "Error: file not found: $TARBALL" >&2
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "Error: private key not found: $KEY_FILE" >&2
    exit 1
fi

# Compute SHA256 of the tarball
SHA256_HEX=$(sha256sum "$TARBALL" | cut -d' ' -f1)
echo "SHA256: $SHA256_HEX" >&2

# Sign the SHA256 hash with Ed25519 using Python
python3 -c "
import sys
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Read the private key
with open('${KEY_FILE}', 'rb') as f:
    key_data = f.read()

private_key = load_pem_private_key(key_data, password=None)
assert isinstance(private_key, Ed25519PrivateKey), 'Key is not Ed25519'

# The message to sign is the 32-byte SHA256 hash
sha256_bytes = bytes.fromhex('${SHA256_HEX}')
assert len(sha256_bytes) == 32

# Sign
signature = private_key.sign(sha256_bytes)
assert len(signature) == 64

# Output hex
print(signature.hex())
"
