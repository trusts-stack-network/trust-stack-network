#!/usr/bin/env python3
"""Sign a TSN release binary with Ed25519.

Usage:
    python3 tools/sign-release.py <binary.tar.gz> [--key /path/to/release_signing.key]

Produces:
    <binary.tar.gz>.sig    — hex-encoded Ed25519 signature of SHA256(binary)
    <binary.tar.gz>.sha256 — SHA256 checksum
"""

import sys
import hashlib
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: pip install cryptography")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Sign a TSN release binary")
    parser.add_argument("binary", help="Path to the release archive")
    parser.add_argument("--key", default="keys/release_signing.key",
                        help="Path to Ed25519 private key (PEM)")
    args = parser.parse_args()

    binary_path = Path(args.binary)
    key_path = Path(args.key)

    if not binary_path.exists():
        print(f"Error: {binary_path} not found")
        sys.exit(1)
    if not key_path.exists():
        print(f"Error: {key_path} not found")
        sys.exit(1)

    # Read binary and compute SHA256
    data = binary_path.read_bytes()
    sha256 = hashlib.sha256(data).hexdigest()
    print(f"SHA256: {sha256}")
    print(f"Size:   {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)")

    # Load private key
    key_pem = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_pem, password=None)

    # Sign the SHA256 hash bytes
    hash_bytes = hashlib.sha256(data).digest()
    signature = private_key.sign(hash_bytes)
    sig_hex = signature.hex()
    print(f"Signature: {sig_hex[:32]}...")

    # Verify with public key
    public_key = private_key.public_key()
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(f"Public key: {pub_raw.hex()}")

    try:
        public_key.verify(signature, hash_bytes)
        print("Verification: OK")
    except Exception as e:
        print(f"Verification FAILED: {e}")
        sys.exit(1)

    # Write outputs
    sha_path = binary_path.with_suffix(binary_path.suffix + ".sha256")
    sig_path = binary_path.with_suffix(binary_path.suffix + ".sig")

    sha_path.write_text(f"{sha256}  {binary_path.name}\n")
    sig_path.write_text(sig_hex + "\n")

    print(f"\nWritten: {sha_path}")
    print(f"Written: {sig_path}")


if __name__ == "__main__":
    main()
