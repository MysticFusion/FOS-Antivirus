#!/usr/bin/env python3
"""
sign_model.py -- Ed25519-sign the ML model (forest.bin) at build/release time.

Usage:
    python scripts/sign_model.py
    python scripts/sign_model.py --model assets/models/forest.bin

Pipeline (MAP R-02):
    1. Read forest.bin
    2. Sign with the Ed25519 private key -> forest.bin.sig (raw 64 bytes)
    3. Print the public key C array to embed in src/engine/ml_engine.c

Key management:
    The private key lives in scripts/secrets/model_ed25519_private.pem and is
    NOT committed (see .gitignore). It is generated once on first run. The
    public key is hardcoded in the C binary; signatures are verified at
    runtime before the model is loaded.
"""

import argparse
import hashlib
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_or_create_key(path: str) -> Ed25519PrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    print(f"[NEW] generated private key -> {path} (keep this secret)")
    return key


def print_pubkey_c(key: Ed25519PrivateKey) -> None:
    pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print("[C] public key for src/engine/ml_engine.c:")
    print("static const uint8_t k_ed25519_pubkey[32] = {")
    for i in range(0, 32, 12):
        print("    " + ", ".join(f"0x{b:02x}" for b in pub[i : i + 12]) + ",")
    print("};")


def main() -> int:
    ap = argparse.ArgumentParser(description="Sign forest.bin with Ed25519")
    ap.add_argument(
        "--model",
        default=os.path.join(ROOT, "assets", "models", "forest.bin"),
        help="Path to the model file (default: assets/models/forest.bin)",
    )
    ap.add_argument("--out", default=None, help="Output .sig path (default: <model>.sig)")
    ap.add_argument(
        "--key",
        default=os.path.join(ROOT, "scripts", "secrets", "model_ed25519_private.pem"),
        help="Ed25519 private key PEM path",
    )
    args = ap.parse_args()

    model_path = os.path.abspath(args.model)
    if not os.path.exists(model_path):
        print(f"[FAIL] model not found: {model_path}")
        return 1

    with open(model_path, "rb") as f:
        model = f.read()

    key = load_or_create_key(args.key)
    signature = key.sign(model)

    out = os.path.abspath(args.out) if args.out else model_path + ".sig"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(signature)

    print(f"[OK] signed {model_path} ({len(model):,} bytes)")
    print(f"[OK] signature -> {out} ({len(signature)} bytes)")
    print(f"[OK] SHA-512(model) = {hashlib.sha512(model).hexdigest()}")

    build_sig = os.path.join(ROOT, "build", "ml", "models", "forest.bin.sig")
    if os.path.isdir(os.path.dirname(build_sig)):
        with open(build_sig, "wb") as f:
            f.write(signature)
        print(f"[OK] staged build copy -> {build_sig}")

    print_pubkey_c(key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
