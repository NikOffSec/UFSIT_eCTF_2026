"""
Author: Ben Janis
Date: 2026
Modified for eCTF Key Generation
"""

import argparse
import json
import secrets as pysecrets
import os
from pathlib import Path

from loguru import logger

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

def generate_key_pair():
    """
    Helper function to generate a single Ed25519 key pair.
    Returns tuple of hex strings: (private_key_hex, public_key_hex)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return private_bytes.hex(), public_bytes.hex()


def gen_secrets(groups: list[int]) -> bytes:
    """Generate deployment secrets JSON consumed by firmware build tooling.

    Includes:
      - deployment groups
      - GMAC/master keys (for message authentication / future KDF use)
      - AES key bytes (legacy/teammate compatibility)
      - per-group Ed25519 keypairs (for asymmetric identity/session work)
    """
    # Normalize groups for determinism and sanity
    norm_groups = sorted(set(int(g) & 0xFFFF for g in groups))

    # Symmetric crypto material
    k_master = pysecrets.token_bytes(16)   # AES-128 sized master
    k_gmac = pysecrets.token_bytes(16)     # AES-GMAC key
    aes_bytes = os.urandom(16)             # teammate compatibility key

    # Per-group asymmetric identity keys
    group_crypto_data = {}
    for group_id in norm_groups:
        priv_hex, pub_hex = generate_key_pair()
        group_crypto_data[str(group_id)] = {
            "private_key": priv_hex,
            "public_key": pub_hex,
        }

    secrets_obj = {
        "version": 2,
        "format": "ectf26-secrets-json",
        "groups": norm_groups,
        "crypto": {
            "aes_key_bytes": 16,
            "gmac_key_hex": k_gmac.hex(),
            "master_key_hex": k_master.hex(),
            "aes_bytes_hex": aes_bytes.hex(),
        },
        "group_keys": group_crypto_data,
    }

    return json.dumps(secrets_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_args():
    """Define and parse the command line arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "groups",
        nargs="+",
        type=lambda x: int(x, 0),
        help="Supported group IDs",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets."""
    args = parse_args()

    secrets_blob = gen_secrets(args.groups)

    # Optional debug: be careful not to leak in shared logs
    logger.debug(f"Generated secrets: {secrets_blob}")

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets_blob)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()