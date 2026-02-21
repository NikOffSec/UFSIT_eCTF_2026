"""
Author: Ben Janis
Date: 2026
Modified for eCTF Key Generation
"""

import argparse
import json
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
    """Generate the contents secrets file"""

    group_crypto_data = {}

    for group_id in groups:
        priv_hex, pub_hex = generate_key_pair()


        group_crypto_data[str(group_id)] = {
            "private_key": priv_hex,
            "public_key": pub_hex
        }

    aes_bytes = os.urandom(16)
    aes_bytes = aes_bytes.hex()

    secrets = {
        "groups": groups,
        "group_keys": group_crypto_data,
        "aes_bytes": aes_bytes,
    }

    return json.dumps(secrets, indent=4).encode()


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
    """Main function of gen_secrets"""
    args = parse_args()

    secrets = gen_secrets(args.groups)

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
