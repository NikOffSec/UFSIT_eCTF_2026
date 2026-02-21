"""
Author: Ben Janis
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import argparse
import json
import secrets as pysecrets
from pathlib import Path

from loguru import logger


def gen_secrets(groups: list[int]) -> bytes:
    """Generate the contents secrets file.

    This file is used by the build system and is not exposed to attackers.

    We store:
      - schema/version info
      - the valid deployment groups
      - a deployment master key (hex-encoded)
      - a dedicated GMAC key (hex-encoded) [optional but convenient]

    :param groups: List of permission groups valid in this deployment
    :returns: bytes for the secrets file
    """
    # Normalize groups for determinism and sanity
    norm_groups = sorted(set(int(g) & 0xFFFF for g in groups))

    # Generate cryptographic secret material
    # 16 bytes = AES-128 key size
    k_master = pysecrets.token_bytes(16)

    # Option A (simple): use a separate random GMAC key directly
    # This is fine for a first implementation.
    k_gmac = pysecrets.token_bytes(16)

    # Option B (better later): derive k_gmac from k_master with a KDF
    # For now, keep it simple and explicit.

    secrets_obj = {
        "version": 1,
        "format": "ectf26-secrets-json",
        "groups": norm_groups,
        "crypto": {
            "aes_key_bytes": 16,
            "gmac_key_hex": k_gmac.hex(),
            "master_key_hex": k_master.hex(),
        },
    }

    # Compact JSON makes debugging easier while staying deterministic-ish
    return json.dumps(secrets_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def parse_args():
    """Define and parse the command line arguments."""
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

    # Debug only; consider removing in production if you don't want secrets in logs.
    logger.debug(f"Generated secrets: {secrets_blob}")

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets_blob)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()