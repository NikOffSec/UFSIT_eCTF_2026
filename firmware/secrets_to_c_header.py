"""
Author: Samuel Meyers
Date: 2026

This source file is part of an example system for MITRE's 2026 Embedded CTF
(eCTF). This code is being provided only for educational purposes for the 2026 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2026 The MITRE Corporation
"""

import os
import json
import argparse
from dataclasses import dataclass


# Keep this in sync with firmware/inc/security.h
# (Reference starter code typically uses MAX_PERMS = 8)
MAX_PERMS = 8


@dataclass
class Permission:
    """Represents a permission for one group."""
    group_id: int = None
    read: bool = False
    write: bool = False
    receive: bool = False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string.

        Format: "<group_id>=<permission>" e.g. "1234=RWC"
        """
        group_id, perm_string = perms.split("=")

        if len(group_id) != 4:
            raise ValueError(f"Group ID must be 4 hex chars, got: {group_id}")
        if len(perm_string) != 3:
            raise ValueError(f"Permission string must be 3 chars, got: {perm_string}")

        perm_obj = cls(
            int(group_id, 16),
            read=(perm_string[0] == "R"),
            write=(perm_string[1] == "W"),
            receive=(perm_string[2] == "C"),
        )
        return perm_obj

    def serialize(self):
        ret = f"{self.group_id:04x}="
        for perm, shorthand in {"read": "R", "write": "W", "receive": "C"}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret


class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with."""
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a colon-separated string."""
        ret = cls()
        if perms.strip() == "":
            return ret

        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            entry = entry.strip()
            if not entry:
                continue
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ":".join(perm.serialize() for perm in self)


def _hex_to_c_array(hex_str: str) -> str:
    """Convert hex string -> C byte initializer string."""
    b = bytes.fromhex(hex_str)
    return ", ".join(f"0x{x:02x}" for x in b)


def _parse_secrets_blob(secrets_blob: bytes) -> dict:
    """Parse the gen_secrets() output (JSON bytes)."""
    try:
        data = json.loads(secrets_blob.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Failed to parse secrets blob as JSON: {e}")

    # Basic schema checks
    if not isinstance(data, dict):
        raise ValueError("Secrets blob JSON must be an object")

    if "groups" not in data:
        raise ValueError("Secrets blob missing 'groups'")

    if "crypto" not in data or not isinstance(data["crypto"], dict):
        raise ValueError("Secrets blob missing 'crypto' object")

    crypto = data["crypto"]

    if "gmac_key_hex" not in crypto:
        raise ValueError("Secrets blob missing crypto.gmac_key_hex")

    gmac_key = bytes.fromhex(crypto["gmac_key_hex"])
    if len(gmac_key) != 16:
        raise ValueError(f"GMAC key must be 16 bytes, got {len(gmac_key)}")

    # master_key_hex is optional for now
    if "master_key_hex" in crypto:
        mk = bytes.fromhex(crypto["master_key_hex"])
        if len(mk) != 16:
            raise ValueError(f"Master key must be 16 bytes, got {len(mk)}")

    return data


def _validate_permissions_against_groups(permissions: PermissionList, valid_groups: list[int]):
    """Ensure build-time PERMISSIONS only references deployment-supported groups."""
    valid = set(int(g) & 0xFFFF for g in valid_groups)

    seen = set()
    for p in permissions:
        gid = p.group_id & 0xFFFF

        if gid in seen:
            raise ValueError(f"Duplicate permission entry for group 0x{gid:04x}")
        seen.add(gid)

        if gid not in valid:
            raise ValueError(
                f"Permission group 0x{gid:04x} is not in deployment groups: "
                f"{', '.join(f'0x{g:04x}' for g in sorted(valid))}"
            )

    if len(permissions) > MAX_PERMS:
        raise ValueError(f"Too many permissions entries ({len(permissions)}), MAX_PERMS={MAX_PERMS}")


def secrets_to_c_header(
    permissions: PermissionList, path: str, hsm_pin: str, secrets: bytes
):
    # Parse deployment secrets from gen_secrets.py output
    secrets_data = _parse_secrets_blob(secrets)
    valid_groups = secrets_data["groups"]
    crypto = secrets_data["crypto"]

    _validate_permissions_against_groups(permissions, valid_groups)

    gmac_key_hex = crypto["gmac_key_hex"]
    gmac_key_c = _hex_to_c_array(gmac_key_hex)

    # Optional master key emission (useful if you want KDFs on-device later)
    master_key_hex = crypto.get("master_key_hex")
    master_key_c = _hex_to_c_array(master_key_hex) if master_key_hex else None

    os.makedirs(path, exist_ok=True)
    out_path = os.path.join(path, "secrets.h")

    with open(out_path, "w") as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")

        f.write('#include <stdint.h>\n')
        f.write('#include "security.h"\n\n')

        # HSM PIN (existing behavior)
        f.write(f'#define HSM_PIN "{hsm_pin}"\n\n')

        # Keys emitted from deployment secrets
        f.write("#define GMAC_KEY_LEN 16\n")
        f.write(f"static const uint8_t GMAC_KEY[GMAC_KEY_LEN] = {{{gmac_key_c}}};\n\n")

        if master_key_c is not None:
            f.write("#define MASTER_KEY_LEN 16\n")
            f.write(f"static const uint8_t MASTER_KEY[MASTER_KEY_LEN] = {{{master_key_c}}};\n\n")

        # Emit valid deployment groups too (optional, but useful for debugging/validation)
        groups_c = ", ".join(f"0x{(int(g) & 0xFFFF):04x}" for g in valid_groups)
        f.write(f"#define DEPLOYMENT_GROUP_COUNT {len(valid_groups)}\n")
        f.write(f"static const uint16_t DEPLOYMENT_GROUPS[DEPLOYMENT_GROUP_COUNT] = {{{groups_c}}};\n\n")

        # Permissions table compiled into firmware
        # Explicitly pad to MAX_PERMS so the array is deterministic and clear.
        f.write("const static group_permission_t global_permissions[MAX_PERMS] = {\n")

        for perm in permissions:
            f.write(
                f"\t{{0x{perm.group_id:04x}, "
                f"{str(perm.read).lower()}, "
                f"{str(perm.write).lower()}, "
                f"{str(perm.receive).lower()}}},\n"
            )

        for _ in range(MAX_PERMS - len(permissions)):
            # unused sentinel entry
            f.write("\t{0x0000, false, false, false},\n")

        f.write("};\n")
        f.write("\n#endif  // __SECRETS_H__\n")


if __name__ == "__main__":
    def parse_args():
        parser = argparse.ArgumentParser()

        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument(
            "permissions",
            type=str,
            help='List of colon-separated permissions. E.g., "1234=R--:4321=RWC"',
        )

        return parser.parse_args()

    args = parse_args()
    perms = PermissionList.deserialize(args.permissions)
    secrets_to_c_header(perms, "./inc/", args.hsm_pin, args.secrets.read())