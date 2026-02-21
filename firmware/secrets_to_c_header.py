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


@dataclass
class Permission:
    """Represents a permission for one group
    """
    group_id: int=None
    read: bool=False
    write: bool=False
    receive: bool=False

    @classmethod
    def deserialize(cls, perms: str):
        """Create a Permission object from a string

        :param perm: A string representing a permission. The permission shall be a pair
            of group ID and permissions separated by an equal sign (e.g.,
            "<group_id>=<permission>"). The group ID shall be a 16-bit hexadecimal
            number padded with 0s to be a total of 4 characters with no preceding '0x'
            (e.g., 4b1d). The permission shall be a 3-character string where present
            permissions are represented by their opcode and absent permissions are
            represented by a '-' (e.g., "RWC", "RW-", "--C").
        """
        group_id, perm_string = perms.split('=')

        perm_obj = cls(
            int(group_id, 16),
            read = perm_string[0] == 'R',
            write = perm_string[1] == 'W',
            receive = perm_string[2] == 'C',
        )
        return perm_obj

    def serialize(self):
        ret = f'{self.group_id:04x}='
        for perm, shorthand in {'read': 'R', 'write': 'W', 'receive': 'C'}.items():
            ret += shorthand if getattr(self, perm) else "-"
        return ret

class PermissionList(list):
    """Represents a set of permissions that an HSM can be built with.
    """
    def __init__(self, *args):
        for item in args:
            if isinstance(item, Permission):
                self.append(item)

    @classmethod
    def deserialize(cls, perms: str):
        """Create a list of permission objects from a string
        representation

        :param perm: A string representing the permission set. The string shall be a
            colon-separated list of permissions (e.g., "<perm1>:<perm2>:<perm3>").

        :returns: An instance of `PermissionList`
        """
        ret = cls()
        permissions_strings = perms.split(":")
        for entry in permissions_strings:
            perm_obj = Permission.deserialize(entry)
            ret.append(perm_obj)
        return ret

    def serialize(self):
        return ':'.join(perm.serialize() for perm in self)

def hex_to_c_array(hex_str: str) -> str:
    bytes_list = [f"0x{hex_str[i:i+2]}" for i in range(0, len(hex_str), 2)]
    return ", ".join(bytes_list)


def secrets_to_c_header(
        permissions: PermissionList, path: str, hsm_pin: str, secrets_bytes: bytes
):
    try:
        secrets_data = json.loads(secrets_bytes.decode('utf-8'))
        group_keys = secrets_data.get("group_keys", {})
        aes_bytes = secrets_data.get("aes_bytes", "")

    except json.JSONDecodeError:
        print("Error: The secrets file is not valid.")
        return


    os.makedirs(path, exist_ok=True)
    header_path = os.path.join(path, "secrets.h")

    with open(header_path, 'w') as f:
        f.write("#ifndef __SECRETS_H__\n")
        f.write("#define __SECRETS_H__\n\n")
        f.write("#include <stdint.h>\n")
        f.write('#include "security.h"\n\n')


        f.write(f'#define HSM_PIN "{hsm_pin}"\n\n')

        sorted_group_ids = sorted(group_keys.keys(), key=lambda x: int(x))

        for gid in sorted_group_ids:
            keys = group_keys[gid]
            pub_hex = keys['public_key']
            priv_hex = keys['private_key']

            f.write(f"const uint8_t Group{gid}_Public[32] = {{ {hex_to_c_array(pub_hex)} }};\n")


            f.write(f"const uint8_t Group{gid}_Private[32] = {{ {hex_to_c_array(priv_hex)} }};\n")
            f.write("\n")

        f.write("const static group_permission_t global_permissions[] = {\n")
        for i, perm in enumerate(permissions):
            if (i == len(permissions)-1):
                f.write(
                    (f"\t{{{hex(perm.group_id)}, {str(perm.read).lower()}, "
                     f"{str(perm.write).lower()}, {str(perm.receive).lower()}}}\n")
                )
            else:
                f.write(
                    (f"\t{{{hex(perm.group_id)}, {str(perm.read).lower()}, "
                     f"{str(perm.write).lower()}, {str(perm.receive).lower()}}},\n")
                )
        f.write("};\n")


        f.write(f"uint8_t AES_KEY[16] = {{ {hex_to_c_array(aes_bytes)} }};\n")


        f.write("\n#endif  // __SECRETS_H__\n")
        f.close()

    #print out file contents
    #print("\nFile: ")
    with open(header_path, 'r') as f:
        content = f.read()
        print(content)

    print(f"Successfully wrote header to {header_path}")

if __name__ == '__main__':
    def parse_args():
        parser = argparse.ArgumentParser()
        parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to secrets file (JSON)")
        parser.add_argument("hsm_pin", type=str, help="User PIN for the HSM")
        parser.add_argument("permissions", type=str, help="List of colon-separated permissions. E.g., \"1234=R--:4321=RWC\"")
        return parser.parse_args()

    args = parse_args()

    perm_str = args.permissions if args.permissions else ""
    perms = PermissionList.deserialize(perm_str)

    secrets_to_c_header(perms, './inc/', args.hsm_pin, args.secrets.read())