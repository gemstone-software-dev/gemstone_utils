# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# emerald_utils/encrypted_fields.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from .crypto import encrypt_with_alg, decrypt_with_alg, b64encode, b64decode

ALG_ID = "A256GCM"  # field-level algorithm id


def is_encrypted_prefix(value: str) -> bool:
    return isinstance(value, str) and value.startswith(f"${ALG_ID}$")


def format_encrypted_field(keyid: int, blob: bytes) -> str:
    return f"${ALG_ID}${keyid}${b64encode(blob)}"


def parse_encrypted_field(value: str) -> Tuple[str, int, bytes]:
    parts = value.split("$")
    if len(parts) != 4 or parts[0] != "":
        raise ValueError("invalid encrypted field format")

    alg_id = parts[1]
    keyid = int(parts[2])
    blob = b64decode(parts[3])
    return alg_id, keyid, blob


@dataclass
class KeyContext:
    keyid: int
    dk: bytes
    alg: str = ALG_ID  # field-level alg; can be extended later


def encrypt_string(plaintext: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if plaintext is None:
        return None
    blob = encrypt_with_alg(keyctx.alg, keyctx.dk, plaintext.encode("utf-8"))
    return format_encrypted_field(keyctx.keyid, blob)


def decrypt_string(value: Optional[str], keyctx: KeyContext) -> Optional[str]:
    if value is None:
        return None

    alg_id, keyid, blob = parse_encrypted_field(value)

    if alg_id != keyctx.alg:
        raise ValueError(f"unsupported algorithm: {alg_id}")
    if keyid != keyctx.keyid:
        raise ValueError(f"unexpected keyid {keyid}")

    return decrypt_with_alg(keyctx.alg, keyctx.dk, blob).decode("utf-8")
