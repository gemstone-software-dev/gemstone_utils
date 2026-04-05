# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/kdf/pbkdf2.py

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from gemstone_utils.crypto import (
    DEFAULT_PBKDF2_ITERATIONS_STRONG,
    b64decode,
    b64encode,
    derive_pbkdf2_hmac_sha256,
)

from ..registry import register_kdf

NAME = "pbkdf2-hmac-sha256"

DEFAULT_DERIVED_KEY_LENGTH = 32


def pbkdf2_params(
    salt: bytes,
    *,
    iterations: int = 200_000,
    length: int = DEFAULT_DERIVED_KEY_LENGTH,
) -> Dict[str, Any]:
    """
    Build a ``params`` dict for :func:`~gemstone_utils.key_mgmt.derive_kek`
    with explicit ``salt`` and PBKDF2 tuning.
    """
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")
    return {
        "kdf": NAME,
        "hash": "sha256",
        "salt": b64encode(bytes(salt)),
        "iterations": iterations,
        "length": length,
    }


def recommended_pbkdf2_params(salt: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Strong defaults for new PBKDF2-HMAC-SHA256 KDF rows (random 16-byte salt
    when ``salt`` is omitted).
    """
    if salt is None:
        salt = os.urandom(16)
    return pbkdf2_params(
        salt,
        iterations=DEFAULT_PBKDF2_ITERATIONS_STRONG,
        length=DEFAULT_DERIVED_KEY_LENGTH,
    )


@register_kdf(NAME)
def _derive_kek_pbkdf2_hmac_sha256(passphrase: str, params: Dict[str, Any]) -> bytes:
    salt_b64 = params.get("salt")
    if not salt_b64 or not isinstance(salt_b64, str):
        raise ValueError("KDF params require non-empty 'salt' (url-safe base64 string)")

    salt = b64decode(salt_b64)
    iterations = int(params.get("iterations", DEFAULT_PBKDF2_ITERATIONS_STRONG))
    length = int(params.get("length", DEFAULT_DERIVED_KEY_LENGTH))
    hash_name = params.get("hash", "sha256")
    if str(hash_name).lower() != "sha256":
        raise ValueError(
            f"Unsupported PBKDF2 hash {hash_name!r} (only 'sha256' is supported)"
        )

    return derive_pbkdf2_hmac_sha256(
        passphrase, salt, iterations=iterations, length=length
    )
