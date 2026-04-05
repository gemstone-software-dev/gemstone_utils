# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/crypto.py

from __future__ import annotations

import os
from base64 import urlsafe_b64encode, urlsafe_b64decode
from typing import Any, Callable, Dict, Final, Mapping, NamedTuple, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---- KEK derivation ---------------------------------------------------------

# OWASP-style order of magnitude for PBKDF2-HMAC-SHA256 when params omit iterations
# (used by key_mgmt persisted KDF defaults).
DEFAULT_PBKDF2_ITERATIONS_STRONG = 600_000


def derive_pbkdf2_hmac_sha256(
    passphrase: str,
    salt: bytes,
    *,
    iterations: int,
    length: int = 32,
) -> bytes:
    """
    Derive key bytes using cryptography's PBKDF2HMAC (SHA-256).
    """
    if not isinstance(passphrase, str):
        raise TypeError("passphrase must be a str")
    if not isinstance(salt, (bytes, bytearray)):
        raise TypeError("salt must be bytes")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


# ---- AES-GCM primitives -----------------------------------------------------


def aesgcm_encrypt(dk: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
    aesgcm = AESGCM(dk)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def aesgcm_decrypt(dk: bytes, blob: bytes, aad: Optional[bytes] = None) -> bytes:
    if len(blob) < 12 + 16:
        raise ValueError("ciphertext blob too short")

    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(dk)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ---- Symmetric algorithm registry -------------------------------------------


def _a256_validate_sym_params(params: Dict[str, Any]) -> None:
    if params:
        raise ValueError(f"A256GCM does not accept algorithm parameters (got {params!r})")


def _a256_encrypt_impl(
    key: bytes, plaintext: bytes, _params: Dict[str, Any]
) -> Tuple[bytes, Dict[str, Any]]:
    return aesgcm_encrypt(key, plaintext), {}


def _a256_decrypt_impl(key: bytes, ciphertext: bytes, _params: Dict[str, Any]) -> bytes:
    return aesgcm_decrypt(key, ciphertext)


class SymAlgSpec(NamedTuple):
    """Registered symmetric algorithm: key size, param validation, and crypto ops."""

    key_length: int
    validate_sym_params: Callable[[Dict[str, Any]], None]
    encrypt_impl: Callable[[bytes, bytes, Dict[str, Any]], Tuple[bytes, Dict[str, Any]]]
    decrypt_impl: Callable[[bytes, bytes, Dict[str, Any]], bytes]


SYM_ALG_REGISTRY: Dict[str, SymAlgSpec] = {
    "A256GCM": SymAlgSpec(
        key_length=32,
        validate_sym_params=_a256_validate_sym_params,
        encrypt_impl=_a256_encrypt_impl,
        decrypt_impl=_a256_decrypt_impl,
    ),
}

RECOMMENDED_DATA_ALG: Final[str] = "A256GCM"
assert RECOMMENDED_DATA_ALG in SYM_ALG_REGISTRY

SUPPORTED_SYM_ALGS: frozenset[str] = frozenset(SYM_ALG_REGISTRY.keys())


def is_supported_sym_alg(alg: str) -> bool:
    return alg in SYM_ALG_REGISTRY


def sym_alg_key_length(alg: str) -> int:
    spec = SYM_ALG_REGISTRY.get(alg)
    if spec is None:
        raise ValueError(f"Unsupported symmetric alg: {alg}")
    return spec.key_length


def recommended_data_alg() -> str:
    """
    Symmetric algorithm id recommended for **new** application field encryption.

    Matches the default for :attr:`~gemstone_utils.types.KeyContext.alg` and
    persisted :attr:`~gemstone_utils.sqlalchemy.key_storage.GemstoneKeyRecord.data_alg`.
    """
    return RECOMMENDED_DATA_ALG


def generate_key_by_alg(alg: str) -> bytes:
    """Return ``os.urandom(key_length)`` for the registered algorithm."""
    return os.urandom(sym_alg_key_length(alg))


def encrypt_alg(
    alg: str,
    key: bytes,
    plaintext: bytes,
    params: Optional[Mapping[str, Any]] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """
    Encrypt with a registered symmetric algorithm.

    Returns ``(ciphertext, updated_params)``. Callers persist ``updated_params``
    in the wire JSON segment when nonces or metadata are stored outside the blob.
    """
    spec = SYM_ALG_REGISTRY.get(alg)
    if spec is None:
        raise ValueError(f"Unsupported symmetric alg: {alg}")
    p = dict(params) if params is not None else {}
    spec.validate_sym_params(p)
    return spec.encrypt_impl(key, plaintext, p)


def decrypt_alg(
    alg: str,
    key: bytes,
    ciphertext: bytes,
    params: Optional[Mapping[str, Any]] = None,
) -> bytes:
    spec = SYM_ALG_REGISTRY.get(alg)
    if spec is None:
        raise ValueError(f"Unsupported symmetric alg: {alg}")
    p = dict(params) if params is not None else {}
    spec.validate_sym_params(p)
    return spec.decrypt_impl(key, ciphertext, p)


def encrypt_with_alg(alg: str, key: bytes, plaintext: bytes) -> bytes:
    """Backward-compatible: same as ``encrypt_alg`` but returns ciphertext only."""
    blob, _params = encrypt_alg(alg, key, plaintext, None)
    return blob


def decrypt_with_alg(alg: str, key: bytes, blob: bytes) -> bytes:
    """Backward-compatible: decrypt with empty symmetric parameters."""
    return decrypt_alg(alg, key, blob, None)


# ---- Base64 helpers ---------------------------------------------------------


def b64encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return urlsafe_b64decode(data.encode("ascii"))
