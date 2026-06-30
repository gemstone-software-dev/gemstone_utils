# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/crypto.py

"""Symmetric encryption registry, PBKDF2 primitive, and wire encoding helpers."""

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
#: OWASP-style iteration count for PBKDF2-HMAC-SHA256 persisted KDF defaults.
DEFAULT_PBKDF2_ITERATIONS_STRONG = 600_000


def derive_pbkdf2_hmac_sha256(
    passphrase: str,
    salt: bytes,
    *,
    iterations: int,
    length: int = 32,
) -> bytes:
    """Derive key bytes with PBKDF2-HMAC-SHA256.

    Args:
        passphrase: UTF-8 passphrase material.
        salt: Salt bytes.
        iterations: PBKDF2 iteration count.
        length: Derived key length in bytes.

    Returns:
        Derived key bytes.

    Raises:
        TypeError: If ``passphrase`` or ``salt`` has the wrong type.
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
#
# New symmetric algorithm ids must be added to _ALLOWED_SYM_ALG_NAMES in the same
# release as the implementation module (future optional extras under crypto/sym/).

_ALLOWED_SYM_ALG_NAMES: frozenset[str] = frozenset({"A256GCM"})
_SYM_ALG_REGISTRY: Dict[str, SymAlgSpec] = {}


def _register_sym_alg(name: str, spec: SymAlgSpec) -> None:
    if name not in _ALLOWED_SYM_ALG_NAMES:
        raise ValueError(f"symmetric algorithm {name!r} is not allowlisted")
    if name in _SYM_ALG_REGISTRY:
        raise ValueError(f"symmetric algorithm {name!r} already registered")
    _SYM_ALG_REGISTRY[name] = spec


def require_supported_sym_alg(alg: str) -> SymAlgSpec:
    spec = _SYM_ALG_REGISTRY.get(alg)
    if spec is None:
        raise ValueError(f"Unsupported symmetric alg: {alg}")
    return spec


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


_register_sym_alg(
    "A256GCM",
    SymAlgSpec(
        key_length=32,
        validate_sym_params=_a256_validate_sym_params,
        encrypt_impl=_a256_encrypt_impl,
        decrypt_impl=_a256_decrypt_impl,
    ),
)

#: Default symmetric algorithm id for new field encryption and ``data_alg`` rows.
RECOMMENDED_DATA_ALG: Final[str] = "A256GCM"
assert RECOMMENDED_DATA_ALG in _SYM_ALG_REGISTRY

#: Registered symmetric algorithm ids (read-only; use ``is_supported_sym_alg``).
SUPPORTED_SYM_ALGS: frozenset[str] = frozenset(_SYM_ALG_REGISTRY.keys())


def is_supported_sym_alg(alg: str) -> bool:
    """Return whether ``alg`` is a registered symmetric algorithm id.

    Args:
        alg: Algorithm id (for example ``"A256GCM"``).

    Returns:
        ``True`` if ``alg`` is registered.
    """
    return alg in _SYM_ALG_REGISTRY


def sym_alg_key_length(alg: str) -> int:
    """Return the required key length in bytes for a registered algorithm.

    Args:
        alg: Registered symmetric algorithm id.

    Returns:
        Key length in bytes.

    Raises:
        ValueError: If ``alg`` is not registered.
    """
    return require_supported_sym_alg(alg).key_length


def recommended_data_alg() -> str:
    """Return the symmetric algorithm id recommended for new field encryption.

    Matches the default for ``KeyContext.alg`` and ``GemstoneKeyRecord.data_alg``.

    Returns:
        Algorithm id string (currently ``RECOMMENDED_DATA_ALG``).
    """
    return RECOMMENDED_DATA_ALG


def generate_key_by_alg(alg: str) -> bytes:
    """Generate random key bytes sized for a registered algorithm.

    Args:
        alg: Registered symmetric algorithm id.

    Returns:
        ``os.urandom(key_length)`` for ``alg``.

    Raises:
        ValueError: If ``alg`` is not registered.
    """
    return os.urandom(sym_alg_key_length(alg))


def encrypt_alg(
    alg: str,
    key: bytes,
    plaintext: bytes,
    params: Optional[Mapping[str, Any]] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    """Encrypt with a registered symmetric algorithm.

    Args:
        alg: Registered symmetric algorithm id.
        key: Key bytes sized for ``alg``.
        plaintext: Plaintext bytes.
        params: Optional algorithm parameters (validated per algorithm).

    Returns:
        A tuple ``(ciphertext, updated_params)``. Persist ``updated_params`` in
        the wire JSON segment when nonces or metadata are stored outside the blob.

    Raises:
        ValueError: If ``alg`` is unsupported or ``params`` are invalid.
    """
    spec = require_supported_sym_alg(alg)
    p = dict(params) if params is not None else {}
    spec.validate_sym_params(p)
    return spec.encrypt_impl(key, plaintext, p)


def decrypt_alg(
    alg: str,
    key: bytes,
    ciphertext: bytes,
    params: Optional[Mapping[str, Any]] = None,
) -> bytes:
    """Decrypt with a registered symmetric algorithm.

    Args:
        alg: Registered symmetric algorithm id.
        key: Key bytes sized for ``alg``.
        ciphertext: Ciphertext blob.
        params: Optional algorithm parameters (validated per algorithm).

    Returns:
        Plaintext bytes.

    Raises:
        ValueError: If ``alg`` is unsupported or ``params`` are invalid.
    """
    spec = require_supported_sym_alg(alg)
    p = dict(params) if params is not None else {}
    spec.validate_sym_params(p)
    return spec.decrypt_impl(key, ciphertext, p)


def encrypt_with_alg(alg: str, key: bytes, plaintext: bytes) -> bytes:
    """Encrypt and return ciphertext only (backward-compatible wrapper).

    Same as :func:`encrypt_alg` with empty params, discarding ``updated_params``.

    Args:
        alg: Registered symmetric algorithm id.
        key: Key bytes sized for ``alg``.
        plaintext: Plaintext bytes.

    Returns:
        Ciphertext bytes.

    Raises:
        ValueError: If ``alg`` is unsupported.
    """
    blob, _params = encrypt_alg(alg, key, plaintext, None)
    return blob


def decrypt_with_alg(alg: str, key: bytes, blob: bytes) -> bytes:
    """Decrypt with empty symmetric parameters (backward-compatible wrapper).

    Args:
        alg: Registered symmetric algorithm id.
        key: Key bytes sized for ``alg``.
        blob: Ciphertext blob.

    Returns:
        Plaintext bytes.

    Raises:
        ValueError: If ``alg`` is unsupported or decryption fails.
    """
    return decrypt_alg(alg, key, blob, None)


# ---- Base64 helpers ---------------------------------------------------------


def b64encode(data: bytes) -> str:
    """URL-safe base64-encode bytes to an ASCII string.

    Args:
        data: Raw bytes.

    Returns:
        URL-safe base64 string without padding issues for wire segments.
    """
    return urlsafe_b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    """Decode a URL-safe base64 ASCII string to bytes.

    Args:
        data: URL-safe base64 string.

    Returns:
        Decoded bytes.
    """
    return urlsafe_b64decode(data.encode("ascii"))
