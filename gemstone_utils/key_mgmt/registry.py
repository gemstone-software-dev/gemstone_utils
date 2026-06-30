# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/registry.py

from __future__ import annotations

from typing import Any, Callable, Dict

# New KDF ids must be added here in the same release as the implementation module.
_ALLOWED_KDF_NAMES: frozenset[str] = frozenset({"pbkdf2-hmac-sha256"})
_KDF_REGISTRY: Dict[str, Callable[[str, Dict[str, Any]], bytes]] = {}


def register_kdf(name: str):
    def decorator(fn):
        if name not in _ALLOWED_KDF_NAMES:
            raise ValueError(f"KDF {name!r} is not allowlisted")
        if name in _KDF_REGISTRY:
            raise ValueError(f"KDF {name!r} already registered")
        _KDF_REGISTRY[name] = fn
        global SUPPORTED_KDF_NAMES
        SUPPORTED_KDF_NAMES = frozenset(_KDF_REGISTRY.keys())
        return fn

    return decorator


def is_supported_kdf(name: str) -> bool:
    return name in _KDF_REGISTRY


def require_supported_kdf(name: str) -> Callable[[str, Dict[str, Any]], bytes]:
    fn = _KDF_REGISTRY.get(name)
    if fn is None:
        raise ValueError(f"Unsupported KDF: {name}")
    return fn


def derive_kek(passphrase: str, params: dict) -> bytes:
    """
    Dispatch to the correct KDF implementation based on params["kdf"].
    """
    kdf_name = params.get("kdf")
    if not kdf_name:
        raise ValueError("KDF parameters missing 'kdf' field")

    fn = require_supported_kdf(kdf_name)
    return fn(passphrase, params)


# Populated when built-in KDF modules import and call register_kdf.
SUPPORTED_KDF_NAMES: frozenset[str] = frozenset()
