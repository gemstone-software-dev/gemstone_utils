# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/registry.py

from __future__ import annotations

from typing import Any, Callable, Dict

_KDF_REGISTRY: Dict[str, Callable[[str, Dict[str, Any]], bytes]] = {}


def register_kdf(name: str):
    def decorator(fn):
        _KDF_REGISTRY[name] = fn
        return fn
    return decorator


def derive_kek(passphrase: str, params: dict) -> bytes:
    """
    Dispatch to the correct KDF implementation based on params["kdf"].
    """
    kdf_name = params.get("kdf")
    if not kdf_name:
        raise ValueError("KDF parameters missing 'kdf' field")

    fn = _KDF_REGISTRY.get(kdf_name)
    if not fn:
        raise ValueError(f"Unsupported KDF: {kdf_name}")

    return fn(passphrase, params)
