# SPDX-License-Identifier: MPL-2.0
# gemstone_utils/key_mgmt/registry.py

"""KDF registry and ``derive_kek`` dispatch."""

from __future__ import annotations

from typing import Any, Callable, Dict

# New KDF ids must be added here in the same release as the implementation module.
_ALLOWED_KDF_NAMES: frozenset[str] = frozenset({"pbkdf2-hmac-sha256"})
_KDF_REGISTRY: Dict[str, Callable[[str, Dict[str, Any]], bytes]] = {}


def register_kdf(name: str):
    """Decorator to register a first-party KDF implementation.

    Only ids in ``_ALLOWED_KDF_NAMES`` may register. Third-party runtime
    registration is not supported.

    Args:
        name: Registry id stored in persisted params as ``"kdf"``.

    Returns:
        Decorator that registers the wrapped function.
    """
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
    """Return whether ``name`` is a registered KDF id.

    Args:
        name: KDF registry id.

    Returns:
        ``True`` if registered.
    """
    return name in _KDF_REGISTRY


def require_supported_kdf(name: str) -> Callable[[str, Dict[str, Any]], bytes]:
    """Return the registered KDF callable for ``name``.

    Args:
        name: KDF registry id.

    Returns:
        Callable ``(passphrase, params) -> kek_bytes``.

    Raises:
        ValueError: If ``name`` is not registered.
    """
    fn = _KDF_REGISTRY.get(name)
    if fn is None:
        raise ValueError(f"Unsupported KDF: {name}")
    return fn


def derive_kek(passphrase: str, params: dict) -> bytes:
    """Derive a KEK using the KDF named in ``params["kdf"]``.

    Args:
        passphrase: Vault passphrase.
        params: Persisted KDF parameters (must include ``"kdf"``).

    Returns:
        Derived KEK bytes.

    Raises:
        ValueError: If ``params`` omit ``"kdf"`` or name an unsupported KDF.
    """
    kdf_name = params.get("kdf")
    if not kdf_name:
        raise ValueError("KDF parameters missing 'kdf' field")

    fn = require_supported_kdf(kdf_name)
    return fn(passphrase, params)


# Populated when built-in KDF modules import and call register_kdf.
#: Registered KDF ids (read-only; updated when built-in modules load).
SUPPORTED_KDF_NAMES: frozenset[str] = frozenset()
