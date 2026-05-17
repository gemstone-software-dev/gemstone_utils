# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/experimental/secrets_resolver.py

from __future__ import annotations

import os
from typing import Callable, Optional

from gemstone_utils.encrypted_fields import (
    decrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
)
from gemstone_utils.types import KeyContext


# ---------------------------------------------------------------------------
# Exceptions + removed backends
# ---------------------------------------------------------------------------


class BackendNotImplemented(RuntimeError):
    """Secret reference uses a backend that is removed or not registered."""

    def __init__(self, prefix: str, message: str, *, reason: str) -> None:
        self.prefix = prefix
        self.reason = reason  # "removed" | "unregistered"
        super().__init__(f"{prefix}: {message}")


_REMOVED_BACKENDS: dict[str, str] = {
    "azexp": (
        "removed in v0.5.0; use secret:name for container-mounted secrets "
        "(Azure Container Apps, quadlet, etc.) or file:/path for a custom mount"
    ),
}


# ---------------------------------------------------------------------------
# Global cache + keyctx resolver
# ---------------------------------------------------------------------------

_cache: dict[str, str] = {}
_backends: dict[str, Callable[[str], str | None]] = {}

_keyctx_resolver: Optional[Callable[[str], KeyContext]] = None


def set_keyctx_resolver(func: Callable[[str], KeyContext]) -> None:
    """
    Register a resolver that, given a key id string (UUID), returns the correct KeyContext.
    The application must call this at startup.
    """
    global _keyctx_resolver
    _keyctx_resolver = func


def _resolve_keyctx_for_ciphertext(value: str) -> KeyContext:
    if _keyctx_resolver is None:
        raise RuntimeError("set_keyctx_resolver(...) must be called before resolving encrypted secrets")

    _, keyid, _, _ = parse_encrypted_field(value)
    return _keyctx_resolver(keyid)


# ---------------------------------------------------------------------------
# env:
# ---------------------------------------------------------------------------

def resolve_env(varname: str) -> str:
    cache_key = f"env:{varname}"
    if cache_key in _cache:
        return _cache[cache_key]

    value = os.environ.get(varname)
    if value is None:
        raise KeyError(f"missing environment variable {varname}")

    _cache[cache_key] = value

    # scrub environment variable after first read
    if varname in os.environ:
        del os.environ[varname]

    return value


# ---------------------------------------------------------------------------
# file:
# ---------------------------------------------------------------------------

def resolve_file(path: str) -> str:
    cache_key = f"file:{path}"
    if cache_key in _cache:
        return _cache[cache_key]

    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()

    _cache[cache_key] = value
    return value


# ---------------------------------------------------------------------------
# secret:
# ---------------------------------------------------------------------------

def resolve_secretfile(name: str) -> str:
    cache_key = f"secret:{name}"
    if cache_key in _cache:
        return _cache[cache_key]

    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")

    search_paths = [
        os.path.join(cred_dir, name) if cred_dir else None,
        f"/run/secrets/{name}",
        f"/var/run/secrets/{name}",
    ]

    for path in search_paths:
        if not path:
            continue
        try:
            value = resolve_file(path)
            _cache[cache_key] = value
            return value
        except FileNotFoundError:
            continue

    raise FileNotFoundError(f"secret '{name}' not found in known secret directories")


# ---------------------------------------------------------------------------
# literal:
# ---------------------------------------------------------------------------

def resolve_literal(body: str) -> str:
    return body


def register_backend(
    prefix: str,
    resolver: Callable[[str], str | None],
    *,
    replace: bool = False,
) -> None:
    """
    Register a pluggable backend resolver for a prefix (without trailing ':').
    """
    norm = prefix.strip().lower().rstrip(":")
    if not norm:
        raise ValueError("backend prefix must not be empty")
    if not replace and norm in _backends:
        raise ValueError(f"backend '{norm}' already registered")
    _backends[norm] = resolver


def unregister_backend(prefix: str) -> None:
    norm = prefix.strip().lower().rstrip(":")
    _backends.pop(norm, None)


def is_backend_registered(prefix: str) -> bool:
    norm = prefix.strip().lower().rstrip(":")
    return norm in _backends


def list_backends() -> list[str]:
    return sorted(_backends.keys())


def _postprocess_resolved(value: str | None) -> str | None:
    if value is None:
        return None
    if is_encrypted_prefix(value):
        keyctx = _resolve_keyctx_for_ciphertext(value)
        return decrypt_string(value, keyctx)
    return value


# ---------------------------------------------------------------------------
# main dispatcher
# ---------------------------------------------------------------------------

def resolve_secret(value: str):
    """
    Resolve a secret reference:
      - env:VAR
      - file:/path
      - secret:name
      - literal:opaque (substring after first colon, unchanged)
      - pluggable backends (registered via register_backend)
      - encrypted field
      - plain string (no colon)
    """
    if is_encrypted_prefix(value):
        keyctx = _resolve_keyctx_for_ciphertext(value)
        return decrypt_string(value, keyctx)

    if ":" not in value:
        return value

    prefix, body = value.split(":", 1)
    norm = prefix.strip().lower()
    backend = _backends.get(norm)
    if backend is not None:
        return _postprocess_resolved(backend(body))

    if norm in _REMOVED_BACKENDS:
        raise BackendNotImplemented(norm, _REMOVED_BACKENDS[norm], reason="removed")

    raise BackendNotImplemented(
        norm,
        "no backend registered; use register_backend(...), "
        "a built-in prefix (env, file, secret), or literal:... for opaque values",
        reason="unregistered",
    )


# Register built-ins.
register_backend("env", resolve_env)
register_backend("file", resolve_file)
register_backend("secret", resolve_secretfile)
register_backend("literal", resolve_literal)
