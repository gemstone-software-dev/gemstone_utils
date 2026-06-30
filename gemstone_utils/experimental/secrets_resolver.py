# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/experimental/secrets_resolver.py

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Callable, Optional, Sequence, Union

from gemstone_utils.encrypted_fields import (
    decrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
)
from gemstone_utils.types import KeyContext

logger = logging.getLogger(__name__)

PathLike = Union[str, os.PathLike[str]]

_SECRET_NAME_RE = re.compile(r"^[A-Za-z]([A-Za-z0-9_-]*[A-Za-z0-9])?$")

_DEFAULT_FILE_PREFIXES: tuple[str, ...] = ("/app/secret",)
_file_path_prefixes: Optional[tuple[Path, ...]] = None


# ---------------------------------------------------------------------------
# Exceptions + removed backends
# ---------------------------------------------------------------------------


class BackendNotImplemented(RuntimeError):
    """Secret reference uses a backend that is removed or not registered."""

    def __init__(self, prefix: str, message: str, *, reason: str) -> None:
        self.prefix = prefix
        self.reason = reason  # "removed" | "unregistered"
        super().__init__(f"{prefix}: {message}")


class FilePathNotAllowed(ValueError):
    """``file:`` path is not under an allowed prefix."""

    def __init__(self, path: str, allowed_prefixes: frozenset[str]) -> None:
        self.path = path
        self.allowed_prefixes = allowed_prefixes
        super().__init__(
            f"file: path {path!r} is not under allowed prefixes "
            f"({', '.join(sorted(allowed_prefixes))})"
        )


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
# file: path allowlist
# ---------------------------------------------------------------------------


def _path_string_has_tilde(path_str: str) -> bool:
    return path_str.startswith("~") or "/~" in path_str or "\\~" in path_str


def _normalize_prefix_path(prefix: PathLike) -> Path:
    text = os.fspath(prefix)
    if not text:
        raise ValueError("file path prefix must not be empty")
    if _path_string_has_tilde(text):
        raise ValueError("file path prefix must not use ~")
    path = Path(text)
    if not path.is_absolute():
        raise ValueError(f"file path prefix must be absolute: {text!r}")
    return path.resolve(strict=False)


def _is_bare_etc_prefix(resolved: Path) -> bool:
    return resolved == Path("/etc").resolve(strict=False)


def _is_filesystem_root_prefix(resolved: Path) -> bool:
    root = Path(resolved.anchor).resolve(strict=False)
    return resolved == root


def _warn_footgun_prefixes(resolved: Path, warned: set[Path]) -> None:
    if resolved in warned:
        return
    if _is_bare_etc_prefix(resolved):
        logger.warning(
            "file: allowlist includes bare /etc; any path under /etc may be readable "
            "via file: references (e.g. file:/etc/passwd). Prefer a narrow prefix "
            "such as /etc/yourapp/ — see secrets_resolver docs."
        )
        warned.add(resolved)
        return
    if _is_filesystem_root_prefix(resolved):
        logger.warning(
            "file: allowlist includes filesystem root %s; any absolute path on that "
            "volume may be readable via file: references. Prefer a narrow prefix — "
            "see secrets_resolver docs.",
            resolved,
        )
        warned.add(resolved)


def set_allowed_file_path_prefixes(prefixes: Sequence[PathLike]) -> None:
    """
    Replace the ``file:`` path allowlist.

    Until this is called, only paths under ``/app/secret`` are allowed. Prefixes must
    be absolute and must not use ``~`` (no tilde expansion). Registering bare ``/etc``
    or a filesystem root logs a warning but is not blocked.
    """
    global _file_path_prefixes
    normalized: list[Path] = []
    warned: set[Path] = set()
    for prefix in prefixes:
        resolved = _normalize_prefix_path(prefix)
        _warn_footgun_prefixes(resolved, warned)
        normalized.append(resolved)
    _file_path_prefixes = tuple(normalized)


def allowed_file_path_prefixes() -> frozenset[str]:
    """Resolved absolute prefix strings for the effective ``file:`` allowlist."""
    return frozenset(p.as_posix() for p in _effective_file_prefixes())


def _effective_file_prefixes() -> tuple[Path, ...]:
    if _file_path_prefixes is not None:
        return _file_path_prefixes
    return tuple(Path(p).resolve(strict=False) for p in _DEFAULT_FILE_PREFIXES)


def _path_under_prefix(resolved: Path, prefix: Path) -> bool:
    if resolved == prefix:
        return True
    try:
        resolved.relative_to(prefix)
    except ValueError:
        return False
    return True


def _assert_under_prefixes(resolved: Path, prefixes: tuple[Path, ...]) -> None:
    for prefix in prefixes:
        if _path_under_prefix(resolved, prefix):
            return
    allowed = frozenset(p.as_posix() for p in prefixes)
    raise FilePathNotAllowed(resolved.as_posix(), allowed)


def _validate_user_file_path(path: str) -> Path:
    if not path:
        raise ValueError("file: path must not be empty")
    if _path_string_has_tilde(path):
        raise ValueError("file: path must not use ~")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise ValueError(f"file: path must be absolute: {path!r}")
    return candidate.resolve(strict=False)


def _assert_under_file_allowlist(resolved: Path) -> None:
    _assert_under_prefixes(resolved, _effective_file_prefixes())


def _read_utf8_file(cache_key: str, resolved: Path) -> str:
    if cache_key in _cache:
        return _cache[cache_key]

    with open(resolved, "r", encoding="utf-8") as f:
        value = f.read().strip()

    _cache[cache_key] = value
    return value


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
    resolved = _validate_user_file_path(path)
    _assert_under_file_allowlist(resolved)
    return _read_utf8_file(f"file:{path}", resolved)


# ---------------------------------------------------------------------------
# secret:
# ---------------------------------------------------------------------------


def _validate_secret_name(name: str) -> None:
    if not _SECRET_NAME_RE.fullmatch(name):
        raise ValueError(
            "secret name must start with a letter, end with a letter or digit, "
            "and contain only [A-Za-z0-9_-]"
        )


def _secret_mount_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        roots.append(Path(cred_dir).resolve(strict=False))
    roots.append(Path("/run/secrets").resolve(strict=False))
    roots.append(Path("/var/run/secrets").resolve(strict=False))
    return tuple(roots)


def _resolve_secret_mount_file(resolved: Path) -> str:
    _assert_under_prefixes(resolved, _secret_mount_roots())
    return _read_utf8_file(f"file:{resolved.as_posix()}", resolved)


def resolve_secretfile(name: str) -> str:
    _validate_secret_name(name)

    cache_key = f"secret:{name}"
    if cache_key in _cache:
        return _cache[cache_key]

    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")

    candidates: list[Path] = []
    if cred_dir:
        candidates.append(Path(cred_dir) / name)
    candidates.append(Path("/run/secrets") / name)
    candidates.append(Path("/var/run/secrets") / name)

    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        try:
            value = _resolve_secret_mount_file(resolved)
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
