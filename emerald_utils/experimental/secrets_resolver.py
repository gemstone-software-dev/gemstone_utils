# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# emerald_utils/experimental/secrets_resolver.py

from __future__ import annotations

import os
from typing import Callable, Optional
from urllib.parse import unquote, urlparse

from emerald_utils.encrypted_fields import (
    decrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
    KeyContext,
)
from emerald_utils.experimental.sqlexp import get_secret


# ---------------------------------------------------------------------------
# Global cache + keyctx resolver
# ---------------------------------------------------------------------------

_cache = {}

_az_clients: dict[str, object] = {}

_keyctx_resolver: Optional[Callable[[int], KeyContext]] = None

_azexp_credential: Optional[object] = None


def set_keyctx_resolver(func: Callable[[int], KeyContext]) -> None:
    """
    Register a resolver that, given a keyid, returns the correct KeyContext.
    The application must call this at startup.
    """
    global _keyctx_resolver
    _keyctx_resolver = func


def set_azexp_credential(credential: object | None) -> None:
    """
    Override the Azure credential used for azexp: (e.g. for tests).
    Pass None to clear and use DefaultAzureCredential again.
    Clears cached Key Vault clients when changed.
    """
    global _azexp_credential
    _azexp_credential = credential
    _az_clients.clear()


def _resolve_keyctx_for_ciphertext(value: str) -> KeyContext:
    if _keyctx_resolver is None:
        raise RuntimeError("set_keyctx_resolver(...) must be called before resolving encrypted secrets")

    _, keyid, _ = parse_encrypted_field(value)
    return _keyctx_resolver(keyid)


# ---------------------------------------------------------------------------
# env:
# ---------------------------------------------------------------------------

def resolve_env(varname: str) -> str:
    if varname in _cache:
        return _cache[varname]

    value = os.environ.get(varname)
    if value is None:
        raise KeyError(f"missing environment variable {varname}")

    _cache[varname] = value

    # scrub environment variable after first read
    if varname in os.environ:
        del os.environ[varname]

    return value


# ---------------------------------------------------------------------------
# file:
# ---------------------------------------------------------------------------

def resolve_file(path: str) -> str:
    if path in _cache:
        return _cache[path]

    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()

    _cache[path] = value
    return value


# ---------------------------------------------------------------------------
# secret:
# ---------------------------------------------------------------------------

def resolve_secretfile(name: str) -> str:
    if name in _cache:
        return _cache[name]

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
            _cache[name] = value
            return value
        except FileNotFoundError:
            continue

    raise FileNotFoundError(f"secret '{name}' not found in known secret directories")


# ---------------------------------------------------------------------------
# sqlexp:
# ---------------------------------------------------------------------------

def resolve_sqlexp(session, logical_key: str) -> str | None:
    stored = get_secret(session, logical_key)
    if stored is None:
        return None

    if is_encrypted_prefix(stored):
        keyctx = _resolve_keyctx_for_ciphertext(stored)
        return decrypt_string(stored, keyctx)

    return stored


# ---------------------------------------------------------------------------
# azexp: (Azure Key Vault — experimental; future plugin-style vault:*)
# ---------------------------------------------------------------------------

def _parse_azexp_key_vault_ref(ref: str) -> tuple[str, str, str | None]:
    """
    Parse the body after ``azexp:`` as a Key Vault secret identifier:
    ``https://{vault}.vault.azure.net/secrets/{name}`` or with optional
    ``/{version}``. Returns ``(vault_url, secret_name, version_or_none)``.
    """
    parsed = urlparse(ref.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(
            "azexp: expects https URL, e.g. "
            "https://myvault.vault.azure.net/secrets/my-secret"
        )

    segments = [unquote(s) for s in parsed.path.strip("/").split("/") if s]
    if len(segments) < 2 or segments[0] != "secrets":
        raise ValueError(
            "azexp: path must be /secrets/{name} or /secrets/{name}/{version}"
        )

    name = segments[1]
    version = segments[2] if len(segments) > 2 else None
    vault_url = f"{parsed.scheme}://{parsed.netloc}/"
    return vault_url, name, version


def _azure_default_credential():
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError as e:
        raise RuntimeError(
            "azexp: install Azure extras: pip install 'emerald_utils[azure]'"
        ) from e
    return DefaultAzureCredential()


def _secret_client_for_vault(vault_url: str):
    if vault_url in _az_clients:
        return _az_clients[vault_url]

    try:
        from azure.keyvault.secrets import SecretClient
    except ImportError as e:
        raise RuntimeError(
            "azexp: install Azure extras: pip install 'emerald_utils[azure]'"
        ) from e

    cred = _azexp_credential if _azexp_credential is not None else _azure_default_credential()
    client = SecretClient(vault_url=vault_url, credential=cred)
    _az_clients[vault_url] = client
    return client


def resolve_azexp(ref_body: str) -> str:
    """
    Fetch a secret from Azure Key Vault. ``ref_body`` is the part after
    ``azexp:``, a standard secret URI without the prefix, for example
    ``https://myvault.vault.azure.net/secrets/my-secret`` (optional
    ``/version`` segment). Uses ``DefaultAzureCredential`` unless
    :func:`set_azexp_credential` was used. Caches by reference string.

    If the stored value uses the encrypted-field prefix, it is decrypted
    using the registered key context resolver (same as ``sqlexp:``).
    """
    cache_key = f"azexp:{ref_body}"
    if cache_key in _cache:
        return _cache[cache_key]

    vault_url, name, version = _parse_azexp_key_vault_ref(ref_body)
    client = _secret_client_for_vault(vault_url)
    if version is not None:
        bundle = client.get_secret(name, version=version)
    else:
        bundle = client.get_secret(name)

    raw = bundle.value
    if raw is None:
        raise KeyError(f"azexp: secret {name!r} has no value")

    if is_encrypted_prefix(raw):
        keyctx = _resolve_keyctx_for_ciphertext(raw)
        raw = decrypt_string(raw, keyctx)

    _cache[cache_key] = raw
    return raw


# ---------------------------------------------------------------------------
# main dispatcher
# ---------------------------------------------------------------------------

def resolve_secret(value: str, *, session=None):
    """
    Resolve a secret reference:
      - env:VAR
      - file:/path
      - secret:name
      - sqlexp:key
      - azexp:https://vault.vault.azure.net/secrets/name
      - encrypted field
      - literal string
    """
    if value.startswith("env:"):
        return resolve_env(value[4:])

    if value.startswith("file:"):
        return resolve_file(value[5:])

    if value.startswith("secret:"):
        return resolve_secretfile(value[7:])

    if value.startswith("sqlexp:"):
        if session is None:
            raise RuntimeError("sqlexp: requires a SQLAlchemy session")
        return resolve_sqlexp(session, value[7:])

    if value.startswith("azexp:"):
        return resolve_azexp(value[6:])

    if is_encrypted_prefix(value):
        keyctx = _resolve_keyctx_for_ciphertext(value)
        return decrypt_string(value, keyctx)

    return value
