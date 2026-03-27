# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch
# emerald_utils/experimental/azexp_backend.py

from __future__ import annotations

import importlib
from urllib.parse import unquote, urlparse

from .secrets_resolver import register_backend

_az_clients: dict[str, object] = {}
_azexp_credential: object | None = None


def set_azexp_credential(credential: object | None) -> None:
    """
    Override Azure credential for azexp:. Pass None to use default credential.
    Clears cached Key Vault clients.
    """
    global _azexp_credential
    _azexp_credential = credential
    _az_clients.clear()


def _parse_azexp_key_vault_ref(ref: str) -> tuple[str, str, str | None]:
    parsed = urlparse(ref.strip())
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(
            "azexp: expects https URL, e.g. "
            "https://myvault.vault.azure.net/secrets/my-secret"
        )

    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("azexp: URL must not contain userinfo, query, or fragment")

    host = parsed.hostname or ""
    if not host.endswith(".vault.azure.net"):
        raise ValueError("azexp: host must be an Azure Key Vault hostname (*.vault.azure.net)")

    segments = [unquote(s) for s in parsed.path.strip("/").split("/") if s]
    if len(segments) not in (2, 3) or segments[0] != "secrets":
        raise ValueError("azexp: path must be /secrets/{name} or /secrets/{name}/{version}")

    name = segments[1]
    version = segments[2] if len(segments) == 3 else None
    vault_url = f"{parsed.scheme}://{parsed.netloc}/"
    return vault_url, name, version


def _azure_default_credential():
    try:
        identity_mod = importlib.import_module("azure.identity")
        credential_cls = getattr(identity_mod, "DefaultAzureCredential")
    except Exception as e:
        raise RuntimeError(
            "azexp: install Azure extras: pip install 'emerald_utils[azure]'"
        ) from e
    return credential_cls()


def _secret_client_for_vault(vault_url: str):
    if vault_url in _az_clients:
        return _az_clients[vault_url]

    try:
        secrets_mod = importlib.import_module("azure.keyvault.secrets")
        secret_client_cls = getattr(secrets_mod, "SecretClient")
    except Exception as e:
        raise RuntimeError(
            "azexp: install Azure extras: pip install 'emerald_utils[azure]'"
        ) from e

    cred = _azexp_credential if _azexp_credential is not None else _azure_default_credential()
    client = secret_client_cls(vault_url=vault_url, credential=cred)
    _az_clients[vault_url] = client
    return client


def resolve_azexp(ref_body: str) -> str:
    vault_url, name, version = _parse_azexp_key_vault_ref(ref_body)
    client = _secret_client_for_vault(vault_url)
    if version is not None:
        bundle = client.get_secret(name, version=version)
    else:
        bundle = client.get_secret(name)

    value = bundle.value
    if value is None:
        raise KeyError(f"azexp: secret {name!r} has no value")
    return value


def enable(*, replace: bool = False) -> None:
    register_backend("azexp", resolve_azexp, replace=replace)


# Explicit import of this module enables azexp: by default.
enable()
