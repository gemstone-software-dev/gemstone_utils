# SPDX-License-Identifier: MPL-2.0

import logging
import os
import sys

import pytest

import gemstone_utils.experimental.secrets_resolver as secrets_resolver
from gemstone_utils.experimental.secrets_resolver import (
    BackendNotImplemented,
    FilePathNotAllowed,
    allowed_file_path_prefixes,
    resolve_secret,
    set_allowed_file_path_prefixes,
)


@pytest.fixture(autouse=True)
def _reset_resolver_state():
    secrets_resolver._file_path_prefixes = None
    secrets_resolver._cache.clear()
    yield
    secrets_resolver._file_path_prefixes = None
    secrets_resolver._cache.clear()


def test_plain_string_without_colon():
    assert resolve_secret("plain-no-colon") == "plain-no-colon"


def test_literal_returns_body():
    assert resolve_secret("literal:http://host") == "http://host"
    assert resolve_secret("literal:a:b:c") == "a:b:c"


def test_literal_preserves_removed_prefix_text():
    value = "literal:azexp:https://vault.vault.azure.net/secrets/foo"
    assert resolve_secret(value) == "azexp:https://vault.vault.azure.net/secrets/foo"


def test_unregistered_prefix_raises():
    with pytest.raises(BackendNotImplemented) as exc_info:
        resolve_secret("foo:bar")
    assert exc_info.value.prefix == "foo"
    assert exc_info.value.reason == "unregistered"


def test_http_without_literal_raises():
    with pytest.raises(BackendNotImplemented) as exc_info:
        resolve_secret("http://example.com")
    assert exc_info.value.prefix == "http"
    assert exc_info.value.reason == "unregistered"


def test_removed_azexp_raises():
    with pytest.raises(BackendNotImplemented) as exc_info:
        resolve_secret("azexp:https://myvault.vault.azure.net/secrets/foo")
    assert exc_info.value.prefix == "azexp"
    assert exc_info.value.reason == "removed"


def test_backend_not_implemented_is_runtime_error():
    with pytest.raises(RuntimeError):
        resolve_secret("foo:bar")


def test_default_allowlist_is_app_secret():
    prefixes = allowed_file_path_prefixes()
    assert len(prefixes) == 1
    assert next(iter(prefixes)).replace("\\", "/").endswith("/app/secret")


def test_file_default_allowlist_denies_outside_app_secret(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("nope\n", encoding="utf-8")
    with pytest.raises(FilePathNotAllowed):
        resolve_secret(f"file:{outside}")


def test_file_relative_path_rejected():
    with pytest.raises(ValueError, match="must be absolute"):
        resolve_secret("file:relative/secret")


def test_file_tilde_rejected():
    with pytest.raises(ValueError, match="must not use ~"):
        resolve_secret("file:~/secret")


def test_file_allowed_under_custom_prefix(tmp_path):
    secret_file = tmp_path / "token"
    secret_file.write_text("sekrit\n", encoding="utf-8")
    set_allowed_file_path_prefixes([tmp_path])
    assert resolve_secret(f"file:{secret_file}") == "sekrit"


@pytest.mark.skipif(sys.platform == "win32", reason="default prefix is POSIX /app/secret")
def test_file_allowed_under_default_app_secret(tmp_path, monkeypatch):
    app_secret = tmp_path / "app" / "secret"
    app_secret.mkdir(parents=True)
    target = app_secret / "vault_passphrase"
    target.write_text("from-container\n", encoding="utf-8")

    monkeypatch.setattr(
        secrets_resolver,
        "_DEFAULT_FILE_PREFIXES",
        (str(app_secret),),
    )
    assert resolve_secret(f"file:{target}") == "from-container"


@pytest.mark.skipif(os.name != "posix", reason="POSIX /etc prefix")
def test_set_allowed_bare_etc_warns(caplog):
    with caplog.at_level(logging.WARNING):
        set_allowed_file_path_prefixes(["/etc"])
    assert any("bare /etc" in record.message for record in caplog.records)


@pytest.mark.skipif(os.name != "posix", reason="POSIX root prefix")
def test_set_allowed_root_warns(caplog):
    with caplog.at_level(logging.WARNING):
        set_allowed_file_path_prefixes(["/"])
    assert any("filesystem root" in record.message for record in caplog.records)


def test_set_allowed_prefix_rejects_relative():
    with pytest.raises(ValueError, match="must be absolute"):
        set_allowed_file_path_prefixes(["relative/dir"])


def test_set_allowed_prefix_rejects_tilde():
    with pytest.raises(ValueError, match="must not use ~"):
        set_allowed_file_path_prefixes(["~/secrets"])


def test_secret_valid_name_via_credentials_directory(tmp_path, monkeypatch):
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    (cred_dir / "api_token").write_text("tok\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(cred_dir))
    assert resolve_secret("secret:api_token") == "tok"


def test_secret_does_not_use_file_allowlist(tmp_path, monkeypatch):
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    (cred_dir / "vault_passphrase").write_text("pass\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(cred_dir))
    # Default file allowlist is /app/secret only; secret: should still work.
    prefixes = allowed_file_path_prefixes()
    assert len(prefixes) == 1
    assert next(iter(prefixes)).replace("\\", "/").endswith("/app/secret")
    assert resolve_secret("secret:vault_passphrase") == "pass"


@pytest.mark.parametrize(
    "reference",
    [
        "secret:",
        "secret:../x",
        "secret:a.b",
        "secret:a/b",
        "secret:bad name",
        "secret:_bad",
        "secret:bad_",
        "secret:bad-",
        "secret:-bad",
    ],
)
def test_secret_invalid_names(reference):
    with pytest.raises(ValueError, match="secret name must start with a letter"):
        resolve_secret(reference)


def test_secret_single_letter_name(tmp_path, monkeypatch):
    cred_dir = tmp_path / "creds"
    cred_dir.mkdir()
    (cred_dir / "x").write_text("one\n", encoding="utf-8")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(cred_dir))
    assert resolve_secret("secret:x") == "one"
