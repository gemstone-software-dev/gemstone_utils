# SPDX-License-Identifier: MPL-2.0

import pytest

from gemstone_utils.experimental.secrets_resolver import (
    BackendNotImplemented,
    resolve_secret,
)


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
