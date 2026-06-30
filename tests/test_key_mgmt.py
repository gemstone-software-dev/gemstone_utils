# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

import pytest

from gemstone_utils.crypto import derive_pbkdf2_hmac_sha256
from gemstone_utils.key_mgmt import derive_kek, recommended_kdf_params, register_kdf
from gemstone_utils.key_mgmt.kdf import RecommendedKdfParamsFn
from gemstone_utils.key_mgmt.kdf.pbkdf2 import (
    NAME as PBKDF2_NAME,
    pbkdf2_params,
    recommended_pbkdf2_params,
)


def test_pbkdf2_params_then_derive_kek_matches_primitive():
    salt = b"eight-bytes-salt!!"
    p = "unit-test-pass"
    params = pbkdf2_params(salt, iterations=50_000)
    expected = derive_pbkdf2_hmac_sha256(p, salt, iterations=50_000, length=32)
    assert derive_kek(p, params) == expected


def test_pbkdf2_params_roundtrip_json_shape():
    salt = b"another-salt-here!"
    params = pbkdf2_params(salt, iterations=10_000)
    assert params["kdf"] == PBKDF2_NAME
    assert params["iterations"] == 10_000
    p = "x"
    assert derive_kek(p, params) == derive_pbkdf2_hmac_sha256(
        p, salt, iterations=10_000, length=32
    )


def test_recommended_kdf_params_delegates_to_pbkdf2():
    p1 = recommended_kdf_params()
    p2 = recommended_pbkdf2_params()
    assert p1.keys() == p2.keys()
    assert p1["kdf"] == p2["kdf"] == PBKDF2_NAME
    assert p1["iterations"] == p2["iterations"]


def test_recommended_pbkdf2_params_is_recommended_kdf_params_fn():
    assert isinstance(recommended_pbkdf2_params, RecommendedKdfParamsFn)


def test_is_supported_kdf_built_in():
    from gemstone_utils.key_mgmt.registry import is_supported_kdf

    assert is_supported_kdf(PBKDF2_NAME) is True
    assert is_supported_kdf("nope") is False


def test_register_kdf_disallowed_name_raises():
    with pytest.raises(ValueError, match="not allowlisted"):

        @register_kdf("evil-kdf")
        def _evil(_passphrase: str, _params: dict) -> bytes:
            return b"\x00" * 32
