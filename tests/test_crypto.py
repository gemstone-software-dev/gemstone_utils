# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

import pytest

import gemstone_utils.crypto as crypto_module
from gemstone_utils.encrypted_fields import (
    decrypt_string,
    encrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
)
from gemstone_utils.crypto import (
    RECOMMENDED_DATA_ALG,
    SUPPORTED_SYM_ALGS,
    decrypt_alg,
    encrypt_alg,
    generate_key_by_alg,
    recommended_data_alg,
    sym_alg_key_length,
)
from gemstone_utils.key_id import new_key_id
from gemstone_utils.types import KeyContext


def test_encrypt_alg_returns_tuple_and_roundtrip():
    key = generate_key_by_alg("A256GCM")
    assert len(key) == sym_alg_key_length("A256GCM")
    pt = b"hello"
    blob, out_params = encrypt_alg("A256GCM", key, pt, None)
    assert out_params == {}
    assert decrypt_alg("A256GCM", key, blob, out_params) == pt


def test_generate_key_by_alg_length():
    k = generate_key_by_alg("A256GCM")
    assert len(k) == 32


def test_unknown_alg_encrypt_raises():
    with pytest.raises(ValueError, match="Unsupported symmetric alg"):
        encrypt_alg("NOPE", b"\x00" * 32, b"x", None)


def test_unknown_alg_generate_raises():
    with pytest.raises(ValueError, match="Unsupported symmetric alg"):
        generate_key_by_alg("NOPE")


def test_encrypt_string_roundtrip_field_format():
    key = generate_key_by_alg(recommended_data_alg())
    kid = new_key_id()
    ctx = KeyContext(keyid=kid, key=key)
    wire = encrypt_string("hello", ctx)
    assert decrypt_string(wire, ctx) == "hello"


def test_recommended_data_alg_matches_registry():
    assert recommended_data_alg() == RECOMMENDED_DATA_ALG
    assert recommended_data_alg() in SUPPORTED_SYM_ALGS


def test_legacy_integer_key_segment_raises():
    # Five $-segments: '' , alg, keyid, params_b64, blob_b64
    legacy = "$A256GCM$1$e30$e30"
    with pytest.raises(ValueError, match="legacy integer"):
        parse_encrypted_field(legacy)


def test_parse_encrypted_field_unknown_alg_raises():
    from gemstone_utils.crypto import b64encode
    from gemstone_utils.encrypted_fields import _encode_params_segment

    kid = new_key_id()
    wire = f"$NOPE${kid}${_encode_params_segment({})}${b64encode(b'x')}"
    with pytest.raises(ValueError, match="Unsupported symmetric alg"):
        parse_encrypted_field(wire)


def test_is_encrypted_prefix_false_for_unknown_alg():
    from gemstone_utils.crypto import b64encode
    from gemstone_utils.encrypted_fields import _encode_params_segment

    kid = new_key_id()
    assert (
        is_encrypted_prefix(
            f"$NOPE${kid}${_encode_params_segment({})}${b64encode(b'x')}"
        )
        is False
    )


def test_sym_alg_registry_not_public():
    assert not hasattr(crypto_module, "SYM_ALG_REGISTRY")
