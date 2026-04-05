# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

import pytest

from gemstone_utils.encrypted_fields import decrypt_string, encrypt_string
from gemstone_utils.crypto import (
    decrypt_alg,
    encrypt_alg,
    generate_key_by_alg,
    sym_alg_key_length,
)
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
    key = generate_key_by_alg("A256GCM")
    ctx = KeyContext(keyid=1, key=key, alg="A256GCM")
    wire = encrypt_string("hello", ctx)
    assert decrypt_string(wire, ctx) == "hello"
