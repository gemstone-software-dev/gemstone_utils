# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

from __future__ import annotations

import os

import pytest

import gemstone_utils.sqlalchemy.key_storage  # noqa: F401 — register ORM models
from gemstone_utils.crypto import DEFAULT_PBKDF2_ITERATIONS_STRONG
from gemstone_utils.db import get_session, init_db
from gemstone_utils.key_mgmt import (
    derive_and_verify_kek,
    derive_kek,
    init as key_mgmt_init,
    make_kek_check_record,
)
from gemstone_utils.key_mgmt.kdf.pbkdf2 import NAME as PBKDF2_NAME, pbkdf2_params
from gemstone_utils.sqlalchemy.key_storage import (
    GemstoneKeyRecord,
    keyrecord_to_wire,
    make_keyctx_resolver,
    new_kdf_params,
    rewrap_key_records,
    set_kdf_params,
    unwrap_stored_key,
    wire_to_keyrecord,
    wire_wrap,
)


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'keys.db'}"


@pytest.fixture
def passphrase():
    return "test-passphrase-unit-test"


def _fast_kdf_params() -> dict:
    """Low iteration count for fast tests (production should use new_kdf_params())."""
    return pbkdf2_params(os.urandom(16), iterations=10_000)


@pytest.fixture
def bootstrapped(db_url, passphrase):
    init_db(db_url)
    key_mgmt_init(
        "test-vault-secret",
        b"canary-plaintext-check",
        env_allowed=True,
    )
    kdf_params = _fast_kdf_params()
    kek = derive_kek(passphrase, kdf_params)
    canary = make_kek_check_record(kek)
    dek = os.urandom(32)
    w0 = keyrecord_to_wire(canary, 1)
    w1 = wire_wrap(1, kek, dek)
    with get_session() as session:
        with session.begin():
            set_kdf_params(session, 1, kdf_params)
            session.add(GemstoneKeyRecord(key_id=0, wrapped=w0))
            session.add(GemstoneKeyRecord(key_id=1, wrapped=w1))
    return {"passphrase": passphrase, "kdf_params": kdf_params, "kek": kek, "dek": dek}


def test_derive_verify_and_unwrap(bootstrapped):
    passphrase = bootstrapped["passphrase"]
    kdf_params = bootstrapped["kdf_params"]
    kek = bootstrapped["kek"]
    dek = bootstrapped["dek"]

    with get_session() as session:
        row0 = session.get(GemstoneKeyRecord, 0)
        row1 = session.get(GemstoneKeyRecord, 1)
        derive_and_verify_kek(
            passphrase,
            kdf_params,
            wire_to_keyrecord(0, row0.wrapped),
        )
        out = unwrap_stored_key(kek, 1, row1.wrapped)
    assert out == dek


def test_rewrap_transaction(bootstrapped):
    passphrase = bootstrapped["passphrase"]
    kdf_params = bootstrapped["kdf_params"]
    old_kek = bootstrapped["kek"]
    dek = bootstrapped["dek"]

    new_pass = "rotated-passphrase-xyz"
    new_kek = derive_kek(new_pass, kdf_params)

    with get_session() as session:
        with session.begin():
            rewrap_key_records(
                session,
                old_kek=old_kek,
                new_kek=new_kek,
                old_wrap_key_id=1,
                new_wrap_key_id=1,
            )

    with get_session() as session:
        row0 = session.get(GemstoneKeyRecord, 0)
        row1 = session.get(GemstoneKeyRecord, 1)
        derive_and_verify_kek(
            new_pass,
            kdf_params,
            wire_to_keyrecord(0, row0.wrapped),
        )
        assert unwrap_stored_key(new_kek, 1, row1.wrapped) == dek


def test_keyctx_resolver(bootstrapped):
    passphrase = bootstrapped["passphrase"]
    dek = bootstrapped["dek"]

    resolve = make_keyctx_resolver(load_passphrase=lambda: passphrase)
    ctx = resolve(1)
    assert ctx.keyid == 1
    assert ctx.key == dek


def test_keyctx_resolver_rejects_zero():
    resolve = make_keyctx_resolver(load_passphrase=lambda: "x")
    with pytest.raises(ValueError, match="canary"):
        resolve(0)


def test_new_kdf_params_strong_defaults():
    p = new_kdf_params()
    assert p["kdf"] == PBKDF2_NAME
    assert p["iterations"] == DEFAULT_PBKDF2_ITERATIONS_STRONG
    assert p["length"] == 32
    assert "salt" in p


def test_rewrap_wrong_segment_raises(bootstrapped):
    old_kek = bootstrapped["kek"]
    new_kek = old_kek

    with get_session() as session:
        with pytest.raises(ValueError, match="old_wrap_key_id"):
            with session.begin():
                rewrap_key_records(
                    session,
                    old_kek=old_kek,
                    new_kek=new_kek,
                    old_wrap_key_id=99,
                    new_wrap_key_id=1,
                )
