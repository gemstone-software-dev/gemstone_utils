# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

from __future__ import annotations

import os

import pytest

import gemstone_utils.sqlalchemy.key_storage  # noqa: F401 — register ORM models
from gemstone_utils.crypto import (
    DEFAULT_PBKDF2_ITERATIONS_STRONG,
    recommended_data_alg,
    sym_alg_key_length,
)
from gemstone_utils.db import get_session, init_db
from gemstone_utils.key_mgmt import (
    derive_and_verify_kek,
    derive_kek,
    init as key_mgmt_init,
    make_kek_check_record,
)
from gemstone_utils.key_mgmt.kdf.pbkdf2 import NAME as PBKDF2_NAME, pbkdf2_params
from gemstone_utils.sqlalchemy.key_storage import (
    GemstoneKeyKdf,
    GemstoneKeyRecord,
    keyrecord_to_wire,
    make_keyctx_resolver,
    new_kdf_params,
    put_keyrecord,
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
    dek = os.urandom(sym_alg_key_length(recommended_data_alg()))
    w0 = keyrecord_to_wire(canary, 1)
    w1 = wire_wrap(1, kek, dek)
    with get_session() as session:
        with session.begin():
            set_kdf_params(session, 1, kdf_params)
            put_keyrecord(session, key_id=0, wrapped=w0, is_active=False)
            put_keyrecord(session, key_id=1, wrapped=w1, is_active=True)
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


def test_rewrap_bumps_updated_at_not_created_or_data_alg(bootstrapped):
    old_kek = bootstrapped["kek"]
    new_kek = old_kek

    with get_session() as session:
        r1_before = session.get(GemstoneKeyRecord, 1)
        c_before = r1_before.created_at
        u_before = r1_before.updated_at
        da_before = r1_before.data_alg

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
        r1_after = session.get(GemstoneKeyRecord, 1)
        assert r1_after.created_at == c_before
        assert r1_after.data_alg == da_before
        assert r1_after.updated_at >= u_before


def test_kdf_timestamps_update_only_when_params_change(bootstrapped):
    kdf_params = bootstrapped["kdf_params"]

    with get_session() as session:
        row = session.get(GemstoneKeyKdf, 1)
        c0 = row.created_at
        u0 = row.updated_at

    with get_session() as session:
        with session.begin():
            set_kdf_params(session, 1, kdf_params)

    with get_session() as session:
        row = session.get(GemstoneKeyKdf, 1)
        assert row.created_at == c0
        assert row.updated_at == u0

    with get_session() as session:
        with session.begin():
            set_kdf_params(session, 1, {**kdf_params, "note": "x"})

    with get_session() as session:
        row = session.get(GemstoneKeyKdf, 1)
        assert row.updated_at > u0


def test_put_keyrecord_duplicate_raises(bootstrapped):
    with get_session() as session:
        with pytest.raises(ValueError, match="already exists"):
            with session.begin():
                put_keyrecord(
                    session,
                    key_id=1,
                    wrapped="dummy",
                    is_active=False,
                )


def test_put_keyrecord_canary_cannot_be_active(db_url):
    init_db(db_url)
    with get_session() as session:
        with pytest.raises(ValueError, match="canary"):
            with session.begin():
                put_keyrecord(
                    session,
                    key_id=0,
                    wrapped="$A256GCM$1$e30$e30$e30",
                    is_active=True,
                )


def test_keyctx_resolver(bootstrapped):
    passphrase = bootstrapped["passphrase"]
    dek = bootstrapped["dek"]

    resolve = make_keyctx_resolver(load_passphrase=lambda: passphrase)
    ctx = resolve(1)
    assert ctx.keyid == 1
    assert ctx.key == dek
    assert ctx.alg == recommended_data_alg()

    with get_session() as session:
        row = session.get(GemstoneKeyRecord, 1)
        assert ctx.alg == row.data_alg == recommended_data_alg()


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
