# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/sqlalchemy/key_storage.py

from __future__ import annotations

import json
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Callable, Iterable, Iterator, Optional

from sqlalchemy import Boolean, Column, DateTime, Select, String, Text, select, update
from sqlalchemy.orm import Session

from gemstone_utils.crypto import RECOMMENDED_DATA_ALG, encrypt_alg, is_supported_sym_alg
from gemstone_utils.db import GemstoneDB, get_session as default_get_session
from gemstone_utils.encrypted_fields import format_encrypted_field, parse_encrypted_field
from gemstone_utils.key_mgmt import (
    derive_kek,
    load_passphrase as default_load_passphrase,
    recommended_kdf_params,
    rotate_kek,
    unwrap_key,
)
from gemstone_utils.types import KeyContext, KeyRecord


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class GemstoneKeyKdf(GemstoneDB):
    """
    KEK slot: persisted KDF parameters, KEK canary wire, and app re-encrypt flag.

    ``key_id`` is the KEK slot id (canonical UUID string) referenced by the
    segment ``keyid`` inside stored wire strings for :class:`GemstoneKeyRecord`.
    """

    __tablename__ = "gemstone_key_kdf"

    key_id = Column(String(36), primary_key=True)
    params = Column(Text, nullable=False)
    canary_wrapped = Column(Text, nullable=True)
    app_reencrypt_pending = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


class GemstoneKeyRecord(GemstoneDB):
    """
    Wrapped DEK material only (no KEK canary).

    ``wrapped`` uses the same five-part wire format as encrypted columns; the
    segment ``keyid`` is the KEK slot (row in :class:`GemstoneKeyKdf`), not this PK.
    ``data_alg`` is the algorithm for application field encryption (``KeyContext.alg``).
    """

    __tablename__ = "gemstone_key_record"

    key_id = Column(String(36), primary_key=True)
    wrapped = Column(Text, nullable=False)
    data_alg = Column(Text, nullable=False, default=RECOMMENDED_DATA_ALG)
    is_active = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    updated_at = Column(DateTime(timezone=True), nullable=False)


def new_kdf_params(salt: Optional[bytes] = None) -> dict:
    """
    Params dict for :func:`~gemstone_utils.key_mgmt.derive_kek` and
    :func:`set_kdf_params`, using the library's recommended KDF (same as
    :func:`~gemstone_utils.key_mgmt.recommended_kdf_params`).
    """
    return recommended_kdf_params(salt=salt)


def wire_wrap(
    wrap_key_id: str,
    kek: bytes,
    plaintext_key_material: bytes,
    alg: str = "A256GCM",
) -> str:
    """Wrap key material as the standard encrypted-field wire string."""
    blob, sym_params = encrypt_alg(alg, kek, plaintext_key_material, None)
    return format_encrypted_field(alg, wrap_key_id, blob, sym_params)


def wire_to_keyrecord(logical_key_id: Optional[str], wire: str) -> KeyRecord:
    """Parse a stored wire string into a :class:`~gemstone_utils.types.KeyRecord`."""
    alg_id, _segment_keyid, params, blob = parse_encrypted_field(wire)
    return KeyRecord(
        keyid=logical_key_id, alg=alg_id, encrypted_key=blob, params=params
    )


def keyrecord_to_wire(record: KeyRecord, wrap_key_id: str) -> str:
    """Serialize a :class:`~gemstone_utils.types.KeyRecord` to wire form."""
    return format_encrypted_field(
        record.alg, wrap_key_id, record.encrypted_key, record.params
    )


def unwrap_stored_key(kek: bytes, logical_key_id: str, wire: str) -> bytes:
    """Unwrap a DEK row. ``logical_key_id`` must match the row's primary key."""
    rec = wire_to_keyrecord(logical_key_id, wire)
    return unwrap_key(kek, rec)


def get_kdf_params(session: Session, key_id: str) -> dict:
    row = session.get(GemstoneKeyKdf, key_id)
    if row is None:
        raise KeyError(f"no KDF params row for key_id={key_id}")
    return json.loads(row.params)


def set_kdf_params(session: Session, key_id: str, params: dict) -> None:
    text = json.dumps(params, sort_keys=True, separators=(",", ":"))
    row = session.get(GemstoneKeyKdf, key_id)
    now = _utcnow()
    if row is None:
        session.add(
            GemstoneKeyKdf(
                key_id=key_id,
                params=text,
                canary_wrapped=None,
                app_reencrypt_pending=False,
                created_at=now,
                updated_at=now,
            )
        )
    elif row.params != text:
        row.params = text
        row.updated_at = now


def set_kek_canary(session: Session, key_id: str, canary_wrapped: str) -> None:
    """Set ``canary_wrapped`` on the KEK slot row. Call :func:`set_kdf_params` first."""
    row = session.get(GemstoneKeyKdf, key_id)
    if row is None:
        raise KeyError(f"no KDF row for key_id={key_id}; call set_kdf_params first")
    now = _utcnow()
    row.canary_wrapped = canary_wrapped
    row.updated_at = now


def set_app_reencrypt_pending(session: Session, key_id: str, pending: bool) -> None:
    """Set ``app_reencrypt_pending`` on the KEK slot row."""
    row = session.get(GemstoneKeyKdf, key_id)
    if row is None:
        raise KeyError(f"no KDF row for key_id={key_id}")
    now = _utcnow()
    row.app_reencrypt_pending = pending
    row.updated_at = now


def get_wrapped(session: Session, logical_key_id: str) -> str:
    row = session.get(GemstoneKeyRecord, logical_key_id)
    if row is None:
        raise KeyError(f"no key record for key_id={logical_key_id}")
    return row.wrapped


def iter_wrapped_rows(
    session: Session, key_ids: Optional[Iterable[str]] = None
) -> Iterator[GemstoneKeyRecord]:
    stmt: Select[GemstoneKeyRecord] = select(GemstoneKeyRecord).order_by(
        GemstoneKeyRecord.key_id
    )
    if key_ids is not None:
        stmt = stmt.where(GemstoneKeyRecord.key_id.in_(frozenset(key_ids)))
    yield from session.scalars(stmt)


def iter_kek_slots(session: Session) -> Iterator[GemstoneKeyKdf]:
    stmt = select(GemstoneKeyKdf).order_by(GemstoneKeyKdf.key_id)
    yield from session.scalars(stmt)


def put_keyrecord(
    session: Session,
    *,
    key_id: str,
    wrapped: str,
    data_alg: str = RECOMMENDED_DATA_ALG,
    is_active: bool = False,
) -> None:
    """
    Insert a single DEK record (new row on rotation).

    Raises if ``key_id`` already exists. When ``is_active`` is True, clears
    ``is_active`` on all other DEK rows in this session.

    ``data_alg`` defaults to :func:`~gemstone_utils.crypto.recommended_data_alg`
    (same as :data:`~gemstone_utils.crypto.RECOMMENDED_DATA_ALG`).
    """
    if not is_supported_sym_alg(data_alg):
        raise ValueError(f"Unsupported symmetric alg for data_alg: {data_alg!r}")
    if session.get(GemstoneKeyRecord, key_id) is not None:
        raise ValueError(f"key record already exists for key_id={key_id}")

    now = _utcnow()
    if is_active:
        session.execute(update(GemstoneKeyRecord).values(is_active=False))

    session.add(
        GemstoneKeyRecord(
            key_id=key_id,
            wrapped=wrapped,
            data_alg=data_alg,
            is_active=is_active,
            created_at=now,
            updated_at=now,
        )
    )


def rewrap_key_records(
    session: Session,
    *,
    old_kek: bytes,
    new_kek: bytes,
    old_wrap_key_id: str,
    new_wrap_key_id: str,
    key_ids: Optional[Iterable[str]] = None,
    new_alg: Optional[str] = None,
) -> None:
    """
    Unwrap stored DEKs and KEK canaries with ``old_kek`` and re-wrap with ``new_kek``,
    updating wire strings in place.

    Run inside an explicit transaction, for example::

        with session.begin():
            rewrap_key_records(session, ...)

    The session is not committed by this function.
    """
    kek_rows = list(iter_kek_slots(session))
    if not kek_rows:
        raise ValueError("no KEK slot rows")

    dek_rows = list(iter_wrapped_rows(session, key_ids))
    if not dek_rows:
        raise ValueError("no DEK key rows to rewrap")

    for kr in kek_rows:
        if kr.canary_wrapped is None:
            raise ValueError(f"KEK slot {kr.key_id!r} has no canary_wrapped")
        alg_id, seg, _p, _b = parse_encrypted_field(kr.canary_wrapped)
        if seg != old_wrap_key_id:
            raise ValueError(
                f"key_id={kr.key_id}: canary wire segment keyid {seg!r} != "
                f"old_wrap_key_id {old_wrap_key_id!r}"
            )

    records: list[KeyRecord] = []
    for row in dek_rows:
        alg_id, seg, _p, _b = parse_encrypted_field(row.wrapped)
        if seg != old_wrap_key_id:
            raise ValueError(
                f"key_id={row.key_id}: wire segment keyid {seg!r} != "
                f"old_wrap_key_id {old_wrap_key_id!r}"
            )
        records.append(wire_to_keyrecord(row.key_id, row.wrapped))

    new_check, updated = rotate_kek(old_kek, new_kek, records, new_alg=new_alg)

    touch = _utcnow()
    for kr in kek_rows:
        kr.canary_wrapped = keyrecord_to_wire(new_check, new_wrap_key_id)
        kr.updated_at = touch

    by_id = {r.key_id: r for r in dek_rows}
    for rec in updated:
        r = by_id[rec.keyid]
        r.wrapped = keyrecord_to_wire(rec, new_wrap_key_id)
        r.updated_at = touch

    session.flush()


def make_keyctx_resolver(
    *,
    get_session: Callable[[], Session] = default_get_session,
    load_passphrase: Callable[[], str] = default_load_passphrase,
    max_cache_size: int = 0,
) -> Callable[[str], KeyContext]:
    """
    Build a resolver suitable for :meth:`~gemstone_utils.sqlalchemy.encrypted_type.EncryptedString.set_keyctx_resolver`.

    Loads the DEK row by logical ``keyid`` string, derives the KEK from persisted KDF
    params for the wire's segment keyid, and returns :class:`~gemstone_utils.types.KeyContext`
    with ``alg`` from the row's ``data_alg``.

    When ``max_cache_size > 0``, resolved contexts are cached in-process (best-effort).
    """
    cache: Optional[OrderedDict[str, KeyContext]] = (
        OrderedDict() if max_cache_size > 0 else None
    )

    def _cache_set(keyid: str, ctx: KeyContext) -> KeyContext:
        assert cache is not None
        cache.pop(keyid, None)
        cache[keyid] = ctx
        while len(cache) > max_cache_size:
            cache.popitem(last=False)
        return ctx

    def resolve(dk_keyid: str) -> KeyContext:
        if cache is not None and dk_keyid in cache:
            ctx_hit = cache[dk_keyid]
            cache.move_to_end(dk_keyid)
            return ctx_hit

        session = get_session()
        try:
            row = session.get(GemstoneKeyRecord, dk_keyid)
            if row is None:
                raise KeyError(f"no key record for key_id={dk_keyid}")

            _alg_id, wrap_key_id, _params, _blob = parse_encrypted_field(row.wrapped)
            kdf_params = get_kdf_params(session, wrap_key_id)
            passphrase = load_passphrase()
            kek = derive_kek(passphrase, kdf_params)
            rec = wire_to_keyrecord(dk_keyid, row.wrapped)
            key = unwrap_key(kek, rec)
            ctx = KeyContext(keyid=dk_keyid, key=key, alg=row.data_alg)
        finally:
            session.close()

        if cache is not None:
            return _cache_set(dk_keyid, ctx)
        return ctx

    return resolve
