# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# emerald_utils/dk.py

from __future__ import annotations

from dataclasses import dataclass

from .crypto import encrypt_with_alg, decrypt_with_alg
from .encrypted_fields import KeyContext


@dataclass
class DKRecord:
    """
    Generic DK metadata container.

    The library makes no assumptions about where this comes from.
    The application constructs it from its own storage.
    """
    keyid: int
    alg: str          # e.g. "A256GCM" for DK encryption
    encrypted_dk: bytes


def unwrap_dk(kek: bytes, dk_record: DKRecord) -> bytes:
    """Decrypt the DK using the KEK and the DK's own alg."""
    return decrypt_with_alg(dk_record.alg, kek, dk_record.encrypted_dk)


def wrap_dk(kek: bytes, dk: bytes, alg: str = "A256GCM") -> DKRecord:
    """Encrypt a DK using the KEK and return a DKRecord (caller sets keyid)."""
    blob = encrypt_with_alg(alg, kek, dk)
    # keyid must be assigned by the caller (e.g. autoincrement in DB)
    return DKRecord(keyid=-1, alg=alg, encrypted_dk=blob)


def load_keyctx(kek: bytes, dk_record: DKRecord) -> KeyContext:
    """Produce a KeyContext from a KEK + DKRecord."""
    dk = unwrap_dk(kek, dk_record)
    return KeyContext(keyid=dk_record.keyid, dk=dk, alg="A256GCM")
