# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/experimental/sqlexp.py

from __future__ import annotations

from sqlalchemy import Column, String, Text
from sqlalchemy.orm import Session

from ..db import GemstoneDB


class SecretKV(GemstoneDB):
    __tablename__ = "gemstone_secret_kv"

    key = Column(String(255), primary_key=True)
    value = Column(Text, nullable=False)


def get_secret(session: Session, key: str) -> str | None:
    row = session.get(SecretKV, key)
    return row.value if row else None


def set_secret(session: Session, key: str, value: str) -> None:
    row = session.get(SecretKV, key)
    if row is None:
        row = SecretKV(key=key, value=value)
        session.add(row)
    else:
        row.value = value
