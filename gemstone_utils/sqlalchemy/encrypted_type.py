# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/sqlalchemy/encrypted_type.py

from __future__ import annotations

from typing import Callable, Optional

from sqlalchemy.types import TypeDecorator, Text

from gemstone_utils.encrypted_fields import (
    encrypt_string,
    is_encrypted_prefix,
    parse_encrypted_field,
)
from gemstone_utils.types import KeyContext
from .lazy_secret import LazySecret


class EncryptedString(TypeDecorator):
    """SQLAlchemy ``TypeDecorator`` for transparent encrypted text columns.

    Writes encrypt with the *current* ``KeyContext``; reads return a
    ``LazySecret`` that decrypts on access.

    Configure once at startup via ``set_current_keyctx`` and
    ``set_keyctx_resolver``. See ``docs/sqlalchemy.md``.
    """

    impl = Text
    cache_ok = True

    _current_keyctx: Optional[KeyContext] = None
    _keyctx_resolver: Optional[Callable[[str], KeyContext]] = None

    # --- configuration hooks -------------------------------------------------

    @classmethod
    def set_current_keyctx(cls, keyctx: KeyContext) -> None:
        """Set the ``KeyContext`` used for new writes.

        Args:
            keyctx: Active DEK context for encrypting plaintext bound parameters.
        """
        cls._current_keyctx = keyctx

    @classmethod
    def set_keyctx_resolver(cls, resolver: Callable[[str], KeyContext]) -> None:
        """Set the resolver that maps stored key ids to ``KeyContext``.

        Args:
            resolver: Callable receiving canonical UUID string (wire segment 2)
                and returning the ``KeyContext`` that can decrypt that row.
        """
        cls._keyctx_resolver = resolver

    @classmethod
    def _get_current_keyctx(cls) -> KeyContext:
        if cls._current_keyctx is None:
            raise RuntimeError("EncryptedString.set_current_keyctx(...) must be called before use")
        return cls._current_keyctx

    @classmethod
    def _resolve_keyctx(cls, keyid: str) -> KeyContext:
        if cls._keyctx_resolver is None:
            raise RuntimeError("EncryptedString.set_keyctx_resolver(...) must be called before use")
        return cls._keyctx_resolver(keyid)

    # --- SQLAlchemy hooks ----------------------------------------------------

    def process_bind_param(self, value, dialect):
        """
        Called when writing to the DB.

        - Rejects already-encrypted values.
        - Encrypts plaintext using the *current* KeyContext.
        """
        if value is None:
            return None
        if is_encrypted_prefix(value):
            raise ValueError("Encrypted values must not be assigned directly")
        return encrypt_string(value, self._get_current_keyctx())

    def process_result_value(self, value, dialect):
        """
        Called when reading from the DB.

        - Parses the prefix to extract key id.
        - Resolves the correct KeyContext for that key id.
        - Returns a LazySecret that decrypts on access.
        """
        if value is None:
            return None

        _, keyid, _, _ = parse_encrypted_field(value)
        keyctx = self._resolve_keyctx(keyid)
        return LazySecret(value, keyctx)
