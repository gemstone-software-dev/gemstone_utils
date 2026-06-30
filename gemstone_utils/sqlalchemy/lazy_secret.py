# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/sqlalchemy/lazy_secret.py

"""Lazy decryption wrapper returned by ``EncryptedString`` on read."""

from __future__ import annotations

from gemstone_utils.types import KeyContext


class LazySecret:
    """Deferred decryption of an encrypted-field wire string.

    Returned by ``EncryptedString.process_result_value``. Decrypts on first
    access via ``str()``, ``get()``, or equality comparison.
    """

    __slots__ = ("_encrypted", "_keyctx", "_plaintext")

    def __init__(self, encrypted: str, keyctx: KeyContext) -> None:
        """Store ciphertext and context for lazy decrypt.

        Args:
            encrypted: Encrypted-field wire string from the database.
            keyctx: Data key context resolved for segment 2 of the wire.
        """
        self._encrypted = encrypted
        self._keyctx = keyctx
        self._plaintext = None

    def _decrypt(self) -> str:
        if self._plaintext is None:
            from gemstone_utils.encrypted_fields import decrypt_string

            self._plaintext = decrypt_string(self._encrypted, self._keyctx)
        return self._plaintext

    def __str__(self) -> str:
        return self._decrypt()

    def __repr__(self) -> str:
        return "<LazySecret ****>"

    def __eq__(self, other: object) -> bool:
        return str(self) == other

    def get(self) -> str:
        """Return the decrypted plaintext string.

        Returns:
            Decrypted UTF-8 string.
        """
        return self._decrypt()
