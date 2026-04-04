# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/sqlalchemy/lazy_secret.py

from __future__ import annotations

class LazySecret:
    __slots__ = ("_encrypted", "_keyctx", "_plaintext")

    def __init__(self, encrypted: str, keyctx):
        self._encrypted = encrypted
        self._keyctx = keyctx
        self._plaintext = None

    def _decrypt(self):
        if self._plaintext is None:
            from gemstone_utils.encrypted_fields import decrypt_string
            self._plaintext = decrypt_string(self._encrypted, self._keyctx)
        return self._plaintext

    def __str__(self):
        return self._decrypt()

    def __repr__(self):
        return "<LazySecret ****>"

    def __eq__(self, other):
        return str(self) == other

    def get(self):
        return self._decrypt()
