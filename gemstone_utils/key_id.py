# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.
# gemstone_utils/key_id.py

"""UUIDv7 key id generation (RFC 9562) for encrypted-field wire segment 2."""

from __future__ import annotations

import sys
from uuid import UUID

if sys.version_info >= (3, 14):
    from uuid import uuid7 as _uuid7
else:
    import uuid6

    def _uuid7() -> UUID:
        return uuid6.uuid7()


def new_key_id() -> str:
    """Generate a new canonical UUIDv7 string.

    Use for DEK or KEK slot primary keys (encrypted-field wire segment 2).

    Returns:
        Canonical UUID string (RFC 9562 UUIDv7).
    """
    return str(_uuid7())


def normalize_key_id(value: str) -> str:
    """Parse and canonicalize a UUID string.

    Args:
        value: UUID text in any accepted ``UUID`` form.

    Returns:
        Canonical 8-4-4-4-12 UUID string.

    Raises:
        ValueError: If ``value`` is not a valid UUID.
    """
    return str(UUID(value))
