# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/experimental/sqlexp_backend.py

from __future__ import annotations

from ..db import get_session
from .secrets_resolver import register_backend
from .sqlexp import get_secret


def resolve_sqlexp(logical_key: str) -> str | None:
    """
    Resolve sqlexp:<logical_key> from the SQL key/value store.

    Requires gemstone_utils.db.init_db(...) to have been called.
    """
    with get_session() as session:
        return get_secret(session, logical_key)


def enable(*, replace: bool = False) -> None:
    register_backend("sqlexp", resolve_sqlexp, replace=replace)


# Explicit import of this module enables sqlexp: by default.
enable()
