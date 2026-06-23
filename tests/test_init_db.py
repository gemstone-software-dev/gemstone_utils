# SPDX-License-Identifier: MPL-2.0
# Copyright 2026, Clinton Bunch. All rights reserved.

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from sqlalchemy import inspect

import gemstone_utils.sqlalchemy.key_storage  # noqa: F401 — register ORM models
from gemstone_utils.db import GemstoneDB, get_session, init_db
from gemstone_utils.sqlalchemy.key_storage import GemstoneKeyKdf, GemstoneKeyRecord


def _postgresql_test_url() -> str | None:
    return os.environ.get("TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")


@pytest.fixture
def sqlite_url(tmp_path):
    return f"sqlite:///{tmp_path / 'init.db'}"


def test_init_db_sqlite_still_works(sqlite_url):
    init_db(sqlite_url)
    with get_session() as session:
        inspector = inspect(session.bind)
        tables = set(inspector.get_table_names())
    assert GemstoneKeyKdf.__tablename__ in tables
    assert GemstoneKeyRecord.__tablename__ in tables


@pytest.mark.skipif(
    _postgresql_test_url() is None,
    reason="set TEST_DATABASE_URL or DATABASE_URL to run PostgreSQL init_db tests",
)
def test_concurrent_init_db_postgresql():
    db_url = _postgresql_test_url()
    assert db_url is not None
    if not db_url.startswith("postgresql"):
        pytest.skip("TEST_DATABASE_URL must use a postgresql driver")

    worker_count = 8

    def _worker() -> None:
        init_db(db_url)

    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        futures = [pool.submit(_worker) for _ in range(worker_count)]
        for future in as_completed(futures):
            future.result()

    init_db(db_url)
    with get_session() as session:
        inspector = inspect(session.bind)
        tables = set(inspector.get_table_names())

    expected = {t.name for t in GemstoneDB.metadata.sorted_tables}
    assert expected.issubset(tables)
