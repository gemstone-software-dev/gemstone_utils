# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/db.py

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class GemstoneDB(DeclarativeBase):
    """Shared declarative base for gemstone_utils ORM models."""


_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker[Session]] = None

# Cross-process schema init lock (PostgreSQL pg_advisory_xact_lock key).
_SCHEMA_INIT_LOCK_KEY = 0x47554E5F44425F494E4954  # GUN_DB_INIT
_MYSQL_SCHEMA_INIT_LOCK_NAME = "gemstone_utils_schema_init"
_MYSQL_SCHEMA_INIT_LOCK_TIMEOUT_SEC = 300


def _is_sqlite(drivername: str) -> bool:
    return drivername == "sqlite" or drivername.startswith("sqlite+")


def _is_mysql_family(drivername: str) -> bool:
    return drivername.startswith("mysql") or drivername.startswith("mariadb")


def _is_postgresql(drivername: str) -> bool:
    return drivername.startswith("postgresql")


def _apply_dialect_engine_kwargs(url: URL, engine_kw: dict[str, Any]) -> URL:
    """
    Apply backend-specific defaults. Caller ``**engine_kw`` values win over
    defaults (via setdefault / merged connect_args).
    """
    kw = engine_kw
    driver = url.drivername

    if _is_mysql_family(driver):
        kw.setdefault("pool_pre_ping", True)
        kw.setdefault("pool_recycle", 3600)
        if "charset" not in url.query:
            url = url.update_query_dict({"charset": "utf8mb4"})

    elif _is_postgresql(driver):
        kw.setdefault("pool_pre_ping", True)
        kw.setdefault("pool_recycle", 3600)
        merged_connect: dict[str, Any] = {}
        merged_connect.setdefault("options", "-c timezone=UTC")
        user_connect = kw.get("connect_args")
        if user_connect:
            merged_connect.update(user_connect)
        kw["connect_args"] = merged_connect

    return url


def _register_sqlite_pragmas(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _on_sqlite_connect(dbapi_conn, connection_record) -> None:
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()


def _create_all_locked(engine: Engine, drivername: str) -> None:
    """
    Create missing tables, serializing DDL on backends where concurrent
    ``create_all`` from multiple workers can race.
    """
    if _is_postgresql(drivername):
        with engine.begin() as conn:
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": _SCHEMA_INIT_LOCK_KEY},
            )
            GemstoneDB.metadata.create_all(bind=conn)
        return

    if _is_mysql_family(drivername):
        with engine.begin() as conn:
            acquired = conn.execute(
                text("SELECT GET_LOCK(:name, :timeout)"),
                {
                    "name": _MYSQL_SCHEMA_INIT_LOCK_NAME,
                    "timeout": _MYSQL_SCHEMA_INIT_LOCK_TIMEOUT_SEC,
                },
            ).scalar_one()
            if acquired != 1:
                raise RuntimeError(
                    f"failed to acquire MySQL schema init lock "
                    f"({_MYSQL_SCHEMA_INIT_LOCK_NAME!r})"
                )
            try:
                GemstoneDB.metadata.create_all(bind=conn)
            finally:
                conn.execute(
                    text("SELECT RELEASE_LOCK(:name)"),
                    {"name": _MYSQL_SCHEMA_INIT_LOCK_NAME},
                )
        return

    GemstoneDB.metadata.create_all(bind=engine)


def init_db(db_url: str, *, echo: bool = False, **engine_kw: Any) -> Engine:
    """
    Configure the process-global SQLAlchemy engine and session factory, then
    create any missing tables for all models registered on
    :attr:`GemstoneDB.metadata` (call after every plugin/module that defines
    ``GemstoneDB`` subclasses has been imported).

    Applies light dialect-specific defaults (SQLite WAL and pragmas; MySQL /
    MariaDB utf8mb4 + pool tuning; PostgreSQL UTC session timezone + pool
    tuning). Pass ``**engine_kw`` to override or extend :func:`create_engine`
    arguments.

    Schema creation uses a dialect advisory lock on PostgreSQL and MySQL /
    MariaDB so multiple workers (e.g. gunicorn) can call ``init_db`` at
    startup without racing on ``CREATE TABLE``.

    Returns the new :class:`~sqlalchemy.engine.Engine`.
    """
    global _engine, _session_factory

    url = make_url(db_url)
    kw = dict(engine_kw)
    url = _apply_dialect_engine_kwargs(url, kw)

    _engine = create_engine(url, echo=echo, **kw)

    if _is_sqlite(url.drivername):
        _register_sqlite_pragmas(_engine)

    _session_factory = sessionmaker(
        bind=_engine,
        autoflush=True,
        autocommit=False,
        expire_on_commit=False,
        class_=Session,
    )
    _create_all_locked(_engine, url.drivername)
    return _engine


def get_session() -> Session:
    """
    Return a new :class:`~sqlalchemy.orm.Session` bound to the engine from
    :func:`init_db`. The caller should close the session when done (or use it
    as a context manager: ``with get_session() as session:``).
    """
    if _session_factory is None:
        raise RuntimeError("init_db(...) must be called before get_session()")

    return _session_factory()
