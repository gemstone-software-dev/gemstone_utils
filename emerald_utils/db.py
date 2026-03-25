# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# emerald_utils/db.py

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class EmeraldDB(DeclarativeBase):
    """Shared declarative base for emerald_utils ORM models."""


_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker[Session]] = None


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


def init_db(db_url: str, *, echo: bool = False, **engine_kw: Any) -> Engine:
    """
    Configure the process-global SQLAlchemy engine and session factory, then
    create any missing tables for all models registered on
    :attr:`EmeraldDB.metadata` (call after every plugin/module that defines
    ``EmeraldDB`` subclasses has been imported).

    Applies light dialect-specific defaults (SQLite WAL and pragmas; MySQL /
    MariaDB utf8mb4 + pool tuning; PostgreSQL UTC session timezone + pool
    tuning). Pass ``**engine_kw`` to override or extend :func:`create_engine`
    arguments.

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
    EmeraldDB.metadata.create_all(bind=_engine)
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
