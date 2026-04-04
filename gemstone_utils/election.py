# SPDX-License-Identifier: MPL-2.0
# Copyright 2026,
# gemstone_utils/election.py

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional, Iterator
from uuid import UUID

from sqlalchemy import DateTime, String, delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import GemstoneDB, get_session


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ns(ns: Optional[str]) -> str:
    return ns or "default"


_expire_seconds: int = 60


def set_expire(sec: int) -> None:
    """
    Set the candidate and leader lease expiration window (seconds).

    The application should call this once at startup.
    """
    global _expire_seconds
    if not isinstance(sec, int) or sec <= 0:
        raise ValueError("expire seconds must be a positive int")
    _expire_seconds = sec


class ElectionCandidate(GemstoneDB):
    __tablename__ = "gemstone_election_candidate"

    ns: Mapped[str] = mapped_column(String(255), primary_key=True)
    candidate_id: Mapped[str] = mapped_column(String(36), primary_key=True)

    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ElectionLeader(GemstoneDB):
    __tablename__ = "gemstone_election_leader"

    ns: Mapped[str] = mapped_column(String(255), primary_key=True)

    leader_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


@dataclass(frozen=True)
class _Lease:
    now: datetime
    expires_at: datetime


def _lease() -> _Lease:
    now = _utcnow()
    return _Lease(now=now, expires_at=now + timedelta(seconds=_expire_seconds))


@contextmanager
def _session_scope(session: Optional[Session]) -> Iterator[Session]:
    if session is not None:
        yield session
        return
    s = get_session()
    try:
        yield s
    finally:
        s.close()


def register_candidate(candidate_id: UUID, ns: Optional[str] = None, *, session: Optional[Session] = None) -> None:
    """
    Register or refresh a candidate in the election namespace.
    """
    n = _ns(ns)
    cid = str(candidate_id)
    lease = _lease()

    with _session_scope(session) as s:
        with s.begin():
            row = s.get(ElectionCandidate, {"ns": n, "candidate_id": cid})
            if row is None:
                s.add(
                    ElectionCandidate(
                        ns=n,
                        candidate_id=cid,
                        last_heartbeat_at=lease.now,
                        expires_at=lease.expires_at,
                    )
                )
            else:
                row.last_heartbeat_at = lease.now
                row.expires_at = lease.expires_at


def heartbeat(candidate_id: UUID, ns: Optional[str] = None, *, session: Optional[Session] = None) -> None:
    """
    Refresh a candidate heartbeat and extend its expiry window.

    If the candidate is missing, this behaves like register_candidate().
    """
    register_candidate(candidate_id, ns, session=session)


def unregister_candidate(candidate_id: UUID, ns: Optional[str] = None, *, session: Optional[Session] = None) -> None:
    """
    Remove a candidate from the registry. If it is currently leader, clear the
    leader row for faster failover (best-effort).
    """
    n = _ns(ns)
    cid = str(candidate_id)
    now = _utcnow()

    with _session_scope(session) as s:
        with s.begin():
            s.execute(delete(ElectionCandidate).where(ElectionCandidate.ns == n, ElectionCandidate.candidate_id == cid))

            leader = s.get(ElectionLeader, n)
            if leader and leader.leader_id == cid:
                leader.leader_id = None
                leader.lease_expires_at = None
                leader.updated_at = now


def list_candidates(ns: Optional[str] = None, *, session: Optional[Session] = None) -> list[UUID]:
    """
    Return the currently-active candidates in the namespace (expires_at > now).
    """
    n = _ns(ns)
    now = _utcnow()

    with _session_scope(session) as s:
        rows = s.execute(
            select(ElectionCandidate.candidate_id)
            .where(ElectionCandidate.ns == n, ElectionCandidate.expires_at > now)
            .order_by(ElectionCandidate.candidate_id)
        ).scalars()
        return [UUID(x) for x in rows]


def is_leader(candidate_id: UUID, ns: Optional[str] = None, *, session: Optional[Session] = None) -> bool:
    """
    Return True if candidate_id holds an unexpired lease for the namespace.
    """
    n = _ns(ns)
    cid = str(candidate_id)
    now = _utcnow()

    with _session_scope(session) as s:
        leader = s.get(ElectionLeader, n)
        if leader is None or leader.leader_id is None or leader.lease_expires_at is None:
            return False
        return leader.leader_id == cid and leader.lease_expires_at > now


def elect(candidate_id: UUID, ns: Optional[str] = None, *, session: Optional[Session] = None) -> UUID:
    """
    Attempt to acquire (or renew) leadership for candidate_id.

    Returns the UUID of the current leader for the namespace after this call.
    """
    n = _ns(ns)
    cid = str(candidate_id)
    with _session_scope(session) as s:
        # Contention-safe: if two candidates attempt to create the leader row at
        # the same time, one may hit IntegrityError on insert/flush. Retry once
        # with a fresh transaction.
        for _ in range(2):
            lease = _lease()
            try:
                with s.begin():
                    # Ensure the candidate is present/active.
                    row = s.get(ElectionCandidate, {"ns": n, "candidate_id": cid})
                    if row is None:
                        s.add(
                            ElectionCandidate(
                                ns=n,
                                candidate_id=cid,
                                last_heartbeat_at=lease.now,
                                expires_at=lease.expires_at,
                            )
                        )
                    else:
                        row.last_heartbeat_at = lease.now
                        row.expires_at = lease.expires_at

                    # Acquire a row lock on the leader entry if supported.
                    try:
                        leader = s.execute(
                            select(ElectionLeader).where(ElectionLeader.ns == n).with_for_update()
                        ).scalar_one_or_none()
                    except Exception:
                        # SQLite and some drivers may not support FOR UPDATE cleanly.
                        leader = s.get(ElectionLeader, n)

                    if leader is None:
                        leader = ElectionLeader(
                            ns=n,
                            leader_id=cid,
                            lease_expires_at=lease.expires_at,
                            updated_at=lease.now,
                        )
                        s.add(leader)
                        s.flush()  # may raise IntegrityError under contention

                    # Renew if we are leader, or take over if expired/cleared.
                    if leader.leader_id is None or leader.lease_expires_at is None:
                        leader.leader_id = cid
                        leader.lease_expires_at = lease.expires_at
                        leader.updated_at = lease.now
                    elif leader.leader_id == cid:
                        leader.lease_expires_at = lease.expires_at
                        leader.updated_at = lease.now
                    elif leader.lease_expires_at <= lease.now:
                        leader.leader_id = cid
                        leader.lease_expires_at = lease.expires_at
                        leader.updated_at = lease.now

                    # Ensure a usable leader_id is returned.
                    if leader.leader_id is None:
                        leader.leader_id = cid
                        leader.lease_expires_at = lease.expires_at
                        leader.updated_at = lease.now

                    return UUID(leader.leader_id)
            except IntegrityError:
                # Auto-rollback occurs; retry once.
                continue

        # If we still can't elect due to persistent contention, fall back to
        # reading current leader without attempting insert again.
        leader = s.get(ElectionLeader, n)
        if leader and leader.leader_id and leader.lease_expires_at and leader.lease_expires_at > _utcnow():
            return UUID(leader.leader_id)
        return UUID(cid)

