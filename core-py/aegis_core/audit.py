"""Audit System.

Provides an immutable, append-only record of every governance decision
made by AEGIS.  Records are stored in a SQLite database and can be
queried for compliance reporting and forensic review.

Design principles
-----------------
* **Immutable** - records are never updated or deleted.
* **Complete** - every AGP request/response pair is recorded regardless
  of the decision outcome.
* **Queryable** - records can be retrieved by audit ID, agent ID, or session.
* **Thread-safe** - all database operations are protected by locks for
  concurrent access from multiple agents.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from . import errors
from .exceptions import AEGISAuditError


@dataclass(frozen=True)
class AuditRecord:
    """An immutable record of a single governance decision.

    Parameters
    ----------
    id : str
        Unique identifier for this audit record.
    request_id : str
        The AGPRequest identifier this audit record documents.
    agent_id : str
        The agent ID that submitted the request.
    action_type : str
        The type of action that was evaluated.
    action_target : str
        The target resource for the action.
    action_parameters : dict
        The action parameters submitted.
    decision : str
        The governance decision (APPROVED, DENIED, etc.).
    reason : str
        Human-readable explanation of the decision.
    policy_evaluations : list
        List of policy evaluation results.
    session_id : str
        The session identifier for this request.
    timestamp : str
        ISO 8601 timestamp when this record was created.
    """

    id: str
    request_id: str
    agent_id: str
    action_type: str
    action_target: str
    action_parameters: dict[str, Any]
    decision: str
    reason: str
    policy_evaluations: list[dict[str, Any]]
    session_id: str
    timestamp: str
    record_hmac: str = ""
    prev_hash: str = ""


class AuditSystem:
    """SQLite-backed, append-only, thread-safe governance audit trail.

    The AuditSystem provides immutable storage of all governance decisions
    with efficient querying by audit ID, agent ID, or session.  All database
    operations use threading locks to ensure thread-safety for concurrent
    access from multiple AI agents.

    Parameters
    ----------
    db_path : str
        File path for the SQLite database.  Defaults to ``":memory:"``
        which is useful for testing.

    Raises
    ------
    AEGISAuditError
        If the database cannot be initialized.
    """

    _CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS audit_records (
            id                 TEXT PRIMARY KEY,
            request_id         TEXT NOT NULL,
            agent_id           TEXT NOT NULL,
            action_type        TEXT NOT NULL,
            action_target      TEXT NOT NULL,
            action_parameters  TEXT NOT NULL,
            decision           TEXT NOT NULL,
            reason             TEXT NOT NULL,
            policy_evaluations TEXT NOT NULL,
            session_id         TEXT NOT NULL,
            timestamp          TEXT NOT NULL,
            record_hmac        TEXT NOT NULL DEFAULT '',
            prev_hash          TEXT NOT NULL DEFAULT ''
        )
    """

    _COLUMNS = (
        "id",
        "request_id",
        "agent_id",
        "action_type",
        "action_target",
        "action_parameters",
        "decision",
        "reason",
        "policy_evaluations",
        "session_id",
        "timestamp",
        "record_hmac",
        "prev_hash",
    )

    # M-4: Checkpoint WAL after this many writes to prevent unbounded growth
    _WAL_CHECKPOINT_INTERVAL = 1000

    # RT-009 / T9002: Genesis hash for the first record in the chain
    _GENESIS_HASH = "0" * 64

    def __init__(self, db_path: str = ":memory:", *, hmac_key: bytes | None = None) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute(self._CREATE_TABLE)
        # RT-009: Add columns to existing tables that lack them (migration)
        self._migrate_integrity_columns()
        self._conn.commit()
        self._write_count = 0

        # RT-009 / T9002: HMAC key for audit record authentication
        self._hmac_key = hmac_key or secrets.token_bytes(32)

        # Cache the latest record's HMAC for hash chaining
        self._last_hmac = self._load_last_hmac()

    def _migrate_integrity_columns(self) -> None:
        """Add record_hmac and prev_hash columns if they don't exist."""
        cursor = self._conn.execute("PRAGMA table_info(audit_records)")
        existing = {row[1] for row in cursor.fetchall()}
        if "record_hmac" not in existing:
            self._conn.execute(
                "ALTER TABLE audit_records ADD COLUMN record_hmac TEXT NOT NULL DEFAULT ''"
            )
        if "prev_hash" not in existing:
            self._conn.execute(
                "ALTER TABLE audit_records ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
            )

    def _load_last_hmac(self) -> str:
        """Load the HMAC of the most recent record for chain continuity."""
        cursor = self._conn.execute(
            "SELECT record_hmac FROM audit_records ORDER BY rowid DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return row[0] if row and row[0] else self._GENESIS_HASH

    def _compute_hmac(
        self,
        audit_id: str,
        request_id: str,
        agent_id: str,
        action_type: str,
        action_target: str,
        action_parameters_json: str,
        decision: str,
        reason: str,
        policy_evaluations_json: str,
        session_id: str,
        timestamp: str,
        prev_hash: str,
    ) -> str:
        """Compute HMAC-SHA256 over the record's content fields.

        The HMAC covers all data fields plus the previous record's hash,
        forming a verifiable chain (RT-009 / T9002, ATM-1 DC-1).
        """
        payload = "|".join([
            audit_id,
            request_id,
            agent_id,
            action_type,
            action_target,
            action_parameters_json,
            decision,
            reason,
            policy_evaluations_json,
            session_id,
            timestamp,
            prev_hash,
        ])
        return hmac.new(
            self._hmac_key, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(
        self,
        *,
        request_id: str,
        agent_id: str,
        action_type: str,
        action_target: str,
        action_parameters: dict[str, Any],
        decision: str,
        reason: str,
        policy_evaluations: list[dict[str, Any]],
        session_id: str,
    ) -> str:
        """Append a governance decision to the audit trail.

        This method is thread-safe and ensures that the audit record is
        persisted atomically before returning.

        Parameters
        ----------
        request_id : str
            The AGPRequest identifier.
        agent_id : str
            The agent ID of the request submitter.
        action_type : str
            The action type being audited.
        action_target : str
            The target resource for the action.
        action_parameters : dict
            The parameters submitted with the action.
        decision : str
            The governance decision outcome.
        reason : str
            Explanation of the decision.
        policy_evaluations : list
            Policy evaluation results.
        session_id : str
            The session identifier.

        Returns
        -------
        str
            The newly generated audit record ID (UUID).

        Raises
        ------
        AEGISAuditError
            If the record cannot be persisted to the database.
        """
        audit_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()
        params_json = json.dumps(action_parameters)
        evals_json = json.dumps(policy_evaluations)

        with self._lock:
            try:
                # RT-009 / T9002: Chain to previous record's HMAC
                prev_hash = self._last_hmac
                record_hmac = self._compute_hmac(
                    audit_id, request_id, agent_id, action_type,
                    action_target, params_json, decision, reason,
                    evals_json, session_id, timestamp, prev_hash,
                )

                self._conn.execute(
                    f"INSERT INTO audit_records ({', '.join(self._COLUMNS)}) "
                    f"VALUES ({', '.join(['?'] * len(self._COLUMNS))})",
                    (
                        audit_id,
                        request_id,
                        agent_id,
                        action_type,
                        action_target,
                        params_json,
                        decision,
                        reason,
                        evals_json,
                        session_id,
                        timestamp,
                        record_hmac,
                        prev_hash,
                    ),
                )
                self._conn.commit()
                self._last_hmac = record_hmac
                self._maybe_checkpoint()
            except sqlite3.Error as exc:
                raise AEGISAuditError(
                    f"Failed to persist audit record: {exc}",
                    error_code=errors.AUD_PERSIST_ERROR,
                    cause="audit_records",
                ) from exc

        return audit_id

    def _maybe_checkpoint(self) -> None:
        """Checkpoint WAL if write count exceeds interval (M-4)."""
        self._write_count += 1
        if self._write_count >= self._WAL_CHECKPOINT_INTERVAL:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            self._write_count = 0

    def batch_record(
        self,
        records: list[dict[str, Any]],
    ) -> list[str]:
        """Append multiple governance decisions to the audit trail in a batch.

        This method is more efficient than calling :meth:`record` multiple
        times, as it batches all inserts into a single transaction. All records
        are inserted atomically.

        Parameters
        ----------
        records : list[dict]
            A list of dictionaries, each containing the keyword arguments for
            a single record (request_id, agent_id, action_type, etc.).

        Returns
        -------
        list[str]
            List of newly generated audit record IDs, in the same order as
            the input records.

        Raises
        ------
        AEGISAuditError
            If any record cannot be persisted.
        """
        if not records:
            return []

        audit_ids = [str(uuid.uuid4()) for _ in records]
        timestamp = datetime.now(UTC).isoformat()

        with self._lock:
            try:
                # H-5: Explicit transaction for atomic batch insert.
                # On failure, all records are rolled back — no partial state.
                chain_hmac = self._last_hmac
                self._conn.execute("BEGIN IMMEDIATE")
                for audit_id, record_data in zip(audit_ids, records, strict=False):
                    params_json = json.dumps(record_data["action_parameters"])
                    evals_json = json.dumps(record_data["policy_evaluations"])
                    prev_hash = chain_hmac
                    record_hmac = self._compute_hmac(
                        audit_id, record_data["request_id"],
                        record_data["agent_id"], record_data["action_type"],
                        record_data["action_target"], params_json,
                        record_data["decision"], record_data["reason"],
                        evals_json, record_data["session_id"],
                        timestamp, prev_hash,
                    )
                    self._conn.execute(
                        f"INSERT INTO audit_records ({', '.join(self._COLUMNS)}) "
                        f"VALUES ({', '.join(['?'] * len(self._COLUMNS))})",
                        (
                            audit_id,
                            record_data["request_id"],
                            record_data["agent_id"],
                            record_data["action_type"],
                            record_data["action_target"],
                            params_json,
                            record_data["decision"],
                            record_data["reason"],
                            evals_json,
                            record_data["session_id"],
                            timestamp,
                            record_hmac,
                            prev_hash,
                        ),
                    )
                    chain_hmac = record_hmac
                self._conn.execute("COMMIT")
                self._last_hmac = chain_hmac
            except sqlite3.Error as exc:
                import contextlib

                with contextlib.suppress(sqlite3.Error):
                    self._conn.execute("ROLLBACK")
                raise AEGISAuditError(
                    f"Failed to persist batch audit records: {exc}",
                    error_code=errors.AUD_BATCH_PERSIST_ERROR,
                    cause="audit_records",
                ) from exc

        return audit_ids

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_record(self, audit_id: str) -> AuditRecord | None:
        """Retrieve a single audit record by its ID.

        Parameters
        ----------
        audit_id : str
            The audit record ID to retrieve.

        Returns
        -------
        AuditRecord or None
            The audit record if found, None otherwise.
        """
        with self._lock:
            cursor = self._conn.execute("SELECT * FROM audit_records WHERE id = ?", (audit_id,))
            row = cursor.fetchone()
        return self._row_to_record(row) if row else None

    def get_agent_history(
        self, agent_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[AuditRecord]:
        """Return the most recent audit records for a given agent.

        Parameters
        ----------
        agent_id : str
            The agent identifier to retrieve history for.
        limit : int, optional
            Maximum number of records to return. Defaults to 100.
        offset : int, optional
            Number of records to skip. Defaults to 0. Useful for pagination.

        Returns
        -------
        list[AuditRecord]
            List of audit records, ordered by timestamp (newest first).
        """
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM audit_records "
                "WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (agent_id, limit, offset),
            )
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def get_session_history(self, session_id: str, *, limit: int = 1000) -> list[AuditRecord]:
        """Return audit records for a given session.

        Parameters
        ----------
        session_id : str
            The session identifier to retrieve history for.
        limit : int, optional
            Maximum number of records to return. Defaults to 1000 (L-4).

        Returns
        -------
        list[AuditRecord]
            List of audit records, ordered by timestamp (oldest first).
        """
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM audit_records WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?",
                (session_id, limit),
            )
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def find_by_decision(self, decision: str, *, limit: int = 100) -> list[AuditRecord]:
        """Find audit records by decision outcome.

        Parameters
        ----------
        decision : str
            The decision value to filter by (e.g., "APPROVED", "DENIED").
        limit : int, optional
            Maximum number of records to return. Defaults to 100.

        Returns
        -------
        list[AuditRecord]
            List of matching audit records, ordered by timestamp (newest first).
        """
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM audit_records WHERE decision = ? ORDER BY timestamp DESC LIMIT ?",
                (decision, limit),
            )
            rows = cursor.fetchall()
        return [self._row_to_record(row) for row in rows]

    def record_count(self, agent_id: str | None = None) -> int:
        """Get the total number of audit records.

        Parameters
        ----------
        agent_id : str, optional
            If provided, count only records for this agent. Defaults to None
            (count all records).

        Returns
        -------
        int
            The number of audit records matching the criteria.
        """
        with self._lock:
            if agent_id is None:
                cursor = self._conn.execute("SELECT COUNT(*) FROM audit_records")
            else:
                cursor = self._conn.execute(
                    "SELECT COUNT(*) FROM audit_records WHERE agent_id = ?",
                    (agent_id,),
                )
            return cursor.fetchone()[0]  # type: ignore

    # ------------------------------------------------------------------
    # Lifecycle (L-6)
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the database connection.

        Safe to call multiple times. After closing, all write and
        read operations will raise ``sqlite3.ProgrammingError``.
        """
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row_to_record(self, row: tuple[Any, ...]) -> AuditRecord:
        """Convert a database row to an AuditRecord.

        BT-AUDIT-007: Handles corrupted JSON gracefully instead of
        propagating unhandled json.JSONDecodeError.
        """
        data = dict(zip(self._COLUMNS, row, strict=False))
        try:
            data["action_parameters"] = json.loads(data["action_parameters"])
        except (json.JSONDecodeError, TypeError):
            data["action_parameters"] = {}
        try:
            data["policy_evaluations"] = json.loads(data["policy_evaluations"])
        except (json.JSONDecodeError, TypeError):
            data["policy_evaluations"] = []
        # Gracefully handle records from before integrity columns existed
        data.setdefault("record_hmac", "")
        data.setdefault("prev_hash", "")
        return AuditRecord(**data)

    # ------------------------------------------------------------------
    # Integrity verification (RT-009 / T9002)
    # ------------------------------------------------------------------

    def verify_chain(self, *, limit: int = 0) -> tuple[bool, list[str]]:
        """Verify the cryptographic integrity of the audit chain.

        Walks the audit trail in insertion order, recomputing each
        record's HMAC and verifying that ``prev_hash`` matches the
        preceding record's HMAC (hash chaining, ATM-1 DC-1).

        Parameters
        ----------
        limit : int, optional
            Maximum number of records to verify.  0 means all records.

        Returns
        -------
        tuple[bool, list[str]]
            ``(is_valid, violations)`` where ``is_valid`` is True if the
            entire chain is intact, and ``violations`` is a list of
            human-readable descriptions of any integrity failures.
        """
        violations: list[str] = []

        with self._lock:
            query = "SELECT * FROM audit_records ORDER BY rowid ASC"
            if limit > 0:
                query += f" LIMIT {limit}"
            cursor = self._conn.execute(query)
            rows = cursor.fetchall()

        expected_prev = self._GENESIS_HASH

        for row in rows:
            data = dict(zip(self._COLUMNS, row, strict=False))
            audit_id = data["id"]
            stored_hmac = data.get("record_hmac", "")
            stored_prev = data.get("prev_hash", "")

            # Skip pre-integrity records (migration: empty HMAC)
            if not stored_hmac:
                continue

            # Verify chain linkage
            if stored_prev != expected_prev:
                violations.append(
                    f"Record {audit_id}: prev_hash mismatch — "
                    f"expected {expected_prev[:16]}…, got {stored_prev[:16]}…"
                )

            # Recompute HMAC and compare
            recomputed = self._compute_hmac(
                data["id"],
                data["request_id"],
                data["agent_id"],
                data["action_type"],
                data["action_target"],
                data["action_parameters"],  # still JSON string from DB
                data["decision"],
                data["reason"],
                data["policy_evaluations"],  # still JSON string from DB
                data["session_id"],
                data["timestamp"],
                stored_prev,
            )

            if not hmac.compare_digest(recomputed, stored_hmac):
                violations.append(
                    f"Record {audit_id}: HMAC mismatch — record has been tampered with"
                )

            expected_prev = stored_hmac

        return (len(violations) == 0, violations)
