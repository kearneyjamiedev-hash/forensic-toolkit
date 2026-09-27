from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


AUDIT_SCHEMA_VERSION = 1
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


def _default_db_path() -> Path:
    configured = os.environ.get("FORENSIC_AUDIT_DB")
    if configured:
        return Path(configured).expanduser().resolve()

    project_root = Path(__file__).resolve().parents[1]
    return project_root / "data" / "audit.sqlite3"


def _resolve_db_path(db_path: Path | str | None) -> Path:
    if db_path is None:
        return _default_db_path()
    return Path(db_path).expanduser().resolve()


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalise_optional_text(
    value: str | None,
    *,
    max_length: int,
) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    return text[:max_length]


def _normalise_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if details is None:
        return {}

    # Round-trip through JSON so the stored value is JSON-safe and stable.
    return json.loads(
        json.dumps(
            details,
            ensure_ascii=False,
            default=str,
        )
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _entry_hash_payload(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": event["schema_version"],
        "event_id": event["event_id"],
        "timestamp_utc": event["timestamp_utc"],
        "event_type": event["event_type"],
        "evidence_id": event["evidence_id"],
        "case_reference": event.get("case_reference"),
        "actor": event.get("actor"),
        "filename": event.get("filename"),
        "sha256": event.get("sha256"),
        "outcome": event.get("outcome"),
        "details": event.get("details") or {},
        "previous_hash": event.get("previous_hash"),
    }


def _calculate_entry_hash(event: dict[str, Any]) -> str:
    payload = _canonical_json(
        _entry_hash_payload(event)
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def _connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    resolved = _resolve_db_path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        resolved,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def init_audit_db(
    db_path: Path | str | None = None,
) -> Path:
    resolved = _resolve_db_path(db_path)

    with _connect(resolved) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
                schema_version INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                case_reference TEXT,
                actor TEXT,
                filename TEXT,
                sha256 TEXT,
                outcome TEXT,
                details_json TEXT NOT NULL,
                previous_hash TEXT,
                entry_hash TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_evidence_sequence
            ON audit_events (evidence_id, sequence_id)
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_event_type
            ON audit_events (event_type)
            """
        )

    return resolved


def record_audit_event(
    *,
    event_type: str,
    evidence_id: str,
    case_reference: str | None = None,
    actor: str | None = None,
    filename: str | None = None,
    sha256: str | None = None,
    outcome: str | None = None,
    details: dict[str, Any] | None = None,
    timestamp_utc: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    event_type = str(event_type).strip().upper()
    evidence_id = str(evidence_id).strip()

    if not event_type:
        raise ValueError("Audit event type is required.")

    if not evidence_id:
        raise ValueError("Evidence ID is required for an audit event.")

    if len(event_type) > 100:
        raise ValueError("Audit event type is too long.")

    if len(evidence_id) > 200:
        raise ValueError("Evidence ID is too long.")

    normalised_sha256 = _normalise_optional_text(
        sha256,
        max_length=128,
    )

    if normalised_sha256 is not None:
        normalised_sha256 = normalised_sha256.lower()

    event: dict[str, Any] = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "event_id": str(uuid4()),
        "timestamp_utc": timestamp_utc or _utc_now(),
        "event_type": event_type,
        "evidence_id": evidence_id,
        "case_reference": _normalise_optional_text(
            case_reference,
            max_length=500,
        ),
        "actor": _normalise_optional_text(
            actor,
            max_length=500,
        ),
        "filename": _normalise_optional_text(
            filename,
            max_length=1000,
        ),
        "sha256": normalised_sha256,
        "outcome": _normalise_optional_text(
            outcome,
            max_length=100,
        ),
        "details": _normalise_details(details),
        "previous_hash": None,
    }

    init_audit_db(db_path)

    with _connect(db_path) as connection:
        # Serialize writers while we read the previous event and append the next
        # chain element. SQLite guarantees the transaction is atomic.
        connection.execute("BEGIN IMMEDIATE")

        previous = connection.execute(
            """
            SELECT entry_hash
            FROM audit_events
            WHERE evidence_id = ?
            ORDER BY sequence_id DESC
            LIMIT 1
            """,
            (evidence_id,),
        ).fetchone()

        event["previous_hash"] = (
            previous["entry_hash"]
            if previous is not None
            else None
        )
        event["entry_hash"] = _calculate_entry_hash(event)

        cursor = connection.execute(
            """
            INSERT INTO audit_events (
                schema_version,
                event_id,
                timestamp_utc,
                event_type,
                evidence_id,
                case_reference,
                actor,
                filename,
                sha256,
                outcome,
                details_json,
                previous_hash,
                entry_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["schema_version"],
                event["event_id"],
                event["timestamp_utc"],
                event["event_type"],
                event["evidence_id"],
                event["case_reference"],
                event["actor"],
                event["filename"],
                event["sha256"],
                event["outcome"],
                _canonical_json(event["details"]),
                event["previous_hash"],
                event["entry_hash"],
            ),
        )

        event["sequence_id"] = cursor.lastrowid

    return event


def get_audit_events(
    evidence_id: str,
    *,
    limit: int = DEFAULT_LIMIT,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    evidence_id = str(evidence_id).strip()
    if not evidence_id:
        raise ValueError("Evidence ID is required.")

    limit = max(1, min(int(limit), MAX_LIMIT))
    init_audit_db(db_path)

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                sequence_id,
                schema_version,
                event_id,
                timestamp_utc,
                event_type,
                evidence_id,
                case_reference,
                actor,
                filename,
                sha256,
                outcome,
                details_json,
                previous_hash,
                entry_hash
            FROM audit_events
            WHERE evidence_id = ?
            ORDER BY sequence_id ASC
            LIMIT ?
            """,
            (evidence_id, limit),
        ).fetchall()

    return [_row_to_event(row) for row in rows]


def _get_all_audit_events(
    evidence_id: str,
    *,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Return the complete chain for verification without the UI result cap."""
    evidence_id = str(evidence_id).strip()
    if not evidence_id:
        raise ValueError("Evidence ID is required.")

    init_audit_db(db_path)

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                sequence_id, schema_version, event_id, timestamp_utc,
                event_type, evidence_id, case_reference, actor, filename,
                sha256, outcome, details_json, previous_hash, entry_hash
            FROM audit_events
            WHERE evidence_id = ?
            ORDER BY sequence_id ASC
            """,
            (evidence_id,),
        ).fetchall()

    return [_row_to_event(row) for row in rows]


def verify_audit_chain(
    evidence_id: str,
    *,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    events = _get_all_audit_events(
        evidence_id,
        db_path=db_path,
    )

    previous_hash: str | None = None

    for index, event in enumerate(events):
        if event.get("previous_hash") != previous_hash:
            return {
                "verified": False,
                "event_count": len(events),
                "failure_index": index,
                "failure_event_id": event.get("event_id"),
                "reason": "Previous-hash link does not match the preceding audit entry.",
            }

        expected_hash = _calculate_entry_hash(event)

        if event.get("entry_hash") != expected_hash:
            return {
                "verified": False,
                "event_count": len(events),
                "failure_index": index,
                "failure_event_id": event.get("event_id"),
                "reason": "Audit entry content does not match its recorded hash.",
            }

        previous_hash = event.get("entry_hash")

    return {
        "verified": True,
        "event_count": len(events),
        "failure_index": None,
        "failure_event_id": None,
        "reason": None,
        "head_hash": previous_hash,
    }



def get_recent_audit_events(
    *,
    limit: int = 50,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Return newest audit events across all evidence items."""
    limit = max(1, min(int(limit), MAX_LIMIT))
    init_audit_db(db_path)

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                sequence_id, schema_version, event_id, timestamp_utc,
                event_type, evidence_id, case_reference, actor, filename,
                sha256, outcome, details_json, previous_hash, entry_hash
            FROM audit_events
            ORDER BY sequence_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [_row_to_event(row) for row in rows]


def get_evidence_audit_summaries(
    *,
    limit: int = 100,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Return one dashboard row per evidence chain, newest first."""
    limit = max(1, min(int(limit), MAX_LIMIT))
    init_audit_db(db_path)

    with _connect(db_path) as connection:
        groups = connection.execute(
            """
            SELECT
                evidence_id,
                COUNT(*) AS event_count,
                MAX(sequence_id) AS latest_sequence_id
            FROM audit_events
            GROUP BY evidence_id
            ORDER BY latest_sequence_id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        summaries = []

        for group in groups:
            latest = connection.execute(
                """
                SELECT
                    sequence_id, schema_version, event_id, timestamp_utc,
                    event_type, evidence_id, case_reference, actor, filename,
                    sha256, outcome, details_json, previous_hash, entry_hash
                FROM audit_events
                WHERE sequence_id = ?
                """,
                (group["latest_sequence_id"],),
            ).fetchone()

            latest_event = _row_to_event(latest)
            chain = verify_audit_chain(
                group["evidence_id"],
                db_path=db_path,
            )

            summaries.append(
                {
                    "evidence_id": group["evidence_id"],
                    "event_count": group["event_count"],
                    "case_reference": latest_event.get("case_reference"),
                    "actor": latest_event.get("actor"),
                    "filename": latest_event.get("filename"),
                    "sha256": latest_event.get("sha256"),
                    "latest_event_type": latest_event.get("event_type"),
                    "latest_timestamp_utc": latest_event.get("timestamp_utc"),
                    "latest_outcome": latest_event.get("outcome"),
                    "chain_verified": chain.get("verified") is True,
                    "head_hash": chain.get("head_hash"),
                }
            )

    return summaries


def get_audit_dashboard_summary(
    *,
    recent_limit: int = 50,
    evidence_limit: int = 100,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """Build the read-only summary used by the audit dashboard."""
    init_audit_db(db_path)

    with _connect(db_path) as connection:
        total_events = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

        evidence_count = connection.execute(
            "SELECT COUNT(DISTINCT evidence_id) FROM audit_events"
        ).fetchone()[0]

        integrity_failures = connection.execute(
            """
            SELECT COUNT(*) FROM audit_events
            WHERE event_type = 'INTEGRITY_FAILURE'
            """
        ).fetchone()[0]

        reports_generated = connection.execute(
            """
            SELECT COUNT(*) FROM audit_events
            WHERE event_type = 'REPORT_GENERATED'
            """
        ).fetchone()[0]

        security_checks = connection.execute(
            """
            SELECT COUNT(*) FROM audit_events
            WHERE event_type = 'SECURITY_CHECK_COMPLETED'
            """
        ).fetchone()[0]

    evidence = get_evidence_audit_summaries(
        limit=evidence_limit,
        db_path=db_path,
    )

    with _connect(db_path) as connection:
        all_evidence_ids = [
            row["evidence_id"]
            for row in connection.execute(
                "SELECT DISTINCT evidence_id FROM audit_events"
            ).fetchall()
        ]

    chain_results = [
        verify_audit_chain(
            evidence_id,
            db_path=db_path,
        )
        for evidence_id in all_evidence_ids
    ]

    verified_chains = sum(
        1 for chain in chain_results if chain.get("verified") is True
    )
    failed_chains = sum(
        1 for chain in chain_results if chain.get("verified") is not True
    )

    return {
        "summary": {
            "total_events": total_events,
            "evidence_count": evidence_count,
            "verified_chains": verified_chains,
            "failed_chains": failed_chains,
            "integrity_failures": integrity_failures,
            "reports_generated": reports_generated,
            "security_checks": security_checks,
        },
        "evidence": evidence,
        "recent_events": get_recent_audit_events(
            limit=recent_limit,
            db_path=db_path,
        ),
    }


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    try:
        details = json.loads(row["details_json"])
    except (TypeError, json.JSONDecodeError):
        # Preserve corruption as data so verify_audit_chain() can flag the
        # resulting hash mismatch rather than crashing the audit viewer.
        details = {
            "_invalid_json": row["details_json"],
        }

    return {
        "sequence_id": row["sequence_id"],
        "schema_version": row["schema_version"],
        "event_id": row["event_id"],
        "timestamp_utc": row["timestamp_utc"],
        "event_type": row["event_type"],
        "evidence_id": row["evidence_id"],
        "case_reference": row["case_reference"],
        "actor": row["actor"],
        "filename": row["filename"],
        "sha256": row["sha256"],
        "outcome": row["outcome"],
        "details": details,
        "previous_hash": row["previous_hash"],
        "entry_hash": row["entry_hash"],
    }
