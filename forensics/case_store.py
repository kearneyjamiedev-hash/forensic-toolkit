from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from forensics.evidence_store import DATABASE_PATH


CASE_SCHEMA_VERSION = 1
DEFAULT_CASE_LIMIT = 100
MAX_CASE_LIMIT = 500
DEFAULT_EVIDENCE_LIMIT = 200
MAX_EVIDENCE_LIMIT = 1000
DEFAULT_ENTRY_LIMIT = 500
MAX_ENTRY_LIMIT = 2000
MAX_ENTRY_CONTENT_LENGTH = 10_000

STANDARD_ENTRY_TYPES = (
    "OBSERVATION",
    "ACTION_TAKEN",
    "COMMAND_EXECUTED",
    "EVIDENCE_IDENTIFIED",
    "FINDING",
    "HYPOTHESIS",
    "VERIFICATION",
    "GENERAL_NOTE",
)
CORRECTION_ENTRY_TYPE = "CORRECTION"
ALL_ENTRY_TYPES = STANDARD_ENTRY_TYPES + (CORRECTION_ENTRY_TYPE,)


class DuplicateCaseReferenceError(ValueError):
    pass


class CaseClosedError(ValueError):
    pass


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _resolve_db_path(db_path: Path | str | None) -> Path:
    if db_path is None:
        return DATABASE_PATH
    return Path(db_path).expanduser().resolve()


def _connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    resolved = _resolve_db_path(db_path)
    resolved.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(resolved, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def _required_text(value: str, *, field_name: str, max_length: int) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{field_name} is required.")
    if len(text) > max_length:
        raise ValueError(f"{field_name} must be {max_length} characters or fewer.")
    return text


def _optional_text(value: str | None, *, max_length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        raise ValueError(f"Value must be {max_length} characters or fewer.")
    return text


def _normalise_entry_type(value: str, *, allow_correction: bool = False) -> str:
    entry_type = _required_text(
        value,
        field_name="Entry type",
        max_length=80,
    ).upper().replace("-", "_").replace(" ", "_")

    allowed = ALL_ENTRY_TYPES if allow_correction else STANDARD_ENTRY_TYPES
    if entry_type not in allowed:
        raise ValueError("Invalid investigation entry type.")
    return entry_type


def _parse_analysis_summary(analysis_json: str | None) -> dict[str, Any]:
    summary = {
        "detected_type": None,
        "findings_count": None,
    }
    if not analysis_json:
        return summary

    try:
        analysis = json.loads(analysis_json)
    except (TypeError, json.JSONDecodeError):
        return summary

    if not isinstance(analysis, dict):
        return summary

    signature = analysis.get("signature")
    if isinstance(signature, dict):
        summary["detected_type"] = signature.get("detected_type")

    security_assessment = analysis.get("security_assessment")
    if isinstance(security_assessment, dict):
        counts = security_assessment.get("counts")
        if isinstance(counts, dict):
            total = counts.get("total")
            if isinstance(total, int) and total >= 0:
                summary["findings_count"] = total

    return summary


def _evidence_row_to_summary(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    analysis_json = result.pop("analysis_json", None)
    result.update(_parse_analysis_summary(analysis_json))
    return result


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def init_case_db(db_path: Path | str | None = None) -> Path:
    resolved = _resolve_db_path(db_path)

    with _connect(resolved) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                case_reference TEXT NOT NULL UNIQUE COLLATE NOCASE,
                title TEXT NOT NULL,
                description TEXT,
                examiner TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                closed_at_utc TEXT
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS case_evidence (
                case_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                added_at_utc TEXT NOT NULL,
                PRIMARY KEY (case_id, evidence_id),
                FOREIGN KEY (case_id)
                    REFERENCES cases(case_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(evidence_id)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_entries (
                entry_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                entry_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                examiner TEXT NOT NULL,
                linked_evidence_id TEXT,
                parent_entry_id TEXT,
                UNIQUE (case_id, sequence_number),
                FOREIGN KEY (case_id)
                    REFERENCES cases(case_id)
                    ON DELETE CASCADE,
                FOREIGN KEY (linked_evidence_id)
                    REFERENCES evidence(evidence_id),
                FOREIGN KEY (parent_entry_id)
                    REFERENCES investigation_entries(entry_id)
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_case_evidence_case_id
            ON case_evidence(case_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_case_evidence_evidence_id
            ON case_evidence(evidence_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_investigation_entries_case_sequence
            ON investigation_entries(case_id, sequence_number)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_investigation_entries_evidence
            ON investigation_entries(linked_evidence_id)
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_investigation_entries_parent
            ON investigation_entries(parent_entry_id)
            """
        )

    return resolved


def create_case(
    *,
    case_reference: str,
    title: str,
    examiner: str,
    description: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    case_reference = _required_text(
        case_reference,
        field_name="Case reference",
        max_length=120,
    )
    title = _required_text(
        title,
        field_name="Title",
        max_length=200,
    )
    examiner = _required_text(
        examiner,
        field_name="Examiner",
        max_length=200,
    )
    description = _optional_text(description, max_length=4000)

    init_case_db(db_path)

    case_id = str(uuid4())
    created_at = _utc_now()

    try:
        with _connect(db_path) as connection:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id,
                    schema_version,
                    case_reference,
                    title,
                    description,
                    examiner,
                    status,
                    created_at_utc,
                    updated_at_utc,
                    closed_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    CASE_SCHEMA_VERSION,
                    case_reference,
                    title,
                    description,
                    examiner,
                    "OPEN",
                    created_at,
                    created_at,
                    None,
                ),
            )
    except sqlite3.IntegrityError as error:
        if "case_reference" in str(error).lower() or "unique" in str(error).lower():
            raise DuplicateCaseReferenceError(
                "A case with that reference already exists."
            ) from error
        raise

    result = get_case(case_id, db_path=db_path)
    if result is None:
        raise RuntimeError("Case was created but could not be loaded.")
    return result


def list_cases(
    *,
    limit: int = DEFAULT_CASE_LIMIT,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), MAX_CASE_LIMIT))
    init_case_db(db_path)

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                c.case_id,
                c.schema_version,
                c.case_reference,
                c.title,
                c.description,
                c.examiner,
                c.status,
                c.created_at_utc,
                c.updated_at_utc,
                c.closed_at_utc,
                (
                    SELECT COUNT(*)
                    FROM case_evidence AS ce
                    WHERE ce.case_id = c.case_id
                ) AS evidence_count,
                (
                    SELECT COUNT(*)
                    FROM investigation_entries AS ie
                    WHERE ie.case_id = c.case_id
                ) AS investigation_entry_count
            FROM cases AS c
            ORDER BY c.updated_at_utc DESC, c.created_at_utc DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_case(
    case_id: str,
    *,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    case_id = str(case_id).strip()
    if not case_id or len(case_id) > 128:
        return None

    init_case_db(db_path)

    with _connect(db_path) as connection:
        case_row = connection.execute(
            """
            SELECT
                case_id,
                schema_version,
                case_reference,
                title,
                description,
                examiner,
                status,
                created_at_utc,
                updated_at_utc,
                closed_at_utc
            FROM cases
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()

        if case_row is None:
            return None

        integrity_expression = "NULL AS integrity_status"
        if _table_exists(connection, "verification_log"):
            integrity_expression = """
                (
                    SELECT vl.status
                    FROM verification_log AS vl
                    WHERE vl.evidence_id = e.evidence_id
                    ORDER BY vl.id DESC
                    LIMIT 1
                ) AS integrity_status
            """

        evidence_rows = connection.execute(
            f"""
            SELECT
                e.evidence_id,
                e.original_filename,
                e.original_sha256,
                e.analysis_timestamp_utc,
                e.analysis_json,
                e.created_at_utc,
                ce.added_at_utc,
                {integrity_expression}
            FROM case_evidence AS ce
            INNER JOIN evidence AS e
                ON e.evidence_id = ce.evidence_id
            WHERE ce.case_id = ?
            ORDER BY ce.added_at_utc DESC
            """,
            (case_id,),
        ).fetchall()

        entry_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM investigation_entries
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()[0]

    result = dict(case_row)
    result["evidence"] = [_evidence_row_to_summary(row) for row in evidence_rows]
    result["evidence_count"] = len(evidence_rows)
    result["investigation_entry_count"] = entry_count
    return result


def close_case(
    case_id: str,
    *,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    case_id = _required_text(case_id, field_name="Case ID", max_length=128)
    init_case_db(db_path)

    with _connect(db_path) as connection:
        row = connection.execute(
            "SELECT status FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Case not found.")

        if row["status"] != "CLOSED":
            closed_at = _utc_now()
            connection.execute(
                """
                UPDATE cases
                SET status = 'CLOSED',
                    closed_at_utc = ?,
                    updated_at_utc = ?
                WHERE case_id = ?
                """,
                (closed_at, closed_at, case_id),
            )

    result = get_case(case_id, db_path=db_path)
    if result is None:
        raise RuntimeError("Case was closed but could not be loaded.")
    return result


def list_available_evidence(
    *,
    limit: int = DEFAULT_EVIDENCE_LIMIT,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), MAX_EVIDENCE_LIMIT))
    init_case_db(db_path)

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT
                e.evidence_id,
                e.original_filename,
                e.original_sha256,
                e.analysis_timestamp_utc,
                e.analysis_json,
                e.created_at_utc,
                COUNT(ce.case_id) AS linked_case_count
            FROM evidence AS e
            LEFT JOIN case_evidence AS ce
                ON ce.evidence_id = e.evidence_id
            GROUP BY e.evidence_id
            ORDER BY e.created_at_utc DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [_evidence_row_to_summary(row) for row in rows]


def _require_case_open(connection: sqlite3.Connection, case_id: str) -> None:
    row = connection.execute(
        "SELECT status FROM cases WHERE case_id = ?",
        (case_id,),
    ).fetchone()
    if row is None:
        raise LookupError("Case not found.")
    if row["status"] == "CLOSED":
        raise CaseClosedError("Case is closed.")


def _require_linked_evidence(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    evidence_id: str,
) -> None:
    row = connection.execute(
        """
        SELECT 1
        FROM case_evidence
        WHERE case_id = ? AND evidence_id = ?
        """,
        (case_id, evidence_id),
    ).fetchone()
    if row is None:
        raise LookupError("Linked evidence is not associated with this case.")


def associate_evidence(
    *,
    case_id: str,
    evidence_id: str,
    db_path: Path | str | None = None,
) -> bool:
    case_id = _required_text(case_id, field_name="Case ID", max_length=128)
    evidence_id = _required_text(evidence_id, field_name="Evidence ID", max_length=128)
    init_case_db(db_path)

    with _connect(db_path) as connection:
        _require_case_open(connection, case_id)

        evidence_exists = connection.execute(
            "SELECT 1 FROM evidence WHERE evidence_id = ?",
            (evidence_id,),
        ).fetchone()
        if evidence_exists is None:
            raise LookupError("Evidence not found.")

        added_at = _utc_now()
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO case_evidence (
                case_id,
                evidence_id,
                added_at_utc
            ) VALUES (?, ?, ?)
            """,
            (case_id, evidence_id, added_at),
        )

        if cursor.rowcount:
            connection.execute(
                """
                UPDATE cases
                SET updated_at_utc = ?
                WHERE case_id = ?
                """,
                (added_at, case_id),
            )

    return bool(cursor.rowcount)


def _insert_investigation_entry(
    *,
    case_id: str,
    entry_type: str,
    content: str,
    examiner: str,
    linked_evidence_id: str | None,
    parent_entry_id: str | None,
    allow_closed_case: bool,
    db_path: Path | str | None,
) -> dict[str, Any]:
    case_id = _required_text(case_id, field_name="Case ID", max_length=128)
    content = _required_text(
        content,
        field_name="Entry content",
        max_length=MAX_ENTRY_CONTENT_LENGTH,
    )
    examiner = _required_text(examiner, field_name="Examiner", max_length=200)
    linked_evidence_id = _optional_text(linked_evidence_id, max_length=128)
    parent_entry_id = _optional_text(parent_entry_id, max_length=128)

    init_case_db(db_path)

    entry_id = str(uuid4())
    created_at = _utc_now()

    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")

        case_row = connection.execute(
            "SELECT status FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case_row is None:
            raise LookupError("Case not found.")
        if case_row["status"] == "CLOSED" and not allow_closed_case:
            raise CaseClosedError("Case is closed.")

        if linked_evidence_id is not None:
            _require_linked_evidence(
                connection,
                case_id=case_id,
                evidence_id=linked_evidence_id,
            )

        if parent_entry_id is not None:
            parent = connection.execute(
                """
                SELECT 1
                FROM investigation_entries
                WHERE entry_id = ? AND case_id = ?
                """,
                (parent_entry_id, case_id),
            ).fetchone()
            if parent is None:
                raise LookupError("Parent investigation entry not found in this case.")

        next_sequence = connection.execute(
            """
            SELECT COALESCE(MAX(sequence_number), 0) + 1
            FROM investigation_entries
            WHERE case_id = ?
            """,
            (case_id,),
        ).fetchone()[0]

        connection.execute(
            """
            INSERT INTO investigation_entries (
                entry_id,
                case_id,
                sequence_number,
                entry_type,
                content,
                created_at_utc,
                examiner,
                linked_evidence_id,
                parent_entry_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                case_id,
                next_sequence,
                entry_type,
                content,
                created_at,
                examiner,
                linked_evidence_id,
                parent_entry_id,
            ),
        )
        connection.execute(
            """
            UPDATE cases
            SET updated_at_utc = ?
            WHERE case_id = ?
            """,
            (created_at, case_id),
        )

    result = get_investigation_entry(entry_id, db_path=db_path)
    if result is None:
        raise RuntimeError("Investigation entry was created but could not be loaded.")
    return result


def add_investigation_entry(
    *,
    case_id: str,
    entry_type: str,
    content: str,
    examiner: str,
    linked_evidence_id: str | None = None,
    parent_entry_id: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    normalised_type = _normalise_entry_type(entry_type, allow_correction=False)
    return _insert_investigation_entry(
        case_id=case_id,
        entry_type=normalised_type,
        content=content,
        examiner=examiner,
        linked_evidence_id=linked_evidence_id,
        parent_entry_id=parent_entry_id,
        allow_closed_case=False,
        db_path=db_path,
    )


def amend_investigation_entry(
    *,
    case_id: str,
    original_entry_id: str,
    content: str,
    examiner: str,
    linked_evidence_id: str | None = None,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    case_id = _required_text(case_id, field_name="Case ID", max_length=128)
    original_entry_id = _required_text(
        original_entry_id,
        field_name="Original entry ID",
        max_length=128,
    )
    init_case_db(db_path)

    with _connect(db_path) as connection:
        original = connection.execute(
            """
            SELECT linked_evidence_id
            FROM investigation_entries
            WHERE entry_id = ? AND case_id = ?
            """,
            (original_entry_id, case_id),
        ).fetchone()
        if original is None:
            raise LookupError("Original investigation entry not found in this case.")

    if linked_evidence_id is None:
        linked_evidence_id = original["linked_evidence_id"]

    return _insert_investigation_entry(
        case_id=case_id,
        entry_type=CORRECTION_ENTRY_TYPE,
        content=content,
        examiner=examiner,
        linked_evidence_id=linked_evidence_id,
        parent_entry_id=original_entry_id,
        allow_closed_case=True,
        db_path=db_path,
    )


def get_investigation_entry(
    entry_id: str,
    *,
    db_path: Path | str | None = None,
) -> dict[str, Any] | None:
    entry_id = str(entry_id).strip()
    if not entry_id or len(entry_id) > 128:
        return None

    init_case_db(db_path)
    with _connect(db_path) as connection:
        row = connection.execute(
            """
            SELECT
                ie.entry_id,
                ie.case_id,
                ie.sequence_number,
                ie.entry_type,
                ie.content,
                ie.created_at_utc,
                ie.examiner,
                ie.linked_evidence_id,
                ie.parent_entry_id,
                parent.sequence_number AS parent_sequence_number,
                evidence.original_filename AS linked_evidence_filename
            FROM investigation_entries AS ie
            LEFT JOIN investigation_entries AS parent
                ON parent.entry_id = ie.parent_entry_id
            LEFT JOIN evidence
                ON evidence.evidence_id = ie.linked_evidence_id
            WHERE ie.entry_id = ?
            """,
            (entry_id,),
        ).fetchone()

    return dict(row) if row is not None else None


def list_investigation_entries(
    case_id: str,
    *,
    entry_type: str | None = None,
    linked_evidence_id: str | None = None,
    limit: int = DEFAULT_ENTRY_LIMIT,
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    case_id = _required_text(case_id, field_name="Case ID", max_length=128)
    limit = max(1, min(int(limit), MAX_ENTRY_LIMIT))
    init_case_db(db_path)

    normalised_type = None
    if entry_type is not None:
        normalised_type = _normalise_entry_type(entry_type, allow_correction=True)
    linked_evidence_id = _optional_text(linked_evidence_id, max_length=128)

    where_parts = ["ie.case_id = ?"]
    parameters: list[Any] = [case_id]
    if normalised_type is not None:
        where_parts.append("ie.entry_type = ?")
        parameters.append(normalised_type)
    if linked_evidence_id is not None:
        where_parts.append("ie.linked_evidence_id = ?")
        parameters.append(linked_evidence_id)
    parameters.append(limit)

    with _connect(db_path) as connection:
        case_exists = connection.execute(
            "SELECT 1 FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if case_exists is None:
            raise LookupError("Case not found.")

        rows = connection.execute(
            f"""
            SELECT
                ie.entry_id,
                ie.case_id,
                ie.sequence_number,
                ie.entry_type,
                ie.content,
                ie.created_at_utc,
                ie.examiner,
                ie.linked_evidence_id,
                ie.parent_entry_id,
                parent.sequence_number AS parent_sequence_number,
                evidence.original_filename AS linked_evidence_filename
            FROM investigation_entries AS ie
            LEFT JOIN investigation_entries AS parent
                ON parent.entry_id = ie.parent_entry_id
            LEFT JOIN evidence
                ON evidence.evidence_id = ie.linked_evidence_id
            WHERE {' AND '.join(where_parts)}
            ORDER BY ie.sequence_number ASC
            LIMIT ?
            """,
            parameters,
        ).fetchall()

    return [dict(row) for row in rows]
