from __future__ import annotations

import json
import sqlite3

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from app.config import (
    DATA_DIR
)


DATABASE_PATH = (
    DATA_DIR
    / "forensics.db"
)


def _utc_now() -> str:

    return (
        datetime
        .now(timezone.utc)
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def _connect():

    connection = sqlite3.connect(
        DATABASE_PATH
    )


    connection.row_factory = (
        sqlite3.Row
    )


    connection.execute(
        "PRAGMA foreign_keys = ON"
    )


    return connection


def init_db() -> None:

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    with _connect() as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                original_sha256 TEXT NOT NULL,
                analysis_timestamp_utc TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                created_at_utc TEXT NOT NULL
            )
            """
        )


        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS verification_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                verified_at_utc TEXT NOT NULL,
                selected_filename TEXT,
                expected_sha256 TEXT NOT NULL,
                current_sha256 TEXT NOT NULL,
                status TEXT NOT NULL,

                FOREIGN KEY (evidence_id)
                    REFERENCES evidence(evidence_id)
            )
            """
        )


        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_verification_evidence_id
            ON verification_log(evidence_id)
            """
        )


        connection.commit()


def save_evidence_record(
    *,
    evidence_id: str,
    original_filename: str,
    stored_path: Path,
    original_sha256: str,
    analysis_timestamp_utc: str,
    analysis: dict,
) -> None:

    with _connect() as connection:

        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id,
                original_filename,
                stored_path,
                original_sha256,
                analysis_timestamp_utc,
                analysis_json,
                created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                original_filename,
                str(
                    stored_path.resolve()
                ),
                original_sha256,
                analysis_timestamp_utc,
                json.dumps(
                    analysis,
                    ensure_ascii=False,
                ),
                _utc_now(),
            ),
        )


        connection.commit()


def get_evidence_record(
    evidence_id: str,
) -> dict | None:

    with _connect() as connection:

        row = connection.execute(
            """
            SELECT
                evidence_id,
                original_filename,
                stored_path,
                original_sha256,
                analysis_timestamp_utc,
                analysis_json,
                created_at_utc
            FROM evidence
            WHERE evidence_id = ?
            """,
            (
                evidence_id,
            ),
        ).fetchone()


    if row is None:

        return None


    result = dict(row)


    try:

        result[
            "analysis"
        ] = json.loads(
            result.pop(
                "analysis_json"
            )
        )


    except json.JSONDecodeError:

        result[
            "analysis"
        ] = None


        result.pop(
            "analysis_json",
            None,
        )


    return result


def record_verification(
    *,
    evidence_id: str,
    selected_filename: str | None,
    expected_sha256: str,
    current_sha256: str,
    status: str,
) -> str:

    verified_at = _utc_now()


    with _connect() as connection:

        connection.execute(
            """
            INSERT INTO verification_log (
                evidence_id,
                verified_at_utc,
                selected_filename,
                expected_sha256,
                current_sha256,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                verified_at,
                selected_filename,
                expected_sha256,
                current_sha256,
                status,
            ),
        )


        connection.commit()


    return verified_at


def get_verification_history(
    evidence_id: str,
) -> list[dict]:

    with _connect() as connection:

        rows = connection.execute(
            """
            SELECT
                id,
                verified_at_utc,
                selected_filename,
                expected_sha256,
                current_sha256,
                status
            FROM verification_log
            WHERE evidence_id = ?
            ORDER BY id ASC
            """,
            (
                evidence_id,
            ),
        ).fetchall()


    return [
        dict(row)
        for row in rows
    ]