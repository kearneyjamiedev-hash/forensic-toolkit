import json
import sqlite3

import pytest

from forensics.audit_log import (
    get_audit_events,
    init_audit_db,
    record_audit_event,
    verify_audit_chain,
)


pytestmark = pytest.mark.unit


def test_records_and_retrieves_audit_event(tmp_path):
    db = tmp_path / "audit.sqlite3"
    init_audit_db(db)

    created = record_audit_event(
        event_type="EVIDENCE_ACQUIRED",
        evidence_id="evidence-1",
        case_reference="CASE-001",
        actor="Training Analyst",
        filename="sample.txt",
        sha256="a" * 64,
        outcome="success",
        details={"master_verified": True},
        db_path=db,
    )

    events = get_audit_events(
        "evidence-1",
        db_path=db,
    )

    assert len(events) == 1
    assert events[0]["event_id"] == created["event_id"]
    assert events[0]["event_type"] == "EVIDENCE_ACQUIRED"
    assert events[0]["details"]["master_verified"] is True
    assert events[0]["previous_hash"] is None
    assert len(events[0]["entry_hash"]) == 64


def test_events_form_hash_chain_per_evidence(tmp_path):
    db = tmp_path / "audit.sqlite3"

    first = record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id="evidence-1",
        db_path=db,
    )

    second = record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id="evidence-1",
        outcome="success",
        db_path=db,
    )

    assert second["previous_hash"] == first["entry_hash"]

    verification = verify_audit_chain(
        "evidence-1",
        db_path=db,
    )

    assert verification["verified"] is True
    assert verification["event_count"] == 2
    assert verification["head_hash"] == second["entry_hash"]


def test_separate_evidence_ids_have_independent_chains(tmp_path):
    db = tmp_path / "audit.sqlite3"

    first_a = record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id="evidence-a",
        db_path=db,
    )

    first_b = record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id="evidence-b",
        db_path=db,
    )

    second_a = record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id="evidence-a",
        db_path=db,
    )

    assert first_a["previous_hash"] is None
    assert first_b["previous_hash"] is None
    assert second_a["previous_hash"] == first_a["entry_hash"]


def test_chain_verification_detects_database_tampering(tmp_path):
    db = tmp_path / "audit.sqlite3"

    record_audit_event(
        event_type="EVIDENCE_ACQUIRED",
        evidence_id="evidence-1",
        details={"integrity": "verified"},
        db_path=db,
    )

    record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id="evidence-1",
        details={"status": "complete"},
        db_path=db,
    )

    with sqlite3.connect(db) as connection:
        connection.execute(
            """
            UPDATE audit_events
            SET details_json = ?
            WHERE evidence_id = ?
            AND sequence_id = (
                SELECT MIN(sequence_id)
                FROM audit_events
                WHERE evidence_id = ?
            )
            """,
            (
                json.dumps({"integrity": "tampered"}),
                "evidence-1",
                "evidence-1",
            ),
        )

    verification = verify_audit_chain(
        "evidence-1",
        db_path=db,
    )

    assert verification["verified"] is False
    assert verification["failure_index"] == 0
    assert "recorded hash" in verification["reason"]


def test_invalid_audit_event_is_rejected(tmp_path):
    db = tmp_path / "audit.sqlite3"

    with pytest.raises(ValueError):
        record_audit_event(
            event_type="",
            evidence_id="evidence-1",
            db_path=db,
        )

    with pytest.raises(ValueError):
        record_audit_event(
            event_type="ANALYSIS_STARTED",
            evidence_id="",
            db_path=db,
        )


def test_dashboard_summary_reports_verified_chain_and_counts(tmp_path):
    from forensics.audit_log import get_audit_dashboard_summary

    db_path = tmp_path / "audit.sqlite3"

    record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id="evidence-dashboard",
        filename="sample.txt",
        outcome="started",
        db_path=db_path,
    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id="evidence-dashboard",
        filename="sample.txt",
        outcome="success",
        details={"report_format": "pdf"},
        db_path=db_path,
    )

    summary = get_audit_dashboard_summary(
        db_path=db_path,
    )

    assert summary["summary"]["total_events"] == 2
    assert summary["summary"]["evidence_count"] == 1
    assert summary["summary"]["verified_chains"] == 1
    assert summary["summary"]["failed_chains"] == 0
    assert summary["summary"]["reports_generated"] == 1
    assert summary["evidence"][0]["chain_verified"] is True
    assert summary["evidence"][0]["latest_event_type"] == "REPORT_GENERATED"


def test_recent_audit_events_are_newest_first(tmp_path):
    from forensics.audit_log import get_recent_audit_events

    db_path = tmp_path / "audit.sqlite3"

    first = record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id="evidence-recent",
        db_path=db_path,
    )

    second = record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id="evidence-recent",
        db_path=db_path,
    )

    events = get_recent_audit_events(
        db_path=db_path,
    )

    assert events[0]["event_id"] == second["event_id"]
    assert events[1]["event_id"] == first["event_id"]
