from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from forensics.case_store import (
    CaseClosedError,
    DuplicateCaseReferenceError,
    MAX_ENTRY_CONTENT_LENGTH,
    add_investigation_entry,
    amend_investigation_entry,
    associate_evidence,
    close_case,
    create_case,
    get_case,
    init_case_db,
    list_available_evidence,
    list_cases,
    list_investigation_entries,
)


def _seed_evidence_db(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE evidence (
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
            INSERT INTO evidence (
                evidence_id,
                original_filename,
                stored_path,
                original_sha256,
                analysis_timestamp_utc,
                analysis_json,
                created_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "ev-001",
                "sample.docx",
                "/tmp/sample.docx",
                "a" * 64,
                "2026-09-27T07:00:00Z",
                "{}",
                "2026-09-27T07:00:00Z",
            ),
        )


def test_create_list_and_get_case(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)
    init_case_db(db_path)

    created = create_case(
        case_reference="DF-2026-001",
        title="Document review",
        examiner="Jamie",
        description="Review suspicious document metadata.",
        db_path=db_path,
    )

    assert created["case_reference"] == "DF-2026-001"
    assert created["status"] == "OPEN"
    assert created["evidence_count"] == 0

    cases = list_cases(db_path=db_path)
    assert len(cases) == 1
    assert cases[0]["case_id"] == created["case_id"]
    assert cases[0]["evidence_count"] == 0

    loaded = get_case(created["case_id"], db_path=db_path)
    assert loaded is not None
    assert loaded["title"] == "Document review"


def test_duplicate_case_reference_is_case_insensitive(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    create_case(
        case_reference="DF-2026-001",
        title="First",
        examiner="Jamie",
        db_path=db_path,
    )

    with pytest.raises(DuplicateCaseReferenceError):
        create_case(
            case_reference="df-2026-001",
            title="Second",
            examiner="Jamie",
            db_path=db_path,
        )


def test_associate_existing_evidence_is_idempotent(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-002",
        title="Evidence linking",
        examiner="Jamie",
        db_path=db_path,
    )

    assert associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    ) is True

    assert associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    ) is False

    loaded = get_case(case["case_id"], db_path=db_path)
    assert loaded is not None
    assert loaded["evidence_count"] == 1
    assert loaded["evidence"][0]["original_filename"] == "sample.docx"
    assert loaded["evidence"][0]["original_sha256"] == "a" * 64


def test_associate_requires_real_case_and_evidence(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-003",
        title="Validation",
        examiner="Jamie",
        db_path=db_path,
    )

    with pytest.raises(LookupError, match="Evidence not found"):
        associate_evidence(
            case_id=case["case_id"],
            evidence_id="missing",
            db_path=db_path,
        )

    with pytest.raises(LookupError, match="Case not found"):
        associate_evidence(
            case_id="missing",
            evidence_id="ev-001",
            db_path=db_path,
        )


def test_available_evidence_reports_case_link_count(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-004",
        title="Available evidence",
        examiner="Jamie",
        db_path=db_path,
    )

    before = list_available_evidence(db_path=db_path)
    assert before[0]["linked_case_count"] == 0

    associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    )

    after = list_available_evidence(db_path=db_path)
    assert after[0]["linked_case_count"] == 1



def test_close_case_marks_case_closed_and_is_idempotent(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-005",
        title="Closure",
        examiner="Jamie",
        db_path=db_path,
    )

    closed = close_case(case["case_id"], db_path=db_path)
    assert closed["status"] == "CLOSED"
    assert closed["closed_at_utc"] is not None

    closed_again = close_case(case["case_id"], db_path=db_path)
    assert closed_again["status"] == "CLOSED"
    assert closed_again["closed_at_utc"] == closed["closed_at_utc"]


def test_closed_case_rejects_new_evidence_and_regular_entries(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-006",
        title="Closed case",
        examiner="Jamie",
        db_path=db_path,
    )
    close_case(case["case_id"], db_path=db_path)

    with pytest.raises(CaseClosedError):
        associate_evidence(
            case_id=case["case_id"],
            evidence_id="ev-001",
            db_path=db_path,
        )

    with pytest.raises(CaseClosedError):
        add_investigation_entry(
            case_id=case["case_id"],
            entry_type="Observation",
            content="Should not be added.",
            examiner="Jamie",
            db_path=db_path,
        )


def test_investigation_entries_have_stable_case_sequence(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-007",
        title="Notebook",
        examiner="Jamie",
        db_path=db_path,
    )
    associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    )

    first = add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Observation",
        content="Author field reports jsmith.",
        examiner="Jamie",
        linked_evidence_id="ev-001",
        db_path=db_path,
    )
    second = add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Verification",
        content="Reviewed metadata source semantics.",
        examiner="Jamie",
        db_path=db_path,
    )

    assert first["sequence_number"] == 1
    assert second["sequence_number"] == 2

    entries = list_investigation_entries(case["case_id"], db_path=db_path)
    assert [entry["sequence_number"] for entry in entries] == [1, 2]
    assert entries[0]["linked_evidence_id"] == "ev-001"

    loaded = get_case(case["case_id"], db_path=db_path)
    assert loaded is not None
    assert loaded["investigation_entry_count"] == 2


def test_note_link_must_belong_to_same_case(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-008",
        title="Notebook validation",
        examiner="Jamie",
        db_path=db_path,
    )

    with pytest.raises(LookupError, match="not associated"):
        add_investigation_entry(
            case_id=case["case_id"],
            entry_type="Evidence Identified",
            content="Attempted external evidence link.",
            examiner="Jamie",
            linked_evidence_id="ev-001",
            db_path=db_path,
        )


def test_amendment_preserves_original_entry(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-009",
        title="Correction handling",
        examiner="Jamie",
        db_path=db_path,
    )
    associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    )

    original = add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Observation",
        content="jsmith is the author.",
        examiner="Jamie",
        linked_evidence_id="ev-001",
        db_path=db_path,
    )

    correction = amend_investigation_entry(
        case_id=case["case_id"],
        original_entry_id=original["entry_id"],
        content="The Author metadata field reports jsmith; this is not proof of authorship.",
        examiner="Jamie",
        db_path=db_path,
    )

    entries = list_investigation_entries(case["case_id"], db_path=db_path)
    assert len(entries) == 2
    assert entries[0]["content"] == "jsmith is the author."
    assert entries[1]["entry_type"] == "CORRECTION"
    assert entries[1]["parent_entry_id"] == original["entry_id"]
    assert entries[1]["parent_sequence_number"] == 1
    assert correction["linked_evidence_id"] == "ev-001"


def test_explicit_correction_can_be_added_after_case_closure(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-010",
        title="Post-close correction",
        examiner="Jamie",
        db_path=db_path,
    )
    original = add_investigation_entry(
        case_id=case["case_id"],
        entry_type="General Note",
        content="Initial wording.",
        examiner="Jamie",
        db_path=db_path,
    )
    close_case(case["case_id"], db_path=db_path)

    correction = amend_investigation_entry(
        case_id=case["case_id"],
        original_entry_id=original["entry_id"],
        content="Clarification added after closure.",
        examiner="Jamie",
        db_path=db_path,
    )

    assert correction["entry_type"] == "CORRECTION"
    assert correction["sequence_number"] == 2


def test_invalid_entry_type_and_oversized_content_are_rejected(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-011",
        title="Input validation",
        examiner="Jamie",
        db_path=db_path,
    )

    with pytest.raises(ValueError, match="Invalid investigation entry type"):
        add_investigation_entry(
            case_id=case["case_id"],
            entry_type="Arbitrary HTML",
            content="Nope",
            examiner="Jamie",
            db_path=db_path,
        )

    with pytest.raises(ValueError, match="characters or fewer"):
        add_investigation_entry(
            case_id=case["case_id"],
            entry_type="Observation",
            content="x" * (MAX_ENTRY_CONTENT_LENGTH + 1),
            examiner="Jamie",
            db_path=db_path,
        )


def test_xss_payload_is_preserved_as_text_not_interpreted_by_store(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-012",
        title="XSS regression",
        examiner="Jamie",
        db_path=db_path,
    )
    payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>'

    created = add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Observation",
        content=payload,
        examiner="Jamie",
        db_path=db_path,
    )

    assert created["content"] == payload
    entries = list_investigation_entries(case["case_id"], db_path=db_path)
    assert entries[0]["content"] == payload


def test_entry_filters_by_type_and_linked_evidence(tmp_path: Path):
    db_path = tmp_path / "cases.sqlite3"
    _seed_evidence_db(db_path)

    case = create_case(
        case_reference="DF-2026-013",
        title="Notebook filters",
        examiner="Jamie",
        db_path=db_path,
    )
    associate_evidence(
        case_id=case["case_id"],
        evidence_id="ev-001",
        db_path=db_path,
    )
    add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Observation",
        content="One",
        examiner="Jamie",
        linked_evidence_id="ev-001",
        db_path=db_path,
    )
    add_investigation_entry(
        case_id=case["case_id"],
        entry_type="Finding",
        content="Two",
        examiner="Jamie",
        db_path=db_path,
    )

    observations = list_investigation_entries(
        case["case_id"], entry_type="observation", db_path=db_path
    )
    linked = list_investigation_entries(
        case["case_id"], linked_evidence_id="ev-001", db_path=db_path
    )

    assert [entry["content"] for entry in observations] == ["One"]
    assert [entry["content"] for entry in linked] == ["One"]
