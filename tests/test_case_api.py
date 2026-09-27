from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.case_api as case_api


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(case_api.router)
    return TestClient(app)


def test_create_case_endpoint(monkeypatch):
    monkeypatch.setattr(
        case_api,
        "create_case",
        lambda **kwargs: {
            "case_id": "case-1",
            "case_reference": kwargs["case_reference"],
            "title": kwargs["title"],
            "examiner": kwargs["examiner"],
            "status": "OPEN",
            "evidence": [],
            "evidence_count": 0,
        },
    )

    response = _client().post(
        "/api/cases",
        json={
            "case_reference": "DF-2026-001",
            "title": "Document review",
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 201
    assert response.json()["case_id"] == "case-1"


def test_duplicate_reference_returns_conflict(monkeypatch):
    def duplicate(**kwargs):
        raise case_api.DuplicateCaseReferenceError("A case with that reference already exists.")

    monkeypatch.setattr(case_api, "create_case", duplicate)

    response = _client().post(
        "/api/cases",
        json={
            "case_reference": "DF-2026-001",
            "title": "Document review",
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 409


def test_case_detail_returns_404(monkeypatch):
    monkeypatch.setattr(case_api, "get_case", lambda case_id: None)

    response = _client().get("/api/cases/missing")

    assert response.status_code == 404


def test_attach_evidence_returns_updated_case(monkeypatch):
    monkeypatch.setattr(case_api, "associate_evidence", lambda **kwargs: True)
    monkeypatch.setattr(
        case_api,
        "get_case",
        lambda case_id: {
            "case_id": case_id,
            "case_reference": "DF-2026-001",
            "evidence_count": 1,
            "evidence": [{"evidence_id": "ev-001"}],
        },
    )

    response = _client().post(
        "/api/cases/case-1/evidence",
        json={"evidence_id": "ev-001"},
    )

    assert response.status_code == 200
    assert response.json()["added"] is True
    assert response.json()["case"]["evidence_count"] == 1



def test_close_case_endpoint(monkeypatch):
    monkeypatch.setattr(
        case_api,
        "close_case",
        lambda case_id: {"case_id": case_id, "status": "CLOSED"},
    )

    response = _client().post("/api/cases/case-1/close")

    assert response.status_code == 200
    assert response.json()["status"] == "CLOSED"


def test_add_investigation_entry_endpoint(monkeypatch):
    monkeypatch.setattr(
        case_api,
        "add_investigation_entry",
        lambda **kwargs: {
            "entry_id": "entry-1",
            "case_id": kwargs["case_id"],
            "sequence_number": 1,
            "entry_type": "OBSERVATION",
            "content": kwargs["content"],
        },
    )

    response = _client().post(
        "/api/cases/case-1/entries",
        json={
            "entry_type": "Observation",
            "content": "Document metadata reviewed.",
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 201
    assert response.json()["sequence_number"] == 1


def test_list_investigation_entries_endpoint(monkeypatch):
    monkeypatch.setattr(
        case_api,
        "list_investigation_entries",
        lambda case_id, **kwargs: [
            {
                "entry_id": "entry-1",
                "case_id": case_id,
                "sequence_number": 1,
                "entry_type": "OBSERVATION",
                "content": "Observed.",
            }
        ],
    )

    response = _client().get("/api/cases/case-1/entries")

    assert response.status_code == 200
    assert response.json()["entries"][0]["entry_id"] == "entry-1"


def test_amendment_endpoint(monkeypatch):
    monkeypatch.setattr(
        case_api,
        "amend_investigation_entry",
        lambda **kwargs: {
            "entry_id": "entry-2",
            "case_id": kwargs["case_id"],
            "sequence_number": 2,
            "entry_type": "CORRECTION",
            "parent_entry_id": kwargs["original_entry_id"],
            "content": kwargs["content"],
        },
    )

    response = _client().post(
        "/api/cases/case-1/entries/entry-1/amendments",
        json={
            "content": "Clarified wording.",
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 201
    assert response.json()["entry_type"] == "CORRECTION"
    assert response.json()["parent_entry_id"] == "entry-1"


def test_closed_case_entry_returns_conflict(monkeypatch):
    def closed(**kwargs):
        raise case_api.CaseClosedError("Case is closed.")

    monkeypatch.setattr(case_api, "add_investigation_entry", closed)

    response = _client().post(
        "/api/cases/case-1/entries",
        json={
            "entry_type": "Observation",
            "content": "Should fail.",
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 409


def test_oversized_entry_is_rejected_by_request_validation():
    response = _client().post(
        "/api/cases/case-1/entries",
        json={
            "entry_type": "Observation",
            "content": "x" * (case_api.MAX_ENTRY_CONTENT_LENGTH + 1),
            "examiner": "Jamie",
        },
    )

    assert response.status_code == 422
