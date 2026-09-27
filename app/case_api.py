from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from forensics.case_store import (
    CaseClosedError,
    DuplicateCaseReferenceError,
    MAX_ENTRY_CONTENT_LENGTH,
    STANDARD_ENTRY_TYPES,
    add_investigation_entry,
    amend_investigation_entry,
    associate_evidence,
    close_case,
    create_case,
    get_case,
    list_available_evidence,
    list_cases,
    list_investigation_entries,
)


router = APIRouter(
    prefix="/api/cases",
    tags=["cases"],
)


class CreateCaseRequest(BaseModel):
    case_reference: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=200)
    examiner: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)


class AssociateEvidenceRequest(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=128)


class InvestigationEntryRequest(BaseModel):
    entry_type: str = Field(min_length=1, max_length=80)
    content: str = Field(min_length=1, max_length=MAX_ENTRY_CONTENT_LENGTH)
    examiner: str = Field(min_length=1, max_length=200)
    linked_evidence_id: str | None = Field(default=None, max_length=128)


class InvestigationAmendmentRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_ENTRY_CONTENT_LENGTH)
    examiner: str = Field(min_length=1, max_length=200)
    linked_evidence_id: str | None = Field(default=None, max_length=128)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_case_record(request: CreateCaseRequest):
    try:
        return create_case(
            case_reference=request.case_reference,
            title=request.title,
            examiner=request.examiner,
            description=request.description,
        )
    except DuplicateCaseReferenceError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.get("")
async def case_list(
    limit: int = Query(default=100, ge=1, le=500),
):
    return {
        "cases": list_cases(limit=limit),
    }


@router.get("/available-evidence")
async def available_evidence(
    limit: int = Query(default=200, ge=1, le=1000),
):
    return {
        "evidence": list_available_evidence(limit=limit),
    }


@router.get("/{case_id}")
async def case_detail(case_id: str):
    result = get_case(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return result


@router.post("/{case_id}/close")
async def close_case_record(case_id: str):
    try:
        return close_case(case_id)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.post("/{case_id}/evidence")
async def attach_evidence(case_id: str, request: AssociateEvidenceRequest):
    try:
        added = associate_evidence(
            case_id=case_id,
            evidence_id=request.evidence_id,
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except CaseClosedError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    result = get_case(case_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    return {
        "added": added,
        "case": result,
    }


@router.get("/{case_id}/entries")
async def investigation_entries(
    case_id: str,
    entry_type: str | None = Query(default=None, max_length=80),
    evidence_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=500, ge=1, le=2000),
):
    try:
        entries = list_investigation_entries(
            case_id,
            entry_type=entry_type,
            linked_evidence_id=evidence_id,
            limit=limit,
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return {
        "entry_types": list(STANDARD_ENTRY_TYPES),
        "entries": entries,
    }


@router.post(
    "/{case_id}/entries",
    status_code=status.HTTP_201_CREATED,
)
async def add_investigation_entry_record(
    case_id: str,
    request: InvestigationEntryRequest,
):
    try:
        return add_investigation_entry(
            case_id=case_id,
            entry_type=request.entry_type,
            content=request.content,
            examiner=request.examiner,
            linked_evidence_id=request.linked_evidence_id,
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except CaseClosedError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@router.post(
    "/{case_id}/entries/{entry_id}/amendments",
    status_code=status.HTTP_201_CREATED,
)
async def amend_investigation_entry_record(
    case_id: str,
    entry_id: str,
    request: InvestigationAmendmentRequest,
):
    try:
        return amend_investigation_entry(
            case_id=case_id,
            original_entry_id=entry_id,
            content=request.content,
            examiner=request.examiner,
            linked_evidence_id=request.linked_evidence_id,
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
