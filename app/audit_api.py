from fastapi import APIRouter, HTTPException, Query

from forensics.audit_log import (
    get_audit_dashboard_summary,
    get_audit_events,
    verify_audit_chain,
)


router = APIRouter(
    prefix="/api/audit",
    tags=["audit"],
)


@router.get("/overview")
async def audit_overview(
    recent_limit: int = Query(default=50, ge=1, le=200),
    evidence_limit: int = Query(default=100, ge=1, le=500),
):
    return get_audit_dashboard_summary(
        recent_limit=recent_limit,
        evidence_limit=evidence_limit,
    )


@router.get("/evidence/{evidence_id}")
async def evidence_audit_trail(
    evidence_id: str,
    limit: int = Query(default=200, ge=1, le=1000),
):
    events = get_audit_events(
        evidence_id,
        limit=limit,
    )

    if not events:
        raise HTTPException(
            status_code=404,
            detail="No audit events were found for this evidence ID.",
        )

    chain = verify_audit_chain(evidence_id)

    return {
        "evidence_id": evidence_id,
        "event_count": chain.get("event_count", len(events)),
        "returned_event_count": len(events),
        "chain": chain,
        "events": events,
    }
