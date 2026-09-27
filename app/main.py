import hashlib

import hmac

import shutil

from contextlib import asynccontextmanager

from datetime import datetime, timezone

from pathlib import Path

from tempfile import TemporaryDirectory

from uuid import uuid4

from app.audit_api import router as audit_router

from forensics.audit_log import (

    init_audit_db,

    record_audit_event,

)

from fastapi import (

    FastAPI,

    File,

    Form,

    Header,

    HTTPException,

    UploadFile,

)

from fastapi.responses import (

    FileResponse,

    Response,

)

from fastapi.staticfiles import StaticFiles

from pydantic import BaseModel

from app.config import (

    ENABLE_API_DOCS,

    MAX_BULK_FILES,

    MAX_BULK_TOTAL_SIZE,

    MAX_UPLOAD_SIZE,

    STATIC_DIR,

    UPLOAD_DIR,

)

from app.http_security import (

    HttpSecurityMiddleware,

)

from app.ingestion import (

    UploadLimitExceeded,

    evidence_directory,

    hash_upload_limited,

    normalise_upload_filename,

    safe_child_path,

    save_upload_limited,

)

from app.native_collector import (

    choose_source_file,

    collector_session_token,

    consume_selection,

    register_selection,

    token_matches,

)

from forensics.acquisition import (

    acquire_logical_file,

    add_source_timeline_events,

    load_acquisition_manifest,

    preview_source,

    verify_after_analysis,

    verify_before_analysis,

)

from forensics.analyzer import analyze_file

from forensics.security_findings import (

    build_security_assessment,

)

from forensics.bulk import (

    build_bulk_summary,

)

from forensics.comparison import (

    compare_analyses,

)

from forensics.demo import (

    ensure_demo_files,

    get_demo_sample,

    list_demo_samples,

)

from forensics.evidence_store import (

    get_evidence_record,

    get_verification_history,

    init_db,

    record_verification,

    save_evidence_record,

)

from forensics.reports import (

    build_artefacts_csv,

    build_html_report,

    build_json_report,

    build_pdf_report,

    build_timeline_csv,

)

from forensics.acquisition_report import (

    build_acquisition_manifest_json,

    build_acquisition_pdf,

)

# -----------------------------------------------------------------------------

# Application lifecycle

# -----------------------------------------------------------------------------

@asynccontextmanager

async def lifespan(

    app: FastAPI,

):

    # Initialise persistent evidence database.

    init_db()

    # Initialise tamper-evident application audit database.
    init_audit_db()

    # Generate safe local portfolio/demo evidence.

    ensure_demo_files()

    yield

app = FastAPI(

    title="Digital Forensic File Analyzer",

    version="1.0.0",

    lifespan=lifespan,

    docs_url=(
        "/docs"
        if ENABLE_API_DOCS
        else None
    ),

    redoc_url=(
        "/redoc"
        if ENABLE_API_DOCS
        else None
    ),

    openapi_url=(
        "/openapi.json"
        if ENABLE_API_DOCS
        else None
    ),

)

app.add_middleware(
    HttpSecurityMiddleware
)

# Read-only audit trail API.
app.include_router(audit_router)

# -----------------------------------------------------------------------------

# Request models

# -----------------------------------------------------------------------------

class AcquireEvidenceRequest(BaseModel):

    selection_id: str

    case_reference: str

    evidence_description: str

    collector_name: str

# -----------------------------------------------------------------------------

# Static frontend

# -----------------------------------------------------------------------------

app.mount(

    "/static",

    StaticFiles(

        directory=STATIC_DIR,

    ),

    name="static",

)

@app.get("/")

async def dashboard():

    return FileResponse(

        STATIC_DIR / "index.html"

    )

@app.get("/forensic")

async def forensic_page():

    return FileResponse(

        STATIC_DIR / "forensic.html"

    )

@app.get("/security")

async def security_page():

    return FileResponse(

        STATIC_DIR / "security.html"

    )

@app.get("/provenance")

async def provenance_page():

    return FileResponse(

        STATIC_DIR / "provenance.html"

    )

@app.get("/compare")

async def compare_page():

    return FileResponse(

        STATIC_DIR / "compare.html"

    )

@app.get("/bulk")

async def bulk_page():

    return FileResponse(

        STATIC_DIR / "bulk.html"

    )

@app.get("/audit")

async def audit_dashboard_page():

    return FileResponse(

        STATIC_DIR / "audit.html"

    )


@app.get("/local")

async def local_evidence_page():

    return FileResponse(

        STATIC_DIR / "local.html"

    )

@app.get("/local-analysis")

async def local_analysis_page():

    return FileResponse(

        STATIC_DIR / "local-analysis.html"

    )

# -----------------------------------------------------------------------------

# Logical evidence collection

# -----------------------------------------------------------------------------

def _require_collector_token(

    supplied_token: str | None,

) -> None:

    if not token_matches(supplied_token):

        raise HTTPException(

            status_code=403,

            detail=(

                "The local collector session token is missing or invalid."

            ),

        )

def _path_is_inside(

    candidate: Path,

    parent: Path,

) -> bool:

    try:

        candidate.resolve().relative_to(parent.resolve())

        return True

    except ValueError:

        return False

def _load_acquisition_manifest_or_404(

    evidence_id: str,

) -> dict:

    try:

        return load_acquisition_manifest(

            evidence_root=UPLOAD_DIR,

            evidence_id=evidence_id,

        )

    except (ValueError, FileNotFoundError) as error:

        raise HTTPException(

            status_code=404,

            detail=str(error),

        ) from error

@app.get("/api/acquisition/session")

async def acquisition_session():

    return {

        "token": collector_session_token(),

        "mode": "local_native",

    }

@app.get(

    "/api/acquisition/{evidence_id}/status"

)

async def acquisition_status(

    evidence_id: str,

    x_collector_token: str | None = Header(

        default=None,

        alias="X-Collector-Token",

    ),

):

    _require_collector_token(

        x_collector_token

    )

    manifest = (

        _load_acquisition_manifest_or_404(

            evidence_id

        )

    )

    evidence = (

        get_evidence_record(

            evidence_id

        )

    )

    analysis_available = bool(

        evidence

        and evidence.get(

            "analysis"

        )

    )

    return {

        "evidence_id":

            evidence_id,

        "case_reference":

            manifest.get(

                "case_reference"

            ),

        "evidence_description":

            manifest.get(

                "evidence_description"

            ),

        "collector_name":

            manifest.get(

                "collector_name"

            ),

        "acquisition":

            manifest.get(

                "acquisition"

            )

            or {},

        "source":

            (

                manifest.get(

                    "source",

                    {}

                )

                .get(

                    "before_acquisition"

                )

                or {}

            ),

        "integrity":

            manifest.get(

                "integrity"

            )

            or {},

        "observable_metadata_changes":

            (

                manifest.get(

                    "source",

                    {}

                )

                .get(

                    "observable_metadata_changes"

                )

                or []

            ),

        "analysis_available":

            analysis_available,

    }

@app.get(

    "/api/acquisition/{evidence_id}/analysis"

)

async def acquired_analysis_result(

    evidence_id: str,

    x_collector_token: str | None = Header(

        default=None,

        alias="X-Collector-Token",

    ),

):

    _require_collector_token(

        x_collector_token

    )

    _load_acquisition_manifest_or_404(

        evidence_id

    )

    evidence = (

        get_evidence_record(

            evidence_id

        )

    )

    if (

        evidence is None

        or evidence.get(

            "analysis"

        )

        is None

    ):

        raise HTTPException(

            status_code=404,

            detail=(

                "Forensic analysis has not "

                "been completed for this "

                "acquisition."

            ),

        )

    return evidence[

        "analysis"

    ]

@app.post("/api/acquisition/select")

def select_acquisition_source(

    x_collector_token: str | None = Header(

        default=None,

        alias="X-Collector-Token",

    ),

):

    _require_collector_token(

        x_collector_token

    )

    try:

        source_path = choose_source_file()

    except RuntimeError as error:

        raise HTTPException(

            status_code=500,

            detail=str(error),

        ) from error

    if source_path is None:

        return {

            "cancelled": True,

        }

    if (

        not source_path.exists()

        or not source_path.is_file()

    ):

        raise HTTPException(

            status_code=400,

            detail=(

                "The selected source is not a readable file."

            ),

        )

    # Do not let Local Acquisition accidentally re-acquire evidence that the

    # analyzer itself already created. The user should select the true source.

    if _path_is_inside(

        source_path,

        UPLOAD_DIR,

    ):

        raise HTTPException(

            status_code=400,

            detail=(

                "Select the original source file, not a file inside the "

                "analyzer-managed evidence store."

            ),

        )

    try:

        source = preview_source(

            source_path

        )

    except (OSError, PermissionError) as error:

        raise HTTPException(

            status_code=403,

            detail=(

                "The selected source metadata could not be read."

            ),

        ) from error

    if source.get("size_bytes", 0) > MAX_UPLOAD_SIZE:

        raise HTTPException(

            status_code=413,

            detail=(

                "The selected evidence exceeds the maximum permitted size."

            ),

        )

    selection = register_selection(

        source_path

    )

    return {

        "cancelled": False,

        "selection_id": selection.selection_id,

        "selected_at_utc": (

            selection.selected_at_utc

            .isoformat()

            .replace("+00:00", "Z")

        ),

        "source": source,

    }

@app.post("/api/acquisition/acquire")

async def acquire_evidence(

    request: AcquireEvidenceRequest,

    x_collector_token: str | None = Header(

        default=None,

        alias="X-Collector-Token",

    ),

):

    _require_collector_token(

        x_collector_token

    )

    if not request.case_reference.strip():

        raise HTTPException(

            status_code=400,

            detail="Case / reference is required.",

        )

    if not request.collector_name.strip():

        raise HTTPException(

            status_code=400,

            detail="Collector / analyst name is required.",

        )

    if not request.evidence_description.strip():

        raise HTTPException(

            status_code=400,

            detail="Evidence description is required.",

        )

    selection = consume_selection(

        request.selection_id

    )

    if selection is None:

        raise HTTPException(

            status_code=410,

            detail=(

                "The source selection expired or was already used. "

                "Select the source evidence again."

            ),

        )

    evidence_id = str(

        uuid4()

    )

    try:

        manifest = acquire_logical_file(

            source_path=selection.path,

            evidence_root=UPLOAD_DIR,

            evidence_id=evidence_id,

            max_size=MAX_UPLOAD_SIZE,

            case_reference=request.case_reference,

            evidence_description=request.evidence_description,

            collector_name=request.collector_name,

        )

    except ValueError as error:

        raise HTTPException(

            status_code=400,

            detail=str(error),

        ) from error

    except PermissionError as error:

        raise HTTPException(

            status_code=403,

            detail=(

                "The source evidence could not be read. Check its permissions."

            ),

        ) from error

    except (OSError, RuntimeError) as error:

        raise HTTPException(

            status_code=500,

            detail=str(error),

        ) from error

    record_audit_event(
        event_type="EVIDENCE_ACQUIRED",
        evidence_id=evidence_id,
        case_reference=manifest.get("case_reference"),
        actor=manifest.get("collector_name"),
        filename=(
            manifest.get("source", {})
            .get("before_acquisition", {})
            .get("filename")
        ),
        sha256=(
            manifest.get("integrity", {})
            .get("master_sha256")
        ),
        outcome="success",
        details={
            "acquisition_type": (
                manifest.get("acquisition", {})
                .get("type")
            ),
            "master_verified": (
                manifest.get("integrity", {})
                .get("master_verified")
            ),
            "working_verified": (
                manifest.get("integrity", {})
                .get("working_verified")
            ),
            "source_content_unchanged": (
                manifest.get("integrity", {})
                .get("source_content_unchanged")
            ),
            "observable_metadata_change_count": len(
                manifest.get("source", {})
                .get("observable_metadata_changes", [])
            ),
        },
    )

    return {

        "evidence_id": evidence_id,

        "case_reference": manifest["case_reference"],

        "evidence_description": manifest["evidence_description"],

        "collector_name": manifest["collector_name"],

        "acquisition": manifest["acquisition"],

        "source": manifest["source"]["before_acquisition"],

        "observable_metadata_changes": (

            manifest["source"]["observable_metadata_changes"]

        ),

        "integrity": manifest["integrity"],

    }

@app.post(

    "/api/acquisition/{evidence_id}/analyze"

)

async def analyze_acquired_evidence(

    evidence_id: str,

    x_collector_token: str | None = Header(

        default=None,

        alias="X-Collector-Token",

    ),

):

    _require_collector_token(

        x_collector_token

    )

    manifest = (

        _load_acquisition_manifest_or_404(

            evidence_id

        )

    )

    record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id=evidence_id,
        case_reference=manifest.get("case_reference"),
        actor=manifest.get("collector_name"),
        filename=(
            manifest.get("source", {})
            .get("before_acquisition", {})
            .get("filename")
        ),
        sha256=(
            manifest.get("integrity", {})
            .get("master_sha256")
        ),
        outcome="started",
        details={
            "analysis_scope": "verified_working_copy",
        },
    )

    pre_analysis = verify_before_analysis(

        manifest

    )

    if (
        not pre_analysis["master_verified"]
        or not pre_analysis["working_verified"]
    ):

        record_audit_event(
            event_type="INTEGRITY_FAILURE",
            evidence_id=evidence_id,
            case_reference=manifest.get("case_reference"),
            actor=manifest.get("collector_name"),
            filename=(
                manifest.get("source", {})
                .get("before_acquisition", {})
                .get("filename")
            ),
            sha256=(
                manifest.get("integrity", {})
                .get("master_sha256")
            ),
            outcome="failed",
            details={
                "stage": "before_analysis",
                "verification": pre_analysis,
            },
        )

        raise HTTPException(

            status_code=409,

            detail=(

                "Acquired evidence failed the pre-analysis integrity check."

            ),

        )

    working_path = Path(

        manifest["storage"]["working_path"]

    )

    result = analyze_file(

        file_path=working_path,

        original_filename=(

            manifest["source"]

            ["before_acquisition"]

            ["filename"]

        ),

    )

    source_filesystem = (

        manifest["source"]

        ["before_acquisition"]

    )

    result["source_filesystem"] = source_filesystem

    result["acquisition"] = manifest

    add_source_timeline_events(

        result["timeline"],

        source_filesystem,

    )

    post_analysis = verify_after_analysis(

        manifest

    )

    if not post_analysis["master_verified"]:

        record_audit_event(
            event_type="INTEGRITY_FAILURE",
            evidence_id=evidence_id,
            case_reference=manifest.get("case_reference"),
            actor=manifest.get("collector_name"),
            filename=(
                manifest.get("source", {})
                .get("before_acquisition", {})
                .get("filename")
            ),
            sha256=(
                manifest.get("integrity", {})
                .get("master_sha256")
            ),
            outcome="failed",
            details={
                "stage": "after_analysis_master",
                "verification": post_analysis,
            },
        )

        raise HTTPException(

            status_code=500,

            detail=(

                "The master evidence copy failed post-analysis verification."

            ),

        )

    if not post_analysis["working_verified"]:

        record_audit_event(
            event_type="INTEGRITY_FAILURE",
            evidence_id=evidence_id,
            case_reference=manifest.get("case_reference"),
            actor=manifest.get("collector_name"),
            filename=(
                manifest.get("source", {})
                .get("before_acquisition", {})
                .get("filename")
            ),
            sha256=(
                manifest.get("integrity", {})
                .get("master_sha256")
            ),
            outcome="failed",
            details={
                "stage": "after_analysis_working_copy",
                "verification": post_analysis,
            },
        )

        raise HTTPException(

            status_code=500,

            detail=(

                "The working copy changed during forensic analysis."

            ),

        )

    expected_sha256 = (

        manifest["integrity"]

        ["master_sha256"]

    )

    analyzer_sha256 = (

        result.get("hashes", {})

        .get("sha256")

    )

    if analyzer_sha256 != expected_sha256:

        record_audit_event(
            event_type="INTEGRITY_FAILURE",
            evidence_id=evidence_id,
            case_reference=manifest.get("case_reference"),
            actor=manifest.get("collector_name"),
            filename=source_filesystem.get("filename"),
            sha256=analyzer_sha256,
            outcome="failed",
            details={
                "stage": "analyzer_hash_check",
                "expected_sha256": expected_sha256,
                "analyzer_sha256": analyzer_sha256,
            },
        )

        raise HTTPException(

            status_code=500,

            detail=(

                "The forensic engine hash does not match the acquired evidence baseline."

            ),

        )

    result["evidence"] = {

        "id": evidence_id,

        "mode": "logical_acquisition",

        "case_reference": manifest["case_reference"],

        "evidence_description": manifest["evidence_description"],

        "collector_name": manifest["collector_name"],

        "original_filename": source_filesystem["filename"],

        "source_path": source_filesystem["path"],

        "browser_reported_last_modified": None,

        "integrity_baseline_sha256": expected_sha256,

        "master_sha256": post_analysis["master_sha256"],

        "working_copy_sha256": post_analysis["working_sha256"],

        "master_preserved": post_analysis["master_verified"],

        "working_copy_preserved": post_analysis["working_verified"],

    }

    save_evidence_record(

        evidence_id=evidence_id,

        original_filename=source_filesystem["filename"],

        stored_path=Path(

            manifest["storage"]["master_path"]

        ),

        original_sha256=expected_sha256,

        analysis_timestamp_utc=(

            result["analysis"]["timestamp_utc"]

        ),

        analysis=result,

    )

    record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id=evidence_id,
        case_reference=manifest.get("case_reference"),
        actor=manifest.get("collector_name"),
        filename=result.get("overview", {}).get("filename"),
        sha256=result.get("hashes", {}).get("sha256"),
        outcome="success",
        details={
            "analysis_scope": "verified_working_copy",
            "analysis_timestamp_utc": (
                result.get("analysis", {})
                .get("timestamp_utc")
            ),
            "post_analysis_master_verified": (
                post_analysis.get("master_verified")
            ),
            "post_analysis_working_verified": (
                post_analysis.get("working_verified")
            ),
            "artefact_count": (
                result.get("artefacts", {})
                .get("total_found", 0)
            ),
        },
    )

    return result

# -----------------------------------------------------------------------------

# Health check

# -----------------------------------------------------------------------------

@app.get("/api/health")

async def health():

    return {

        "status":

            "ok",

        "application":

            (

                "Digital Forensic "

                "File Analyzer"

            ),

        "version":

            "1.0.0",

    }

# -----------------------------------------------------------------------------

# Upload ingestion helpers

# -----------------------------------------------------------------------------

async def _store_persistent_upload(
    upload: UploadFile,
    *,
    evidence_id: str,
    fallback_filename: str,
) -> tuple[str, Path, Path]:

    filename = normalise_upload_filename(
        upload.filename,
        fallback=fallback_filename,
    )

    evidence_dir = evidence_directory(
        UPLOAD_DIR,
        evidence_id,
    )

    try:
        evidence_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        destination = safe_child_path(
            evidence_dir,
            filename,
        )

        await save_upload_limited(
            upload,
            destination,
            max_size=MAX_UPLOAD_SIZE,
        )

    except UploadLimitExceeded as error:

        shutil.rmtree(
            evidence_dir,
            ignore_errors=True,
        )

        raise HTTPException(
            status_code=413,
            detail=(
                "File exceeds maximum upload size."
            ),
        ) from error

    except Exception:

        shutil.rmtree(
            evidence_dir,
            ignore_errors=True,
        )

        raise

    return (
        filename,
        evidence_dir,
        destination,
    )


def _browser_last_modified(
    value: str | None,
) -> str | None:

    if not value:
        return None

    try:
        timestamp = (
            int(value)
            / 1000
        )

        return (
            datetime
            .fromtimestamp(
                timestamp,
                tz=timezone.utc,
            )
            .isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

    except (
        ValueError,
        OverflowError,
        OSError,
    ):
        return None


def _remove_unpersisted_evidence(
    evidence_directory_path: Path,
) -> None:

    shutil.rmtree(
        evidence_directory_path,
        ignore_errors=True,
    )


# -----------------------------------------------------------------------------

# File analysis

# -----------------------------------------------------------------------------

@app.post("/api/analyze")

async def analyze_upload(

    file: UploadFile = File(...),

    browser_last_modified_ms:

        str | None = Form(

            default=None

        ),

):

    evidence_id = str(
        uuid4()
    )

    (
        original_filename,
        evidence_directory_path,
        destination,
    ) = await _store_persistent_upload(
        file,
        evidence_id=evidence_id,
        fallback_filename="evidence.bin",
    )

    record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id=evidence_id,
        filename=original_filename,
        outcome="started",
        details={
            "analysis_scope": "browser_upload",
        },
    )

    try:

        result = analyze_file(

            file_path=destination,

            original_filename=(

                original_filename

            ),

        )

        browser_last_modified = (
            _browser_last_modified(
                browser_last_modified_ms
            )
        )

        result["evidence"] = {

            "id":
                evidence_id,

            "original_filename":
                original_filename,

            "browser_reported_last_modified":
                browser_last_modified,

            "integrity_baseline_sha256":
                result[
                    "hashes"
                ][
                    "sha256"
                ],

        }

        save_evidence_record(

            evidence_id=(
                evidence_id
            ),

            original_filename=(
                original_filename
            ),

            stored_path=(
                destination
            ),

            original_sha256=(
                result[
                    "hashes"
                ][
                    "sha256"
                ]
            ),

            analysis_timestamp_utc=(
                result[
                    "analysis"
                ][
                    "timestamp_utc"
                ]
            ),

            analysis=result,

        )

    except Exception as error:

        record_audit_event(
            event_type="ANALYSIS_FAILED",
            evidence_id=evidence_id,
            filename=original_filename,
            outcome="failed",
            details={
                "analysis_scope": "browser_upload",
                "error_type": (
                    type(error).__name__
                ),
            },
        )

        _remove_unpersisted_evidence(
            evidence_directory_path
        )

        raise

    record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id=evidence_id,
        filename=original_filename,
        sha256=result.get("hashes", {}).get("sha256"),
        outcome="success",
        details={
            "analysis_scope": "browser_upload",
            "analysis_timestamp_utc": (
                result.get("analysis", {})
                .get("timestamp_utc")
            ),
            "artefact_count": (
                result.get("artefacts", {})
                .get("total_found", 0)
            ),
        },
    )

    return result

# -----------------------------------------------------------------------------

# Quick security check

# -----------------------------------------------------------------------------

@app.post("/api/security-check")

async def security_check(

    file: UploadFile = File(...),

    browser_last_modified_ms:

        str | None = Form(

            default=None

        ),

):

    evidence_id = str(
        uuid4()
    )

    (
        original_filename,
        evidence_directory_path,
        destination,
    ) = await _store_persistent_upload(
        file,
        evidence_id=evidence_id,
        fallback_filename="evidence.bin",
    )

    record_audit_event(
        event_type="ANALYSIS_STARTED",
        evidence_id=evidence_id,
        filename=original_filename,
        outcome="started",
        details={
            "analysis_scope": "security_check",
        },
    )

    try:

        result = analyze_file(

            file_path=destination,

            original_filename=(

                original_filename

            ),

        )

        browser_last_modified = (
            _browser_last_modified(
                browser_last_modified_ms
            )
        )

        result["evidence"] = {

            "id":
                evidence_id,

            "original_filename":
                original_filename,

            "browser_reported_last_modified":
                browser_last_modified,

            "integrity_baseline_sha256":
                result[
                    "hashes"
                ][
                    "sha256"
                ],

        }

        security_assessment = (
            build_security_assessment(
                result
            )
        )

        result["security_assessment"] = (
            security_assessment
        )

        save_evidence_record(

            evidence_id=(
                evidence_id
            ),

            original_filename=(
                original_filename
            ),

            stored_path=(
                destination
            ),

            original_sha256=(
                result[
                    "hashes"
                ][
                    "sha256"
                ]
            ),

            analysis_timestamp_utc=(
                result[
                    "analysis"
                ][
                    "timestamp_utc"
                ]
            ),

            analysis=result,

        )

    except Exception as error:

        record_audit_event(
            event_type="ANALYSIS_FAILED",
            evidence_id=evidence_id,
            filename=original_filename,
            outcome="failed",
            details={
                "analysis_scope": "security_check",
                "error_type": (
                    type(error).__name__
                ),
            },
        )

        _remove_unpersisted_evidence(
            evidence_directory_path
        )

        raise

    record_audit_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id=evidence_id,
        filename=original_filename,
        sha256=result.get("hashes", {}).get("sha256"),
        outcome="success",
        details={
            "analysis_scope": "security_check",
            "analysis_timestamp_utc": (
                result.get("analysis", {})
                .get("timestamp_utc")
            ),
            "artefact_count": (
                result.get("artefacts", {})
                .get("total_found", 0)
            ),
        },
    )

    record_audit_event(
        event_type="SECURITY_CHECK_COMPLETED",
        evidence_id=evidence_id,
        filename=original_filename,
        sha256=result.get("hashes", {}).get("sha256"),
        outcome="success",
        details={
            "disposition": (
                security_assessment.get(
                    "disposition"
                )
            ),
            "finding_count": (
                security_assessment.get(
                    "counts",
                    {},
                )
                .get(
                    "total",
                    len(
                        security_assessment.get(
                            "findings",
                            [],
                        )
                    ),
                )
            ),
            "high_count": (
                security_assessment.get(
                    "counts",
                    {},
                )
                .get(
                    "high",
                    0,
                )
            ),
            "medium_count": (
                security_assessment.get(
                    "counts",
                    {},
                )
                .get(
                    "medium",
                    0,
                )
            ),
        },
    )

    return result

# -----------------------------------------------------------------------------

# Evidence integrity verification

# -----------------------------------------------------------------------------

@app.post(

    "/api/evidence/"

    "{evidence_id}/verify"

)

async def verify_file(

    evidence_id: str,

    file: UploadFile = File(...),

):

    evidence = (

        get_evidence_record(

            evidence_id

        )

    )

    if evidence is None:

        raise HTTPException(

            status_code=404,

            detail=(

                "Evidence record "

                "not found."

            ),

        )

    selected_filename = normalise_upload_filename(
        file.filename,
        fallback="selected-file",
    )

    try:
        (
            current_sha256,
            _verification_size,
        ) = await hash_upload_limited(
            file,
            max_size=MAX_UPLOAD_SIZE,
        )

    except UploadLimitExceeded as error:

        raise HTTPException(
            status_code=413,
            detail=(
                "Verification file exceeds "
                "maximum upload size."
            ),
        ) from error

    expected_sha256 = (

        evidence[

            "original_sha256"

        ]

    )

    verified = (

        hmac.compare_digest(

            current_sha256,

            expected_sha256,

        )

    )

    status = (

        "verified"

        if verified

        else "failed"

    )

    verified_at = (

        record_verification(

            evidence_id=(

                evidence_id

            ),

            selected_filename=(

                selected_filename

            ),

            expected_sha256=(

                expected_sha256

            ),

            current_sha256=(

                current_sha256

            ),

            status=status,

        )

    )

    record_audit_event(
        event_type=(
            "EVIDENCE_VERIFIED"
            if verified
            else "INTEGRITY_FAILURE"
        ),
        evidence_id=evidence_id,
        filename=selected_filename,
        sha256=current_sha256,
        outcome=(
            "verified"
            if verified
            else "failed"
        ),
        details={
            "expected_sha256": expected_sha256,
            "current_sha256": current_sha256,
            "verification_type": "user_supplied_file",
        },
    )

    return {

        "evidence_id":

            evidence_id,

        "selected_filename":

            selected_filename,

        "verified":

            verified,

        "status":

            status,

        "message":

            (

                "VERIFIED — file unchanged"

                if verified

                else (

                    "FAILED — current hash "

                    "does not match original "

                    "evidence hash"

                )

            ),

        "expected_sha256":

            expected_sha256,

        "current_sha256":

            current_sha256,

        "verified_at_utc":

            verified_at,

    }

# -----------------------------------------------------------------------------

# File comparison

# -----------------------------------------------------------------------------

@app.post("/api/compare")

async def compare_files(

    file_a: UploadFile = File(...),

    file_b: UploadFile = File(...),

):

    with TemporaryDirectory() as temp_dir:

        temp_path = Path(

            temp_dir

        )

        path_a = (

            temp_path

            / "file_a.bin"

        )

        path_b = (

            temp_path

            / "file_b.bin"

        )

        filename_a = normalise_upload_filename(
            file_a.filename,
            fallback="file-a",
        )

        filename_b = normalise_upload_filename(
            file_b.filename,
            fallback="file-b",
        )

        await _save_temporary_upload(

            file_a,

            path_a,

        )

        await _save_temporary_upload(

            file_b,

            path_b,

        )

        analysis_a = analyze_file(

            file_path=path_a,

            original_filename=(

                filename_a

            ),

        )

        analysis_b = analyze_file(

            file_path=path_b,

            original_filename=(

                filename_b

            ),

        )

        comparison = (

            compare_analyses(

                analysis_a,

                analysis_b,

            )

        )

        return comparison

# -----------------------------------------------------------------------------

# Bulk analysis

# -----------------------------------------------------------------------------

@app.post("/api/bulk-analyze")

async def bulk_analyze(

    files: list[UploadFile] = File(...),

):

    if not files:

        raise HTTPException(

            status_code=400,

            detail=(

                "No files were supplied."

            ),

        )

    if (

        len(files)

        > MAX_BULK_FILES

    ):

        raise HTTPException(

            status_code=400,

            detail=(

                "Bulk analysis is limited "

                f"to {MAX_BULK_FILES} files "

                "per batch."

            ),

        )

    analyses = []
    total_request_bytes = 0

    with TemporaryDirectory() as temp_dir:

        temp_path = Path(

            temp_dir

        )

        for index, upload in enumerate(

            files

        ):

            filename = normalise_upload_filename(
                upload.filename,
                fallback=f"file-{index}",
            )

            destination = (

                temp_path

                / f"{index}.bin"

            )

            saved_bytes = await _save_temporary_upload(

                upload,

                destination,

            )

            total_request_bytes += (
                saved_bytes
            )

            if (
                total_request_bytes
                > MAX_BULK_TOTAL_SIZE
            ):

                raise HTTPException(
                    status_code=413,
                    detail=(
                        "Combined bulk upload size "
                        "exceeds the permitted request limit."
                    ),
                )

            analysis = analyze_file(

                file_path=destination,

                original_filename=(

                    filename

                ),

            )

            analyses.append(

                analysis

            )

    rows = build_bulk_summary(

        analyses

    )

    return {

        "file_count":

            len(rows),

        "rows":

            rows,

    }

# -----------------------------------------------------------------------------

# Temporary upload helper

# -----------------------------------------------------------------------------

async def _save_temporary_upload(

    upload: UploadFile,

    destination: Path,

) -> int:

    try:
        return await save_upload_limited(
            upload,
            destination,
            max_size=MAX_UPLOAD_SIZE,
        )

    except UploadLimitExceeded as error:

        raise HTTPException(
            status_code=413,
            detail=(
                "File exceeds maximum upload size."
            ),
        ) from error


# -----------------------------------------------------------------------------

# Portfolio / Demo Mode

# -----------------------------------------------------------------------------

@app.get(

    "/api/demo/samples"

)

async def demo_samples():

    return {

        "samples":

            list_demo_samples()

    }

@app.get(

    "/api/demo/file/"

    "{sample_id}"

)

async def demo_file(

    sample_id: str,

):

    sample = (

        get_demo_sample(

            sample_id

        )

    )

    if sample is None:

        raise HTTPException(

            status_code=404,

            detail=(

                "Demo sample "

                "not found."

            ),

        )

    path = sample[

        "path"

    ]

    if (

        not path.exists()

        or not path.is_file()

    ):

        raise HTTPException(

            status_code=404,

            detail=(

                "Demo evidence file "

                "is unavailable."

            ),

        )

    return FileResponse(

        path,

        filename=(

            sample[

                "filename"

            ]

        ),

    )

@app.post(

    "/api/demo/analyze/"

    "{sample_id}"

)

async def analyze_demo_sample(

    sample_id: str,

):

    sample = (

        get_demo_sample(

            sample_id

        )

    )

    if sample is None:

        raise HTTPException(

            status_code=404,

            detail=(

                "Demo sample "

                "not found."

            ),

        )

    sample_path = (

        sample[

            "path"

        ]

    )

    if (

        not sample_path.exists()

        or not sample_path.is_file()

    ):

        raise HTTPException(

            status_code=404,

            detail=(

                "Demo evidence file "

                "is unavailable."

            ),

        )

    evidence_id = str(

        uuid4()

    )

    result = analyze_file(

        file_path=(

            sample_path

        ),

        original_filename=(

            sample[

                "filename"

            ]

        ),

    )

    # -------------------------------------------------------------------------

    # Mark this result as a persisted evidence analysis

    # -------------------------------------------------------------------------

    result["evidence"] = {

        "id":

            evidence_id,

        "original_filename":

            sample[

                "filename"

            ],

        "browser_reported_last_modified":

            None,

        "integrity_baseline_sha256":

            result[

                "hashes"

            ][

                "sha256"

            ],

    }

    # -------------------------------------------------------------------------

    # Demo metadata

    # -------------------------------------------------------------------------

    result["demo"] = {

        "sample_id":

            sample_id,

        "title":

            sample[

                "title"

            ],

        "description":

            sample[

                "description"

            ],

    }

    # -------------------------------------------------------------------------

    # Persist demo analysis so reports work exactly like real analysis

    # -------------------------------------------------------------------------

    save_evidence_record(

        evidence_id=(

            evidence_id

        ),

        original_filename=(

            sample[

                "filename"

            ]

        ),

        stored_path=(

            sample_path

        ),

        original_sha256=(

            result[

                "hashes"

            ][

                "sha256"

            ]

        ),

        analysis_timestamp_utc=(

            result[

                "analysis"

            ][

                "timestamp_utc"

            ]

        ),

        analysis=result,

    )

    return result

# -----------------------------------------------------------------------------

# Report helpers

# -----------------------------------------------------------------------------

def _get_report_evidence(

    evidence_id: str,

) -> dict:

    evidence = (

        get_evidence_record(

            evidence_id

        )

    )

    if (

        evidence is None

        or evidence.get(

            "analysis"

        ) is None

    ):

        raise HTTPException(

            status_code=404,

            detail=(

                "Evidence analysis "

                "was not found."

            ),

        )

    return evidence

def _report_filename(

    evidence: dict,

    suffix: str,

) -> str:

    original_filename = (

        evidence.get(

            "original_filename"

        )

        or "evidence"

    )

    stem = (

        Path(

            original_filename

        )

        .stem

    )

    safe_stem = "".join(

        character

        if (

            character.isalnum()

            or character

            in (

                "-",

                "_",

            )

        )

        else "_"

        for character

        in stem

    )

    safe_stem = (

        safe_stem.strip(

            "_"

        )

        or "evidence"

    )

    return (

        f"{safe_stem}"

        f"_forensic_report"

        f"{suffix}"

    )

def _acquisition_report_filename(

    manifest: dict,

    suffix: str,

) -> str:

    source = (

        manifest.get(

            "source",

            {}

        )

        .get(

            "before_acquisition"

        )

        or {}

    )

    original_filename = (

        source.get(

            "filename"

        )

        or "evidence"

    )

    stem = (

        Path(

            original_filename

        )

        .stem

    )

    safe_stem = "".join(

        character

        if (

            character.isalnum()

            or character in (

                "-",

                "_",

            )

        )

        else "_"

        for character in stem

    )

    safe_stem = (

        safe_stem.strip(

            "_"

        )

        or "evidence"

    )

    return (

        f"{safe_stem}"

        f"_acquisition"

        f"{suffix}"

    )

# -----------------------------------------------------------------------------

# PDF forensic report

# -----------------------------------------------------------------------------

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/pdf"

)

async def report_pdf(

    evidence_id: str,

):

    evidence = (

        _get_report_evidence(

            evidence_id

        )

    )

    verification_history = (

        get_verification_history(

            evidence_id

        )

    )

    content = (

        build_pdf_report(

            evidence,

            verification_history,

        )

    )

    filename = (

        _report_filename(

            evidence,

            ".pdf",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        filename=evidence.get("original_filename"),
        sha256=evidence.get("original_sha256"),
        outcome="success",
        details={
            "report_format": "pdf",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "application/pdf"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

# -----------------------------------------------------------------------------

# JSON report

# -----------------------------------------------------------------------------

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/json"

)

async def report_json(

    evidence_id: str,

):

    evidence = (

        _get_report_evidence(

            evidence_id

        )

    )

    verification_history = (

        get_verification_history(

            evidence_id

        )

    )

    content = (

        build_json_report(

            evidence,

            verification_history,

        )

    )

    filename = (

        _report_filename(

            evidence,

            ".json",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        filename=evidence.get("original_filename"),
        sha256=evidence.get("original_sha256"),
        outcome="success",
        details={
            "report_format": "json",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "application/json"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

# -----------------------------------------------------------------------------

# Timeline CSV report

# -----------------------------------------------------------------------------

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/timeline.csv"

)

async def report_timeline_csv(

    evidence_id: str,

):

    evidence = (

        _get_report_evidence(

            evidence_id

        )

    )

    content = (

        build_timeline_csv(

            evidence

        )

    )

    filename = (

        _report_filename(

            evidence,

            "_timeline.csv",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        filename=evidence.get("original_filename"),
        sha256=evidence.get("original_sha256"),
        outcome="success",
        details={
            "report_format": "timeline_csv",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "text/csv; charset=utf-8"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

# -----------------------------------------------------------------------------

# Acquisition reports

# -----------------------------------------------------------------------------

@app.get(

    "/api/acquisition/{evidence_id}/report/pdf"

)

async def acquisition_report_pdf(

    evidence_id: str,

):

    manifest = (

        _load_acquisition_manifest_or_404(

            evidence_id

        )

    )

    content = (

        build_acquisition_pdf(

            manifest

        )

    )

    filename = (

        _acquisition_report_filename(

            manifest,

            ".pdf",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        case_reference=manifest.get("case_reference"),
        actor=manifest.get("collector_name"),
        filename=(
            manifest.get("source", {})
            .get("before_acquisition", {})
            .get("filename")
        ),
        sha256=(
            manifest.get("integrity", {})
            .get("master_sha256")
        ),
        outcome="success",
        details={
            "report_format": "acquisition_pdf",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type="application/pdf",

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

@app.get(

    "/api/acquisition/{evidence_id}/manifest.json"

)

async def acquisition_manifest_json(

    evidence_id: str,

):

    manifest = (

        _load_acquisition_manifest_or_404(

            evidence_id

        )

    )

    content = (

        build_acquisition_manifest_json(

            manifest

        )

    )

    filename = (

        _acquisition_report_filename(

            manifest,

            "_manifest.json",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        case_reference=manifest.get("case_reference"),
        actor=manifest.get("collector_name"),
        filename=(
            manifest.get("source", {})
            .get("before_acquisition", {})
            .get("filename")
        ),
        sha256=(
            manifest.get("integrity", {})
            .get("master_sha256")
        ),
        outcome="success",
        details={
            "report_format": "acquisition_manifest_json",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "application/json; charset=utf-8"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

# Backward-compatible aliases for the earlier UI paths.

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/acquisition.pdf"

)

async def legacy_acquisition_report_pdf(

    evidence_id: str,

):

    return await acquisition_report_pdf(

        evidence_id

    )

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/"

    "acquisition-manifest.json"

)

async def legacy_acquisition_manifest_json(

    evidence_id: str,

):

    return await acquisition_manifest_json(

        evidence_id

    )

# -----------------------------------------------------------------------------

# Artefacts CSV report

# -----------------------------------------------------------------------------

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/artefacts.csv"

)

async def report_artefacts_csv(

    evidence_id: str,

):

    evidence = (

        _get_report_evidence(

            evidence_id

        )

    )

    content = (

        build_artefacts_csv(

            evidence

        )

    )

    filename = (

        _report_filename(

            evidence,

            "_artefacts.csv",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        filename=evidence.get("original_filename"),
        sha256=evidence.get("original_sha256"),
        outcome="success",
        details={
            "report_format": "artefacts_csv",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "text/csv; charset=utf-8"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )

# -----------------------------------------------------------------------------

# HTML forensic report

# -----------------------------------------------------------------------------

@app.get(

    "/api/evidence/"

    "{evidence_id}/report/html"

)

async def report_html(

    evidence_id: str,

):

    evidence = (

        _get_report_evidence(

            evidence_id

        )

    )

    verification_history = (

        get_verification_history(

            evidence_id

        )

    )

    content = (

        build_html_report(

            evidence,

            verification_history,

        )

    )

    filename = (

        _report_filename(

            evidence,

            ".html",

        )

    )

    record_audit_event(
        event_type="REPORT_GENERATED",
        evidence_id=evidence_id,
        filename=evidence.get("original_filename"),
        sha256=evidence.get("original_sha256"),
        outcome="success",
        details={
            "report_format": "html",
            "download_filename": filename,
        },
    )

    return Response(

        content=content,

        media_type=(

            "text/html; charset=utf-8"

        ),

        headers={

            "Content-Disposition":

                (

                    "attachment; "

                    f'filename="{filename}"'

                )

        },

    )
