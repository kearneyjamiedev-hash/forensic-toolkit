import hashlib
import hmac
import shutil

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from fastapi import (
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
)

from fastapi.responses import (
    FileResponse,
    Response,
)

from fastapi.staticfiles import StaticFiles

from app.config import (
    MAX_UPLOAD_SIZE,
    STATIC_DIR,
    UPLOAD_DIR,
)

from forensics.analyzer import analyze_file

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


# -----------------------------------------------------------------------------
# Application lifecycle
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    # Initialise persistent evidence database.
    init_db()

    # Generate safe local portfolio/demo evidence.
    ensure_demo_files()

    yield


app = FastAPI(
    title="Digital Forensic File Analyzer",
    version="0.9.0",
    lifespan=lifespan,
)


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
        STATIC_DIR
        / "index.html"
    )


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
            "0.9.0",
    }


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

    original_filename = Path(
        (
            file.filename
            or "evidence.bin"
        )
        .replace(
            "\\",
            "/",
        )
    ).name


    evidence_id = str(
        uuid4()
    )


    evidence_directory = (
        UPLOAD_DIR
        / evidence_id
    )


    evidence_directory.mkdir(
        parents=True,
        exist_ok=True,
    )


    destination = (
        evidence_directory
        / original_filename
    )


    total_bytes = 0


    try:

        with destination.open(
            "wb"
        ) as output:

            while chunk := await file.read(
                1024 * 1024
            ):

                total_bytes += len(
                    chunk
                )


                if (
                    total_bytes
                    > MAX_UPLOAD_SIZE
                ):

                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "File exceeds "
                            "maximum upload size."
                        ),
                    )


                output.write(
                    chunk
                )


    except Exception:

        if destination.exists():

            destination.unlink()


        if evidence_directory.exists():

            shutil.rmtree(
                evidence_directory,
                ignore_errors=True,
            )


        raise


    finally:

        await file.close()


    # -------------------------------------------------------------------------
    # Run forensic analysis engine
    # -------------------------------------------------------------------------

    result = analyze_file(
        file_path=destination,
        original_filename=(
            original_filename
        ),
    )


    # -------------------------------------------------------------------------
    # Browser-provided modification timestamp
    # -------------------------------------------------------------------------

    browser_last_modified = None


    if browser_last_modified_ms:

        try:

            timestamp = (
                int(
                    browser_last_modified_ms
                )
                / 1000
            )


            browser_last_modified = (
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

            browser_last_modified = (
                None
            )


    # -------------------------------------------------------------------------
    # Evidence record
    # -------------------------------------------------------------------------

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


    # -------------------------------------------------------------------------
    # Persist analysis
    # -------------------------------------------------------------------------

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


    selected_filename = Path(
        (
            file.filename
            or "selected-file"
        )
        .replace(
            "\\",
            "/",
        )
    ).name


    sha256 = hashlib.sha256()

    total_bytes = 0


    try:

        while chunk := await file.read(
            1024 * 1024
        ):

            total_bytes += len(
                chunk
            )


            if (
                total_bytes
                > MAX_UPLOAD_SIZE
            ):

                raise HTTPException(
                    status_code=413,
                    detail=(
                        "Verification file "
                        "exceeds maximum "
                        "upload size."
                    ),
                )


            sha256.update(
                chunk
            )


    finally:

        await file.close()


    current_sha256 = (
        sha256.hexdigest()
    )


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


        filename_a = Path(
            (
                file_a.filename
                or "file-a"
            )
            .replace(
                "\\",
                "/",
            )
        ).name


        filename_b = Path(
            (
                file_b.filename
                or "file-b"
            )
            .replace(
                "\\",
                "/",
            )
        ).name


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

MAX_BULK_FILES = 25


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


    with TemporaryDirectory() as temp_dir:

        temp_path = Path(
            temp_dir
        )


        for index, upload in enumerate(
            files
        ):

            filename = Path(
                (
                    upload.filename
                    or f"file-{index}"
                )
                .replace(
                    "\\",
                    "/",
                )
            ).name


            destination = (
                temp_path
                / f"{index}.bin"
            )


            await _save_temporary_upload(
                upload,
                destination,
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
) -> None:

    total_bytes = 0


    try:

        with destination.open(
            "wb"
        ) as output:

            while chunk := await upload.read(
                1024 * 1024
            ):

                total_bytes += len(
                    chunk
                )


                if (
                    total_bytes
                    > MAX_UPLOAD_SIZE
                ):

                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "File exceeds "
                            "maximum upload size."
                        ),
                    )


                output.write(
                    chunk
                )


    finally:

        await upload.close()


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