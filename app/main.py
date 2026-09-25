import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import MAX_UPLOAD_SIZE, STATIC_DIR, UPLOAD_DIR
from forensics.analyzer import analyze_file


app = FastAPI(
    title="Digital Forensic File Analyzer",
    version="0.1.0",
)


app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/")
async def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "application": "Digital Forensic File Analyzer",
    }


@app.post("/api/analyze")
async def analyze_upload(
    file: UploadFile = File(...),
    browser_last_modified_ms: str | None = Form(default=None),
):
    original_filename = Path(
        file.filename or "evidence.bin"
    ).name

    evidence_id = str(uuid4())

    evidence_directory = UPLOAD_DIR / evidence_id
    evidence_directory.mkdir(parents=True, exist_ok=True)

    destination = evidence_directory / original_filename

    total_bytes = 0

    try:
        with destination.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)

                if total_bytes > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds maximum upload size.",
                    )

                output.write(chunk)

    except Exception:
        if destination.exists():
            destination.unlink()

        if evidence_directory.exists():
            shutil.rmtree(
                evidence_directory,
                ignore_errors=True,
            )

        raise

    result = analyze_file(
        file_path=destination,
        original_filename=original_filename,
    )

    browser_last_modified = None

    if browser_last_modified_ms:
        try:
            timestamp = int(browser_last_modified_ms) / 1000

            browser_last_modified = (
                datetime
                .fromtimestamp(
                    timestamp,
                    tz=timezone.utc,
                )
                .isoformat()
                .replace("+00:00", "Z")
            )

        except (ValueError, OverflowError):
            browser_last_modified = None

    result["evidence"] = {
        "id": evidence_id,
        "original_filename": original_filename,
        "browser_reported_last_modified": browser_last_modified,
    }

    return result