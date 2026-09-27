# Reproducibility Notes

## Python runtime

Validated target:

```text
Python 3.12
```

The Docker image currently uses:

```text
python:3.12.14-slim-bookworm
```

This fixes the Python patch release and Debian family used by the container.

---

## Runtime dependency policy

`requirements.txt` contains the project's direct Python runtime dependencies with fixed versions.

Current direct runtime dependencies:

- FastAPI
- Uvicorn
- python-multipart
- ReportLab
- pypdf
- Pillow
- pefile
- olefile
- defusedxml

ExifTool is not a Python package.

Windows development uses the bundled Windows ExifTool when available.

Linux/Docker installs:

```text
libimage-exiftool-perl
```

and the application resolves `exiftool` from `PATH`.

---

## Development dependencies

`requirements-dev.txt` extends the runtime environment with:

- pytest
- pytest-cov
- httpx

Security-analysis tooling remains separate in:

```text
requirements-security.txt
```

This avoids making Bandit and pip-audit runtime application dependencies.

---

## Fresh local setup

Windows:

```powershell
py -3.12 -m venv .venv

.\.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel

.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

.\.venv\Scripts\python.exe .\scripts\environment_check.py

.\.venv\Scripts\python.exe -m pytest -q
```

Then run:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

---

## Security tooling

Install separately:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-security.txt
```

Run:

```powershell
.\scripts\security_scan.ps1
```

The GitHub workflows independently run:

- pytest;
- Bandit;
- pip-audit;
- CodeQL.

---

## What is and is not fully reproducible

The project now pins its direct Python dependencies and container Python version.

It does **not** currently hash-lock every transitive Python wheel or pin the exact Debian package snapshot used by `apt`.

Therefore the deployment is reproducible at the practical portfolio/application level, but it should not be described as a byte-for-byte hermetic build.

A future production-grade build could add:

- `pip-tools`/`uv` lock files with hashes;
- a digest-pinned base image;
- Debian snapshot repositories;
- SBOM generation;
- signed container images;
- provenance attestations.

Those are intentionally beyond the current local portfolio scope.

---

## Native acquisition versus portable analysis

The architecture deliberately keeps these separate:

```text
Windows native workstation
    → logical evidence acquisition
    → native file picker
    → source/master/working copies

Portable / Docker runtime
    → browser-upload analysis
    → static security triage
    → reports
    → audit trail
```

This is a security boundary, not simply a missing Docker feature.

A container should not be presented as having direct access to the analyst's source filesystem merely to make the feature list look identical.
