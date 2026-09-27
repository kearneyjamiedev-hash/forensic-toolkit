# Deployment Guide

## Supported operating modes

The toolkit now has two deliberately different deployment modes.

### 1. Native Windows workstation — full feature set

Recommended when you need logical evidence acquisition.

Supported workflows:

- Dashboard
- Full Forensic Examination
- Quick Security Check
- Metadata & Provenance
- Compare Files
- Bulk Triage
- Audit Dashboard
- Logical Evidence Collection
- Acquired Evidence Analysis

The native logical-acquisition workflow depends on the analyst workstation and its native file-selection/PowerShell integration.

Run:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Uvicorn defaults to `127.0.0.1`, which matches the project's local-only threat model.

---

### 2. Docker — portable analysis mode

The container supports the browser-upload/static-analysis workflows.

Supported:

- Full Forensic Examination
- Quick Security Check
- Metadata & Provenance
- Compare Files
- Bulk Triage
- Audit Dashboard
- reports
- persisted evidence/audit data

Not supported as a container capability:

- Windows native logical evidence selection/acquisition

The `/local` UI may still exist in the web application, but the container does not provide the Windows desktop/native-picker environment required by that workflow.

This is intentional. Containerization does not replace the source-acquisition trust boundary.

---

# Build and run with Docker Compose

```powershell
docker compose build
docker compose up
```

Open:

```text
http://127.0.0.1:8000
```

Stop:

```powershell
docker compose down
```

Persisted evidence and SQLite state are stored in the named Docker volume:

```text
forensic_data
```

To remove the container while keeping evidence:

```powershell
docker compose down
```

To remove the named data volume too:

```powershell
docker compose down -v
```

**The `-v` form deletes the container's persisted forensic data.**

---

# Why the container listens on 0.0.0.0 internally

The Dockerfile starts Uvicorn with:

```text
--host 0.0.0.0
```

That is required so Docker can forward traffic into the container.

The Compose configuration publishes it as:

```text
127.0.0.1:8000:8000
```

so the host-side listener remains loopback-only.

Do not change this casually to:

```text
8000:8000
```

on an untrusted network, because the current product intentionally has no remote-user authentication model.

---

# Container hardening

The Compose/Docker configuration uses:

- fixed non-root UID/GID (`10001`);
- `read_only: true` for the container filesystem;
- writable named volume only for `/app/data`;
- tmpfs for `/tmp`;
- all Linux capabilities dropped;
- `no-new-privileges`;
- API docs disabled;
- host port bound to `127.0.0.1`;
- native Linux ExifTool package;
- Docker health check.

This does not turn the application into a malware sandbox. Hostile file parsers still run in the application process.

---

# Health check

Docker runs:

```text
scripts/container_healthcheck.py
```

against:

```text
GET /api/health
```

Inspect:

```powershell
docker compose ps
```

The service should eventually show:

```text
healthy
```

---

# Environment check

For normal local development:

```powershell
.\.venv\Scripts\python.exe .\scripts\environment_check.py
```

This checks:

- Python version;
- required Python imports;
- ExifTool discovery;
- writable data directory;
- native Windows acquisition prerequisites where relevant.

---

# Building directly without Compose

```powershell
docker build -t forensic-toolkit .
```

Run while keeping the HTTP service local-only:

```powershell
docker run --rm `
  -p 127.0.0.1:8000:8000 `
  --read-only `
  --tmpfs /tmp:rw,size=256m `
  --cap-drop ALL `
  --security-opt no-new-privileges `
  forensic-toolkit
```

Compose is preferred because it also creates persistent `/app/data` storage.

---

# Evidence/storage warning

Do not bake evidence, SQLite databases or acquired files into the image.

The `.dockerignore` excludes:

```text
data/
```

and the application writes runtime state into the mounted `/app/data` volume.

The repository `.gitignore` should continue to exclude runtime forensic data as well.
