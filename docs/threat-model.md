# Digital Forensic Toolkit — Threat Model

**Project scope:** Local digital-forensics and static security-analysis platform  
**Model version:** 1.0  
**Status:** Portfolio / engineering threat model  
**Primary deployment assumption:** Local workstation application bound to loopback (`127.0.0.1`)  
**Security objective:** Analyze untrusted evidence without executing it, preserve evidential integrity, and make important handling actions auditable.

---

## 1. System summary

The application provides several workflows over a shared forensic engine:

- Full Forensic Examination
- Quick Security Check
- Metadata & Provenance
- Compare Files
- Bulk Triage
- Logical Evidence Collection
- Acquired Evidence Analysis
- Audit Dashboard

The forensic engine performs static analysis only. It does not intentionally execute evidence files.

Major analysis capabilities include:

- SHA-256, SHA-1 and MD5 hashing
- file signature / extension comparison
- filesystem metadata collection
- ExifTool metadata extraction
- timeline reconstruction
- interesting string / artefact extraction
- PDF analysis
- Office / OOXML analysis
- image analysis
- ZIP/archive inspection
- PE/static executable analysis
- report generation
- tamper-evident audit logging

Logical evidence acquisition uses:

```text
SOURCE
  ↓
hash while copying
  ↓
MASTER EVIDENCE COPY
  ↓
verify
  ↓
WORKING COPY
  ↓
verify
  ↓
ANALYSIS
```

The working copy is analyzed; the master copy is retained separately.

---

# 2. Security objectives

The application should:

1. avoid executing untrusted evidence;
2. prevent uploaded filenames from escaping controlled storage;
3. bound resource use when handling hostile input;
4. preserve evidence integrity and provenance;
5. detect changes to acquired evidence where possible;
6. make important evidence-handling actions auditable;
7. prevent ordinary websites from silently driving the local API;
8. avoid exposing the local API beyond the intended workstation;
9. prevent third-party parser/tool failures from crashing the entire application where practical;
10. continuously detect code and dependency security regressions.

---

# 3. Assets

| Asset | Why it matters |
|---|---|
| Source evidence | Original user-selected file. Must not be modified by the application. |
| Master evidence copy | Preservation copy used as the integrity reference for acquired evidence. |
| Working evidence copy | Copy used for analysis so the master is not directly examined. |
| Browser-upload evidence | Persisted input used for normal analysis/security workflows. |
| SHA-256 integrity values | Primary integrity baseline. |
| SHA-1 / MD5 reference hashes | Secondary forensic compatibility/reference values only. |
| Acquisition manifest | Records acquisition context, hashes and observable metadata changes. |
| Analysis results | Contains metadata, artefacts, timestamps and security findings. |
| Forensic reports | Investigator-facing output used to communicate findings. |
| Evidence database | Stores persisted analysis and verification information. |
| Audit database | Stores tamper-evident operational history. |
| Collector session token | Protects local acquisition actions from arbitrary callers. |
| Native selection token | Opaque handle representing a selected source file. |
| Local workstation filesystem | Contains evidence, reports, databases and project runtime data. |
| Application source code | Security controls and forensic logic depend on its integrity. |
| CI/CD configuration | Provides automated regression and security gates. |

---

# 4. Trust boundaries

## TB-01 — Browser → FastAPI

The browser submits files, metadata and API requests to the local FastAPI application.

**Untrusted inputs include:**

- uploaded filenames
- file contents
- multipart form bodies
- browser timestamps
- evidence IDs supplied in URLs
- report requests
- request headers

**Existing controls:**

- upload byte limits
- bulk request limit
- filename normalization
- path containment checks
- UUID validation for evidence directories
- Host allowlist
- Origin / Fetch Metadata checks for state-changing API calls
- security headers
- API `no-store` cache policy

---

## TB-02 — Evidence file → Forensic parsers

Evidence is attacker-controlled by definition.

Parsers include:

- ExifTool
- PDF parser
- Office / OOXML parser
- ZIP parser
- image parser
- PE parser
- string/artefact scanner

**Existing controls:**

- static analysis only
- evidence is never intentionally executed
- ExifTool timeout
- safer XML parser (`defusedxml`)
- ZIP members are inspected without extraction
- archive member inspection bounds
- declared uncompressed-size warnings
- compression-ratio warnings
- path traversal detection
- string scan byte limit

---

## TB-03 — FastAPI → External/local tools

The application launches:

- ExifTool
- PowerShell for the Windows native file picker

**Existing controls:**

- argument-list subprocess invocation
- `shell=False` for ExifTool
- ExifTool executable discovery
- ExifTool timeout
- fixed PowerShell script rather than evidence-derived command text
- local-only application assumption

**Residual concern:**

Subprocess execution remains security-sensitive and is intentionally retained in the threat model.

---

## TB-04 — Native collector → Source filesystem

The native picker obtains a real local source path.

**Existing controls:**

- native picker rather than arbitrary path entry
- opaque in-memory selection token
- token TTL
- selection consumed after use
- collector session token required by acquisition APIs
- source is copied rather than edited
- source is re-hashed after acquisition

---

## TB-05 — Acquisition → Evidence storage

Logical acquisition creates:

```text
data/uploads/<evidence-id>/
├── acquisition_manifest.json
├── master/
└── working/
```

**Existing controls:**

- UUID-derived evidence directory
- source/master/working separation
- hash while copying
- master verification
- working verification
- source re-hash after acquisition
- master read-only attempt
- analysis only against working copy

---

## TB-06 — Application → SQLite databases

SQLite stores analysis records and audit history.

**Existing controls:**

- application-owned local DB files
- tamper-evident chained hashes for audit events
- audit verification API
- runtime DB excluded from source control

**Residual concern:**

A sufficiently privileged local user can delete or rebuild the database. Hash chaining is tamper-evident, not immutable.

---

## TB-07 — Source repository → CI/CD

Pushes and pull requests trigger:

- pytest
- coverage
- Bandit
- pip-audit
- CodeQL

**Existing controls:**

- automated regression suite
- integration tests
- Python SAST
- dependency vulnerability scanning
- Python + JavaScript CodeQL analysis

---

# 5. Threat actors

The model considers:

### A. Malicious evidence author
Creates a file specifically intended to exploit or exhaust forensic parsers.

### B. Malicious website
Attempts to send requests to the local FastAPI service through the victim's browser.

### C. Local unprivileged user
Attempts to alter evidence, reports or application data available through normal filesystem permissions.

### D. Local privileged user / administrator
Can modify application files, SQLite databases or evidence storage.

This actor cannot be fully prevented by an application that runs under the same workstation trust boundary.

### E. Supply-chain attacker
Attempts to exploit a vulnerable or malicious third-party package/tool.

### F. Accidental operator error
Incorrect file selection, accidental deletion, wrong evidence association or unintentional overwriting.

---

# 6. STRIDE analysis

## Spoofing

### T-01 — Spoofed local API origin

**Scenario:** A malicious webpage attempts to call the local forensic API.

**Impact:** Unauthorized analysis, file-processing requests or local workflow actions.

**Controls:**

- Host allowlist
- Origin validation
- `Sec-Fetch-Site` cross-site rejection
- local loopback deployment

**Residual risk:** Non-browser local processes can still call the API. The application currently has no user-authentication model.

**Status:** Mitigated for browser-originated cross-site requests; residual local-process risk accepted for current local-only scope.

---

### T-02 — Collector token spoofing

**Scenario:** Another local process obtains or guesses the collector token and invokes acquisition APIs.

**Controls:**

- random collector session token
- token comparison
- opaque selection IDs
- short-lived in-memory selection records
- consumed selections

**Residual risk:** Same-user local compromise may observe or invoke the local service.

**Status:** Partially mitigated.

---

## Tampering

### T-03 — Evidence modified after acquisition

**Scenario:** Master or working evidence is changed after collection.

**Impact:** Analysis may no longer represent the acquired source.

**Controls:**

- source/master/working hash checkpoints
- pre-analysis verification
- post-analysis verification
- SHA-256 integrity baseline
- integrity failure audit event

**Residual risk:** A privileged attacker capable of changing both evidence and stored reference data may defeat purely local controls.

**Status:** Strongly mitigated within local application trust boundary.

---

### T-04 — Source changes during logical acquisition

**Scenario:** Another process modifies the original source while acquisition is occurring.

**Controls:**

- source hash captured during copy
- source re-hashed after acquisition
- source filesystem metadata before/after acquisition
- observable changes recorded in manifest

**Residual risk:** Logical acquisition cannot provide the guarantees of hardware write-blocked physical imaging.

**Status:** Detected where observable; accepted limitation.

---

### T-05 — Audit trail tampering

**Scenario:** An audit row is edited directly in SQLite.

**Controls:**

- previous-event hash
- current-entry hash
- audit-chain verification
- chain status surfaced in UI/dashboard

**Residual risk:** A privileged local actor could delete the entire DB or reconstruct a new internally consistent chain.

**Status:** Tamper-evident, not immutable.

---

### T-06 — Path traversal through uploaded filename

**Scenario:** Filename contains `../`, absolute paths, Windows paths, control characters or reserved device names.

**Impact:** Evidence stored outside the intended evidence directory or files overwritten.

**Controls:**

- directory components discarded
- invalid/control characters normalized
- reserved names neutralized
- filename length bound
- UUID evidence directories
- resolved path containment check
- exclusive file creation

**Status:** Mitigated.

---

### T-07 — Archive path traversal

**Scenario:** ZIP contains members such as `../outside.txt`.

**Impact:** Dangerous extraction path if archive were naively unpacked.

**Controls:**

- archive is not extracted
- `..`, absolute and drive-prefixed members detected
- traversal surfaced as security finding

**Status:** Mitigated for current metadata-only archive design.

---

## Repudiation

### T-08 — Operator denies an evidence-handling action

**Scenario:** It is disputed whether acquisition, analysis, verification or report generation occurred.

**Controls:**

- UTC audit events
- evidence ID
- case reference / actor where available
- SHA-256 context
- event outcome/details
- hash-chained audit history

**Residual risk:** Local audit identity is operator-supplied; no cryptographic user identity or external timestamp authority exists.

**Status:** Partially mitigated.

---

## Information disclosure

### T-09 — Sensitive evidence data cached by browser/proxies

**Controls:**

- `/api/*` responses return `Cache-Control: no-store`
- `Pragma: no-cache`
- local deployment model

**Residual risk:** Generated reports and evidence remain files on disk and must be protected by workstation permissions.

**Status:** Mitigated at HTTP cache layer.

---

### T-10 — Runtime evidence accidentally committed to Git

**Scenario:** SQLite databases, uploads or generated evidence are added to source control.

**Controls:**

- `.gitignore` excludes runtime DB/evidence paths
- repository cleanup completed
- generated/runtime data treated separately from source

**Residual risk:** Operator may override ignore rules or manually add sensitive files.

**Status:** Operationally mitigated.

---

### T-11 — Internal path disclosure through errors

**Scenario:** Exceptions reveal filesystem paths or implementation details.

**Current controls:** FastAPI error handling plus controlled error responses in several ingestion/tool paths.

**Residual risk:** Development mode and unhandled exceptions may still reveal operational details in local logs.

**Status:** Residual risk. Review before any networked deployment.

---

## Denial of service

### T-12 — Oversized upload

**Controls:**

- per-file upload maximum
- streaming size enforcement
- partial-file cleanup
- no blind full request buffering by application code

**Status:** Mitigated within configured bounds.

---

### T-13 — Bulk analysis resource exhaustion

**Scenario:** Many valid-sized files are submitted together.

**Controls:**

- maximum file count
- per-file size cap
- total bulk-request byte cap

**Residual risk:** CPU-intensive parsing of many small hostile files can still consume resources.

**Status:** Partially mitigated.

---

### T-14 — ZIP bomb / archive resource exhaustion

**Controls:**

- members are not extracted
- compression ratio calculated
- declared uncompressed size inspected
- member-level inspection bounded
- warnings produced for suspicious resource characteristics

**Residual risk:** Reading a very large central directory still consumes some resources.

**Status:** Strongly mitigated for current non-extraction model.

---

### T-15 — Parser hang / expensive metadata extraction

**Controls:**

- ExifTool timeout
- bounded string scan
- archive member bounds
- static-only analysis

**Residual risk:** Not every in-process Python parser currently has a separate OS-level timeout or memory sandbox.

**Status:** Partially mitigated; important residual risk.

---

### T-16 — XML expansion / malicious OOXML XML

**Controls:**

- `defusedxml` used instead of the standard unsafe XML parser for Office XML parsing

**Status:** Mitigated.

---

## Elevation of privilege

### T-17 — Evidence causes command execution

**Scenario:** Malicious strings such as PowerShell commands are embedded in evidence.

**Controls:**

- strings are treated as data
- static analysis only
- no execution of extracted command artefacts
- executable content is inspected statically

**Status:** Mitigated by architecture.

---

### T-18 — Subprocess command injection through ExifTool invocation

**Controls:**

- executable resolved separately
- arguments passed as an array
- `shell=False`
- evidence path is a subprocess argument, not interpolated shell text
- timeout

**Residual risk:** ExifTool itself remains a large parser exposed to hostile files.

**Status:** Command injection strongly mitigated; parser risk remains.

---

### T-19 — Native PowerShell picker misuse

**Scenario:** Native collector process invocation is abused.

**Controls:**

- PowerShell script is application-defined
- evidence path is returned by a native dialog rather than injected into command text
- no evidence-derived PowerShell script construction

**Residual risk:** Starting an external interpreter remains a sensitive operation. Scanner findings are retained for review rather than globally suppressed.

**Status:** Accepted local design dependency; review for packaged distribution.

---

### T-20 — Vulnerable third-party dependency

**Controls:**

- `pip-audit`
- CodeQL
- Bandit
- GitHub Actions
- regression tests
- explicit ExifTool discovery rather than arbitrary execution

**Residual risk:** Zero-day vulnerabilities and non-Python native tools cannot be fully eliminated.

**Status:** Continuously monitored.

---

# 7. Additional security findings / design decisions

## File-type mismatch is evidence, not rejection

The tool intentionally does not reject a file simply because the extension and detected signature disagree.

Example:

```text
image.png renamed to notes.txt
```

The correct forensic behavior is:

```text
accept within resource boundaries
    ↓
analyze actual content/signature
    ↓
record extension mismatch
    ↓
surface security finding
```

Blocking the file would discard potentially important evidence.

---

## MD5 and SHA-1 remain present intentionally

The application calculates:

- SHA-256 — primary integrity/security baseline
- SHA-1 — secondary reference hash
- MD5 — secondary reference hash

SHA-1 and MD5 are explicitly marked as non-security uses in code.

They are not used as the evidence-integrity decision mechanism.

---

## Audit logging is tamper-evident, not immutable

The audit hash chain detects ordinary modification of historical records.

It does not create externally trusted immutability.

Stronger future options could include:

- remote append-only logging
- signed log checkpoints
- trusted timestamp service
- WORM/object-lock storage

These are outside the current local portfolio scope.

---

# 8. Residual risks

The major residual risks are:

1. **Third-party parser vulnerabilities**
   - ExifTool, PDF/image/PE libraries may contain unknown vulnerabilities.

2. **In-process parser isolation**
   - Most parsers run inside the FastAPI Python process rather than a dedicated sandbox.

3. **Privileged local attacker**
   - A local administrator can alter/delete application state and evidence files.

4. **No authentication**
   - The product relies on loopback/local-workstation isolation rather than user authentication.

5. **Logical acquisition limitations**
   - No hardware write blocker.
   - No physical disk image.
   - No deleted/unallocated recovery.
   - Source may change because it remains mounted/live.

6. **Audit identity**
   - Collector/operator identity is not backed by an identity provider or digital signature.

7. **Availability**
   - Deliberately hostile but small files may still trigger expensive parser behavior.

These risks should be stated rather than hidden.

---

# 9. Out of scope

The current project is not intended to provide:

- physical disk imaging
- E01 acquisition
- hardware write-blocker integration
- deleted-file recovery
- unallocated-space analysis
- memory acquisition or memory forensics
- full Windows Registry / MFT analysis
- mobile-device acquisition
- dynamic malware detonation
- remote multi-user hosting
- enterprise authentication / RBAC
- cloud evidence vaulting
- legally certified immutable audit storage
- replacement for FTK, EnCase, X-Ways, Autopsy or Magnet AXIOM

---

# 10. Security verification matrix

| Control | Verification |
|---|---|
| Filename/path normalization | `tests/test_ingestion.py` |
| Evidence-directory containment | `tests/test_ingestion.py` |
| Upload byte limits | `tests/test_ingestion.py` |
| Archive traversal | `tests/test_archive_hardening.py`, integration suite |
| Archive symlink detection | `tests/test_archive_hardening.py` |
| Archive inspection bounds | `tests/test_archive_hardening.py` |
| Security findings | `tests/test_security_findings.py` |
| Artefact false positives | `tests/test_artefacts.py` |
| Timeline normalization | `tests/test_timeline.py` |
| Acquisition integrity | `tests/test_acquisition.py` |
| Full analyzer pipeline | `tests/test_analyzer_integration.py` |
| Audit hash-chain integrity | `tests/test_audit_log.py` |
| HTTP security headers/origin controls | `tests/test_http_security.py` |
| ExifTool discovery/failure behavior | `tests/test_exiftool_resolution.py` |
| Python SAST | Bandit GitHub Action |
| Dependency vulnerabilities | pip-audit GitHub Action |
| Semantic code analysis | CodeQL Python + JavaScript |
| Regression suite | pytest GitHub Action |

---

# 11. Security assumptions

The current threat model assumes:

- the application runs on a trusted analyst workstation;
- Uvicorn remains bound to loopback;
- the workstation OS and Python environment are reasonably maintained;
- evidence storage permissions are limited to the analyst account / trusted administrators;
- source code and CI configuration are obtained from the legitimate repository;
- users understand that static analysis cannot prove a file is safe.

If these assumptions change, the threat model must be revisited.

---

# 12. Recommended future hardening

The next security improvements, if the project scope grows, are:

### Priority 1
- isolate high-risk parsers into worker subprocesses;
- apply per-parser CPU/memory/time limits;
- formalize and pin runtime dependencies;
- package application with a reproducible deployment process.

### Priority 2
- signed audit checkpoints;
- optional remote append-only audit sink;
- stronger collector/operator identity;
- report-signing support.

### Priority 3
- authentication/RBAC if remote or multi-user deployment is ever introduced;
- TLS if the application ever stops being loopback-only;
- separate evidence storage service;
- malware-scanning/sandbox integrations with explicit evidence-handling consent.

---

# 13. Threat-model conclusion

The project's security design is based on a simple principle:

> Treat every evidence file as hostile while preserving it as evidence.

The implementation therefore prefers:

- bounded static inspection over execution;
- explicit integrity verification over trust;
- controlled storage over browser filenames;
- non-extraction over automatic archive unpacking;
- recorded residual risk over unsupported claims of safety;
- automated security checks over one-time manual review.

The application is appropriate for its defined local static-analysis and logical-acquisition portfolio scope, while several residual risks remain intentionally documented for future work.
