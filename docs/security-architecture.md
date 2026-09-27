# Security Architecture Notes

This document is a shorter companion to `threat-model.md`.

## Security layers

```mermaid
flowchart TD
    U[Analyst Browser] --> H[HTTP Security Middleware]
    H --> A[FastAPI API]
    A --> I[Secure Ingestion]
    I --> F[Forensic Analysis Engine]

    F --> M[Metadata / ExifTool]
    F --> P[PDF Parser]
    F --> O[Office / defusedxml]
    F --> Z[ZIP Metadata Inspection]
    F --> E[PE Static Analysis]
    F --> S[String / Artefact Scanner]

    A --> D[(Evidence SQLite)]
    A --> L[(Audit SQLite)]

    C[Native Collector] --> Q[Source Evidence]
    Q --> MC[Master Copy]
    MC --> WC[Working Copy]
    WC --> F

    L --> V[Hash-chain Verification]
```

## Evidence-preservation model

```mermaid
flowchart LR
    S[Source File] -->|hash while copying| M[Master Copy]
    M -->|SHA-256 verify| W[Working Copy]
    W -->|analyze only this copy| A[Analysis]
    A -->|post-analysis verification| V[Integrity Result]
    S -->|rehash after acquisition| V
```

## Browser/API model

```mermaid
flowchart LR
    B[Browser] -->|127.0.0.1 only| H[Host + Origin Checks]
    H -->|size/path controls| API[FastAPI]
    X[Malicious Web Site] -. cross-site request .-> H
    H -. rejected .-> X
```

## CI security model

```mermaid
flowchart LR
    G[Git Push / PR] --> T[pytest]
    G --> B[Bandit]
    G --> P[pip-audit]
    G --> C[CodeQL]
    T --> R[Security / Quality Gate]
    B --> R
    P --> R
    C --> R
```

## Important design boundaries

The application is deliberately:

- local-only;
- static-analysis focused;
- single-analyst/workstation oriented;
- not an evidence-vault service;
- not a malware sandbox;
- not a physical imaging product.

Any future change to remote/multi-user operation invalidates several current security assumptions and must trigger a new threat-model review.
