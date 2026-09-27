# Security Decision Register

| ID | Decision | Rationale | Trade-off |
|---|---|---|---|
| SD-01 | Bind the application to loopback only | Avoid exposing an unauthenticated forensic API to the network | No remote collaboration |
| SD-02 | Do not execute evidence | Evidence is untrusted by definition | Cannot perform dynamic malware behavior analysis |
| SD-03 | Use SHA-256 as integrity baseline | Modern collision resistance suitable for integrity verification | SHA-1/MD5 retained only for forensic compatibility |
| SD-04 | Keep SHA-1 and MD5 as non-security reference hashes | Useful when comparing against legacy forensic/tool outputs | Must be clearly labelled to avoid implying security strength |
| SD-05 | Analyze working copy, not master | Preserve a separate reference copy | Additional disk usage |
| SD-06 | Do not extract ZIP members | Avoid traversal and decompression/execution risks | Less deep content inspection |
| SD-07 | Treat extension mismatch as evidence, not rejection | Deceptive naming is itself forensically relevant | Analyzer must safely handle unexpected formats |
| SD-08 | Use defusedxml for OOXML XML | Office content is untrusted XML | Additional dependency |
| SD-09 | Use ExifTool with timeout and shell disabled | Broad metadata support while reducing command-injection/hang risk | External parser still increases attack surface |
| SD-10 | Use hash-chained local audit log | Detect historical row modification | Does not protect against deletion/reconstruction by local admin |
| SD-11 | Reject cross-site local API requests | Mitigate malicious-webpage attacks against localhost | Some unusual clients may need explicit configuration |
| SD-12 | Disable FastAPI docs by default | Reduce unnecessary local attack surface | Developers must opt in when needed |
| SD-13 | Enforce byte/resource limits | Prevent simple storage/DoS abuse | Very large legitimate evidence requires config change |
| SD-14 | Keep security scanners as CI gates | Catch regressions continuously | Scanner findings require human triage |
| SD-15 | Do not claim a file is safe | Static analysis cannot prove absence of malicious behavior | Security workflow uses evidence-based dispositions instead |
| SD-16 | Keep case records separate from evidence-scoped audit chains in Case Workspace v0.1 | The existing audit chain is keyed by `evidence_id`; inventing synthetic evidence IDs for case-only actions would weaken its semantics | Case creation/linking is not yet represented in the tamper-evident audit chain; a later audit schema version should add first-class case events deliberately |
