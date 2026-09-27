# Attack Surface Review

## Primary externally influenced inputs

| Input | Trust level | Main controls |
|---|---|---|
| Uploaded file contents | Hostile | size limit, static-only analysis, parser hardening |
| Uploaded filename | Hostile | normalization, containment, exclusive creation |
| ZIP member names | Hostile | no extraction, traversal detection |
| Office XML | Hostile | defusedxml |
| Embedded metadata | Hostile | parsed as data, not executed |
| Embedded command strings | Hostile | displayed as findings only |
| Browser timestamp | Untrusted metadata | parse/validate, optional |
| Evidence ID URL parameter | Untrusted | UUID/path validation and DB lookup |
| Origin / Host headers | Untrusted | allowlists |
| Native selected source | Locally trusted user choice | tokenized selection + verification |
| Dependency updates | Supply-chain input | pip-audit + CodeQL + tests |

## High-risk components

### ExifTool

Risk:
- complex native/external parser processing hostile evidence.

Controls:
- explicit executable resolution;
- argument-list invocation;
- `shell=False`;
- timeout;
- clean failure status.

Residual:
- parser-level vulnerabilities remain possible.

### Office / OOXML

Risk:
- ZIP container + XML under attacker control.

Controls:
- no general extraction into filesystem;
- defusedxml;
- structured package inspection;
- archive/path observations.

### PDF

Risk:
- complex format;
- active-content indicators.

Controls:
- static parsing only;
- JavaScript/action indicators surfaced;
- file never launched.

### ZIP

Risk:
- path traversal;
- symlinks;
- high compression;
- huge member count;
- large declared size.

Controls:
- no extraction;
- bounded inspection;
- traversal/symlink detection;
- compression and declared-size observations.

### Native collector

Risk:
- privileged relationship to analyst filesystem.

Controls:
- user-visible native picker;
- opaque selection ID;
- TTL;
- one-time consumption;
- collector token;
- source/master/working verification.

## Main residual attack surface

The largest remaining technical risk is hostile input reaching in-process third-party parsers.

A future hardened edition should place higher-risk parsing in isolated worker processes with resource limits and a narrow result-serialization boundary.
