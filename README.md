# Digital Forensic File Analyzer

A local digital forensic triage application for examining files,
extracting metadata, validating file signatures and recording
cryptographic hashes.

## Current MVP

The current version supports:

- File upload
- SHA-256 hashing
- SHA-1 hashing
- MD5 hashing for forensic compatibility
- Magic-byte/file-signature inspection
- File-extension mismatch detection
- Filesystem metadata for the evidence copy
- ExifTool metadata extraction
- Categorised metadata display
- Local FastAPI dashboard

## Architecture

The project separates the forensic-analysis engine from the web
application.

The modules in `forensics/` can therefore be reused by other
applications without depending on FastAPI or the dashboard.

## Technologies

- Python
- FastAPI
- HTML
- CSS
- JavaScript
- ExifTool

## Forensic Considerations

Metadata should not automatically be interpreted as fact.

For example:

- Document Author does not prove authorship.
- Metadata can be intentionally modified.
- Filesystem timestamps may be altered.
- Browser uploads do not preserve complete original filesystem metadata.
- File access itself may affect timestamps depending on the filesystem
  and operating-system configuration.

This application is currently intended as an analysis and triage tool,
not a forensic acquisition or disk-imaging system.

## Planned Features

- Unified forensic timeline
- Interesting string / IOC extraction
- File integrity verification
- Persistent evidence records
- Two-file comparison
- Bulk analysis
- Office document analysis
- PDF analysis
- Image / EXIF analysis
- Exportable JSON reports
- CSV reports
- HTML forensic reports
- Demonstration evidence mode
- Portfolio mode