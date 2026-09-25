import os
from datetime import datetime, timezone
from pathlib import Path


def _utc_timestamp(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None

    return (
        datetime
        .fromtimestamp(timestamp, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def get_filesystem_metadata(file_path: Path) -> dict:
    stat = file_path.stat()

    created = None
    created_type = None

    if os.name == "nt":
        created = _utc_timestamp(stat.st_ctime)
        created_type = "windows_creation_time"

    elif hasattr(stat, "st_birthtime"):
        created = _utc_timestamp(stat.st_birthtime)
        created_type = "filesystem_birth_time"

    metadata_changed = None

    if os.name != "nt":
        metadata_changed = _utc_timestamp(stat.st_ctime)

    return {
        "scope": "evidence_copy",
        "size_bytes": stat.st_size,
        "created": created,
        "created_type": created_type,
        "modified": _utc_timestamp(stat.st_mtime),
        "accessed": _utc_timestamp(stat.st_atime),
        "metadata_changed": metadata_changed,
        "warning": (
            "These timestamps describe the local evidence copy managed by "
            "the analyzer. A browser upload does not preserve the complete "
            "filesystem metadata of the original source file."
        ),
    }