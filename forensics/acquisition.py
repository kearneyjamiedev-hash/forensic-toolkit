from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID


CHUNK_SIZE = 1024 * 1024
MANIFEST_FILENAME = "acquisition_manifest.json"


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def collect_source_filesystem(file_path: Path) -> dict:
    """Capture source filesystem context without opening file contents."""
    file_path = file_path.resolve()
    result = file_path.stat()

    created = None
    created_basis = None
    metadata_changed = None

    if os.name == "nt":
        created = _epoch_to_utc(result.st_ctime)
        created_basis = "Windows filesystem creation time"
    elif hasattr(result, "st_birthtime"):
        created = _epoch_to_utc(result.st_birthtime)
        created_basis = "Filesystem birth time"
        metadata_changed = _epoch_to_utc(result.st_ctime)
    else:
        metadata_changed = _epoch_to_utc(result.st_ctime)

    return {
        "scope": "source_filesystem",
        "path": str(file_path),
        "filename": file_path.name,
        "size_bytes": result.st_size,
        "created": created,
        "created_basis": created_basis,
        "modified": _epoch_to_utc(result.st_mtime),
        "accessed": _epoch_to_utc(result.st_atime),
        "metadata_changed": metadata_changed,
        "file_id": getattr(result, "st_ino", None),
        "device_id": getattr(result, "st_dev", None),
        "platform": platform.system(),
    }


def preview_source(file_path: Path) -> dict:
    source = collect_source_filesystem(file_path)
    source["warning"] = (
        "Source filesystem values are captured as observed by the host operating "
        "system. They can be affected by filesystem policy, prior copying, normal "
        "OS behaviour or deliberate modification."
    )
    return source


def acquire_logical_file(
    *,
    source_path: Path,
    evidence_root: Path,
    evidence_id: str,
    max_size: int,
    case_reference: str,
    evidence_description: str,
    collector_name: str,
) -> dict:
    """
    Perform a logical single-file acquisition.

    The source is captured to a master evidence copy, verified with SHA-256,
    then a separate working copy is made from that master. Source filesystem
    metadata is recorded before and after acquisition so any observable change
    is explicit in the manifest.
    """
    started_at = utc_now()
    source_path = source_path.resolve()

    if not source_path.exists() or not source_path.is_file():
        raise ValueError("The selected source evidence is no longer available.")

    source_before = collect_source_filesystem(source_path)

    if source_before["size_bytes"] > max_size:
        raise ValueError("The selected evidence exceeds the maximum permitted size.")

    evidence_dir = _evidence_directory(evidence_root, evidence_id)
    master_dir = evidence_dir / "master"
    working_dir = evidence_dir / "working"

    master_dir.mkdir(parents=True, exist_ok=False)
    working_dir.mkdir(parents=True, exist_ok=False)

    master_path = master_dir / source_path.name
    working_path = working_dir / source_path.name

    # One source-content read creates the master and calculates the acquisition
    # hash at the same time.
    source_sha256_during_copy = _stream_copy_and_hash(
        source_path,
        master_path,
    )

    master_sha256 = calculate_sha256(master_path)

    if master_sha256 != source_sha256_during_copy:
        raise RuntimeError("Master evidence copy failed SHA-256 verification.")

    # Create the analysis copy from the verified master, never from the source.
    working_sha256 = _stream_copy_and_hash(
        master_path,
        working_path,
    )

    if working_sha256 != master_sha256:
        raise RuntimeError("Working copy failed SHA-256 verification.")

    # Re-read the source after acquisition. This is an explicit integrity check,
    # not an assertion that reading a live filesystem cannot affect metadata.
    source_sha256_after = calculate_sha256(source_path)
    source_after = collect_source_filesystem(source_path)

    source_content_unchanged = (
        source_sha256_after == source_sha256_during_copy
    )

    source_metadata_changes = _metadata_changes(
        source_before,
        source_after,
    )

    if not source_content_unchanged:
        raise RuntimeError(
            "The source evidence changed while logical acquisition was in progress."
        )

    read_only_applied = _set_master_read_only(master_path)

    completed_at = utc_now()

    manifest = {
        "schema_version": "1.0",
        "evidence_id": evidence_id,
        "case_reference": case_reference.strip(),
        "evidence_description": evidence_description.strip(),
        "collector_name": collector_name.strip(),
        "acquisition": {
            "type": "logical_file",
            "started_at_utc": started_at,
            "completed_at_utc": completed_at,
            "tool": "Digital Forensic File Analyzer",
            "tool_version": "1.0.0",
            "host": platform.node(),
            "host_platform": platform.platform(),
            "process_user": getpass.getuser(),
            "write_blocker_used": False,
            "protection_note": (
                "Logical acquisition from a live filesystem. No hardware write "
                "blocker is asserted. Source content integrity is checked with "
                "SHA-256 before/during and after acquisition."
            ),
        },
        "source": {
            "before_acquisition": source_before,
            "after_acquisition": source_after,
            "observable_metadata_changes": source_metadata_changes,
        },
        "integrity": {
            "algorithm": "SHA-256",
            "source_sha256_during_copy": source_sha256_during_copy,
            "source_sha256_after": source_sha256_after,
            "master_sha256": master_sha256,
            "working_sha256": working_sha256,
            "source_content_unchanged": source_content_unchanged,
            "master_verified": master_sha256 == source_sha256_during_copy,
            "working_verified": working_sha256 == master_sha256,
        },
        "storage": {
            "evidence_directory": str(evidence_dir),
            "master_path": str(master_path),
            "working_path": str(working_path),
            "master_read_only_applied": read_only_applied,
        },
    }

    manifest_path = evidence_dir / MANIFEST_FILENAME
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return manifest


def load_acquisition_manifest(
    *,
    evidence_root: Path,
    evidence_id: str,
) -> dict:
    evidence_dir = _evidence_directory(evidence_root, evidence_id)
    manifest_path = evidence_dir / MANIFEST_FILENAME

    if not manifest_path.exists():
        raise FileNotFoundError("Acquisition manifest was not found.")

    return json.loads(manifest_path.read_text(encoding="utf-8"))


def verify_before_analysis(manifest: dict) -> dict:
    master_path = Path(manifest["storage"]["master_path"])
    working_path = Path(manifest["storage"]["working_path"])
    expected = manifest["integrity"]["master_sha256"]

    master_sha256 = calculate_sha256(master_path)
    working_sha256 = calculate_sha256(working_path)

    return {
        "master_sha256": master_sha256,
        "working_sha256": working_sha256,
        "master_verified": master_sha256 == expected,
        "working_verified": working_sha256 == expected,
    }


def verify_after_analysis(manifest: dict) -> dict:
    # Analysis is performed only on the working copy. Both master and working
    # are checked after parsers complete so accidental mutation is detected.
    return verify_before_analysis(manifest)


def add_source_timeline_events(timeline: dict, source: dict) -> None:
    mappings = [
        ("created", "created", "Source filesystem created"),
        ("modified", "modified", "Source filesystem modified"),
        ("accessed", "accessed", "Source filesystem accessed"),
        (
            "metadata_changed",
            "metadata_changed",
            "Source filesystem metadata changed",
        ),
    ]

    events = timeline.setdefault("events", [])
    added = 0

    for field_name, event_type, label in mappings:
        value = source.get(field_name)
        if not value:
            continue

        notes = [
            "Captured from the original source filesystem before logical acquisition."
        ]

        if field_name == "created" and source.get("created_basis"):
            notes.append(source["created_basis"])

        events.append(
            {
                "timestamp_original": value,
                "timestamp_utc": value,
                "timezone_known": True,
                "event_type": event_type,
                "label": label,
                "scope": "source_filesystem",
                "source": "SourceFilesystem",
                "source_group": "SourceFilesystem",
                "source_field": field_name,
                "notes": notes,
            }
        )
        added += 1

    events.sort(
        key=lambda event: (
            event.get("timestamp_utc")
            or event.get("timestamp_original")
            or ""
        )
    )

    timeline["event_count"] = len(events)
    timeline["utc_normalised_count"] = sum(
        1 for event in events if event.get("timestamp_utc")
    )

    observations = timeline.setdefault("observations", [])
    if added:
        observations.append(
            {
                "severity": "info",
                "title": "Source filesystem timestamps",
                "message": (
                    f"{added} timestamp(s) were captured from the original source "
                    "filesystem before logical acquisition."
                ),
            }
        )
    timeline["observation_count"] = len(observations)


def calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _stream_copy_and_hash(source: Path, destination: Path) -> str:
    digest = hashlib.sha256()

    with source.open("rb") as source_handle, destination.open("xb") as output:
        while True:
            chunk = source_handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            output.write(chunk)

    return digest.hexdigest()


def _metadata_changes(before: dict, after: dict) -> list[dict]:
    fields = [
        "size_bytes",
        "created",
        "modified",
        "accessed",
        "metadata_changed",
        "file_id",
    ]

    changes = []
    for field in fields:
        if before.get(field) != after.get(field):
            changes.append(
                {
                    "field": field,
                    "before": before.get(field),
                    "after": after.get(field),
                }
            )
    return changes


def _set_master_read_only(master_path: Path) -> bool:
    try:
        current_mode = master_path.stat().st_mode
        master_path.chmod(current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
        return True
    except OSError:
        return False


def _evidence_directory(evidence_root: Path, evidence_id: str) -> Path:
    # Enforce UUID syntax before using an externally supplied ID in a path.
    UUID(evidence_id)
    return evidence_root.resolve() / evidence_id


def _epoch_to_utc(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        return (
            datetime.fromtimestamp(value, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (ValueError, OverflowError, OSError):
        return None
