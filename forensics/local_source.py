from __future__ import annotations

import os
import shutil

from datetime import (
    datetime,
    timezone,
)

from pathlib import Path

from forensics.hashing import (
    calculate_hashes,
)


def _utc_from_epoch(
    value: float | None,
) -> str | None:

    if value is None:
        return None

    try:

        return (
            datetime
            .fromtimestamp(
                value,
                tz=timezone.utc,
            )
            .isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

    except (
        ValueError,
        OverflowError,
        OSError,
    ):

        return None


def resolve_local_evidence(
    *,
    root: Path,
    requested_path: str,
) -> Path:
    """
    Resolve a user-selected local evidence path while
    preventing access outside the configured evidence root.

    Both absolute and root-relative paths are accepted.
    """

    if not requested_path.strip():

        raise ValueError(
            "No evidence path was supplied."
        )


    root = root.resolve()


    supplied = Path(
        requested_path.strip()
    )


    if supplied.is_absolute():

        candidate = (
            supplied.resolve()
        )

    else:

        candidate = (
            root
            / supplied
        ).resolve()


    try:

        candidate.relative_to(
            root
        )

    except ValueError:

        raise ValueError(
            (
                "The requested file is outside "
                "the configured local evidence root."
            )
        )


    if not candidate.exists():

        raise ValueError(
            "The requested evidence file does not exist."
        )


    if not candidate.is_file():

        raise ValueError(
            "The requested path is not a file."
        )


    return candidate


def collect_source_filesystem(
    file_path: Path,
    root: Path,
) -> dict:
    """
    Capture filesystem context from the original source
    file before creating the analyzer working copy.
    """

    stat_result = (
        file_path.stat()
    )


    created = None
    metadata_changed = None
    created_basis = None


    # Windows st_ctime represents file creation time.
    if os.name == "nt":

        created = _utc_from_epoch(
            stat_result.st_ctime
        )

        created_basis = (
            "Windows filesystem creation time"
        )


    # Some Unix-like filesystems expose birth time.
    elif hasattr(
        stat_result,
        "st_birthtime",
    ):

        created = _utc_from_epoch(
            stat_result.st_birthtime
        )

        created_basis = (
            "Filesystem birth time"
        )


        metadata_changed = (
            _utc_from_epoch(
                stat_result.st_ctime
            )
        )


    else:

        # On Unix/Linux st_ctime is metadata-change time,
        # not creation time.
        metadata_changed = (
            _utc_from_epoch(
                stat_result.st_ctime
            )
        )


    try:

        relative_path = str(
            file_path.relative_to(
                root
            )
        )

    except ValueError:

        relative_path = (
            file_path.name
        )


    return {
        "scope":
            "source_filesystem",

        "absolute_path":
            str(
                file_path
            ),

        "relative_path":
            relative_path,

        "filename":
            file_path.name,

        "size_bytes":
            stat_result.st_size,

        "created":
            created,

        "created_basis":
            created_basis,

        "modified":
            _utc_from_epoch(
                stat_result.st_mtime
            ),

        "accessed":
            _utc_from_epoch(
                stat_result.st_atime
            ),

        "metadata_changed":
            metadata_changed,

        "platform":
            os.name,

        "warning": (
            "These values were collected directly "
            "from the source filesystem before the "
            "analyzer created its working copy. "
            "Filesystem timestamps can still be "
            "altered by operating-system behaviour, "
            "copying or deliberate manipulation."
        ),
    }


def create_verified_working_copy(
    *,
    source: Path,
    destination: Path,
) -> dict:
    """
    Hash the original, create a byte-for-byte working
    copy, and verify the copy before analysis begins.
    """

    source_hash_before = (
        calculate_hashes(
            source
        )["sha256"]
    )


    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )


    # copyfile copies content only rather than intentionally
    # preserving the source timestamps onto the working copy.
    shutil.copyfile(
        source,
        destination,
    )


    working_hash_before = (
        calculate_hashes(
            destination
        )["sha256"]
    )


    if (
        source_hash_before
        != working_hash_before
    ):

        destination.unlink(
            missing_ok=True
        )


        raise RuntimeError(
            (
                "Working-copy integrity verification "
                "failed before analysis."
            )
        )


    return {
        "source_sha256_before":
            source_hash_before,

        "working_sha256_before":
            working_hash_before,

        "copy_verified":
            True,
    }


def verify_local_preservation(
    *,
    source: Path,
    working_copy: Path,
    original_sha256: str,
) -> dict:
    """
    Verify both the source evidence and analyzer copy
    after analysis has completed.
    """

    source_after = (
        calculate_hashes(
            source
        )["sha256"]
    )


    working_after = (
        calculate_hashes(
            working_copy
        )["sha256"]
    )


    return {
        "source_sha256_after":
            source_after,

        "working_sha256_after":
            working_after,

        "source_unchanged":
            (
                source_after
                == original_sha256
            ),

        "working_copy_unchanged":
            (
                working_after
                == original_sha256
            ),
    }


def add_source_timeline_events(
    timeline: dict,
    source: dict,
) -> None:
    """
    Add original filesystem timestamps to the existing
    unified forensic timeline without confusing them
    with evidence-copy timestamps.
    """

    mappings = [
        (
            "created",
            "created",
            "Source filesystem created",
        ),

        (
            "modified",
            "modified",
            "Source filesystem modified",
        ),

        (
            "accessed",
            "accessed",
            "Source filesystem accessed",
        ),

        (
            "metadata_changed",
            "metadata_changed",
            "Source filesystem metadata changed",
        ),
    ]


    events = timeline.setdefault(
        "events",
        [],
    )


    added = 0


    for (
        field_name,
        event_type,
        label,
    ) in mappings:

        value = source.get(
            field_name
        )


        if not value:
            continue


        notes = [
            (
                "Collected directly from the "
                "configured local source filesystem "
                "before analysis."
            )
        ]


        if (
            field_name == "created"
            and source.get(
                "created_basis"
            )
        ):

            notes.append(
                source[
                    "created_basis"
                ]
            )


        events.append(
            {
                "timestamp_original":
                    value,

                "timestamp_utc":
                    value,

                "timezone_known":
                    True,

                "event_type":
                    event_type,

                "label":
                    label,

                "scope":
                    "source_filesystem",

                "source":
                    "SourceFilesystem",

                "source_group":
                    "SourceFilesystem",

                "source_field":
                    field_name,

                "notes":
                    notes,
            }
        )


        added += 1


    events.sort(
        key=lambda event: (
            event.get(
                "timestamp_utc"
            )
            or event.get(
                "timestamp_original"
            )
            or ""
        )
    )


    timeline[
        "event_count"
    ] = len(
        events
    )


    timeline[
        "utc_normalised_count"
    ] = sum(
        1
        for event in events
        if event.get(
            "timestamp_utc"
        )
    )


    observations = timeline.setdefault(
        "observations",
        [],
    )


    if added:

        observations.append(
            {
                "severity":
                    "info",

                "title":
                    "Source filesystem timestamps",

                "message":
                    (
                        f"{added} timestamp(s) were "
                        "captured directly from the "
                        "original local filesystem."
                    ),
            }
        )


    timeline[
        "observation_count"
    ] = len(
        observations
    )