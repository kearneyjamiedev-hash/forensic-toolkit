from datetime import datetime, timezone
from pathlib import Path

from forensics.filesystem import (
    get_filesystem_metadata
)

from forensics.hashing import (
    calculate_hashes
)

from forensics.metadata import (
    extract_metadata
)

from forensics.signatures import (
    detect_file_type
)

from forensics.strings import (
    extract_interesting_artefacts
)

from forensics.timeline import (
    build_timeline
)


def _utc_now() -> str:
    return (
        datetime
        .now(timezone.utc)
        .isoformat()
        .replace(
            "+00:00",
            "Z",
        )
    )


def analyze_file(
    file_path: Path,
    original_filename: str,
) -> dict:

    hashes = calculate_hashes(
        file_path
    )


    signature = detect_file_type(
        file_path=file_path,
        original_filename=(
            original_filename
        ),
    )


    filesystem = (
        get_filesystem_metadata(
            file_path
        )
    )


    metadata = extract_metadata(
        file_path
    )


    timeline = build_timeline(
        filesystem=filesystem,
        metadata=metadata,
    )


    artefacts = (
        extract_interesting_artefacts(
            file_path
        )
    )


    warnings = []


    if (
        signature[
            "extension_matches"
        ]
        is False
    ):

        warnings.append(
            {
                "type":
                    "extension_mismatch",

                "severity":
                    "warning",

                "message":
                    (
                        "The filename extension "
                        "does not match the detected "
                        "file signature."
                    ),
            }
        )


    if (
        metadata["status"]
        != "ok"
    ):

        warnings.append(
            {
                "type":
                    "metadata_extractor",

                "severity":
                    "warning",

                "message":
                    metadata.get(
                        "error",
                        (
                            "Metadata extraction "
                            "was incomplete."
                        ),
                    ),
            }
        )


    if artefacts["truncated"]:

        warnings.append(
            {
                "type":
                    "string_scan_truncated",

                "severity":
                    "info",

                "message":
                    (
                        "Interesting artefact "
                        "extraction was limited "
                        "to the first "
                        f"{artefacts['scan_limit_bytes']} "
                        "bytes."
                    ),
            }
        )


    filesystem_timestamp_count = sum(
        value is not None
        for value in [
            filesystem.get(
                "created"
            ),

            filesystem.get(
                "modified"
            ),

            filesystem.get(
                "accessed"
            ),

            filesystem.get(
                "metadata_changed"
            ),
        ]
    )


    artifact_count = (
        metadata[
            "field_count"
        ]
        + filesystem_timestamp_count
        + len(hashes)
        + 1
        + artefacts[
            "total_found"
        ]
    )


    return {
        "analysis": {
            "timestamp_utc":
                _utc_now(),

            "artifact_count":
                artifact_count,
        },


        "overview": {
            "filename":
                original_filename,

            "extension":
                (
                    Path(
                        original_filename
                    )
                    .suffix
                    .lower()
                    or None
                ),

            "size_bytes":
                filesystem[
                    "size_bytes"
                ],
        },


        "hashes":
            hashes,


        "signature":
            signature,


        "filesystem":
            filesystem,


        "metadata":
            metadata,


        "timeline":
            timeline,


        "artefacts":
            artefacts,


        "warnings":
            warnings,
    }