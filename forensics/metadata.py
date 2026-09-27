import json
import subprocess
from pathlib import Path

from app.config import (
    resolve_exiftool_path,
)


CATEGORY_MAP = {
    "EXIF": "image_exif",
    "GPS": "image_exif",
    "IPTC": "image_metadata",
    "XMP": "image_metadata",

    "PDF": "pdf_metadata",

    "ZIP": "archive_metadata",
    "RAR": "archive_metadata",
    "GZIP": "archive_metadata",

    "PE": "executable_metadata",
    "COFF": "executable_metadata",
    "ELF": "executable_metadata",
    "MachO": "executable_metadata",

    "Microsoft": "document_metadata",
    "OOXML": "document_metadata",
    "DOCX": "document_metadata",
    "DOC": "document_metadata",

    "File": "file_properties",
    "System": "filesystem_metadata",

    "Composite": "computed_metadata",
}


EXIFTOOL_TIMEOUT_SECONDS = 30


def _split_exiftool_key(
    key: str,
) -> tuple[str, str]:

    if ":" not in key:
        return (
            "Other",
            key,
        )

    group, name = key.split(
        ":",
        1,
    )

    return (
        group,
        name,
    )


def _category_for_group(
    group: str,
) -> str:

    return CATEGORY_MAP.get(
        group,
        "other_metadata",
    )


def _empty_result(
    *,
    status: str,
    error: str | None = None,
) -> dict:

    result = {
        "status": status,
        "categories": {},
        "summary": {},
        "field_count": 0,
    }

    if error:
        result["error"] = error

    return result


def extract_metadata(
    file_path: Path,
) -> dict:

    exiftool_path = (
        resolve_exiftool_path()
    )

    if not exiftool_path:
        return _empty_result(
            status="unavailable",
            error=(
                "ExifTool could not be found. "
                "Install ExifTool or configure "
                "EXIFTOOL_PATH."
            ),
        )

    command = [
        exiftool_path,
        "-j",
        "-G1",
        "-a",
        "-s",
        str(file_path),
    ]

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=(
                EXIFTOOL_TIMEOUT_SECONDS
            ),
            check=False,
            shell=False,
        )

    except FileNotFoundError:
        return _empty_result(
            status="unavailable",
            error=(
                "ExifTool could not be found. "
                "Install ExifTool or configure "
                "EXIFTOOL_PATH."
            ),
        )

    except PermissionError:
        return _empty_result(
            status="unavailable",
            error=(
                "ExifTool was found but could not "
                "be executed. Check the executable "
                "permissions or EXIFTOOL_PATH."
            ),
        )

    except subprocess.TimeoutExpired:
        return _empty_result(
            status="error",
            error=(
                "ExifTool analysis timed out."
            ),
        )

    except OSError as error:
        return _empty_result(
            status="error",
            error=(
                "ExifTool could not be started: "
                f"{error}"
            ),
        )

    if process.returncode != 0:
        return _empty_result(
            status="error",
            error=(
                process.stderr.strip()
                or (
                    "ExifTool returned an error."
                )
            ),
        )

    try:
        records = json.loads(
            process.stdout
        )

    except json.JSONDecodeError:
        return _empty_result(
            status="error",
            error=(
                "ExifTool returned invalid JSON."
            ),
        )

    if not records:
        return _empty_result(
            status="ok",
        )

    raw = records[0]

    categories = {}
    summary = {}

    for key, value in raw.items():
        if key == "SourceFile":
            continue

        group, name = (
            _split_exiftool_key(
                key
            )
        )

        category = (
            _category_for_group(
                group
            )
        )

        categories.setdefault(
            category,
            [],
        )

        categories[
            category
        ].append(
            {
                "group": group,
                "name": name,
                "value": value,
            }
        )

        if name == "FileType":
            summary[
                "file_type"
            ] = value

        elif name == "MIMEType":
            summary[
                "mime_type"
            ] = value

        elif (
            name
            == "FileTypeExtension"
        ):
            summary[
                "file_type_extension"
            ] = value

    field_count = sum(
        len(fields)
        for fields
        in categories.values()
    )

    return {
        "status": "ok",
        "categories": categories,
        "summary": summary,
        "field_count": field_count,
    }
