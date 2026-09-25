from pathlib import Path
import re


MAX_ANALYSIS_BYTES = (
    64
    * 1024
    * 1024
)


def analyze_pdf(
    file_path: Path,
) -> dict:

    observations = []

    with file_path.open("rb") as file:

        data = file.read(
            MAX_ANALYSIS_BYTES + 1
        )


    truncated = (
        len(data)
        > MAX_ANALYSIS_BYTES
    )


    if truncated:

        data = data[
            :MAX_ANALYSIS_BYTES
        ]


        observations.append(
            {
                "severity": "info",
                "title": "PDF scan limited",
                "message": (
                    "Format analysis was limited "
                    "to the first 64 MB."
                ),
            }
        )


    version = None


    version_match = re.match(
        rb"%PDF-(\d\.\d)",
        data,
    )


    if version_match:

        version = (
            version_match
            .group(1)
            .decode(
                "ascii",
                errors="replace",
            )
        )


    eof_matches = list(
        re.finditer(
            rb"%%EOF",
            data,
        )
    )


    eof_count = len(
        eof_matches
    )


    trailing_bytes = 0


    if eof_matches:

        end = (
            eof_matches[-1]
            .end()
        )


        trailing = (
            data[end:]
            .strip(
                b"\x00"
                b"\x09"
                b"\x0a"
                b"\x0d"
                b"\x20"
            )
        )


        trailing_bytes = len(
            trailing
        )


    page_markers = len(
        re.findall(
            rb"/Type\s*/Page(?!s)\b",
            data,
        )
    )


    object_count = len(
        re.findall(
            rb"\b\d+\s+\d+\s+obj\b",
            data,
        )
    )


    javascript_markers = (
        len(
            re.findall(
                rb"/JavaScript\b",
                data,
            )
        )
        +
        len(
            re.findall(
                rb"/JS\b",
                data,
            )
        )
    )


    embedded_file_markers = len(
        re.findall(
            rb"/EmbeddedFile\b",
            data,
        )
    )


    form_present = bool(
        re.search(
            rb"/AcroForm\b",
            data,
        )
    )


    xfa_present = bool(
        re.search(
            rb"/XFA\b",
            data,
        )
    )


    open_action_present = bool(
        re.search(
            rb"/OpenAction\b",
            data,
        )
    )


    additional_action_present = bool(
        re.search(
            rb"/AA\b",
            data,
        )
    )


    launch_action_present = bool(
        re.search(
            rb"/Launch\b",
            data,
        )
    )


    encrypted = bool(
        re.search(
            rb"/Encrypt\b",
            data,
        )
    )


    linearized = bool(
        re.search(
            rb"/Linearized\b",
            data,
        )
    )


    if eof_count > 1:

        observations.append(
            {
                "severity": "info",
                "title": "Multiple EOF markers",
                "message": (
                    "Multiple PDF EOF markers were found. "
                    "This can occur with incremental updates "
                    "and should be interpreted in context."
                ),
            }
        )


    if trailing_bytes:

        observations.append(
            {
                "severity": "warning",
                "title": "Data after final EOF",
                "message": (
                    f"{trailing_bytes} non-whitespace "
                    "bytes were found after the final "
                    "PDF EOF marker."
                ),
            }
        )


    if javascript_markers:

        observations.append(
            {
                "severity": "warning",
                "title": "JavaScript references present",
                "message": (
                    f"{javascript_markers} JavaScript-related "
                    "PDF markers were identified. Presence "
                    "alone does not establish malicious activity."
                ),
            }
        )


    if embedded_file_markers:

        observations.append(
            {
                "severity": "info",
                "title": "Embedded file references",
                "message": (
                    f"{embedded_file_markers} embedded-file "
                    "markers were identified."
                ),
            }
        )


    if launch_action_present:

        observations.append(
            {
                "severity": "warning",
                "title": "Launch action reference",
                "message": (
                    "A PDF Launch action marker was found."
                ),
            }
        )


    if open_action_present:

        observations.append(
            {
                "severity": "info",
                "title": "OpenAction present",
                "message": (
                    "The PDF contains an OpenAction reference."
                ),
            }
        )


    return {
        "format": "pdf",

        "status": "ok",

        "properties": {
            "pdf_version":
                version,

            "page_markers":
                page_markers,

            "object_count":
                object_count,

            "eof_markers":
                eof_count,

            "trailing_bytes_after_eof":
                trailing_bytes,

            "encrypted":
                encrypted,

            "linearized":
                linearized,

            "forms_present":
                form_present,

            "xfa_present":
                xfa_present,

            "javascript_markers":
                javascript_markers,

            "embedded_file_markers":
                embedded_file_markers,

            "open_action":
                open_action_present,

            "additional_actions":
                additional_action_present,

            "launch_action":
                launch_action_present,
        },

        "observations":
            observations,

        "embedded_objects": [],

        "limitations": [
            (
                "PDF structural analysis identifies "
                "markers and relationships without "
                "executing PDF content."
            ),
            (
                "Page-marker counts are structural "
                "estimates rather than rendered page counts."
            ),
        ],
    }