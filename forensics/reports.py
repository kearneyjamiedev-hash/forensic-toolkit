from __future__ import annotations

import csv
import html
import io
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# -----------------------------------------------------------------------------
# JSON
# -----------------------------------------------------------------------------

def build_json_report(
    evidence: dict,
    verification_history: list[dict],
) -> str:

    report = {
        "report": {
            "type":
                "digital_forensic_file_analysis",

            "evidence_id":
                evidence[
                    "evidence_id"
                ],

            "original_filename":
                evidence[
                    "original_filename"
                ],

            "original_sha256":
                evidence[
                    "original_sha256"
                ],

            "analysis_timestamp_utc":
                evidence[
                    "analysis_timestamp_utc"
                ],
        },

        "verification_history":
            verification_history,

        "analysis":
            evidence[
                "analysis"
            ],
    }


    return json.dumps(
        report,
        indent=2,
        ensure_ascii=False,
    )


# -----------------------------------------------------------------------------
# Timeline CSV
# -----------------------------------------------------------------------------

def build_timeline_csv(
    evidence: dict,
) -> str:

    analysis = (
        evidence.get(
            "analysis"
        )
        or {}
    )


    timeline = (
        analysis.get(
            "timeline"
        )
        or {}
    )


    events = (
        timeline.get(
            "events"
        )
        or []
    )


    output = io.StringIO()


    fieldnames = [
        "timestamp_utc",
        "timestamp_original",
        "timezone_known",
        "event_type",
        "label",
        "scope",
        "source",
        "source_group",
        "source_field",
        "notes",
    ]


    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )


    writer.writeheader()


    for event in events:

        writer.writerow(
            {
                "timestamp_utc":
                    event.get(
                        "timestamp_utc"
                    ),

                "timestamp_original":
                    event.get(
                        "timestamp_original"
                    ),

                "timezone_known":
                    event.get(
                        "timezone_known"
                    ),

                "event_type":
                    event.get(
                        "event_type"
                    ),

                "label":
                    event.get(
                        "label"
                    ),

                "scope":
                    event.get(
                        "scope"
                    ),

                "source":
                    event.get(
                        "source"
                    ),

                "source_group":
                    event.get(
                        "source_group"
                    ),

                "source_field":
                    event.get(
                        "source_field"
                    ),

                "notes":
                    " ".join(
                        event.get(
                            "notes"
                        )
                        or []
                    ),
            }
        )


    return output.getvalue()


# -----------------------------------------------------------------------------
# Artefacts CSV
# -----------------------------------------------------------------------------

def build_artefacts_csv(
    evidence: dict,
) -> str:

    analysis = (
        evidence.get(
            "analysis"
        )
        or {}
    )


    artefacts = (
        analysis.get(
            "artefacts"
        )
        or {}
    )


    categories = (
        artefacts.get(
            "categories"
        )
        or {}
    )


    output = io.StringIO()


    fieldnames = [
        "category",
        "value",
        "occurrences",
        "encodings",
        "offsets_hex",
    ]


    writer = csv.DictWriter(
        output,
        fieldnames=fieldnames,
    )


    writer.writeheader()


    for (
        category_name,
        category,
    ) in categories.items():

        for item in (
            category.get(
                "items"
            )
            or []
        ):

            writer.writerow(
                {
                    "category":
                        category_name,

                    "value":
                        item.get(
                            "value"
                        ),

                    "occurrences":
                        item.get(
                            "occurrences",
                            1,
                        ),

                    "encodings":
                        ", ".join(
                            item.get(
                                "encodings"
                            )
                            or []
                        ),

                    "offsets_hex":
                        ", ".join(
                            item.get(
                                "offsets_hex"
                            )
                            or []
                        ),
                }
            )


    return output.getvalue()


# -----------------------------------------------------------------------------
# HTML forensic report
# -----------------------------------------------------------------------------

def build_html_report(
    evidence: dict,
    verification_history: list[dict],
) -> str:

    analysis = (
        evidence.get(
            "analysis"
        )
        or {}
    )


    overview = (
        analysis.get(
            "overview"
        )
        or {}
    )


    hashes = (
        analysis.get(
            "hashes"
        )
        or {}
    )


    signature = (
        analysis.get(
            "signature"
        )
        or {}
    )


    filesystem = (
        analysis.get(
            "filesystem"
        )
        or {}
    )


    timeline = (
        analysis.get(
            "timeline"
        )
        or {}
    )


    artefacts = (
        analysis.get(
            "artefacts"
        )
        or {}
    )


    metadata = (
        analysis.get(
            "metadata"
        )
        or {}
    )


    format_analysis = (
        analysis.get(
            "format_analysis"
        )
        or {}
    )


    warnings = (
        analysis.get(
            "warnings"
        )
        or []
    )


    filesystem_note = (
        _filesystem_context_note(
            analysis,
            filesystem,
        )
    )


    return f"""<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    Forensic Analysis Report
</title>


<style>

:root {{
    --background: #f3f5f8;
    --surface: #ffffff;
    --surface-soft: #f8fafc;
    --border: #dce3ea;
    --text: #18212b;
    --muted: #657383;
    --accent: #4169e1;
    --success: #26734d;
    --warning: #966515;
}}


* {{
    box-sizing: border-box;
}}


body {{
    margin: 0;

    background:
        var(--background);

    color:
        var(--text);

    font-family:
        Inter,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}}


main {{
    width:
        min(
            1100px,
            94%
        );

    margin:
        40px auto 80px;
}}


.header {{
    margin-bottom:
        28px;
}}


.eyebrow {{
    color:
        var(--muted);

    text-transform:
        uppercase;

    letter-spacing:
        .06em;

    font-size:
        11px;

    font-weight:
        650;
}}


h1 {{
    margin:
        6px 0 8px;

    font-size:
        30px;
}}


.subtitle {{
    color:
        var(--muted);

    font-size:
        13px;
}}


.panel {{
    background:
        var(--surface);

    border:
        1px solid
        var(--border);

    border-radius:
        12px;

    padding:
        22px;

    margin-bottom:
        18px;
}}


h2 {{
    margin:
        0 0 16px;

    font-size:
        18px;
}}


h3 {{
    margin-top:
        18px;

    font-size:
        14px;
}}


.grid {{
    display:
        grid;

    grid-template-columns:
        repeat(
            auto-fit,
            minmax(
                220px,
                1fr
            )
        );

    gap:
        10px;
}}


.item {{
    background:
        var(--surface-soft);

    border:
        1px solid
        var(--border);

    border-radius:
        8px;

    padding:
        13px;
}}


.label {{
    display:
        block;

    color:
        var(--muted);

    text-transform:
        uppercase;

    letter-spacing:
        .04em;

    font-size:
        10px;

    margin-bottom:
        6px;
}}


.value {{
    font-size:
        13px;

    overflow-wrap:
        anywhere;
}}


.code {{
    font-family:
        ui-monospace,
        SFMono-Regular,
        Menlo,
        Consolas,
        monospace;
}}


table {{
    width:
        100%;

    border-collapse:
        collapse;

    font-size:
        12px;
}}


th,
td {{
    text-align:
        left;

    vertical-align:
        top;

    padding:
        10px;

    border-top:
        1px solid
        var(--border);
}}


th {{
    color:
        var(--muted);
}}


.warning {{
    padding:
        12px 14px;

    margin-bottom:
        10px;

    border-radius:
        8px;

    background:
        #fff8e8;

    color:
        var(--warning);
}}


.success {{
    color:
        var(--success);

    font-weight:
        650;
}}


.timeline-event {{
    border-left:
        2px solid
        var(--accent);

    padding:
        4px 0 18px 16px;
}}


.timeline-event:last-child {{
    padding-bottom:
        4px;
}}


.timeline-time {{
    font-size:
        12px;

    font-weight:
        650;
}}


.timeline-source {{
    color:
        var(--muted);

    margin-top:
        4px;

    font-size:
        11px;
}}


.metadata-group {{
    margin-top:
        16px;
}}


footer {{
    color:
        var(--muted);

    font-size:
        11px;

    margin-top:
        30px;
}}


@media print {{

    body {{
        background:
            white;
    }}


    main {{
        width:
            100%;

        margin:
            0;
    }}


    .panel {{
        break-inside:
            avoid;

        box-shadow:
            none;
    }}

}}

</style>

</head>


<body>

<main>


<div class="header">

    <div class="eyebrow">
        Digital Forensic Analysis
    </div>

    <h1>
        Forensic File Analysis Report
    </h1>

    <div class="subtitle">
        Evidence ID:
        {e(evidence.get("evidence_id"))}
    </div>

</div>


<section class="panel">

<h2>
    Evidence overview
</h2>

<div class="grid">

{report_item(
    "Filename",
    overview.get(
        "filename"
    ),
)}

{report_item(
    "Detected type",
    signature.get(
        "detected_type"
    ),
)}

{report_item(
    "MIME type",
    signature.get(
        "detected_mime"
    ),
)}

{report_item(
    "File size",
    _format_bytes(
        overview.get(
            "size_bytes"
        )
    ),
)}

{report_item(
    "Analysis timestamp",
    evidence.get(
        "analysis_timestamp_utc"
    ),
    code=True,
)}

{report_item(
    "Evidence ID",
    evidence.get(
        "evidence_id"
    ),
    code=True,
)}

</div>

</section>


<section class="panel">

<h2>
    Integrity
</h2>

{report_item(
    "Original SHA-256",
    evidence.get(
        "original_sha256"
    ),
    code=True,
)}

{report_item(
    "SHA-1",
    hashes.get(
        "sha1"
    ),
    code=True,
)}

{report_item(
    "MD5",
    hashes.get(
        "md5"
    ),
    code=True,
)}

<h3>
    Verification history
</h3>

{verification_table(
    verification_history
)}

</section>


<section class="panel">

<h2>
    File identification
</h2>

<div class="grid">

{report_item(
    "Filename extension",
    signature.get(
        "extension"
    ),
)}

{report_item(
    "Detected type",
    signature.get(
        "detected_type"
    ),
)}

{report_item(
    "Detected MIME",
    signature.get(
        "detected_mime"
    ),
)}

{report_item(
    "Extension MIME",
    signature.get(
        "extension_mime"
    ),
)}

{report_item(
    "Extension matches",
    signature.get(
        "extension_matches"
    ),
)}

</div>

</section>


{warnings_section(
    warnings
)}


<section class="panel">

<h2>
    Filesystem context
</h2>

<div class="grid">

{report_item(
    "Scope",
    filesystem.get(
        "scope"
    ),
)}

{report_item(
    "Created",
    filesystem.get(
        "created"
    ),
    code=True,
)}

{report_item(
    "Modified",
    filesystem.get(
        "modified"
    ),
    code=True,
)}

{report_item(
    "Accessed",
    filesystem.get(
        "accessed"
    ),
    code=True,
)}

{report_item(
    "Metadata changed",
    filesystem.get(
        "metadata_changed"
    ),
    code=True,
)}

</div>

<p class="subtitle">
    {e(filesystem_note)}
</p>

</section>


{format_analysis_html(
    format_analysis
)}


<section class="panel">

<h2>
    Forensic timeline
</h2>

{timeline_html(
    timeline
)}

</section>


<section class="panel">

<h2>
    Interesting artefacts
</h2>

<p class="subtitle">
    Artefacts are investigative leads and are not,
    by themselves, evidence of malicious activity.
</p>

{artefacts_html(
    artefacts
)}

</section>


<section class="panel">

<h2>
    Extracted metadata
</h2>

{metadata_html(
    metadata
)}

</section>


<section class="panel">

<h2>
    Interpretation limitations
</h2>

<ul>

    <li>
        Embedded metadata can be altered,
        removed or generated by software.
    </li>

    <li>
        Author or creator metadata does not
        independently prove human authorship.
    </li>

    <li>
        Filesystem timestamps may change
        because of copying,
        operating-system behaviour
        or deliberate manipulation.
    </li>

    <li>
        Evidence-copy filesystem timestamps
        do not necessarily represent timestamps
        from the original source filesystem.
    </li>

    <li>
        Extracted URLs, domains, addresses,
        paths and commands should be interpreted
        in context and are not automatically malicious.
    </li>

    <li>
        The analyzer performs static analysis
        and does not execute the analysed file.
    </li>

</ul>

</section>


<footer>

Generated by Digital Forensic File Analyzer.

The original SHA-256 stored at first analysis is
included above as the integrity baseline.

</footer>


</main>

</body>

</html>
"""


def report_item(
    label,
    value,
    code=False,
):

    class_name = (
        "value code"
        if code
        else "value"
    )


    return f"""
<div class="item">

    <span class="label">
        {e(label)}
    </span>

    <span class="{class_name}">
        {e(value)}
    </span>

</div>
"""


def verification_table(
    history,
):

    if not history:

        return """
<p class="subtitle">
    No integrity verification has been recorded.
</p>
"""


    rows = []


    for item in history:

        rows.append(
            f"""
<tr>

<td>
    {e(item.get("verified_at_utc"))}
</td>

<td>
    {e(item.get("selected_filename"))}
</td>

<td>
    {e(item.get("status"))}
</td>

<td class="code">
    {e(item.get("current_sha256"))}
</td>

</tr>
"""
        )


    return f"""
<table>

<thead>

<tr>
<th>Verified at</th>
<th>Selected file</th>
<th>Status</th>
<th>SHA-256</th>
</tr>

</thead>

<tbody>
{"".join(rows)}
</tbody>

</table>
"""


def warnings_section(
    warnings,
):

    if not warnings:

        return ""


    blocks = []


    for warning in warnings:

        blocks.append(
            f"""
<div class="warning">

<strong>
    {e(
        warning.get(
            "type"
        )
        or warning.get(
            "title"
        )
        or "Observation"
    )}
</strong>

<br>

{e(
    warning.get(
        "message"
    )
)}

</div>
"""
        )


    return f"""
<section class="panel">

<h2>
    Analysis observations
</h2>

{"".join(blocks)}

</section>
"""


def format_analysis_html(
    analysis,
):

    if not analysis:

        return ""


    if (
        analysis.get(
            "status"
        )
        == "not_applicable"
    ):

        return ""


    properties = (
        analysis.get(
            "properties"
        )
        or {}
    )


    observations = (
        analysis.get(
            "observations"
        )
        or []
    )


    embedded_objects = (
        analysis.get(
            "embedded_objects"
        )
        or []
    )


    parts = [
        '<section class="panel">',

        "<h2>"
        "Format-specific analysis"
        "</h2>",

        '<div class="grid">',

        report_item(
            "Format",
            analysis.get(
                "format"
            ),
        ),

        report_item(
            "Status",
            analysis.get(
                "status"
            ),
        ),

        "</div>",
    ]


    if properties:

        parts.append(
            "<h3>"
            "Properties"
            "</h3>"
            "<table>"
            "<tbody>"
        )


        for (
            name,
            value,
        ) in properties.items():

            parts.append(
                f"""
<tr>

<td>
    {e(
        _humanize(
            name
        )
    )}
</td>

<td class="code">
    {e(
        format_value(
            value
        )
    )}
</td>

</tr>
"""
            )


        parts.append(
            "</tbody>"
            "</table>"
        )


    if observations:

        parts.append(
            "<h3>"
            "Format observations"
            "</h3>"
        )


        for observation in observations:

            parts.append(
                f"""
<div class="warning">

<strong>
    {e(
        observation.get(
            "title"
        )
        or "Observation"
    )}
</strong>

<br>

{e(
    observation.get(
        "message"
    )
)}

</div>
"""
            )


    if embedded_objects:

        parts.append(
            "<h3>"
            "Internal objects"
            "</h3>"
            "<table>"
            "<tbody>"
        )


        for obj in embedded_objects:

            name = (
                obj.get(
                    "name"
                )
                or obj.get(
                    "type"
                )
                or "Object"
            )


            parts.append(
                f"""
<tr>

<td>
    {e(name)}
</td>

<td class="code">
    {e(
        json.dumps(
            obj,
            ensure_ascii=False,
        )
    )}
</td>

</tr>
"""
            )


        parts.append(
            "</tbody>"
            "</table>"
        )


    parts.append(
        "</section>"
    )


    return "".join(
        parts
    )


def timeline_html(
    timeline,
):

    events = (
        timeline.get(
            "events"
        )
        or []
    )


    observations = (
        timeline.get(
            "observations"
        )
        or []
    )


    parts = []


    for observation in observations:

        parts.append(
            f"""
<div class="warning">

<strong>
    {e(
        observation.get(
            "title"
        )
    )}
</strong>

<br>

{e(
    observation.get(
        "message"
    )
)}

</div>
"""
        )


    if not events:

        parts.append(
            """
<p class="subtitle">
    No recognised forensic timestamps were found.
</p>
"""
        )


    for event in events:

        timestamp = (
            event.get(
                "timestamp_utc"
            )
            or event.get(
                "timestamp_original"
            )
        )


        parts.append(
            f"""
<div class="timeline-event">

<div class="timeline-time code">
    {e(timestamp)}
</div>

<strong>
    {e(
        event.get(
            "label"
        )
    )}
</strong>

<div class="timeline-source">

    {e(
        event.get(
            "source_group"
        )
    )}:

    {e(
        event.get(
            "source_field"
        )
    )}

    —

    {e(
        event.get(
            "scope"
        )
    )}

</div>

</div>
"""
        )


    return "".join(
        parts
    )


def artefacts_html(
    artefacts,
):

    categories = (
        artefacts.get(
            "categories"
        )
        or {}
    )


    sections = []


    for category in categories.values():

        items = (
            category.get(
                "items"
            )
            or []
        )


        if not items:

            continue


        rows = []


        for item in items:

            rows.append(
                f"""
<tr>

<td class="code">
    {e(
        item.get(
            "value"
        )
    )}
</td>

<td>
    {e(
        item.get(
            "occurrences"
        )
    )}
</td>

<td class="code">
    {e(
        ", ".join(
            item.get(
                "offsets_hex"
            )
            or []
        )
    )}
</td>

</tr>
"""
            )


        sections.append(
            f"""
<div class="metadata-group">

<h3>

    {e(
        category.get(
            "label"
        )
    )}

    ({len(items)})

</h3>


<table>

<thead>

<tr>
<th>Value</th>
<th>Occurrences</th>
<th>Offsets</th>
</tr>

</thead>

<tbody>

{"".join(rows)}

</tbody>

</table>

</div>
"""
        )


    if not sections:

        return """
<p class="subtitle">
    No interesting artefacts were identified.
</p>
"""


    return "".join(
        sections
    )


def metadata_html(
    metadata,
):

    if (
        metadata.get(
            "status"
        )
        != "ok"
    ):

        return f"""
<div class="warning">

{e(
    metadata.get(
        "error"
    )
    or "Metadata extraction failed."
)}

</div>
"""


    categories = (
        metadata.get(
            "categories"
        )
        or {}
    )


    sections = []


    for (
        category_name,
        fields,
    ) in categories.items():

        if not fields:

            continue


        rows = []


        for field in fields:

            rows.append(
                f"""
<tr>

<td>

    {e(
        field.get(
            "group"
        )
    )}:

    {e(
        field.get(
            "name"
        )
    )}

</td>

<td class="code">

    {e(
        format_value(
            field.get(
                "value"
            )
        )
    )}

</td>

</tr>
"""
            )


        sections.append(
            f"""
<div class="metadata-group">

<h3>
    {e(
        _humanize(
            category_name
        )
    )}
</h3>

<table>

<tbody>
{"".join(rows)}
</tbody>

</table>

</div>
"""
        )


    if not sections:

        return """
<p class="subtitle">
    No metadata was extracted.
</p>
"""


    return "".join(
        sections
    )


def format_value(
    value,
):

    if isinstance(
        value,
        (
            dict,
            list,
            tuple,
        ),
    ):

        return json.dumps(
            value,
            ensure_ascii=False,
        )


    return value


def e(
    value,
):

    if value is None:

        return "Unavailable"


    return html.escape(
        str(
            value
        )
    )


# -----------------------------------------------------------------------------
# PDF forensic report
# -----------------------------------------------------------------------------

def build_pdf_report(
    evidence: dict,
    verification_history: list[dict],
) -> bytes:

    analysis = (
        evidence.get(
            "analysis"
        )
        or {}
    )


    # -------------------------------------------------------------------------
    # Determine whether this evidence came through Logical Acquisition.
    #
    # This matters because filesystem timestamps generated while analysing the
    # working copy are not the original source filesystem timestamps.
    # -------------------------------------------------------------------------

    acquisition = (
        analysis.get(
            "acquisition"
        )
        or {}
    )


    evidence_info = (
        analysis.get(
            "evidence"
        )
        or {}
    )


    is_logical_acquisition = (
        evidence_info.get(
            "mode"
        )
        == "logical_acquisition"
    )


    overview = (
        analysis.get(
            "overview"
        )
        or {}
    )


    hashes = (
        analysis.get(
            "hashes"
        )
        or {}
    )


    signature = (
        analysis.get(
            "signature"
        )
        or {}
    )


    filesystem = (
        analysis.get(
            "filesystem"
        )
        or {}
    )


    timeline = (
        analysis.get(
            "timeline"
        )
        or {}
    )


    artefacts = (
        analysis.get(
            "artefacts"
        )
        or {}
    )


    metadata = (
        analysis.get(
            "metadata"
        )
        or {}
    )


    format_analysis = (
        analysis.get(
            "format_analysis"
        )
        or {}
    )


    warnings = (
        analysis.get(
            "warnings"
        )
        or []
    )


    # Retained for the forthcoming dedicated acquisition report.
    _ = acquisition


    buffer = io.BytesIO()


    document = SimpleDocTemplate(
        buffer,

        pagesize=A4,

        rightMargin=
            16 * mm,

        leftMargin=
            16 * mm,

        topMargin=
            18 * mm,

        bottomMargin=
            18 * mm,

        title=
            "Forensic File Analysis Report",

        author=
            "Digital Forensic File Analyzer",
    )


    # -------------------------------------------------------------------------
    # Styles
    # -------------------------------------------------------------------------

    base_styles = (
        getSampleStyleSheet()
    )


    body_style = ParagraphStyle(
        "ReportBody",

        parent=
            base_styles[
                "BodyText"
            ],

        fontName=
            "Helvetica",

        fontSize=
            9,

        leading=
            12,

        textColor=
            colors.HexColor(
                "#273142"
            ),

        spaceAfter=
            5,
    )


    small_style = ParagraphStyle(
        "ReportSmall",

        parent=
            body_style,

        fontSize=
            7.5,

        leading=
            10,

        textColor=
            colors.HexColor(
                "#667085"
            ),
    )


    title_style = ParagraphStyle(
        "ReportTitle",

        parent=
            base_styles[
                "Title"
            ],

        fontName=
            "Helvetica-Bold",

        fontSize=
            21,

        leading=
            25,

        textColor=
            colors.HexColor(
                "#0F1C2E"
            ),

        alignment=
            TA_LEFT,

        spaceAfter=
            6,
    )


    eyebrow_style = ParagraphStyle(
        "ReportEyebrow",

        parent=
            small_style,

        fontName=
            "Helvetica-Bold",

        fontSize=
            7,

        leading=
            9,

        textColor=
            colors.HexColor(
                "#4169E1"
            ),

        spaceAfter=
            4,
    )


    section_style = ParagraphStyle(
        "ReportSection",

        parent=
            base_styles[
                "Heading2"
            ],

        fontName=
            "Helvetica-Bold",

        fontSize=
            12,

        leading=
            15,

        textColor=
            colors.HexColor(
                "#172033"
            ),

        spaceBefore=
            10,

        spaceAfter=
            7,
    )


    subsection_style = ParagraphStyle(
        "ReportSubsection",

        parent=
            base_styles[
                "Heading3"
            ],

        fontName=
            "Helvetica-Bold",

        fontSize=
            9.5,

        leading=
            12,

        textColor=
            colors.HexColor(
                "#344054"
            ),

        spaceBefore=
            8,

        spaceAfter=
            5,
    )


    code_style = ParagraphStyle(
        "ReportCode",

        parent=
            small_style,

        fontName=
            "Courier",

        fontSize=
            7,

        leading=
            9,

        textColor=
            colors.HexColor(
                "#1D2939"
            ),

        wordWrap=
            "CJK",
    )


    header_cell_style = ParagraphStyle(
        "ReportHeaderCell",

        parent=
            body_style,

        fontName=
            "Helvetica-Bold",

        fontSize=
            7.5,

        textColor=
            colors.HexColor(
                "#344054"
            ),
    )


    story = []


    # -------------------------------------------------------------------------
    # Local helpers
    # -------------------------------------------------------------------------

    def add_section(
        title: str,
    ):

        story.append(
            Paragraph(
                _pdf_safe(
                    title
                ),
                section_style,
            )
        )


    def add_table(
        rows: list,
        widths=None,
        header: bool = False,
    ):

        if not rows:

            return


        converted_rows = []


        for (
            row_index,
            row,
        ) in enumerate(
            rows
        ):

            converted_cells = []


            for cell in row:

                if (
                    header
                    and row_index == 0
                ):

                    style = (
                        header_cell_style
                    )


                elif _pdf_looks_like_code(
                    cell
                ):

                    style = (
                        code_style
                    )


                else:

                    style = (
                        body_style
                    )


                converted_cells.append(
                    _pdf_paragraph(
                        cell,
                        style,
                    )
                )


            converted_rows.append(
                converted_cells
            )


        table = Table(
            converted_rows,

            colWidths=
                widths,

            repeatRows=
                (
                    1
                    if header
                    else 0
                ),

            hAlign=
                "LEFT",
        )


        commands = [
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.35,
                colors.HexColor(
                    "#D8DEE8"
                ),
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                5,
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5,
            ),
        ]


        if header:

            commands.insert(
                0,
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#F5F7FA"
                    ),
                ),
            )


        table.setStyle(
            TableStyle(
                commands
            )
        )


        story.append(
            table
        )


        story.append(
            Spacer(
                1,
                3 * mm,
            )
        )


    # -------------------------------------------------------------------------
    # Header
    # -------------------------------------------------------------------------

    story.append(
        Paragraph(
            (
                "DIGITAL FORENSIC "
                "ANALYSIS"
            ),
            eyebrow_style,
        )
    )


    story.append(
        Paragraph(
            (
                "Forensic File "
                "Analysis Report"
            ),
            title_style,
        )
    )


    story.append(
        Paragraph(
            (
                "Evidence ID: "
                f"{_pdf_safe(evidence.get('evidence_id'))}"
                "<br/>"
                "Analysis timestamp: "
                f"{_pdf_safe(evidence.get('analysis_timestamp_utc'))}"
            ),
            small_style,
        )
    )


    story.append(
        Spacer(
            1,
            5 * mm,
        )
    )


    # -------------------------------------------------------------------------
    # Evidence overview
    # -------------------------------------------------------------------------

    add_section(
        "Evidence overview"
    )


    add_table(
        [
            [
                "Filename",
                overview.get(
                    "filename"
                ),
            ],

            [
                "Detected type",
                signature.get(
                    "detected_type"
                ),
            ],

            [
                "MIME type",
                signature.get(
                    "detected_mime"
                ),
            ],

            [
                "File size",
                _pdf_format_bytes(
                    overview.get(
                        "size_bytes"
                    )
                ),
            ],

            [
                "Evidence ID",
                evidence.get(
                    "evidence_id"
                ),
            ],
        ],

        widths=[
            45 * mm,

            document.width
            - 45 * mm,
        ],
    )


    # -------------------------------------------------------------------------
    # Integrity
    # -------------------------------------------------------------------------

    add_section(
        "Integrity"
    )


    add_table(
        [
            [
                "Original SHA-256",
                evidence.get(
                    "original_sha256"
                ),
            ],

            [
                "SHA-1",
                hashes.get(
                    "sha1"
                ),
            ],

            [
                "MD5",
                hashes.get(
                    "md5"
                ),
            ],
        ],

        widths=[
            45 * mm,

            document.width
            - 45 * mm,
        ],
    )


    story.append(
        Paragraph(
            "Verification history",
            subsection_style,
        )
    )


    if verification_history:

        verification_rows = [
            [
                "Verified at",
                "File",
                "Status",
                "Current SHA-256",
            ]
        ]


        for item in verification_history:

            verification_rows.append(
                [
                    item.get(
                        "verified_at_utc"
                    ),

                    item.get(
                        "selected_filename"
                    ),

                    item.get(
                        "status"
                    ),

                    item.get(
                        "current_sha256"
                    ),
                ]
            )


        add_table(
            verification_rows,

            widths=[
                35 * mm,
                35 * mm,
                22 * mm,

                document.width
                - 92 * mm,
            ],

            header=True,
        )


    else:

        story.append(
            Paragraph(
                (
                    "No integrity verification "
                    "has been recorded."
                ),
                small_style,
            )
        )


    # -------------------------------------------------------------------------
    # File identification
    # -------------------------------------------------------------------------

    add_section(
        "File identification"
    )


    add_table(
        [
            [
                "Extension",
                signature.get(
                    "extension"
                ),
            ],

            [
                "Detected type",
                signature.get(
                    "detected_type"
                ),
            ],

            [
                "Detected MIME",
                signature.get(
                    "detected_mime"
                ),
            ],

            [
                "Extension MIME",
                signature.get(
                    "extension_mime"
                ),
            ],

            [
                "Extension matches",
                signature.get(
                    "extension_matches"
                ),
            ],
        ],

        widths=[
            45 * mm,

            document.width
            - 45 * mm,
        ],
    )


    # -------------------------------------------------------------------------
    # Analysis observations
    # -------------------------------------------------------------------------

    if warnings:

        add_section(
            "Analysis observations"
        )


        for warning in warnings:

            story.append(
                Paragraph(
                    (
                        "<b>"
                        + _pdf_safe(
                            warning.get(
                                "type"
                            )
                            or warning.get(
                                "title"
                            )
                            or "Observation"
                        )
                        + "</b>"
                        + "<br/>"
                        + _pdf_safe(
                            warning.get(
                                "message"
                            )
                        )
                    ),
                    body_style,
                )
            )


            story.append(
                Spacer(
                    1,
                    2 * mm,
                )
            )


    # -------------------------------------------------------------------------
    # Filesystem
    # -------------------------------------------------------------------------

    add_section(
        "Filesystem context"
    )


    add_table(
        [
            [
                "Scope",
                filesystem.get(
                    "scope"
                ),
            ],

            [
                "Created",
                filesystem.get(
                    "created"
                ),
            ],

            [
                "Modified",
                filesystem.get(
                    "modified"
                ),
            ],

            [
                "Accessed",
                filesystem.get(
                    "accessed"
                ),
            ],

            [
                "Metadata changed",
                filesystem.get(
                    "metadata_changed"
                ),
            ],
        ],

        widths=[
            45 * mm,

            document.width
            - 45 * mm,
        ],
    )


    if is_logical_acquisition:

        story.append(
            Paragraph(
                (
                    "These timestamps describe the "
                    "analyzer working copy. Original "
                    "source filesystem timestamps were "
                    "captured separately during logical "
                    "acquisition."
                ),
                small_style,
            )
        )


    elif filesystem.get(
        "warning"
    ):

        story.append(
            Paragraph(
                _pdf_safe(
                    filesystem.get(
                        "warning"
                    )
                ),
                small_style,
            )
        )


    # -------------------------------------------------------------------------
    # Format-specific analysis
    # -------------------------------------------------------------------------

    if (
        format_analysis
        and format_analysis.get(
            "status"
        )
        != "not_applicable"
    ):

        add_section(
            "Format-specific analysis"
        )


        format_name = (
            format_analysis.get(
                "format"
            )
            or "Unknown"
        )


        story.append(
            Paragraph(
                (
                    "Format: <b>"
                    + _pdf_safe(
                        format_name.upper()
                    )
                    + "</b>"
                    + " &nbsp;&nbsp; "
                    + "Status: <b>"
                    + _pdf_safe(
                        format_analysis.get(
                            "status"
                        )
                    )
                    + "</b>"
                ),
                body_style,
            )
        )


        properties = (
            format_analysis.get(
                "properties"
            )
            or {}
        )


        if properties:

            add_table(
                [
                    [
                        _pdf_humanize(
                            name
                        ),

                        _pdf_format_value(
                            value
                        ),
                    ]

                    for (
                        name,
                        value,
                    ) in properties.items()
                ],

                widths=[
                    55 * mm,

                    document.width
                    - 55 * mm,
                ],
            )


        format_observations = (
            format_analysis.get(
                "observations"
            )
            or []
        )


        if format_observations:

            story.append(
                Paragraph(
                    "Format observations",
                    subsection_style,
                )
            )


            for observation in (
                format_observations
            ):

                story.append(
                    Paragraph(
                        (
                            "<b>"
                            + _pdf_safe(
                                observation.get(
                                    "title"
                                )
                                or "Observation"
                            )
                            + "</b>"
                            + "<br/>"
                            + _pdf_safe(
                                observation.get(
                                    "message"
                                )
                            )
                        ),
                        body_style,
                    )
                )


        embedded_objects = (
            format_analysis.get(
                "embedded_objects"
            )
            or []
        )


        if embedded_objects:

            story.append(
                Paragraph(
                    "Internal objects",
                    subsection_style,
                )
            )


            object_rows = [
                [
                    "Object",
                    "Details",
                ]
            ]


            for obj in embedded_objects:

                object_rows.append(
                    [
                        (
                            obj.get(
                                "name"
                            )
                            or obj.get(
                                "type"
                            )
                            or "Object"
                        ),

                        json.dumps(
                            obj,
                            ensure_ascii=False,
                        ),
                    ]
                )


            add_table(
                object_rows,

                widths=[
                    55 * mm,

                    document.width
                    - 55 * mm,
                ],

                header=True,
            )


    # -------------------------------------------------------------------------
    # Timeline
    # -------------------------------------------------------------------------

    add_section(
        "Forensic timeline"
    )


    timeline_observations = (
        timeline.get(
            "observations"
        )
        or []
    )


    for observation in (
        timeline_observations
    ):

        story.append(
            Paragraph(
                (
                    "<b>"
                    + _pdf_safe(
                        observation.get(
                            "title"
                        )
                        or (
                            "Timeline "
                            "observation"
                        )
                    )
                    + "</b>"
                    + "<br/>"
                    + _pdf_safe(
                        observation.get(
                            "message"
                        )
                    )
                ),
                body_style,
            )
        )


    events = (
        timeline.get(
            "events"
        )
        or []
    )


    if events:

        timeline_rows = [
            [
                "Timestamp",
                "Event",
                "Source",
                "Scope",
            ]
        ]


        for event in events:

            timeline_rows.append(
                [
                    (
                        event.get(
                            "timestamp_utc"
                        )
                        or event.get(
                            "timestamp_original"
                        )
                    ),

                    (
                        event.get(
                            "label"
                        )
                        or event.get(
                            "event_type"
                        )
                    ),

                    (
                        f"{event.get('source_group') or event.get('source') or 'Unknown'}:"
                        f"{event.get('source_field') or 'unknown'}"
                    ),

                    event.get(
                        "scope"
                    ),
                ]
            )


        add_table(
            timeline_rows,

            widths=[
                41 * mm,
                46 * mm,
                55 * mm,

                document.width
                - 142 * mm,
            ],

            header=True,
        )


    else:

        story.append(
            Paragraph(
                (
                    "No recognised forensic "
                    "timestamps were found."
                ),
                small_style,
            )
        )


    # -------------------------------------------------------------------------
    # Artefacts
    # -------------------------------------------------------------------------

    add_section(
        "Interesting artefacts"
    )


    categories = (
        artefacts.get(
            "categories"
        )
        or {}
    )


    populated = [
        (
            name,
            category,
        )

        for (
            name,
            category,
        ) in categories.items()

        if category.get(
            "items"
        )
    ]


    if not populated:

        story.append(
            Paragraph(
                (
                    "No interesting artefacts "
                    "were identified."
                ),
                small_style,
            )
        )


    else:

        for (
            _,
            category,
        ) in populated:

            items = (
                category.get(
                    "items"
                )
                or []
            )


            story.append(
                Paragraph(
                    (
                        _pdf_safe(
                            category.get(
                                "label"
                            )
                            or "Artefacts"
                        )
                        + f" ({len(items)})"
                    ),
                    subsection_style,
                )
            )


            artefact_rows = [
                [
                    "Value",
                    "Occurrences",
                    "Offsets",
                ]
            ]


            for item in items:

                artefact_rows.append(
                    [
                        item.get(
                            "value"
                        ),

                        item.get(
                            "occurrences",
                            1,
                        ),

                        ", ".join(
                            item.get(
                                "offsets_hex"
                            )
                            or []
                        ),
                    ]
                )


            add_table(
                artefact_rows,

                widths=[
                    document.width
                    - 55 * mm,

                    22 * mm,

                    33 * mm,
                ],

                header=True,
            )


    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------

    add_section(
        "Extracted metadata"
    )


    if (
        metadata.get(
            "status"
        )
        != "ok"
    ):

        story.append(
            Paragraph(
                _pdf_safe(
                    metadata.get(
                        "error"
                    )
                    or (
                        "Metadata extraction "
                        "failed."
                    )
                ),
                body_style,
            )
        )


    else:

        metadata_categories = (
            metadata.get(
                "categories"
            )
            or {}
        )


        if not metadata_categories:

            story.append(
                Paragraph(
                    (
                        "No metadata was "
                        "extracted."
                    ),
                    small_style,
                )
            )


        else:

            for (
                category_name,
                fields,
            ) in metadata_categories.items():

                if not fields:

                    continue


                story.append(
                    Paragraph(
                        _pdf_safe(
                            _pdf_humanize(
                                category_name
                            )
                        ),
                        subsection_style,
                    )
                )


                metadata_rows = [
                    [
                        "Field",
                        "Value",
                    ]
                ]


                for field in fields:

                    metadata_rows.append(
                        [
                            (
                                f"{field.get('group')}:"
                                f"{field.get('name')}"
                            ),

                            _pdf_format_value(
                                field.get(
                                    "value"
                                )
                            ),
                        ]
                    )


                add_table(
                    metadata_rows,

                    widths=[
                        58 * mm,

                        document.width
                        - 58 * mm,
                    ],

                    header=True,
                )


    # -------------------------------------------------------------------------
    # Interpretation limitations
    # -------------------------------------------------------------------------

    add_section(
        "Interpretation limitations"
    )


    limitations = [
        (
            "Embedded metadata can be altered, "
            "removed or generated by software."
        ),

        (
            "Author or creator metadata does not "
            "independently prove human authorship."
        ),

        (
            "Filesystem timestamps may change "
            "because of copying, operating-system "
            "behaviour or deliberate manipulation."
        ),

        (
            "Evidence-copy filesystem timestamps "
            "do not necessarily represent the "
            "original source filesystem."
        ),

        (
            "Extracted URLs, domains, addresses, "
            "paths and command strings are "
            "investigative leads and are not "
            "automatically malicious."
        ),

        (
            "The analyzer performs static analysis "
            "and does not execute the analysed file."
        ),
    ]


    for limitation in limitations:

        story.append(
            Paragraph(
                (
                    "• "
                    + _pdf_safe(
                        limitation
                    )
                ),
                body_style,
            )
        )


    # -------------------------------------------------------------------------
    # Build PDF
    # -------------------------------------------------------------------------

    document.build(
        story,

        onFirstPage=
            _draw_pdf_footer,

        onLaterPages=
            _draw_pdf_footer,
    )


    return (
        buffer.getvalue()
    )


# -----------------------------------------------------------------------------
# Shared reporting helpers
# -----------------------------------------------------------------------------

def _filesystem_context_note(
    analysis: dict,
    filesystem: dict,
) -> str | None:

    evidence_info = (
        analysis.get(
            "evidence"
        )
        or {}
    )


    if (
        evidence_info.get(
            "mode"
        )
        == "logical_acquisition"
    ):

        return (
            "These timestamps describe the analyzer "
            "working copy. Original source filesystem "
            "timestamps were captured separately "
            "during logical acquisition."
        )


    return filesystem.get(
        "warning"
    )


def _humanize(
    value,
) -> str:

    if not value:

        return "Other"


    return (
        str(
            value
        )
        .replace(
            "_",
            " ",
        )
        .title()
    )


def _format_bytes(
    value,
) -> str:

    if value is None:

        return "Unavailable"


    try:

        size = float(
            value
        )


    except (
        TypeError,
        ValueError,
    ):

        return str(
            value
        )


    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]


    index = 0


    while (
        size >= 1024
        and index
        < len(units) - 1
    ):

        size /= 1024

        index += 1


    return (
        f"{size:.2f} "
        f"{units[index]}"
    )


# -----------------------------------------------------------------------------
# PDF helpers
# -----------------------------------------------------------------------------

def _draw_pdf_footer(
    canvas,
    document,
):

    canvas.saveState()


    page_width, _ = A4


    canvas.setStrokeColor(
        colors.HexColor(
            "#D8DEE8"
        )
    )


    canvas.setLineWidth(
        0.5
    )


    canvas.line(
        16 * mm,
        13 * mm,

        page_width
        - 16 * mm,

        13 * mm,
    )


    canvas.setFont(
        "Helvetica",
        7,
    )


    canvas.setFillColor(
        colors.HexColor(
            "#667085"
        )
    )


    canvas.drawString(
        16 * mm,
        8.5 * mm,

        (
            "Digital Forensic "
            "File Analyzer"
        ),
    )


    canvas.drawRightString(
        page_width
        - 16 * mm,

        8.5 * mm,

        f"Page {document.page}",
    )


    canvas.restoreState()


def _pdf_paragraph(
    value,
    style,
):

    text = (
        _pdf_safe(
            value
        )
        .replace(
            "\n",
            "<br/>",
        )
    )


    return Paragraph(
        text,
        style,
    )


def _pdf_safe(
    value,
):

    if value is None:

        return "Unavailable"


    text = (
        str(
            value
        )
        .replace(
            "—",
            "-",
        )
        .replace(
            "–",
            "-",
        )
    )


    return html.escape(
        text
    )


def _pdf_humanize(
    value,
):

    return _humanize(
        value
    )


def _pdf_format_value(
    value,
):

    if value is None:

        return "Unavailable"


    if isinstance(
        value,
        (
            dict,
            list,
            tuple,
        ),
    ):

        return json.dumps(
            value,
            ensure_ascii=False,
        )


    return str(
        value
    )


def _pdf_format_bytes(
    value,
):

    return _format_bytes(
        value
    )


def _pdf_looks_like_code(
    value,
):

    if value is None:

        return False


    text = str(
        value
    )


    if (
        len(
            text
        )
        >= 32
        and " " not in text
    ):

        return True


    return any(
        token in text.lower()

        for token in (
            "sha-256",
            "sha256",
            "0x",
        )
    )