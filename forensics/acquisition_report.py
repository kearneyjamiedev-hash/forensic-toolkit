from __future__ import annotations



import html

import io

import json



from reportlab.lib import colors

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





def build_acquisition_pdf(
    manifest: dict,
) -> bytes:

    if not manifest:
        raise ValueError(
            "Acquisition manifest is unavailable."
        )

    acquisition = (
        manifest.get(
            "acquisition"
        )
        or {}
    )

    source = (
        manifest.get(
            "source"
        )
        or {}
    )

    source_before = (
        source.get(
            "before_acquisition"
        )
        or {}
    )

    source_after = (
        source.get(
            "after_acquisition"
        )
        or {}
    )

    changes = (
        source.get(
            "observable_metadata_changes"
        )
        or []
    )

    integrity = (
        manifest.get(
            "integrity"
        )
        or {}
    )

    storage = (
        manifest.get(
            "storage"
        )
        or {}
    )


    buffer = io.BytesIO()





    document = SimpleDocTemplate(

        buffer,



        pagesize=A4,



        leftMargin=

            16 * mm,



        rightMargin=

            16 * mm,



        topMargin=

            18 * mm,



        bottomMargin=

            18 * mm,



        title=(

            "Logical Evidence Acquisition Report"

        ),



        author=(

            "Digital Forensic File Analyzer"

        ),

    )





    styles = (

        getSampleStyleSheet()

    )





    title_style = ParagraphStyle(

        "AcquisitionTitle",



        parent=

            styles["Title"],



        fontName=

            "Helvetica-Bold",



        fontSize=20,



        leading=24,



        textColor=

            colors.HexColor(

                "#0F1C2E"

            ),



        spaceAfter=7,

    )





    section_style = ParagraphStyle(

        "AcquisitionSection",



        parent=

            styles["Heading2"],



        fontName=

            "Helvetica-Bold",



        fontSize=12,



        leading=15,



        textColor=

            colors.HexColor(

                "#172033"

            ),



        spaceBefore=10,



        spaceAfter=7,

    )





    body_style = ParagraphStyle(

        "AcquisitionBody",



        parent=

            styles["BodyText"],



        fontName=

            "Helvetica",



        fontSize=9,



        leading=12,



        textColor=

            colors.HexColor(

                "#273142"

            ),

    )





    code_style = ParagraphStyle(

        "AcquisitionCode",



        parent=body_style,



        fontName=

            "Courier",



        fontSize=7,



        leading=9,



        wordWrap="CJK",

    )





    small_style = ParagraphStyle(

        "AcquisitionSmall",



        parent=body_style,



        fontSize=7.5,



        leading=10,



        textColor=

            colors.HexColor(

                "#667085"

            ),

    )





    eyebrow_style = ParagraphStyle(

        "AcquisitionEyebrow",



        parent=small_style,



        fontName=

            "Helvetica-Bold",



        fontSize=7,



        textColor=

            colors.HexColor(

                "#4169E1"

            ),

    )





    story = []





    def safe(

        value,

    ) -> str:



        if value is None:



            return "Unavailable"





        return html.escape(

            str(

                value

            )

            .replace(

                "—",

                "-"

            )

            .replace(

                "–",

                "-"

            )

        )





    def bool_text(

        value,

    ) -> str:



        if value is True:



            return "YES"





        if value is False:



            return "NO"





        return "Unavailable"





    def add_section(

        title: str,

    ) -> None:



        story.append(

            Paragraph(

                safe(

                    title

                ),

                section_style,

            )

        )





    def add_table(

        rows: list,

    ) -> None:



        converted = []





        for row in rows:



            converted.append(

                [

                    Paragraph(

                        safe(

                            row[0]

                        ),

                        body_style,

                    ),



                    Paragraph(

                        safe(

                            row[1]

                        ),

                        (

                            code_style

                            if _looks_like_code(

                                row[1]

                            )

                            else body_style

                        ),

                    ),

                ]

            )





        table = Table(

            converted,



            colWidths=[

                52 * mm,



                document.width

                - 52 * mm,

            ],



            hAlign="LEFT",

        )





        table.setStyle(

            TableStyle(

                [

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

                        "BACKGROUND",

                        (0, 0),

                        (0, -1),

                        colors.HexColor(

                            "#F5F7FA"

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





    story.append(

        Paragraph(

            "DIGITAL FORENSIC ANALYSIS",

            eyebrow_style,

        )

    )





    story.append(

        Paragraph(

            (

                "Logical Evidence "

                "Acquisition Report"

            ),

            title_style,

        )

    )





    story.append(

        Paragraph(

            (

                "This report documents the logical "

                "collection and preservation of an "

                "individual source file."

            ),

            small_style,

        )

    )





    add_section(

        "Case and evidence"

    )





    add_table(

        [

            [

                "Evidence ID",

                manifest.get(

                    "evidence_id"

                ),

            ],



            [

                "Case / reference",

                manifest.get(

                    "case_reference"

                ),

            ],



            [

                "Evidence description",

                manifest.get(

                    "evidence_description"

                ),

            ],



            [

                "Collector / analyst",

                manifest.get(

                    "collector_name"

                ),

            ],

        ]

    )





    add_section(

        "Acquisition details"

    )





    add_table(

        [

            [

                "Acquisition type",

                acquisition.get(

                    "type"

                ),

            ],



            [

                "Started",

                acquisition.get(

                    "started_at_utc"

                ),

            ],



            [

                "Completed",

                acquisition.get(

                    "completed_at_utc"

                ),

            ],



            [

                "Tool",

                acquisition.get(

                    "tool"

                ),

            ],



            [

                "Tool version",

                acquisition.get(

                    "tool_version"

                ),

            ],



            [

                "Acquisition host",

                acquisition.get(

                    "host"

                ),

            ],



            [

                "Process user",

                acquisition.get(

                    "process_user"

                ),

            ],



            [

                "Write blocker used",

                bool_text(

                    acquisition.get(

                        "write_blocker_used"

                    )

                ),

            ],



            [

                "Protection note",

                acquisition.get(

                    "protection_note"

                ),

            ],

        ]

    )





    add_section(

        "Original source filesystem"

    )





    add_table(

        [

            [

                "Original path",

                source_before.get(

                    "path"

                ),

            ],



            [

                "Filename",

                source_before.get(

                    "filename"

                ),

            ],



            [

                "Size",

                (

                    f"{source_before.get('size_bytes')} bytes"

                    if source_before.get(

                        "size_bytes"

                    )

                    is not None

                    else None

                ),

            ],



            [

                "Created",

                source_before.get(

                    "created"

                ),

            ],



            [

                "Modified",

                source_before.get(

                    "modified"

                ),

            ],



            [

                "Accessed",

                source_before.get(

                    "accessed"

                ),

            ],



            [

                "Metadata changed",

                source_before.get(

                    "metadata_changed"

                ),

            ],



            [

                "Creation basis",

                source_before.get(

                    "created_basis"

                ),

            ],



            [

                "File ID",

                source_before.get(

                    "file_id"

                ),

            ],



            [

                "Device ID",

                source_before.get(

                    "device_id"

                ),

            ],



            [

                "Platform",

                source_before.get(

                    "platform"

                ),

            ],

        ]

    )





    add_section(

        "Evidence integrity"

    )





    add_table(

        [

            [

                (

                    "Source SHA-256 "

                    "during acquisition"

                ),

                integrity.get(

                    "source_sha256_during_copy"

                ),

            ],



            [

                "Source SHA-256 after",

                integrity.get(

                    "source_sha256_after"

                ),

            ],



            [

                "Master evidence SHA-256",

                integrity.get(

                    "master_sha256"

                ),

            ],



            [

                "Working copy SHA-256",

                integrity.get(

                    "working_sha256"

                ),

            ],



            [

                "Source content unchanged",

                bool_text(

                    integrity.get(

                        "source_content_unchanged"

                    )

                ),

            ],



            [

                "Master verified",

                bool_text(

                    integrity.get(

                        "master_verified"

                    )

                ),

            ],



            [

                "Working copy verified",

                bool_text(

                    integrity.get(

                        "working_verified"

                    )

                ),

            ],

        ]

    )





    add_section(

        "Observed source changes"

    )





    if not changes:



        story.append(

            Paragraph(

                (

                    "No observable source filesystem "

                    "metadata changes were detected "

                    "during logical acquisition."

                ),

                body_style,

            )

        )





    else:



        rows = []





        for change in changes:



            rows.append(

                [

                    change.get(

                        "field"

                    ),



                    (

                        f"Before: "

                        f"{change.get('before')} "

                        f"| After: "

                        f"{change.get('after')}"

                    ),

                ]

            )





        add_table(

            rows

        )





    add_section(

        "Evidence storage"

    )





    add_table(

        [

            [

                "Master evidence",

                storage.get(

                    "master_path"

                ),

            ],



            [

                "Working copy",

                storage.get(

                    "working_path"

                ),

            ],



            [

                "Master read-only applied",

                bool_text(

                    storage.get(

                        "master_read_only_applied"

                    )

                ),

            ],

        ]

    )





    add_section(

        "Interpretation notes"

    )





    notes = [

        (

            "This was a logical file acquisition "

            "from a live filesystem."

        ),



        (

            "No hardware write blocker is claimed "

            "unless explicitly recorded above."

        ),



        (

            "Filesystem timestamps represent values "

            "observed by the collector and may have "

            "been affected by prior filesystem or "

            "operating-system activity."

        ),



        (

            "SHA-256 verification demonstrates "

            "content equality between the observed "

            "source, master evidence copy and "

            "working copy at the stated checkpoints."

        ),



        (

            "The acquisition report documents "

            "collection and preservation. Findings "

            "from forensic examination belong in "

            "the separate forensic analysis report."

        ),

    ]





    for note in notes:



        story.append(

            Paragraph(

                (

                    "• "

                    + safe(

                        note

                    )

                ),

                body_style,

            )

        )





    document.build(

        story,

        onFirstPage=_footer,

        onLaterPages=_footer,

    )





    return buffer.getvalue()





def build_acquisition_manifest_json(
    manifest: dict,
) -> str:

    if not manifest:
        raise ValueError(
            "Acquisition manifest is unavailable."
        )

    return json.dumps(
        manifest,
        indent=2,
        ensure_ascii=False,
    )


def _looks_like_code(

    value,

) -> bool:



    if value is None:



        return False





    text = str(

        value

    )





    if len(

        text

    ) >= 32:



        return True





    if (

        "\\\\"

        in text

        or "/"

        in text

    ):



        return True





    return False





def _footer(

    canvas,

    document,

) -> None:



    canvas.saveState()





    width, _ = A4





    canvas.setStrokeColor(

        colors.HexColor(

            "#D8DEE8"

        )

    )





    canvas.line(

        16 * mm,

        13 * mm,

        width - 16 * mm,

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

        width - 16 * mm,

        8.5 * mm,

        f"Page {document.page}",

    )





    canvas.restoreState()