from pathlib import Path
import binascii
import struct
import zipfile
import zlib

from app.config import DATA_DIR


DEMO_DIR = (
    DATA_DIR
    / "demo"
)


DEMO_SAMPLES = {
    "artefact_text": {
        "filename":
            "forensic_artefacts.txt",

        "title":
            "Artefact extraction",

        "description":
            (
                "Safe text evidence containing "
                "URLs, IP addresses, paths, "
                "email addresses and commands."
            ),
    },

    "signature_mismatch": {
        "filename":
            "invoice.pdf",

        "title":
            "File signature mismatch",

        "description":
            (
                "A PNG image deliberately named "
                "with a .pdf extension."
            ),
    },

    "office_metadata": {
        "filename":
            "demo_document.docx",

        "title":
            "Office metadata",

        "description":
            (
                "A safe DOCX package containing "
                "author, revision and external "
                "relationship metadata."
            ),
    },

    "pdf_structure": {
        "filename":
            "demo_report.pdf",

        "title":
            "PDF structure",

        "description":
            (
                "A minimal safe PDF used to "
                "demonstrate structural analysis."
            ),
    },

    "archive_paths": {
        "filename":
            "demo_archive.zip",

        "title":
            "Archive path analysis",

        "description":
            (
                "A safe ZIP containing a deliberately "
                "suspicious member path. The archive "
                "is never extracted."
            ),
    },

    "integrity_original": {
        "filename":
            "integrity_original.txt",

        "title":
            "Integrity verification",

        "description":
            (
                "Original evidence for demonstrating "
                "SHA-256 verification."
            ),
    },

    "integrity_modified": {
        "filename":
            "integrity_modified.txt",

        "title":
            "Modified integrity sample",

        "description":
            (
                "Modified version of the integrity "
                "sample for demonstrating a failed "
                "verification."
            ),
    },
}


def ensure_demo_files() -> None:

    DEMO_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )


    _write_text_samples()

    _write_png(
        DEMO_DIR
        / "invoice.pdf"
    )

    _write_pdf(
        DEMO_DIR
        / "demo_report.pdf"
    )

    _write_docx(
        DEMO_DIR
        / "demo_document.docx"
    )

    _write_archive(
        DEMO_DIR
        / "demo_archive.zip"
    )


def list_demo_samples() -> list[dict]:

    ensure_demo_files()


    return [
        {
            "id":
                sample_id,

            **sample,
        }

        for (
            sample_id,
            sample,
        ) in DEMO_SAMPLES.items()
    ]


def get_demo_sample(
    sample_id: str,
) -> dict | None:

    ensure_demo_files()


    sample = DEMO_SAMPLES.get(
        sample_id
    )


    if not sample:

        return None


    path = (
        DEMO_DIR
        / sample[
            "filename"
        ]
    )


    return {
        "id":
            sample_id,

        **sample,

        "path":
            path,
    }


def _write_text_samples():

    artefact_text = """
Portfolio demonstration evidence.

URL:
https://example.com/demo-login

Email:
analyst@example.com

IPv4:
192.168.10.42

Windows path:
C:\\Users\\DemoAnalyst\\Documents\\case.txt

Unix path:
/home/demo/evidence/report.txt

Registry:
HKCU\\Software\\ForensicDemo

Command example:
powershell.exe -ExecutionPolicy Bypass -File demo.ps1

These values are intentionally harmless demonstration data.
""".strip()


    (
        DEMO_DIR
        / "forensic_artefacts.txt"
    ).write_text(
        artefact_text,
        encoding="utf-8",
    )


    (
        DEMO_DIR
        / "integrity_original.txt"
    ).write_text(
        (
            "Digital forensic integrity "
            "demonstration evidence.\n"
            "Version: original\n"
        ),
        encoding="utf-8",
    )


    (
        DEMO_DIR
        / "integrity_modified.txt"
    ).write_text(
        (
            "Digital forensic integrity "
            "demonstration evidence.\n"
            "Version: modified\n"
        ),
        encoding="utf-8",
    )


def _png_chunk(
    chunk_type: bytes,
    data: bytes,
) -> bytes:

    return (
        struct.pack(
            ">I",
            len(data),
        )
        + chunk_type
        + data
        + struct.pack(
            ">I",
            binascii.crc32(
                chunk_type
                + data
            )
            & 0xFFFFFFFF,
        )
    )


def _write_png(
    path: Path,
):

    width = 2
    height = 2


    raw = (
        b"\x00"
        + b"\x40\x80\xc0"
        * width
    ) * height


    png = (
        b"\x89PNG\r\n\x1a\n"

        + _png_chunk(
            b"IHDR",
            struct.pack(
                ">IIBBBBB",
                width,
                height,
                8,
                2,
                0,
                0,
                0,
            ),
        )

        + _png_chunk(
            b"IDAT",
            zlib.compress(
                raw
            ),
        )

        + _png_chunk(
            b"IEND",
            b"",
        )
    )


    path.write_bytes(
        png
    )


def _write_pdf(
    path: Path,
):

    objects = [
        (
            b"<< /Type /Catalog "
            b"/Pages 2 0 R >>"
        ),

        (
            b"<< /Type /Pages "
            b"/Kids [3 0 R] "
            b"/Count 1 >>"
        ),

        (
            b"<< /Type /Page "
            b"/Parent 2 0 R "
            b"/MediaBox [0 0 612 792] "
            b">>"
        ),

        (
            b"<< "
            b"/Author (Portfolio Demo) "
            b"/Creator (Forensic File Analyzer) "
            b"/Title (Demo Report) "
            b">>"
        ),
    ]


    output = bytearray(
        b"%PDF-1.4\n"
    )


    offsets = [
        0
    ]


    for index, body in enumerate(
        objects,
        start=1,
    ):

        offsets.append(
            len(output)
        )


        output.extend(
            (
                f"{index} 0 obj\n"
            ).encode()
        )


        output.extend(
            body
        )


        output.extend(
            b"\nendobj\n"
        )


    xref_offset = len(
        output
    )


    output.extend(
        (
            f"xref\n"
            f"0 {len(objects) + 1}\n"
        ).encode()
    )


    output.extend(
        b"0000000000 65535 f \n"
    )


    for offset in offsets[
        1:
    ]:

        output.extend(
            (
                f"{offset:010d} "
                f"00000 n \n"
            ).encode()
        )


    output.extend(
        (
            "trailer\n"
            f"<< /Size {len(objects) + 1} "
            "/Root 1 0 R "
            "/Info 4 0 R >>\n"
            "startxref\n"
            f"{xref_offset}\n"
            "%%EOF\n"
        ).encode()
    )


    path.write_bytes(
        output
    )


def _write_docx(
    path: Path,
):

    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""


    core = """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties
xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
xmlns:dc="http://purl.org/dc/elements/1.1/"
xmlns:dcterms="http://purl.org/dc/terms/"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

<dc:title>Portfolio Demo Document</dc:title>
<dc:creator>Demo Analyst</dc:creator>
<cp:lastModifiedBy>Forensic Demo User</cp:lastModifiedBy>
<cp:revision>4</cp:revision>
<dcterms:created xsi:type="dcterms:W3CDTF">2026-09-20T10:15:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2026-09-21T14:30:00Z</dcterms:modified>

</cp:coreProperties>
"""


    app = """<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>Microsoft Office Word</Application>
<AppVersion>16.0</AppVersion>
<Company>Portfolio Demonstration</Company>
</Properties>
"""


    package_rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
Target="word/document.xml"/>
</Relationships>
"""


    document = """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
<w:p>
<w:r>
<w:t>Safe portfolio demonstration document.</w:t>
</w:r>
</w:p>
</w:body>
</w:document>
"""


    document_rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship
Id="rId2"
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
Target="https://example.com/demo-resource"
TargetMode="External"/>
</Relationships>
"""


    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        archive.writestr(
            "[Content_Types].xml",
            content_types,
        )

        archive.writestr(
            "_rels/.rels",
            package_rels,
        )

        archive.writestr(
            "docProps/core.xml",
            core,
        )

        archive.writestr(
            "docProps/app.xml",
            app,
        )

        archive.writestr(
            "word/document.xml",
            document,
        )

        archive.writestr(
            "word/_rels/document.xml.rels",
            document_rels,
        )


def _write_archive(
    path: Path,
):

    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:

        archive.writestr(
            "evidence/readme.txt",
            (
                "Safe archive demonstration."
            ),
        )


        archive.writestr(
            "../demo_escape.txt",
            (
                "This member demonstrates "
                "path traversal detection. "
                "The analyzer never extracts it."
            ),
        )