from __future__ import annotations

import base64
import hashlib
import zipfile

import pytest

try:
    from forensics.analyzer import analyze_file
except ModuleNotFoundError:
    pytest.skip(
        "forensics.analyzer is unavailable in this isolated test-pack check.",
        allow_module_level=True,
    )

from forensics.security_findings import build_security_assessment

from .conftest import finding_ids


pytestmark = pytest.mark.integration


# Valid 1x1 PNG. Keeping this as base64 makes the fixture deterministic and
# avoids requiring Pillow merely to generate the test input.
ONE_PIXEL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def test_plain_text_pipeline_produces_core_analysis_sections(tmp_path):
    content = b"Ordinary forensic regression fixture.\n"
    path = tmp_path / "clean.txt"
    path.write_bytes(content)

    result = analyze_file(
        file_path=path,
        original_filename="clean.txt",
    )

    assert result["overview"]["filename"] == "clean.txt"
    assert result["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()

    assert "signature" in result
    assert "filesystem" in result
    assert "metadata" in result
    assert "timeline" in result
    assert "artefacts" in result

    # Plain text does not require a format-specific parser.
    # If the analyzer supplies a format_analysis block, it should
    # be structurally valid, but the key is optional for unsupported formats.
    format_analysis = result.get("format_analysis")

    if format_analysis is not None:
        assert isinstance(format_analysis, dict)


def test_real_png_named_txt_is_reported_as_extension_mismatch(tmp_path):
    path = tmp_path / "renamed.txt"
    path.write_bytes(ONE_PIXEL_PNG)

    result = analyze_file(
        file_path=path,
        original_filename="renamed.txt",
    )

    signature = result["signature"]

    assert signature["extension_matches"] is False

    detected_type = str(
        signature.get("detected_type") or ""
    ).lower()
    detected_mime = str(
        signature.get("detected_mime") or ""
    ).lower()

    assert (
        "png" in detected_type
        or detected_mime == "image/png"
    )


def test_command_strings_reach_security_findings_engine(tmp_path):
    path = tmp_path / "commands.txt"
    path.write_text(
        (
            "Training fixture only.\n"
            "powershell.exe -enc QUJDREVGRw==\n"
            "cmd.exe /c whoami\n"
        ),
        encoding="utf-8",
    )

    result = analyze_file(
        file_path=path,
        original_filename="commands.txt",
    )

    assessment = build_security_assessment(result)

    assert assessment["disposition"] == "review_recommended"
    assert "COMMAND_STRINGS_PRESENT" in finding_ids(assessment)


def test_archive_traversal_flows_from_parser_to_security_assessment(tmp_path):
    path = tmp_path / "traversal.zip"

    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        archive.writestr(
            "normal/readme.txt",
            "Normal member.",
        )
        archive.writestr(
            "../outside.txt",
            "Traversal marker for static-analysis regression testing.",
        )

    result = analyze_file(
        file_path=path,
        original_filename="traversal.zip",
    )

    assessment = build_security_assessment(result)

    assert "ARCHIVE_PATH_TRAVERSAL" in finding_ids(assessment)
    assert assessment["disposition"] == "suspicious_indicators_detected"
