import pytest

from forensics.security_findings import build_security_assessment

from .conftest import finding_ids


pytestmark = pytest.mark.unit


def base_analysis() -> dict:
    return {
        "signature": {
            "extension": ".txt",
            "extension_matches": True,
            "detected_type": "Plain text",
            "detected_mime": "text/plain",
        },
        "artefacts": {
            "truncated": False,
            "categories": {
                "command_lines": {
                    "count": 0,
                    "items": [],
                },
                "executables": {
                    "count": 0,
                    "items": [],
                },
            },
        },
        "format_analysis": {
            "status": "not_applicable",
            "format": None,
            "properties": {},
            "observations": [],
        },
        "warnings": [],
    }


def test_clean_analysis_has_no_significant_indicators():
    assessment = build_security_assessment(base_analysis())

    assert assessment["disposition"] == "no_significant_indicators"
    assert assessment["state"] == "good"
    assert assessment["counts"]["high"] == 0
    assert assessment["counts"]["medium"] == 0


def test_command_strings_trigger_review():
    analysis = base_analysis()
    analysis["artefacts"]["categories"]["command_lines"]["count"] = 2

    assessment = build_security_assessment(analysis)

    assert assessment["disposition"] == "review_recommended"
    assert "COMMAND_STRINGS_PRESENT" in finding_ids(assessment)
    assert assessment["counts"]["medium"] >= 1


def test_extension_mismatch_triggers_review():
    analysis = base_analysis()
    analysis["signature"].update(
        {
            "extension": ".txt",
            "extension_matches": False,
            "detected_type": "PNG image",
            "detected_mime": "image/png",
        }
    )

    assessment = build_security_assessment(analysis)

    assert assessment["disposition"] == "review_recommended"
    assert "FILE_EXTENSION_MISMATCH" in finding_ids(assessment)


def test_archive_path_traversal_is_high_attention():
    analysis = base_analysis()
    analysis["format_analysis"] = {
        "status": "ok",
        "format": "zip",
        "properties": {
            "archive": {
                "path_traversal_detected": True,
            }
        },
        "observations": [],
    }

    assessment = build_security_assessment(analysis)

    assert assessment["disposition"] == "suspicious_indicators_detected"
    assert assessment["state"] == "danger"
    assert "ARCHIVE_PATH_TRAVERSAL" in finding_ids(assessment)
    assert assessment["counts"]["high"] >= 1


def test_macro_signal_is_review_not_malware_verdict():
    analysis = base_analysis()
    analysis["format_analysis"] = {
        "status": "ok",
        "format": "office",
        "properties": {
            "contains_vba": True,
        },
        "observations": [],
    }

    assessment = build_security_assessment(analysis)

    assert assessment["disposition"] == "review_recommended"
    assert "MACRO_OR_VBA_CONTENT" in finding_ids(assessment)
    assert "not a malware verdict" in assessment["summary"].lower()


def test_low_context_finding_does_not_escalate_disposition():
    analysis = base_analysis()
    analysis["artefacts"]["categories"]["executables"]["count"] = 1

    assessment = build_security_assessment(analysis)

    assert assessment["disposition"] == "no_significant_indicators"
    assert "EXECUTABLE_REFERENCES" in finding_ids(assessment)
    assert assessment["counts"]["low"] == 1
