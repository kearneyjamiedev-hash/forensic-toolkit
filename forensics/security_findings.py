from __future__ import annotations

from collections.abc import Callable
from typing import Any


SEVERITY_WEIGHT = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def build_security_assessment(analysis: dict[str, Any]) -> dict[str, Any]:
    """Build an explainable static-security assessment from forensic output.

    This function does not determine whether a file is safe or malicious. It
    converts existing forensic signals into a triage-oriented view that can be
    consumed by the API, UI, reports and automated tests.
    """

    findings: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []

    signature = analysis.get("signature") or {}
    artefacts = analysis.get("artefacts") or {}
    categories = artefacts.get("categories") or {}
    format_analysis = analysis.get("format_analysis") or {}
    warnings = analysis.get("warnings") or []

    _evaluate_signature(signature, findings, checks)
    _evaluate_format_analysis(format_analysis, findings, checks)
    _evaluate_command_strings(categories, findings, checks)
    _evaluate_executable_context(signature, categories, findings, checks)
    _evaluate_scan_coverage(artefacts, findings, checks)
    _evaluate_warnings(warnings, findings)

    findings = _deduplicate_findings(findings)
    findings = sorted(
        findings,
        key=lambda item: SEVERITY_WEIGHT.get(
            str(item.get("severity", "info")),
            0,
        ),
        reverse=True,
    )

    high_count = sum(
        1 for item in findings if item.get("severity") == "high"
    )
    medium_count = sum(
        1 for item in findings if item.get("severity") == "medium"
    )
    low_count = sum(
        1 for item in findings if item.get("severity") == "low"
    )

    if high_count > 0:
        disposition = "suspicious_indicators_detected"
        title = "Suspicious indicators detected"
        badge = "High attention"
        state = "danger"
        summary = (
            f"{high_count} high-attention finding"
            f"{'s' if high_count != 1 else ''} and "
            f"{medium_count} review finding"
            f"{'s' if medium_count != 1 else ''} were identified. "
            "Review the evidence below before making a security decision."
        )
    elif medium_count > 0:
        disposition = "review_recommended"
        title = "Review recommended"
        badge = "Needs review"
        state = "warning"
        summary = (
            f"{medium_count} finding"
            f"{'s' if medium_count != 1 else ''} deserve analyst review. "
            "The result is not a malware verdict."
        )
    else:
        disposition = "no_significant_indicators"
        title = "No significant suspicious indicators identified"
        badge = "No major indicators"
        state = "good"
        summary = (
            "The static checks completed without identifying a significant "
            "suspicious indicator. This does not prove that the file is safe "
            "or benign."
        )

    return {
        "version": 1,
        "disposition": disposition,
        "title": title,
        "badge": badge,
        "state": state,
        "summary": summary,
        "counts": {
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total": len(findings),
        },
        "checks": checks,
        "findings": findings,
        "limitations": [
            (
                "Static analysis cannot prove that a file is safe or benign. "
                "Packed, encrypted, obfuscated or runtime-only behaviour may "
                "not be visible."
            ),
            (
                "Findings are investigative indicators and require analyst "
                "context before a security conclusion is made."
            ),
        ],
    }


def _evaluate_signature(
    signature: dict[str, Any],
    findings: list[dict[str, Any]],
    checks: list[dict[str, str]],
) -> None:
    extension_matches = signature.get("extension_matches")

    if extension_matches is False:
        findings.append(
            _finding(
                finding_id="FILE_EXTENSION_MISMATCH",
                severity="medium",
                title="Filename extension does not match detected file type",
                message=(
                    "The file extension is inconsistent with the detected "
                    f"content type ({signature.get('detected_type') or 'unknown'})."
                ),
                source="Signature analysis",
                evidence={
                    "extension": signature.get("extension"),
                    "detected_type": signature.get("detected_type"),
                    "detected_mime": signature.get("detected_mime"),
                },
            )
        )
        checks.append(
            _check(
                "review",
                "File extension and signature",
                "The filename extension does not match the detected content type.",
            )
        )
    elif extension_matches is True:
        checks.append(
            _check(
                "pass",
                "File extension and signature",
                "The filename extension is consistent with the detected file structure.",
            )
        )
    else:
        checks.append(
            _check(
                "neutral",
                "File extension and signature",
                "The analyzer could not make a definitive extension comparison.",
            )
        )


def _evaluate_format_analysis(
    format_analysis: dict[str, Any],
    findings: list[dict[str, Any]],
    checks: list[dict[str, str]],
) -> None:
    status = format_analysis.get("status")
    format_name = str(format_analysis.get("format") or "file")

    if status == "error":
        findings.append(
            _finding(
                finding_id="FORMAT_PARSER_ERROR",
                severity="medium",
                title="Format-specific parser reported an issue",
                message=(
                    "The dedicated format analyzer could not complete normally. "
                    "A malformed or unsupported structure can require manual review."
                ),
                source="Format analysis",
            )
        )
        checks.append(
            _check(
                "review",
                "Format-specific parsing",
                "The dedicated parser encountered an issue.",
            )
        )
    elif status == "ok":
        checks.append(
            _check(
                "pass",
                "Format-specific parsing",
                f"The {format_name.upper()} analyzer completed successfully.",
            )
        )
    else:
        checks.append(
            _check(
                "neutral",
                "Format-specific parsing",
                "No dedicated format parser was required for this file.",
            )
        )

    observations = format_analysis.get("observations") or []
    if isinstance(observations, list):
        for index, observation in enumerate(observations):
            severity = _normalise_observation_severity(observation)
            if severity == "info":
                continue

            if isinstance(observation, dict):
                title = observation.get("title") or "Format-specific observation"
                message = (
                    observation.get("message")
                    or "The format analyzer identified an item that deserves review."
                )
            else:
                title = "Format-specific observation"
                message = str(observation)

            findings.append(
                _finding(
                    finding_id=f"FORMAT_OBSERVATION_{index + 1}",
                    severity=severity,
                    title=str(title),
                    message=str(message),
                    source=f"{format_name.upper()} analysis",
                )
            )

    findings.extend(
        _detect_structured_format_signals(
            format_analysis.get("properties") or {}
        )
    )


def _evaluate_command_strings(
    categories: dict[str, Any],
    findings: list[dict[str, Any]],
    checks: list[dict[str, str]],
) -> None:
    command_count = _category_count(categories.get("command_lines"))

    if command_count > 0:
        findings.append(
            _finding(
                finding_id="COMMAND_STRINGS_PRESENT",
                severity="medium",
                title="Command-like strings identified",
                message=(
                    f"{command_count} command-like string"
                    f"{' was' if command_count == 1 else 's were'} extracted from "
                    "readable content. These may be benign, but deserve review "
                    "in an unexpected file type."
                ),
                source="String artefacts",
                evidence={"count": command_count},
            )
        )
        checks.append(
            _check(
                "review",
                "Command-like strings",
                f"{command_count} candidate command string"
                f"{'' if command_count == 1 else 's'} identified.",
            )
        )
    else:
        checks.append(
            _check(
                "pass",
                "Command-like strings",
                "No command-like strings were identified by the artefact extractor.",
            )
        )


def _evaluate_executable_context(
    signature: dict[str, Any],
    categories: dict[str, Any],
    findings: list[dict[str, Any]],
    checks: list[dict[str, str]],
) -> None:
    executable_count = _category_count(categories.get("executables"))
    detected_type = str(signature.get("detected_type") or "").lower()
    file_is_executable = any(
        marker in detected_type
        for marker in (
            "executable",
            "portable executable",
            "pe32",
            "pe32+",
        )
    )

    if file_is_executable:
        findings.append(
            _finding(
                finding_id="EXECUTABLE_FILE",
                severity="medium",
                title="Executable file requires deeper review",
                message=(
                    "The file itself is executable content. Static triage cannot "
                    "determine whether runtime behaviour is benign or malicious."
                ),
                source="File identification",
                evidence={"detected_type": signature.get("detected_type")},
            )
        )
        checks.append(
            _check(
                "review",
                "Executable content",
                (
                    "The selected file is executable content and should receive "
                    "deeper static or dynamic malware analysis when appropriate."
                ),
            )
        )
    elif executable_count > 0:
        findings.append(
            _finding(
                finding_id="EXECUTABLE_REFERENCES",
                severity="low",
                title="Executable or script references found",
                message=(
                    f"{executable_count} executable/script reference"
                    f"{' was' if executable_count == 1 else 's were'} found in "
                    "readable strings. References alone do not prove embedded "
                    "executable content."
                ),
                source="String artefacts",
                evidence={"count": executable_count},
            )
        )
        checks.append(
            _check(
                "neutral",
                "Executable/script references",
                f"{executable_count} readable reference"
                f"{'' if executable_count == 1 else 's'} identified for analyst context.",
            )
        )
    else:
        checks.append(
            _check(
                "pass",
                "Executable/script references",
                "No executable or script references were identified in readable strings.",
            )
        )


def _evaluate_scan_coverage(
    artefacts: dict[str, Any],
    findings: list[dict[str, Any]],
    checks: list[dict[str, str]],
) -> None:
    if artefacts.get("truncated") is True:
        findings.append(
            _finding(
                finding_id="ARTEFACT_SCAN_TRUNCATED",
                severity="low",
                title="String scan reached its configured limit",
                message=(
                    "The readable-string scan reached its configured byte limit, "
                    "so later content may not have been inspected by this stage."
                ),
                source="Artefact extraction",
                evidence={
                    "scanned_bytes": artefacts.get("scanned_bytes"),
                    "scan_limit_bytes": artefacts.get("scan_limit_bytes"),
                },
            )
        )
        checks.append(
            _check(
                "neutral",
                "Artefact scan coverage",
                "The readable-string scan reached its configured byte limit.",
            )
        )
    else:
        checks.append(
            _check(
                "pass",
                "Artefact scan coverage",
                "The readable-string scan did not report truncation.",
            )
        )


def _evaluate_warnings(
    warnings: Any,
    findings: list[dict[str, Any]],
) -> None:
    if not isinstance(warnings, list):
        return

    for index, warning in enumerate(warnings):
        if isinstance(warning, dict):
            text = warning.get("message") or warning.get("title")
        else:
            text = str(warning) if warning is not None else ""

        if not text:
            continue

        findings.append(
            _finding(
                finding_id=f"ANALYZER_WARNING_{index + 1}",
                severity="medium",
                title="Analyzer warning",
                message=str(text),
                source="Core analyzer",
            )
        )


def _normalise_observation_severity(observation: Any) -> str:
    if isinstance(observation, dict):
        explicit = str(observation.get("severity") or "").lower()
        combined = (
            f"{observation.get('title') or ''} "
            f"{observation.get('message') or ''}"
        ).lower()
    else:
        explicit = ""
        combined = str(observation or "").lower()

    if explicit in {"critical", "danger", "high", "error"}:
        return "high"

    if explicit in {"warning", "warn", "medium", "suspicious"}:
        return "medium"

    if any(
        phrase in combined
        for phrase in (
            "path traversal",
            "launch action",
            "embedded executable",
            "active content",
        )
    ):
        return "high"

    if any(
        phrase in combined
        for phrase in (
            "macro",
            "vba",
            "javascript",
            "openaction",
            "powershell",
            "command",
            "unsigned",
            "high entropy",
            "suspicious",
        )
    ):
        return "medium"

    return "info"


def _detect_structured_format_signals(
    properties: Any,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    def visitor(path: list[str], value: Any) -> None:
        key = "_".join(path).lower()
        key = "".join(
            character if character.isalnum() else "_"
            for character in key
        )

        if not _truthy_security_value(value):
            return

        path_label = " → ".join(path) or "format property"

        if any(marker in key for marker in ("path_traversal", "traversal_detected", "zip_slip")):
            findings.append(
                _finding(
                    finding_id="ARCHIVE_PATH_TRAVERSAL",
                    severity="high",
                    title="Archive path traversal indicator",
                    message=(
                        f"A structured format field ({path_label}) indicates "
                        "a path-traversal condition."
                    ),
                    source="Format properties",
                    evidence={"property_path": path_label, "value": value},
                )
            )
            return

        if any(marker in key for marker in ("launch_action", "has_launch", "embedded_executable")):
            findings.append(
                _finding(
                    finding_id="ACTIVE_OR_EXECUTABLE_CONTENT",
                    severity="high",
                    title="Active or executable content indicator",
                    message=(
                        f"A structured format field ({path_label}) indicates "
                        "active or executable content."
                    ),
                    source="Format properties",
                    evidence={"property_path": path_label, "value": value},
                )
            )
            return

        if any(
            marker in key
            for marker in (
                "has_macro",
                "macros_present",
                "contains_macro",
                "has_vba",
                "vba_present",
                "contains_vba",
            )
        ):
            findings.append(
                _finding(
                    finding_id="MACRO_OR_VBA_CONTENT",
                    severity="medium",
                    title="Macro or VBA content indicated",
                    message=(
                        f"A structured format field ({path_label}) indicates "
                        "macro/VBA content."
                    ),
                    source="Format properties",
                    evidence={"property_path": path_label, "value": value},
                )
            )
            return

        if any(
            marker in key
            for marker in (
                "has_javascript",
                "contains_javascript",
                "javascript_present",
                "open_action",
                "openaction",
            )
        ):
            findings.append(
                _finding(
                    finding_id="ACTIVE_DOCUMENT_CONTENT",
                    severity="medium",
                    title="Active document content indicated",
                    message=(
                        f"A structured format field ({path_label}) indicates "
                        "JavaScript or automatic-open behaviour."
                    ),
                    source="Format properties",
                    evidence={"property_path": path_label, "value": value},
                )
            )

    _walk_properties(properties, [], visitor)
    return findings


def _walk_properties(
    value: Any,
    path: list[str],
    visitor: Callable[[list[str], Any], None],
) -> None:
    if value is None:
        return

    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_properties(item, [*path, str(index)], visitor)
        return

    if isinstance(value, dict):
        for key, child in value.items():
            _walk_properties(child, [*path, str(key)], visitor)
        return

    visitor(path, value)


def _truthy_security_value(value: Any) -> bool:
    if value is True:
        return True

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value > 0

    text = str(value).strip().lower()
    return text in {"true", "yes", "present", "detected", "found"}


def _category_count(category: Any) -> int:
    if not isinstance(category, dict):
        return 0

    try:
        return int(category.get("count") or 0)
    except (TypeError, ValueError):
        return 0


def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    output: list[dict[str, Any]] = []

    for finding in findings:
        key = (
            str(finding.get("id") or "").casefold(),
            str(finding.get("severity") or "").casefold(),
            str(finding.get("title") or "").casefold(),
            str(finding.get("message") or "").casefold(),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(finding)

    return output


def _finding(
    *,
    finding_id: str,
    severity: str,
    title: str,
    message: str,
    source: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "id": finding_id,
        "severity": severity,
        "title": title,
        "message": message,
        "source": source,
    }

    if evidence:
        result["evidence"] = evidence

    return result


def _check(state: str, title: str, message: str) -> dict[str, str]:
    return {
        "state": state,
        "title": title,
        "message": message,
    }
