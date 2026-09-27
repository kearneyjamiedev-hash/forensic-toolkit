from __future__ import annotations

from pathlib import Path
from typing import Any


def category_values(result: dict[str, Any], category_name: str) -> set[str]:
    """Return case-preserving artefact values from one result category."""
    category = (
        result.get("categories", {})
        .get(category_name, {})
    )

    return {
        str(item.get("value"))
        for item in category.get("items", [])
        if item.get("value") is not None
    }


def finding_ids(assessment: dict[str, Any]) -> set[str]:
    """Return stable finding IDs from a security assessment."""
    return {
        str(finding.get("id"))
        for finding in assessment.get("findings", [])
        if finding.get("id")
    }


def write_text_fixture(
    directory: Path,
    filename: str,
    content: str,
) -> Path:
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    return path
