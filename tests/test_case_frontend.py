from pathlib import Path


def test_investigation_note_content_is_rendered_with_text_content():
    project_root = Path(__file__).resolve().parents[1]
    javascript = (project_root / "static" / "js" / "case.js").read_text(encoding="utf-8")

    assert "content.textContent = entry.content;" in javascript
    assert ".innerHTML" not in javascript
