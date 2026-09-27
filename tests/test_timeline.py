import pytest

from forensics.timeline import build_timeline


pytestmark = pytest.mark.unit


def metadata_with(*fields):
    return {
        "status": "ok",
        "categories": {
            "Other Metadata": list(fields),
        },
    }


def event_by_field(timeline: dict, field_name: str) -> dict:
    for event in timeline["events"]:
        if event.get("source_field") == field_name:
            return event

    raise AssertionError(
        f"Timeline event for {field_name!r} was not produced."
    )


def test_timezone_aware_timestamp_is_normalised_to_utc():
    metadata = metadata_with(
        {
            "group": "EXIF",
            "name": "CreateDate",
            "value": "2026:09:20 14:30:00+02:00",
        }
    )

    timeline = build_timeline({}, metadata)
    event = event_by_field(timeline, "CreateDate")

    assert event["timezone_known"] is True
    assert event["timestamp_utc"] == "2026-09-20T12:30:00Z"
    assert event["scope"] == "embedded_metadata"


def test_timezone_unknown_timestamp_is_not_falsely_converted_to_utc():
    metadata = metadata_with(
        {
            "group": "EXIF",
            "name": "DateTimeOriginal",
            "value": "2026:09:20 15:00:00",
        }
    )

    timeline = build_timeline({}, metadata)
    event = event_by_field(timeline, "DateTimeOriginal")

    assert event["timezone_known"] is False
    assert event["timestamp_utc"] is None
    assert event["sort_basis"] == "recorded_wall_clock"

    assert any(
        "No timezone was recorded" in note
        for note in event["notes"]
    )


def test_exiftool_system_timestamps_are_not_duplicated():
    metadata = metadata_with(
        {
            "group": "System",
            "name": "FileModifyDate",
            "value": "2026:09:20 16:00:00+00:00",
        }
    )

    timeline = build_timeline({}, metadata)

    assert timeline["event_count"] == 0


def test_filesystem_and_embedded_timestamp_scopes_stay_separate():
    filesystem = {
        "created": "2026-09-25T15:21:55Z",
        "modified": "2026-09-25T15:22:00Z",
        "accessed": None,
        "metadata_changed": None,
    }

    metadata = metadata_with(
        {
            "group": "EXIF",
            "name": "CreateDate",
            "value": "2026:09:20 14:30:00+00:00",
        }
    )

    timeline = build_timeline(filesystem, metadata)

    scopes = {
        event["scope"]
        for event in timeline["events"]
    }

    assert "evidence_copy" in scopes
    assert "embedded_metadata" in scopes
