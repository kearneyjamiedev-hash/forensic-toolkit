from collections import defaultdict
from datetime import datetime, timedelta, timezone
import re


EXIF_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<year>\d{4}):"
    r"(?P<month>\d{2}):"
    r"(?P<day>\d{2})"
    r"[ T]"
    r"(?P<hour>\d{2}):"
    r"(?P<minute>\d{2}):"
    r"(?P<second>\d{2})"
    r"(?P<fraction>\.\d+)?"
    r"(?P<timezone>Z|[+-]\d{2}:\d{2})?$"
)


PDF_TIMESTAMP_PATTERN = re.compile(
    r"^D:"
    r"(?P<year>\d{4})"
    r"(?P<month>\d{2})"
    r"(?P<day>\d{2})"
    r"(?P<hour>\d{2})?"
    r"(?P<minute>\d{2})?"
    r"(?P<second>\d{2})?"
    r"(?P<timezone>Z|[+-]\d{2}'?\d{2}'?)?$"
)


TIMESTAMP_TOKENS = (
    "createdate",
    "creationdate",
    "modifydate",
    "modifieddate",
    "moddate",
    "accessdate",
    "datetimeoriginal",
    "datetimecreated",
    "metadatadate",
    "datestamp",
    "timestamp",
    "filecreatedate",
    "filemodifydate",
    "fileaccessdate",
    "mediacreatedate",
    "trackcreatedate",
    "mediaheadertime",
)


def build_timeline(filesystem: dict, metadata: dict) -> dict:
    """
    Convert timestamps from different forensic sources into a common
    timeline model.

    UTC normalisation is only performed where the source timestamp
    contains timezone information.
    """

    events = []

    _add_filesystem_events(
        events,
        filesystem,
    )

    _add_metadata_events(
        events,
        metadata,
    )

    observations = _build_observations(events)

    events.sort(
        key=_timeline_sort_key
    )

    # Internal sorting values should not be exposed through the API.
    for event in events:
        event.pop("_sort_timestamp", None)

    return {
        "event_count": len(events),
        "observation_count": len(observations),
        "utc_normalised_count": sum(
            1
            for event in events
            if event["timestamp_utc"] is not None
        ),
        "timezone_unknown_count": sum(
            1
            for event in events
            if not event["timezone_known"]
        ),
        "events": events,
        "observations": observations,
    }


def _add_filesystem_events(
    events: list,
    filesystem: dict,
) -> None:

    mappings = [
        (
            "created",
            "Evidence copy created",
            "created",
        ),
        (
            "modified",
            "Evidence copy modified",
            "modified",
        ),
        (
            "accessed",
            "Evidence copy accessed",
            "accessed",
        ),
        (
            "metadata_changed",
            "Evidence copy metadata changed",
            "metadata_changed",
        ),
    ]

    for (
        field_name,
        label,
        event_type,
    ) in mappings:

        value = filesystem.get(field_name)

        if not value:
            continue

        parsed = _parse_timestamp(
            str(value)
        )

        if not parsed:
            continue

        events.append(
            _make_event(
                label=label,
                event_type=event_type,
                source="filesystem",
                source_group="Filesystem",
                source_field=field_name,
                scope="evidence_copy",
                original_value=str(value),
                parsed=parsed,
                notes=[
                    (
                        "This timestamp relates to the local evidence "
                        "copy managed by the analyzer, not necessarily "
                        "the original source filesystem."
                    )
                ],
            )
        )


def _add_metadata_events(
    events: list,
    metadata: dict,
) -> None:

    if metadata.get("status") != "ok":
        return

    categories = metadata.get(
        "categories",
        {},
    )

    for fields in categories.values():

        for field in fields:

            group = str(
                field.get("group", "")
            )

            name = str(
                field.get("name", "")
            )

            value = field.get("value")

            # ExifTool System timestamps describe the copy that
            # ExifTool is currently reading. filesystem.py already
            # records these more explicitly, so including them again
            # would create misleading duplicates.
            if group.lower() == "system":
                continue

            if not _looks_like_timestamp(
                name
            ):
                continue

            if value is None:
                continue

            if isinstance(
                value,
                (dict, list),
            ):
                continue

            original_value = str(value)

            parsed = _parse_timestamp(
                original_value
            )

            if not parsed:
                continue

            event_type = (
                _classify_event_type(name)
            )

            notes = [
                (
                    "This value comes from embedded metadata. "
                    "Metadata may be altered, removed or created "
                    "by software and should be interpreted in context."
                )
            ]

            if not parsed["timezone_known"]:
                notes.append(
                    (
                        "No timezone was recorded, so this timestamp "
                        "has not been converted to UTC."
                    )
                )

            events.append(
                _make_event(
                    label=_humanise_field_name(
                        name
                    ),
                    event_type=event_type,
                    source="exiftool",
                    source_group=group,
                    source_field=name,
                    scope="embedded_metadata",
                    original_value=original_value,
                    parsed=parsed,
                    notes=notes,
                )
            )


def _make_event(
    *,
    label: str,
    event_type: str,
    source: str,
    source_group: str,
    source_field: str,
    scope: str,
    original_value: str,
    parsed: dict,
    notes: list[str],
) -> dict:

    return {
        "label": label,
        "event_type": event_type,

        "timestamp_original":
            original_value,

        "timestamp_utc":
            parsed["timestamp_utc"],

        "timezone_known":
            parsed["timezone_known"],

        "sort_basis":
            parsed["sort_basis"],

        "source":
            source,

        "source_group":
            source_group,

        "source_field":
            source_field,

        "scope":
            scope,

        "notes": notes,

        "_sort_timestamp":
            parsed["_sort_timestamp"],
    }


def _looks_like_timestamp(
    field_name: str,
) -> bool:

    normalised = (
        field_name
        .replace("_", "")
        .replace("-", "")
        .lower()
    )

    return any(
        token in normalised
        for token in TIMESTAMP_TOKENS
    )


def _classify_event_type(
    field_name: str,
) -> str:

    name = (
        field_name
        .replace("_", "")
        .lower()
    )

    if (
        "datetimeoriginal" in name
        or "originaldate" in name
    ):
        return "original_timestamp"

    if "access" in name:
        return "accessed"

    if (
        "modify" in name
        or "modified" in name
        or "moddate" in name
    ):
        return "modified"

    if "metadata" in name:
        return "metadata_timestamp"

    if (
        "create" in name
        or "creation" in name
    ):
        return "created"

    return "timestamp"


def _parse_timestamp(
    value: str,
) -> dict | None:

    value = value.strip()

    if not value:
        return None

    parsed = _parse_iso_timestamp(value)

    if parsed:
        return parsed

    parsed = _parse_exif_timestamp(value)

    if parsed:
        return parsed

    parsed = _parse_pdf_timestamp(value)

    if parsed:
        return parsed

    return None


def _parse_iso_timestamp(
    value: str,
) -> dict | None:

    iso_value = value

    if iso_value.endswith("Z"):
        iso_value = (
            iso_value[:-1]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            iso_value
        )

    except ValueError:
        return None

    return _normalise_datetime(parsed)


def _parse_exif_timestamp(
    value: str,
) -> dict | None:

    match = EXIF_TIMESTAMP_PATTERN.match(
        value
    )

    if not match:
        return None

    parts = match.groupdict()

    microsecond = 0

    if parts["fraction"]:
        fraction = (
            parts["fraction"][1:]
            .ljust(6, "0")[:6]
        )

        microsecond = int(fraction)

    tzinfo = _parse_timezone(
        parts["timezone"]
    )

    try:
        parsed = datetime(
            year=int(parts["year"]),
            month=int(parts["month"]),
            day=int(parts["day"]),
            hour=int(parts["hour"]),
            minute=int(parts["minute"]),
            second=int(parts["second"]),
            microsecond=microsecond,
            tzinfo=tzinfo,
        )

    except ValueError:
        return None

    return _normalise_datetime(parsed)


def _parse_pdf_timestamp(
    value: str,
) -> dict | None:

    match = PDF_TIMESTAMP_PATTERN.match(
        value
    )

    if not match:
        return None

    parts = match.groupdict()

    timezone_value = (
        parts["timezone"]
    )

    if (
        timezone_value
        and timezone_value not in ("Z",)
    ):
        timezone_value = (
            timezone_value
            .replace("'", "")
        )

        timezone_value = (
            timezone_value[:3]
            + ":"
            + timezone_value[3:]
        )

    tzinfo = _parse_timezone(
        timezone_value
    )

    try:
        parsed = datetime(
            year=int(parts["year"]),
            month=int(parts["month"]),
            day=int(parts["day"]),
            hour=int(
                parts["hour"] or 0
            ),
            minute=int(
                parts["minute"] or 0
            ),
            second=int(
                parts["second"] or 0
            ),
            tzinfo=tzinfo,
        )

    except ValueError:
        return None

    return _normalise_datetime(parsed)


def _parse_timezone(
    value: str | None,
):
    if not value:
        return None

    if value == "Z":
        return timezone.utc

    sign = (
        1
        if value.startswith("+")
        else -1
    )

    try:
        hours = int(
            value[1:3]
        )

        minutes = int(
            value[4:6]
        )

    except (
        ValueError,
        IndexError,
    ):
        return None

    if hours > 23 or minutes > 59:
        return None

    offset = timedelta(
        hours=hours,
        minutes=minutes,
    )

    try:
        return timezone(
            sign * offset
        )
    except ValueError:
        return None


def _normalise_datetime(
    parsed: datetime,
) -> dict:

    timezone_known = (
        parsed.tzinfo is not None
        and parsed.utcoffset() is not None
    )

    if timezone_known:

        utc_value = (
            parsed
            .astimezone(timezone.utc)
            .isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )

        sort_timestamp = (
            parsed
            .astimezone(timezone.utc)
            .timestamp()
        )

        sort_basis = "utc"

    else:

        utc_value = None

        # This is used only to position an unknown-timezone timestamp
        # in the visual timeline. It is NOT being treated as UTC.
        sort_timestamp = (
            parsed
            .replace(
                tzinfo=timezone.utc
            )
            .timestamp()
        )

        sort_basis = (
            "recorded_wall_clock"
        )

    return {
        "timestamp_utc":
            utc_value,

        "timezone_known":
            timezone_known,

        "sort_basis":
            sort_basis,

        "_sort_timestamp":
            sort_timestamp,
    }


def _timeline_sort_key(
    event: dict,
):
    return event[
        "_sort_timestamp"
    ]


def _build_observations(
    events: list,
) -> list:

    observations = []

    observations.extend(
        _find_timestamp_order_conflicts(
            events
        )
    )

    observations.extend(
        _find_metadata_disagreements(
            events
        )
    )

    return observations


def _find_timestamp_order_conflicts(
    events: list,
) -> list:

    observations = []

    grouped = defaultdict(
        lambda: {
            "created": [],
            "modified": [],
        }
    )

    for event in events:

        if (
            event["scope"]
            != "embedded_metadata"
        ):
            continue

        if event["event_type"] not in (
            "created",
            "modified",
        ):
            continue

        grouped[
            event["source_group"]
        ][
            event["event_type"]
        ].append(event)

    for (
        source_group,
        timestamps,
    ) in grouped.items():

        created_events = (
            timestamps["created"]
        )

        modified_events = (
            timestamps["modified"]
        )

        for created in created_events:
            for modified in modified_events:

                comparable = (
                    created[
                        "timezone_known"
                    ]
                    == modified[
                        "timezone_known"
                    ]
                )

                if not comparable:
                    continue

                if (
                    modified[
                        "_sort_timestamp"
                    ]
                    <
                    created[
                        "_sort_timestamp"
                    ]
                ):

                    observations.append(
                        {
                            "type":
                                "timestamp_order_conflict",

                            "severity":
                                "warning",

                            "title":
                                "Timestamp ordering conflict",

                            "message":
                                (
                                    f"{source_group} reports a modified "
                                    f"timestamp that predates a creation "
                                    f"timestamp. This may result from "
                                    f"metadata editing, file copying, "
                                    f"software behaviour, timezone issues "
                                    f"or other causes."
                                ),
                        }
                    )

                    break

    return observations


def _find_metadata_disagreements(
    events: list,
) -> list:

    observations = []

    for event_type in (
        "created",
        "modified",
    ):

        relevant = [
            event
            for event in events
            if (
                event["scope"]
                == "embedded_metadata"
                and event["event_type"]
                == event_type
                and event["timezone_known"]
            )
        ]

        if len(relevant) < 2:
            continue

        timestamps = [
            event["_sort_timestamp"]
            for event in relevant
        ]

        difference = (
            max(timestamps)
            - min(timestamps)
        )

        if difference <= 60:
            continue

        sources = sorted(
            {
                (
                    f"{event['source_group']}:"
                    f"{event['source_field']}"
                )
                for event in relevant
            }
        )

        observations.append(
            {
                "type":
                    "metadata_timestamp_difference",

                "severity":
                    "info",

                "title":
                    "Metadata timestamps differ",

                "message":
                    (
                        f"Multiple embedded metadata fields report "
                        f"different {event_type} timestamps: "
                        f"{', '.join(sources)}. Different metadata "
                        f"layers may legitimately record different "
                        f"events, so this should be interpreted in "
                        f"context."
                    ),
            }
        )

    return observations


def _humanise_field_name(
    value: str,
) -> str:

    value = value.replace(
        "_",
        " ",
    )

    value = re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        " ",
        value,
    )

    value = re.sub(
        r"\s+",
        " ",
        value,
    )

    return value.strip()
