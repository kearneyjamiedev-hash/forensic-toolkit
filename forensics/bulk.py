from __future__ import annotations


def build_bulk_summary(
    analyses: list[dict],
) -> list[dict]:

    rows = []


    for analysis in analyses:

        overview = analysis.get(
            "overview",
            {}
        )


        signature = analysis.get(
            "signature",
            {}
        )


        hashes = analysis.get(
            "hashes",
            {}
        )


        timeline = analysis.get(
            "timeline",
            {}
        )


        artefacts = analysis.get(
            "artefacts",
            {}
        )


        created = _find_timeline_value(
            timeline,
            "created",
        )


        modified = _find_timeline_value(
            timeline,
            "modified",
        )


        observations = []


        if (
            signature.get(
                "extension_matches"
            )
            is False
        ):

            observations.append(
                "Extension mismatch"
            )


        timeline_observations = (
            timeline.get(
                "observations",
                []
            )
        )


        for observation in (
            timeline_observations[:3]
        ):

            title = observation.get(
                "title"
            )

            if title:

                observations.append(
                    title
                )


        artefact_count = (
            artefacts.get(
                "total_found",
                0
            )
        )


        if artefact_count:

            observations.append(
                (
                    f"{artefact_count} "
                    "interesting artefacts"
                )
            )


        rows.append(
            {
                "filename":
                    overview.get(
                        "filename"
                    ),

                "type":
                    signature.get(
                        "detected_type"
                    ),

                "mime_type":
                    signature.get(
                        "detected_mime"
                    ),

                "sha256":
                    hashes.get(
                        "sha256"
                    ),

                "size_bytes":
                    overview.get(
                        "size_bytes"
                    ),

                "created":
                    created[
                        "value"
                    ],

                "created_source":
                    created[
                        "source"
                    ],

                "modified":
                    modified[
                        "value"
                    ],

                "modified_source":
                    modified[
                        "source"
                    ],

                "artefact_count":
                    artefact_count,

                "observations":
                    observations,
            }
        )


    return rows


def _find_timeline_value(
    timeline: dict,
    event_type: str,
) -> dict:

    events = timeline.get(
        "events",
        []
    )


    # Prefer embedded metadata because
    # evidence-copy timestamps were introduced
    # during the local analysis process.

    for event in events:

        if (
            event.get(
                "event_type"
            )
            == event_type
            and event.get(
                "scope"
            )
            == "embedded_metadata"
        ):

            return {
                "value":
                    (
                        event.get(
                            "timestamp_utc"
                        )
                        or event.get(
                            "timestamp_original"
                        )
                    ),

                "source":
                    (
                        f"{event.get('source_group')}:"
                        f"{event.get('source_field')}"
                    ),
            }


    for event in events:

        if (
            event.get(
                "event_type"
            )
            == event_type
        ):

            return {
                "value":
                    (
                        event.get(
                            "timestamp_utc"
                        )
                        or event.get(
                            "timestamp_original"
                        )
                    ),

                "source":
                    (
                        f"{event.get('source_group')}:"
                        f"{event.get('source_field')}"
                    ),
            }


    return {
        "value":
            None,

        "source":
            None,
    }