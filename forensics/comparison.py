from __future__ import annotations


def compare_analyses(
    analysis_a: dict,
    analysis_b: dict,
) -> dict:

    metadata_a = _flatten_metadata(
        analysis_a.get(
            "metadata",
            {}
        )
    )

    metadata_b = _flatten_metadata(
        analysis_b.get(
            "metadata",
            {}
        )
    )


    metadata_diff = _compare_mappings(
        metadata_a,
        metadata_b,
    )


    artefact_diff = _compare_artefacts(
        analysis_a.get(
            "artefacts",
            {}
        ),
        analysis_b.get(
            "artefacts",
            {}
        ),
    )


    timeline_diff = _compare_timelines(
        analysis_a.get(
            "timeline",
            {}
        ),
        analysis_b.get(
            "timeline",
            {}
        ),
    )


    hashes_a = analysis_a.get(
        "hashes",
        {}
    )

    hashes_b = analysis_b.get(
        "hashes",
        {}
    )


    overview_a = analysis_a.get(
        "overview",
        {}
    )

    overview_b = analysis_b.get(
        "overview",
        {}
    )


    signature_a = analysis_a.get(
        "signature",
        {}
    )

    signature_b = analysis_b.get(
        "signature",
        {}
    )


    sha256_match = (
        hashes_a.get("sha256")
        == hashes_b.get("sha256")
    )


    return {
        "summary": {
            "same_sha256":
                sha256_match,

            "same_size":
                (
                    overview_a.get(
                        "size_bytes"
                    )
                    ==
                    overview_b.get(
                        "size_bytes"
                    )
                ),

            "same_detected_type":
                (
                    signature_a.get(
                        "detected_type"
                    )
                    ==
                    signature_b.get(
                        "detected_type"
                    )
                ),

            "same_extension":
                (
                    overview_a.get(
                        "extension"
                    )
                    ==
                    overview_b.get(
                        "extension"
                    )
                ),

            "metadata_changes":
                metadata_diff[
                    "change_count"
                ],

            "artefact_changes":
                artefact_diff[
                    "change_count"
                ],

            "timeline_changes":
                timeline_diff[
                    "change_count"
                ],
        },

        "files": {
            "a": {
                "filename":
                    overview_a.get(
                        "filename"
                    ),

                "sha256":
                    hashes_a.get(
                        "sha256"
                    ),

                "size_bytes":
                    overview_a.get(
                        "size_bytes"
                    ),

                "detected_type":
                    signature_a.get(
                        "detected_type"
                    ),

                "extension":
                    overview_a.get(
                        "extension"
                    ),
            },

            "b": {
                "filename":
                    overview_b.get(
                        "filename"
                    ),

                "sha256":
                    hashes_b.get(
                        "sha256"
                    ),

                "size_bytes":
                    overview_b.get(
                        "size_bytes"
                    ),

                "detected_type":
                    signature_b.get(
                        "detected_type"
                    ),

                "extension":
                    overview_b.get(
                        "extension"
                    ),
            },
        },

        "metadata":
            metadata_diff,

        "artefacts":
            artefact_diff,

        "timeline":
            timeline_diff,

        "interpretation": (
            "Differences identify changes between "
            "the two analysed files. They do not "
            "by themselves explain why a change "
            "occurred."
        ),
    }


def _flatten_metadata(
    metadata: dict,
) -> dict:

    if (
        metadata.get(
            "status"
        )
        != "ok"
    ):
        return {}


    result = {}


    categories = metadata.get(
        "categories",
        {}
    )


    analyzer_copy_fields = {
        "filename",
        "directory",
        "filemodifydate",
        "fileaccessdate",
        "filecreatedate",
        "filepermissions",
    }


    for fields in categories.values():

        for field in fields:

            group = str(
                field.get(
                    "group",
                    ""
                )
            )


            name = str(
                field.get(
                    "name",
                    ""
                )
            )

            if (
                group.lower()
                == "system"
            ):
                continue


            if (
                name.lower()
                in analyzer_copy_fields
            ):
                continue


            key = (
                f"{group}:"
                f"{name}"
            )


            result[key] = (
                field.get(
                    "value"
                )
            )


    return result


def _compare_mappings(
    a: dict,
    b: dict,
) -> dict:

    added = []
    removed = []
    changed = []
    unchanged = []


    all_keys = sorted(
        set(a)
        | set(b)
    )


    for key in all_keys:

        in_a = key in a
        in_b = key in b


        if (
            not in_a
            and in_b
        ):

            added.append(
                {
                    "field":
                        key,

                    "value":
                        b[key],
                }
            )


        elif (
            in_a
            and not in_b
        ):

            removed.append(
                {
                    "field":
                        key,

                    "value":
                        a[key],
                }
            )


        elif (
            a[key]
            != b[key]
        ):

            changed.append(
                {
                    "field":
                        key,

                    "file_a":
                        a[key],

                    "file_b":
                        b[key],
                }
            )


        else:

            unchanged.append(
                {
                    "field":
                        key,

                    "value":
                        a[key],
                }
            )


    return {
        "added":
            added,

        "removed":
            removed,

        "changed":
            changed,

        "unchanged_count":
            len(unchanged),

        "change_count":
            (
                len(added)
                + len(removed)
                + len(changed)
            ),
    }


def _compare_artefacts(
    artefacts_a: dict,
    artefacts_b: dict,
) -> dict:

    categories_a = (
        artefacts_a.get(
            "categories",
            {}
        )
    )

    categories_b = (
        artefacts_b.get(
            "categories",
            {}
        )
    )


    category_names = sorted(
        set(categories_a)
        | set(categories_b)
    )


    result = {}

    total_changes = 0


    for category in category_names:

        values_a = {
            item.get(
                "value"
            )
            for item in (
                categories_a.get(
                    category,
                    {}
                )
                .get(
                    "items",
                    []
                )
            )
        }


        values_b = {
            item.get(
                "value"
            )
            for item in (
                categories_b.get(
                    category,
                    {}
                )
                .get(
                    "items",
                    []
                )
            )
        }


        added = sorted(
            values_b
            - values_a
        )


        removed = sorted(
            values_a
            - values_b
        )


        if (
            added
            or removed
        ):

            result[
                category
            ] = {
                "added":
                    added,

                "removed":
                    removed,
            }


            total_changes += (
                len(added)
                + len(removed)
            )


    return {
        "categories":
            result,

        "change_count":
            total_changes,
    }


def _compare_timelines(
    timeline_a: dict,
    timeline_b: dict,
) -> dict:

    embedded_a = (
        _timeline_event_set(
            timeline_a,
            scope=(
                "embedded_metadata"
            ),
        )
    )


    embedded_b = (
        _timeline_event_set(
            timeline_b,
            scope=(
                "embedded_metadata"
            ),
        )
    )


    added = sorted(
        embedded_b
        - embedded_a
    )


    removed = sorted(
        embedded_a
        - embedded_b
    )


    return {
        "added":
            [
                _timeline_tuple_to_dict(
                    event
                )
                for event in added
            ],

        "removed":
            [
                _timeline_tuple_to_dict(
                    event
                )
                for event in removed
            ],

        "change_count":
            (
                len(added)
                + len(removed)
            ),

        "note": (
            "Evidence-copy filesystem timestamps "
            "are excluded from timeline comparison "
            "because the uploaded comparison copies "
            "are created during analysis."
        ),
    }


def _timeline_event_set(
    timeline: dict,
    *,
    scope: str,
) -> set:

    result = set()


    for event in timeline.get(
        "events",
        []
    ):

        if (
            event.get(
                "scope"
            )
            != scope
        ):
            continue


        result.add(
            (
                event.get(
                    "event_type"
                ),

                event.get(
                    "source_group"
                ),

                event.get(
                    "source_field"
                ),

                event.get(
                    "timestamp_utc"
                ),

                event.get(
                    "timestamp_original"
                ),
            )
        )


    return result


def _timeline_tuple_to_dict(
    event: tuple,
) -> dict:

    return {
        "event_type":
            event[0],

        "source_group":
            event[1],

        "source_field":
            event[2],

        "timestamp_utc":
            event[3],

        "timestamp_original":
            event[4],
    }