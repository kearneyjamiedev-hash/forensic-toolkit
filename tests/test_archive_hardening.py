import stat
import zipfile

import pytest

import forensics.archives as archives


pytestmark = pytest.mark.unit


def test_archive_traversal_is_reported(
    tmp_path,
):
    path = (
        tmp_path
        / "traversal.zip"
    )

    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:
        archive.writestr(
            "../outside.txt",
            "fixture",
        )

    result = (
        archives.analyze_zip_archive(
            path
        )
    )

    assert (
        result["properties"][
            "path_traversal_members"
        ]
        == 1
    )

    assert any(
        observation.get("severity")
        == "warning"
        for observation
        in result["observations"]
    )


def test_archive_symlink_member_is_reported(
    tmp_path,
):
    path = (
        tmp_path
        / "symlink.zip"
    )

    link = zipfile.ZipInfo(
        "link-to-file"
    )

    link.create_system = 3
    link.external_attr = (
        (
            stat.S_IFLNK
            | 0o777
        )
        << 16
    )

    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:
        archive.writestr(
            link,
            "target.txt",
        )

    result = (
        archives.analyze_zip_archive(
            path
        )
    )

    assert (
        result["properties"][
            "symlink_members"
        ]
        == 1
    )


def test_member_inspection_is_bounded(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        archives,
        "MAX_INSPECTED_MEMBERS",
        3,
    )

    path = (
        tmp_path
        / "many.zip"
    )

    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:

        for index in range(5):
            archive.writestr(
                f"{index}.txt",
                "fixture",
            )

    result = (
        archives.analyze_zip_archive(
            path
        )
    )

    properties = (
        result["properties"]
    )

    assert (
        properties["member_count"]
        == 5
    )
    assert (
        properties[
            "members_inspected"
        ]
        == 3
    )
    assert (
        properties[
            "inspection_truncated"
        ]
        is True
    )


def test_declared_size_warning_uses_configured_threshold(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        archives,
        "MAX_DECLARED_UNCOMPRESSED_BYTES",
        5,
    )

    path = (
        tmp_path
        / "large.zip"
    )

    with zipfile.ZipFile(
        path,
        "w",
    ) as archive:
        archive.writestr(
            "payload.txt",
            "1234567890",
        )

    result = (
        archives.analyze_zip_archive(
            path
        )
    )

    assert (
        result["properties"][
            "declared_size_limit_exceeded"
        ]
        is True
    )
