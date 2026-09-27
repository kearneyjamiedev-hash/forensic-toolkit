import asyncio
from io import BytesIO
from pathlib import Path
from uuid import uuid4

import pytest

from app.ingestion import (
    MAX_STORED_FILENAME_LENGTH,
    UploadLimitExceeded,
    evidence_directory,
    hash_upload_limited,
    normalise_upload_filename,
    safe_child_path,
    save_upload_limited,
)


pytestmark = pytest.mark.unit


class FakeUpload:
    def __init__(
        self,
        data: bytes,
        filename: str = "fixture.bin",
    ):
        self.filename = filename
        self._stream = BytesIO(
            data
        )
        self.closed = False

    async def read(
        self,
        size: int,
    ) -> bytes:
        return self._stream.read(
            size
        )

    async def close(
        self,
    ) -> None:
        self.closed = True
        self._stream.close()


def test_filename_discards_directory_components():
    assert (
        normalise_upload_filename(
            "../../secret.txt"
        )
        == "secret.txt"
    )

    assert (
        normalise_upload_filename(
            r"C:\Users\Analyst\payload.exe"
        )
        == "payload.exe"
    )


def test_filename_neutralises_windows_reserved_names():
    assert (
        normalise_upload_filename(
            "CON.txt"
        )
        == "_CON.txt"
    )

    assert (
        normalise_upload_filename(
            "lpt1"
        )
        == "_lpt1"
    )


def test_filename_removes_control_and_invalid_characters():
    result = normalise_upload_filename(
        ' bad\x00:name?.txt. '
    )

    assert "\x00" not in result
    assert ":" not in result
    assert "?" not in result
    assert not result.endswith(
        "."
    )


def test_filename_length_is_bounded_and_suffix_preserved():
    result = normalise_upload_filename(
        ("a" * 400)
        + ".txt"
    )

    assert len(result) <= (
        MAX_STORED_FILENAME_LENGTH
    )
    assert result.endswith(
        ".txt"
    )


def test_safe_child_path_rejects_escape(
    tmp_path,
):
    with pytest.raises(
        ValueError
    ):
        safe_child_path(
            tmp_path,
            "../outside.txt",
        )


def test_evidence_directory_requires_uuid(
    tmp_path,
):
    with pytest.raises(
        ValueError
    ):
        evidence_directory(
            tmp_path,
            "../../escape",
        )

    evidence_id = str(
        uuid4()
    )

    result = evidence_directory(
        tmp_path,
        evidence_id,
    )

    assert (
        result.parent
        == tmp_path.resolve()
    )


def test_limited_upload_writes_content_and_closes(
    tmp_path,
):
    upload = FakeUpload(
        b"hello world"
    )

    destination = (
        tmp_path
        / "sample.bin"
    )

    size = asyncio.run(
        save_upload_limited(
            upload,
            destination,
            max_size=100,
        )
    )

    assert size == 11
    assert (
        destination.read_bytes()
        == b"hello world"
    )
    assert upload.closed is True


def test_oversized_upload_removes_partial_file(
    tmp_path,
):
    upload = FakeUpload(
        b"A" * 32
    )

    destination = (
        tmp_path
        / "oversized.bin"
    )

    with pytest.raises(
        UploadLimitExceeded
    ):
        asyncio.run(
            save_upload_limited(
                upload,
                destination,
                max_size=10,
            )
        )

    assert (
        destination.exists()
        is False
    )
    assert upload.closed is True


def test_hash_upload_enforces_limit_without_persisting():
    upload = FakeUpload(
        b"abc"
    )

    digest, size = asyncio.run(
        hash_upload_limited(
            upload,
            max_size=10,
        )
    )

    assert size == 3
    assert digest == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )
    assert upload.closed is True
