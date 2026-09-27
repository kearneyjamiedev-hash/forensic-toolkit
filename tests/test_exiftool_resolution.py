from pathlib import Path
from types import SimpleNamespace

import pytest

import app.config as config
import forensics.metadata as metadata


pytestmark = pytest.mark.unit


def test_explicit_exiftool_path_wins(
    tmp_path,
    monkeypatch,
):
    executable = (
        tmp_path
        / "custom-exiftool"
    )
    executable.write_text(
        "test",
        encoding="utf-8",
    )

    monkeypatch.setenv(
        "EXIFTOOL_PATH",
        str(executable),
    )

    monkeypatch.setattr(
        config.shutil,
        "which",
        lambda _name: None,
    )

    resolved = (
        config.resolve_exiftool_path()
    )

    assert resolved == str(
        executable.resolve()
    )


def test_exiftool_environment_command_name_uses_path(
    monkeypatch,
):
    monkeypatch.setenv(
        "EXIFTOOL_PATH",
        "custom-exiftool",
    )

    monkeypatch.setattr(
        config.shutil,
        "which",
        lambda name: (
            "/opt/tools/custom-exiftool"
            if name == "custom-exiftool"
            else None
        ),
    )

    assert (
        config.resolve_exiftool_path()
        == "/opt/tools/custom-exiftool"
    )


def test_windows_prefers_bundled_executable(
    tmp_path,
    monkeypatch,
):
    executable = (
        tmp_path
        / "exiftool.exe"
    )
    executable.write_text(
        "test",
        encoding="utf-8",
    )

    monkeypatch.delenv(
        "EXIFTOOL_PATH",
        raising=False,
    )

    monkeypatch.setattr(
        config.sys,
        "platform",
        "win32",
    )

    monkeypatch.setattr(
        config,
        "BUNDLED_EXIFTOOL_PATH",
        executable,
    )

    monkeypatch.setattr(
        config.shutil,
        "which",
        lambda _name: (
            "/should/not/be/used"
        ),
    )

    assert (
        config.resolve_exiftool_path()
        == str(executable.resolve())
    )


def test_non_windows_uses_native_exiftool_from_path(
    monkeypatch,
):
    monkeypatch.delenv(
        "EXIFTOOL_PATH",
        raising=False,
    )

    monkeypatch.setattr(
        config.sys,
        "platform",
        "linux",
    )

    monkeypatch.setattr(
        config.shutil,
        "which",
        lambda name: (
            "/usr/bin/exiftool"
            if name == "exiftool"
            else None
        ),
    )

    assert (
        config.resolve_exiftool_path()
        == "/usr/bin/exiftool"
    )


def test_missing_exiftool_returns_none(
    monkeypatch,
):
    monkeypatch.delenv(
        "EXIFTOOL_PATH",
        raising=False,
    )

    monkeypatch.setattr(
        config.sys,
        "platform",
        "linux",
    )

    monkeypatch.setattr(
        config.shutil,
        "which",
        lambda _name: None,
    )

    assert (
        config.resolve_exiftool_path()
        is None
    )


def test_metadata_returns_unavailable_when_exiftool_missing(
    tmp_path,
    monkeypatch,
):
    sample = (
        tmp_path
        / "sample.txt"
    )
    sample.write_text(
        "test",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        metadata,
        "resolve_exiftool_path",
        lambda: None,
    )

    called = False

    def should_not_run(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError(
            "subprocess.run should not be called"
        )

    monkeypatch.setattr(
        metadata.subprocess,
        "run",
        should_not_run,
    )

    result = (
        metadata.extract_metadata(
            sample
        )
    )

    assert result["status"] == "unavailable"
    assert result["field_count"] == 0
    assert called is False


def test_metadata_executes_resolved_binary_without_shell(
    tmp_path,
    monkeypatch,
):
    sample = (
        tmp_path
        / "sample.jpg"
    )
    sample.write_bytes(
        b"fixture"
    )

    monkeypatch.setattr(
        metadata,
        "resolve_exiftool_path",
        lambda: "/usr/bin/exiftool",
    )

    captured = {}

    def fake_run(
        command,
        **kwargs,
    ):
        captured[
            "command"
        ] = command
        captured[
            "kwargs"
        ] = kwargs

        return SimpleNamespace(
            returncode=0,
            stdout=(
                '[{"SourceFile":"sample.jpg",'
                '"File:FileType":"JPEG",'
                '"File:MIMEType":"image/jpeg"}]'
            ),
            stderr="",
        )

    monkeypatch.setattr(
        metadata.subprocess,
        "run",
        fake_run,
    )

    result = (
        metadata.extract_metadata(
            sample
        )
    )

    assert (
        captured["command"][0]
        == "/usr/bin/exiftool"
    )
    assert (
        captured["command"][-1]
        == str(sample)
    )
    assert (
        captured["kwargs"]["shell"]
        is False
    )
    assert (
        captured["kwargs"]["timeout"]
        == metadata.EXIFTOOL_TIMEOUT_SECONDS
    )

    assert result["status"] == "ok"
    assert (
        result["summary"]["file_type"]
        == "JPEG"
    )
    assert (
        result["summary"]["mime_type"]
        == "image/jpeg"
    )


def test_metadata_timeout_is_reported_cleanly(
    tmp_path,
    monkeypatch,
):
    sample = (
        tmp_path
        / "sample.bin"
    )
    sample.write_bytes(
        b"fixture"
    )

    monkeypatch.setattr(
        metadata,
        "resolve_exiftool_path",
        lambda: "/usr/bin/exiftool",
    )

    def timeout(
        command,
        **_kwargs,
    ):
        raise (
            metadata.subprocess.TimeoutExpired(
                command,
                30,
            )
        )

    monkeypatch.setattr(
        metadata.subprocess,
        "run",
        timeout,
    )

    result = (
        metadata.extract_metadata(
            sample
        )
    )

    assert result["status"] == "error"
    assert "timed out" in (
        result["error"].lower()
    )
