import pytest

from forensics.strings import extract_interesting_artefacts

from .conftest import category_values, write_text_fixture


pytestmark = pytest.mark.unit


def test_real_artefacts_are_retained(tmp_path):
    path = write_text_fixture(
        tmp_path,
        "artefacts.txt",
        r"""
URL: https://example.com/login
Email: analyst@example.org
Domain: ns.adobe.com
Windows: C:\Users\jamie\Downloads\payload.exe
Unix: /home/analyst/scripts/run.sh
Executable: payload.exe
Script: script.ps1
powershell.exe -enc QUJDREVGRw==
cmd.exe /c whoami
""".strip(),
    )

    result = extract_interesting_artefacts(path)

    assert "https://example.com/login" in category_values(result, "urls")
    assert "analyst@example.org" in category_values(result, "email_addresses")
    assert "ns.adobe.com" in category_values(result, "domains")
    assert r"C:\Users\jamie\Downloads\payload.exe" in category_values(
        result,
        "windows_paths",
    )
    assert "/home/analyst/scripts/run.sh" in category_values(
        result,
        "unix_paths",
    )
    assert "payload.exe" in category_values(result, "executables")
    assert "script.ps1" in category_values(result, "executables")
    assert "powershell.exe -enc QUJDREVGRw==" in category_values(
        result,
        "command_lines",
    )
    assert "cmd.exe /c whoami" in category_values(result, "command_lines")


def test_known_binary_false_positives_are_rejected(tmp_path):
    path = write_text_fixture(
        tmp_path,
        "false-positives.txt",
        r"""
2@B.Tv
i:\V)4
w:\r_j
/17/Q
/ColorSpace/DeviceRGB/Subtype/Image/Height
/Filter/FlateDecode/Length
/Type/Pages/Count
sH,.>H
SH>U"L
Sh.\|
""".strip(),
    )

    result = extract_interesting_artefacts(path)

    assert "2@B.Tv" not in category_values(result, "email_addresses")
    assert r"i:\V)4" not in category_values(result, "windows_paths")
    assert r"w:\r_j" not in category_values(result, "windows_paths")
    assert "/17/Q" not in category_values(result, "unix_paths")
    assert (
        "/ColorSpace/DeviceRGB/Subtype/Image/Height"
        not in category_values(result, "unix_paths")
    )
    assert "/Filter/FlateDecode/Length" not in category_values(
        result,
        "unix_paths",
    )
    assert "/Type/Pages/Count" not in category_values(result, "unix_paths")

    commands = category_values(result, "command_lines")
    assert "sH,.>H" not in commands
    assert 'SH>U"L' not in commands
    assert r"Sh.\|" not in commands


def test_dot_com_domains_are_not_executable_references(tmp_path):
    path = write_text_fixture(
        tmp_path,
        "domains.txt",
        """
ns.adobe.com
ns.google.com
example.com
payload.com
""".strip(),
    )

    result = extract_interesting_artefacts(path)

    domains = category_values(result, "domains")
    executables = category_values(result, "executables")

    assert "ns.adobe.com" in domains
    assert "ns.google.com" in domains
    assert "example.com" in domains
    assert "payload.com" in domains

    assert "ns.adobe.com" not in executables
    assert "ns.google.com" not in executables
    assert "example.com" not in executables
    assert "payload.com" not in executables


def test_offsets_are_recorded_for_detected_artefacts(tmp_path):
    path = write_text_fixture(
        tmp_path,
        "offset.txt",
        "prefix\npowershell.exe -enc QUJDREVGRw==\nsuffix\n",
    )

    result = extract_interesting_artefacts(path)

    command_category = result["categories"]["command_lines"]
    assert command_category["count"] == 1

    item = command_category["items"][0]
    assert item["offsets"]
    assert item["offsets_hex"]
    assert item["encodings"]
