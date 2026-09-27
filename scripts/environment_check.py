from __future__ import annotations

import importlib
import platform
import shutil
import sys
from pathlib import Path


# When this file is executed directly:
#
#     python scripts/environment_check.py
#
# Python places the scripts/ directory on sys.path, not the repository root.
# Add the project root explicitly so imports such as app.config work without
# requiring PYTHONPATH or installing the project as a package.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from app.config import (  # noqa: E402
    DATA_DIR,
    UPLOAD_DIR,
    resolve_exiftool_path,
)


REQUIRED_MODULES = {
    "fastapi": "FastAPI",
    "uvicorn": "Uvicorn",
    "multipart": "python-multipart",
    "reportlab": "ReportLab",
    "pypdf": "pypdf",
    "PIL": "Pillow",
    "pefile": "pefile",
    "olefile": "olefile",
    "defusedxml": "defusedxml",
}


def check_imports() -> list[str]:
    failures = []

    for module_name, label in REQUIRED_MODULES.items():
        try:
            importlib.import_module(
                module_name
            )
            print(
                f"[OK] {label}"
            )
        except ImportError:
            failures.append(
                label
            )
            print(
                f"[FAIL] {label}"
            )

    return failures


def check_data_directory() -> bool:
    try:
        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )
        UPLOAD_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        probe = (
            DATA_DIR
            / ".environment-write-test"
        )

        probe.write_text(
            "ok",
            encoding="utf-8",
        )

        probe.unlink()

        print(
            f"[OK] Writable data directory: {DATA_DIR}"
        )

        return True

    except OSError as error:
        print(
            f"[FAIL] Data directory is not writable: {error}"
        )

        return False


def main() -> int:
    print(
        "Digital Forensic Toolkit environment check"
    )
    print(
        "==========================================="
    )

    print(
        f"Python: {sys.version.split()[0]}"
    )
    print(
        f"Platform: {platform.platform()}"
    )

    if sys.version_info[:2] != (
        3,
        12,
    ):
        print(
            "[WARN] The validated project runtime is Python 3.12."
        )

    print()
    print(
        "Python modules"
    )
    print(
        "--------------"
    )

    import_failures = (
        check_imports()
    )

    print()
    print(
        "ExifTool"
    )
    print(
        "--------"
    )

    exiftool = (
        resolve_exiftool_path()
    )

    if exiftool:
        print(
            f"[OK] {exiftool}"
        )
    else:
        print(
            "[FAIL] ExifTool could not be resolved."
        )

    print()
    print(
        "Storage"
    )
    print(
        "-------"
    )

    writable = (
        check_data_directory()
    )

    print()
    print(
        "Native acquisition"
    )
    print(
        "------------------"
    )

    if sys.platform.startswith(
        "win"
    ):
        powershell = (
            shutil.which(
                "powershell.exe"
            )
            or shutil.which(
                "powershell"
            )
        )

        if powershell:
            print(
                f"[OK] Windows native collector prerequisites present: {powershell}"
            )
        else:
            print(
                "[WARN] PowerShell was not found; native file selection may fail."
            )

    else:
        print(
            "[INFO] Browser/static analysis workflows are supported."
        )
        print(
            "[INFO] Windows native logical acquisition is not supported in this runtime."
        )

    failed = (
        bool(import_failures)
        or not exiftool
        or not writable
    )

    print()
    print(
        "Result"
    )
    print(
        "------"
    )

    if failed:
        print(
            "Environment check FAILED."
        )
        return 1

    print(
        "Environment check PASSED."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
