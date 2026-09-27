import os
import shutil
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"

STATIC_DIR = BASE_DIR / "static"

BUNDLED_EXIFTOOL_PATH = (
    BASE_DIR
    / "tools"
    / "exiftool"
    / "exiftool.exe"
)


def resolve_exiftool_path() -> str | None:
    """
    Resolve the ExifTool executable without assuming a single operating system.

    Resolution order:
    1. Explicit EXIFTOOL_PATH environment variable.
       - May be a full path or a command name available on PATH.
    2. Bundled Windows executable when running on Windows.
    3. Native `exiftool` command available on PATH.

    Returns None when no usable executable can be resolved.
    """

    configured = (
        os.getenv(
            "EXIFTOOL_PATH",
            "",
        )
        .strip()
    )

    if configured:
        expanded = os.path.expandvars(
            os.path.expanduser(
                configured
            )
        )

        candidate = Path(
            expanded
        )

        if (
            candidate.exists()
            and candidate.is_file()
        ):
            return str(
                candidate.resolve()
            )

        located = shutil.which(
            configured
        )

        if located:
            return located

        return None

    if sys.platform.startswith(
        "win"
    ):
        if (
            BUNDLED_EXIFTOOL_PATH.exists()
            and BUNDLED_EXIFTOOL_PATH.is_file()
        ):
            return str(
                BUNDLED_EXIFTOOL_PATH.resolve()
            )

    return shutil.which(
        "exiftool"
    )


# Compatibility value for any older code that still imports EXIFTOOL_PATH.
# New code should call resolve_exiftool_path() when it needs to execute ExifTool
# so environment changes and platform-specific discovery are handled cleanly.
EXIFTOOL_PATH = resolve_exiftool_path()


LOCAL_EVIDENCE_ROOT = Path(
    os.getenv(
        "LOCAL_EVIDENCE_ROOT",
        r"C:\ForensicEvidence",
    )
).resolve()

MAX_UPLOAD_SIZE = (
    250
    * 1024
    * 1024
)  # 250 MB

MAX_BULK_FILES = 25

MAX_BULK_TOTAL_SIZE = (
    500
    * 1024
    * 1024
)  # 500 MB per bulk request


UPLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True,
)



def _csv_environment(
    name: str,
    default: str,
) -> tuple[str, ...]:

    raw = os.getenv(
        name,
        default,
    )

    values = [
        value.strip()
        for value in raw.split(",")
        if value.strip()
    ]

    return tuple(
        values
    )


HTTP_ALLOWED_HOSTS = _csv_environment(
    "HTTP_ALLOWED_HOSTS",
    "127.0.0.1,localhost,::1,testserver",
)

HTTP_ALLOWED_ORIGIN_HOSTS = _csv_environment(
    "HTTP_ALLOWED_ORIGIN_HOSTS",
    "127.0.0.1,localhost,::1,testserver",
)

ENABLE_API_DOCS = (
    os.getenv(
        "ENABLE_API_DOCS",
        "0",
    )
    .strip()
    .lower()
    in {
        "1",
        "true",
        "yes",
        "on",
    }
)
