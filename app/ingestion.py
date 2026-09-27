from __future__ import annotations

import hashlib
import re
from pathlib import Path
from uuid import UUID


UPLOAD_CHUNK_SIZE = 1024 * 1024
MAX_STORED_FILENAME_LENGTH = 180

_CONTROL_CHARACTERS = re.compile(
    r"[\x00-\x1f\x7f]"
)

_INVALID_FILENAME_CHARACTERS = set(
    '<>:"/\\|?*'
)

_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *{
        f"COM{index}"
        for index in range(1, 10)
    },
    *{
        f"LPT{index}"
        for index in range(1, 10)
    },
}


class UploadLimitExceeded(ValueError):
    def __init__(
        self,
        *,
        limit_bytes: int,
        observed_bytes: int,
    ):
        self.limit_bytes = limit_bytes
        self.observed_bytes = observed_bytes

        super().__init__(
            "Upload exceeds the permitted size."
        )


def normalise_upload_filename(
    filename: str | None,
    *,
    fallback: str = "evidence.bin",
) -> str:
    """
    Convert a browser-supplied filename into a safe single filesystem component.

    The browser filename is untrusted input. Directory components are discarded,
    control characters and Windows-invalid filename characters are replaced,
    reserved device names are neutralised and the stored component is bounded.
    """

    fallback = (
        fallback.strip()
        or "evidence.bin"
    )

    raw = (
        filename
        or fallback
    )

    # Browser implementations normally send only a basename, but some clients
    # may submit a full Windows or POSIX-style path.
    raw = raw.replace(
        "\\",
        "/",
    )

    name = raw.rsplit(
        "/",
        1,
    )[-1]

    name = _CONTROL_CHARACTERS.sub(
        "_",
        name,
    )

    name = "".join(
        "_"
        if character
        in _INVALID_FILENAME_CHARACTERS
        else character
        for character in name
    )

    # Windows silently strips trailing spaces/dots from ordinary path
    # components. Removing them explicitly prevents ambiguous storage names.
    name = (
        name.strip()
        .rstrip(" .")
    )

    if name in {
        "",
        ".",
        "..",
    }:
        name = fallback

    first_component = (
        name.split(
            ".",
            1,
        )[0]
        .upper()
    )

    if (
        first_component
        in _WINDOWS_RESERVED_NAMES
    ):
        name = (
            "_"
            + name
        )

    name = _truncate_filename(
        name,
        MAX_STORED_FILENAME_LENGTH,
    )

    if name in {
        "",
        ".",
        "..",
    }:
        return fallback

    return name


def safe_child_path(
    parent: Path,
    filename: str,
) -> Path:
    """
    Resolve a path and prove that it remains beneath its intended directory.
    """

    resolved_parent = (
        parent.resolve()
    )

    candidate = (
        resolved_parent
        / filename
    ).resolve()

    try:
        candidate.relative_to(
            resolved_parent
        )
    except ValueError as error:
        raise ValueError(
            "The requested storage path escapes its permitted directory."
        ) from error

    return candidate


def evidence_directory(
    root: Path,
    evidence_id: str,
) -> Path:
    """
    Build an evidence directory only from a syntactically valid UUID.
    """

    parsed = UUID(
        evidence_id
    )

    canonical_id = str(
        parsed
    )

    directory = (
        root.resolve()
        / canonical_id
    ).resolve()

    try:
        directory.relative_to(
            root.resolve()
        )
    except ValueError as error:
        raise ValueError(
            "The evidence directory escapes the configured evidence root."
        ) from error

    return directory


async def save_upload_limited(
    upload,
    destination: Path,
    *,
    max_size: int,
) -> int:
    """
    Stream an upload to a new file while enforcing a hard byte limit.

    Partial files are removed on every failure and the UploadFile is always
    closed. Existing files are never overwritten.
    """

    if max_size <= 0:
        raise ValueError(
            "max_size must be greater than zero."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    total_bytes = 0

    try:
        with destination.open(
            "xb"
        ) as output:

            while True:
                chunk = await upload.read(
                    UPLOAD_CHUNK_SIZE
                )

                if not chunk:
                    break

                total_bytes += len(
                    chunk
                )

                if (
                    total_bytes
                    > max_size
                ):
                    raise UploadLimitExceeded(
                        limit_bytes=max_size,
                        observed_bytes=(
                            total_bytes
                        ),
                    )

                output.write(
                    chunk
                )

    except Exception:
        try:
            destination.unlink(
                missing_ok=True
            )
        except OSError:
            pass

        raise

    finally:
        await upload.close()

    return total_bytes


async def hash_upload_limited(
    upload,
    *,
    max_size: int,
) -> tuple[str, int]:
    """
    SHA-256 an uploaded stream without persisting it, while enforcing the same
    request-size boundary used by stored uploads.
    """

    if max_size <= 0:
        raise ValueError(
            "max_size must be greater than zero."
        )

    digest = hashlib.sha256()
    total_bytes = 0

    try:
        while True:
            chunk = await upload.read(
                UPLOAD_CHUNK_SIZE
            )

            if not chunk:
                break

            total_bytes += len(
                chunk
            )

            if (
                total_bytes
                > max_size
            ):
                raise UploadLimitExceeded(
                    limit_bytes=max_size,
                    observed_bytes=(
                        total_bytes
                    ),
                )

            digest.update(
                chunk
            )

    finally:
        await upload.close()

    return (
        digest.hexdigest(),
        total_bytes,
    )


def _truncate_filename(
    filename: str,
    maximum_length: int,
) -> str:
    if len(filename) <= maximum_length:
        return filename

    path = Path(
        filename
    )

    suffix = path.suffix

    if (
        suffix
        and len(suffix) < 32
    ):
        stem_length = (
            maximum_length
            - len(suffix)
        )

        if stem_length > 0:
            return (
                filename[:stem_length]
                + suffix
            )

    return filename[
        :maximum_length
    ]
