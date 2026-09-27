from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


MAX_LISTED_MEMBERS = 100
MAX_INSPECTED_MEMBERS = 10_000

MAX_DECLARED_UNCOMPRESSED_BYTES = (
    5
    * 1024
    * 1024
    * 1024
)

HIGH_COMPRESSION_RATIO = 100


ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".gz",
    ".tar",
    ".jar",
}


EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
}


def analyze_zip_archive(
    file_path: Path,
) -> dict:

    observations = []
    embedded_objects = []

    try:

        with zipfile.ZipFile(
            file_path
        ) as archive:

            infos = archive.infolist()

            member_count = len(
                infos
            )

            inspected_infos = infos[
                :MAX_INSPECTED_MEMBERS
            ]

            inspection_truncated = (
                member_count
                > len(inspected_infos)
            )

            total_compressed = sum(
                info.compress_size
                for info in infos
            )

            total_uncompressed = sum(
                info.file_size
                for info in infos
            )

            encrypted_members = [
                info
                for info in inspected_infos
                if (
                    info.flag_bits
                    & 0x1
                )
            ]

            traversal_members = []
            nested_archives = []
            executable_members = []
            symlink_members = []

            for info in inspected_infos:

                name = (
                    info.filename
                    .replace(
                        "\\",
                        "/",
                    )
                )

                if _is_suspicious_path(
                    name
                ):

                    traversal_members.append(
                        name
                    )

                if _is_symlink_member(
                    info
                ):

                    symlink_members.append(
                        name
                    )

                suffix = (
                    Path(name)
                    .suffix
                    .lower()
                )

                if (
                    suffix
                    in ARCHIVE_EXTENSIONS
                ):

                    nested_archives.append(
                        name
                    )

                if (
                    suffix
                    in EXECUTABLE_EXTENSIONS
                ):

                    executable_members.append(
                        name
                    )

            compression_ratio = None

            if total_compressed > 0:

                compression_ratio = (
                    total_uncompressed
                    / total_compressed
                )

            if traversal_members:

                observations.append(
                    {
                        "severity": "warning",
                        "title": (
                            "Potential path traversal "
                            "members"
                        ),
                        "message": (
                            f"{len(traversal_members)} "
                            "archive member(s) contain "
                            "paths that could escape a "
                            "naive extraction directory."
                        ),
                    }
                )

            if symlink_members:

                observations.append(
                    {
                        "severity": "warning",
                        "title": (
                            "Symbolic-link archive members"
                        ),
                        "message": (
                            f"{len(symlink_members)} "
                            "archive member(s) are marked "
                            "as symbolic links. Extraction "
                            "requires destination/path review."
                        ),
                    }
                )

            if encrypted_members:

                observations.append(
                    {
                        "severity": "info",
                        "title": "Encrypted members",
                        "message": (
                            f"{len(encrypted_members)} "
                            "encrypted archive member(s) "
                            "were identified in the inspected "
                            "member set."
                        ),
                    }
                )

            if (
                compression_ratio is not None
                and compression_ratio
                > HIGH_COMPRESSION_RATIO
            ):

                observations.append(
                    {
                        "severity": "warning",
                        "title": "High compression ratio",
                        "message": (
                            "The archive has a very high "
                            "overall compression ratio. "
                            "This may warrant resource-usage "
                            "review before extraction."
                        ),
                    }
                )

            declared_size_limit_exceeded = (
                total_uncompressed
                > MAX_DECLARED_UNCOMPRESSED_BYTES
            )

            if declared_size_limit_exceeded:

                observations.append(
                    {
                        "severity": "warning",
                        "title": (
                            "Very large declared "
                            "uncompressed size"
                        ),
                        "message": (
                            "The archive declares more than "
                            f"{MAX_DECLARED_UNCOMPRESSED_BYTES} "
                            "bytes of uncompressed content. "
                            "Do not extract it without explicit "
                            "resource controls."
                        ),
                    }
                )

            if inspection_truncated:

                observations.append(
                    {
                        "severity": "warning",
                        "title": (
                            "Archive member inspection "
                            "limit reached"
                        ),
                        "message": (
                            f"The archive contains {member_count} "
                            "members. Static member-level checks "
                            f"were limited to the first "
                            f"{MAX_INSPECTED_MEMBERS} entries."
                        ),
                    }
                )

            for info in inspected_infos[
                :MAX_LISTED_MEMBERS
            ]:

                embedded_objects.append(
                    {
                        "type":
                            "archive_member",

                        "name":
                            info.filename,

                        "size":
                            info.file_size,

                        "compressed_size":
                            info.compress_size,

                        "encrypted":
                            bool(
                                info.flag_bits
                                & 0x1
                            ),

                        "symlink":
                            _is_symlink_member(
                                info
                            ),
                    }
                )

            return {
                "format": "zip",

                "status": "ok",

                "properties": {
                    "member_count":
                        member_count,

                    "members_inspected":
                        len(
                            inspected_infos
                        ),

                    "inspection_truncated":
                        inspection_truncated,

                    "total_compressed_bytes":
                        total_compressed,

                    "total_uncompressed_bytes":
                        total_uncompressed,

                    "declared_size_limit_exceeded":
                        declared_size_limit_exceeded,

                    "compression_ratio":
                        compression_ratio,

                    "encrypted_members":
                        len(
                            encrypted_members
                        ),

                    "path_traversal_members":
                        len(
                            traversal_members
                        ),

                    "symlink_members":
                        len(
                            symlink_members
                        ),

                    "nested_archives":
                        len(
                            nested_archives
                        ),

                    "executable_members":
                        len(
                            executable_members
                        ),
                },

                "observations":
                    observations,

                "embedded_objects":
                    embedded_objects,

                "limitations": [
                    (
                        "Archive members are inspected "
                        "from directory metadata only. "
                        "They are not extracted or executed."
                    ),
                    (
                        "Member-level security checks are "
                        f"limited to the first "
                        f"{MAX_INSPECTED_MEMBERS} entries."
                    ),
                ],
            }

    except zipfile.BadZipFile:

        return {
            "format": "zip",
            "status": "error",
            "properties": {},
            "observations": [
                {
                    "severity": "warning",
                    "title": "Malformed archive",
                    "message": (
                        "The file could not be parsed "
                        "as a valid ZIP archive."
                    ),
                }
            ],
            "embedded_objects": [],
        }


def _is_suspicious_path(
    name: str,
) -> bool:

    path = PurePosixPath(
        name
    )

    if path.is_absolute():

        return True

    if ".." in path.parts:

        return True

    if re.match(
        r"^[A-Za-z]:",
        name,
    ):

        return True

    return False


def _is_symlink_member(
    info: zipfile.ZipInfo,
) -> bool:

    mode = (
        info.external_attr
        >> 16
    )

    return stat.S_ISLNK(
        mode
    )
