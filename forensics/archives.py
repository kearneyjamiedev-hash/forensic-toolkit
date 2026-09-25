from pathlib import Path, PurePosixPath
import re
import zipfile


MAX_LISTED_MEMBERS = 100


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
                for info in infos
                if (
                    info.flag_bits
                    & 0x1
                )
            ]


            traversal_members = []


            nested_archives = []


            executable_members = []


            for info in infos:

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


            if encrypted_members:

                observations.append(
                    {
                        "severity": "info",
                        "title": "Encrypted members",
                        "message": (
                            f"{len(encrypted_members)} "
                            "encrypted archive member(s) "
                            "were identified."
                        ),
                    }
                )


            if (
                compression_ratio is not None
                and compression_ratio > 100
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


            for info in infos[
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
                    }
                )


            return {
                "format": "zip",

                "status": "ok",

                "properties": {
                    "member_count":
                        len(infos),

                    "total_compressed_bytes":
                        total_compressed,

                    "total_uncompressed_bytes":
                        total_uncompressed,

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
                    )
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