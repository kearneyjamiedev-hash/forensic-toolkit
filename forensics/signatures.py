import mimetypes
import struct
import zipfile
from pathlib import Path


SIGNATURES = [
    {
        "name": "PDF document",
        "mime": "application/pdf",
        "magic": b"%PDF-",
        "extensions": {".pdf"},
    },
    {
        "name": "PNG image",
        "mime": "image/png",
        "magic": b"\x89PNG\r\n\x1a\n",
        "extensions": {".png"},
    },
    {
        "name": "JPEG image",
        "mime": "image/jpeg",
        "magic": b"\xff\xd8\xff",
        "extensions": {".jpg", ".jpeg", ".jpe"},
    },
    {
        "name": "GIF image",
        "mime": "image/gif",
        "magic": b"GIF8",
        "extensions": {".gif"},
    },
    {
        "name": "7-Zip archive",
        "mime": "application/x-7z-compressed",
        "magic": b"7z\xbc\xaf\x27\x1c",
        "extensions": {".7z"},
    },
    {
        "name": "RAR archive",
        "mime": "application/vnd.rar",
        "magic": b"Rar!\x1a\x07",
        "extensions": {".rar"},
    },
    {
        "name": "GZIP archive",
        "mime": "application/gzip",
        "magic": b"\x1f\x8b",
        "extensions": {".gz", ".gzip"},
    },
    {
        "name": "OLE Compound File",
        "mime": "application/x-ole-storage",
        "magic": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "extensions": {
            ".doc",
            ".xls",
            ".ppt",
            ".msg",
            ".msi",
        },
    },
    {
        "name": "SQLite database",
        "mime": "application/vnd.sqlite3",
        "magic": b"SQLite format 3\x00",
        "extensions": {".sqlite", ".sqlite3", ".db"},
    },
    {
        "name": "ELF executable",
        "mime": "application/x-elf",
        "magic": b"\x7fELF",
        "extensions": {".elf", ".so"},
    },
]


def _detect_pe(file_path: Path) -> dict | None:
    with file_path.open("rb") as file:
        if file.read(2) != b"MZ":
            return None

        file.seek(0x3C)
        pe_offset_bytes = file.read(4)

        if len(pe_offset_bytes) != 4:
            return None

        pe_offset = struct.unpack("<I", pe_offset_bytes)[0]

        file.seek(pe_offset)

        if file.read(4) != b"PE\x00\x00":
            return None

    return {
        "name": "Windows Portable Executable",
        "mime": "application/vnd.microsoft.portable-executable",
        "extensions": {
            ".exe",
            ".dll",
            ".sys",
            ".scr",
            ".cpl",
            ".ocx",
        },
    }


def _detect_zip_type(file_path: Path) -> dict | None:
    if not zipfile.is_zipfile(file_path):
        return None

    try:
        with zipfile.ZipFile(file_path) as archive:
            names = set(archive.namelist())

            if "[Content_Types].xml" in names:
                if any(name.startswith("word/") for name in names):
                    return {
                        "name": "Microsoft Word OOXML document",
                        "mime": (
                            "application/vnd.openxmlformats-officedocument."
                            "wordprocessingml.document"
                        ),
                        "extensions": {".docx", ".docm"},
                    }

                if any(name.startswith("xl/") for name in names):
                    return {
                        "name": "Microsoft Excel OOXML workbook",
                        "mime": (
                            "application/vnd.openxmlformats-officedocument."
                            "spreadsheetml.sheet"
                        ),
                        "extensions": {".xlsx", ".xlsm"},
                    }

                if any(name.startswith("ppt/") for name in names):
                    return {
                        "name": "Microsoft PowerPoint OOXML presentation",
                        "mime": (
                            "application/vnd.openxmlformats-officedocument."
                            "presentationml.presentation"
                        ),
                        "extensions": {".pptx", ".pptm"},
                    }

            if "META-INF/MANIFEST.MF" in names:
                return {
                    "name": "Java archive",
                    "mime": "application/java-archive",
                    "extensions": {".jar"},
                }

            if "AndroidManifest.xml" in names:
                return {
                    "name": "Android application package",
                    "mime": "application/vnd.android.package-archive",
                    "extensions": {".apk"},
                }

    except (zipfile.BadZipFile, OSError):
        pass

    return {
        "name": "ZIP archive",
        "mime": "application/zip",
        "extensions": {
            ".zip",
            ".docx",
            ".xlsx",
            ".pptx",
            ".odt",
            ".ods",
            ".odp",
            ".epub",
        },
    }


def detect_file_type(file_path: Path, original_filename: str) -> dict:
    extension = Path(original_filename).suffix.lower()

    with file_path.open("rb") as file:
        header = file.read(64)

    pe_result = _detect_pe(file_path)

    if pe_result:
        detected = pe_result
    else:
        zip_result = _detect_zip_type(file_path)

        if zip_result:
            detected = zip_result
        else:
            detected = None

            for signature in SIGNATURES:
                if header.startswith(signature["magic"]):
                    detected = signature
                    break

    if detected is None:
        extension_mime, _ = mimetypes.guess_type(original_filename)

        return {
            "detected_type": "Unknown signature",
            "detected_mime": None,
            "extension": extension or None,
            "extension_mime": extension_mime,
            "signature_recognised": False,
            "extension_matches": None,
        }

    compatible_extensions = detected["extensions"]

    return {
        "detected_type": detected["name"],
        "detected_mime": detected["mime"],
        "extension": extension or None,
        "extension_mime": mimetypes.guess_type(original_filename)[0],
        "signature_recognised": True,
        "extension_matches": extension in compatible_extensions,
    }