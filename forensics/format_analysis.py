from pathlib import Path
import zipfile

from forensics.pdf import analyze_pdf
from forensics.office import (
    analyze_office,
    identify_office_package,
)
from forensics.images import analyze_image
from forensics.archives import analyze_zip_archive
from forensics.executables import analyze_pe


def analyze_format(
    file_path: Path,
    original_filename: str,
) -> dict:

    try:

        with file_path.open("rb") as file:
            header = file.read(4096)

    except OSError as error:

        return {
            "format": None,
            "status": "error",
            "properties": {},
            "observations": [
                {
                    "severity": "warning",
                    "title": "Format analysis failed",
                    "message": str(error),
                }
            ],
            "embedded_objects": [],
        }


    if header.startswith(b"%PDF-"):

        return analyze_pdf(
            file_path
        )


    if (
        header.startswith(
            b"\x89PNG\r\n\x1a\n"
        )
        or header.startswith(
            b"\xff\xd8"
        )
    ):

        return analyze_image(
            file_path
        )


    if header.startswith(b"MZ"):

        return analyze_pe(
            file_path
        )


    if zipfile.is_zipfile(
        file_path
    ):

        office_type = (
            identify_office_package(
                file_path
            )
        )


        if office_type:

            return analyze_office(
                file_path,
                office_type,
            )


        return analyze_zip_archive(
            file_path
        )


    return {
        "format": None,
        "status": "not_applicable",
        "properties": {},
        "observations": [],
        "embedded_objects": [],
    }