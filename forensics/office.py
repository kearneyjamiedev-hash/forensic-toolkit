from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET


MAX_XML_BYTES = (
    2
    * 1024
    * 1024
)


CORE_NAMESPACES = {
    "dc":
        "http://purl.org/dc/elements/1.1/",

    "cp":
        (
            "http://schemas.openxmlformats.org/"
            "package/2006/metadata/core-properties"
        ),

    "dcterms":
        "http://purl.org/dc/terms/",
}


def identify_office_package(
    file_path: Path,
) -> str | None:

    try:

        with zipfile.ZipFile(
            file_path
        ) as archive:

            names = set(
                archive.namelist()
            )


    except (
        zipfile.BadZipFile,
        OSError,
    ):

        return None


    if any(
        name.startswith(
            "word/"
        )
        for name in names
    ):

        return "docx"


    if any(
        name.startswith(
            "xl/"
        )
        for name in names
    ):

        return "xlsx"


    if any(
        name.startswith(
            "ppt/"
        )
        for name in names
    ):

        return "pptx"


    return None


def analyze_office(
    file_path: Path,
    office_type: str,
) -> dict:

    observations = []

    properties = {
        "office_type":
            office_type,

        "package_members":
            0,

        "embedded_objects":
            0,

        "media_files":
            0,

        "external_relationships":
            0,

        "macros_present":
            False,
    }


    embedded_objects = []


    try:

        with zipfile.ZipFile(
            file_path
        ) as archive:

            infos = archive.infolist()

            properties[
                "package_members"
            ] = len(
                infos
            )


            names = [
                info.filename
                for info in infos
            ]


            macro_names = [
                name
                for name in names
                if (
                    "vbaproject.bin"
                    in name.lower()
                )
            ]


            properties[
                "macros_present"
            ] = bool(
                macro_names
            )


            if macro_names:

                observations.append(
                    {
                        "severity": "warning",
                        "title": "Macro project present",
                        "message": (
                            "A VBA project was identified "
                            "inside the Office package. "
                            "The analyzer does not execute it."
                        ),
                    }
                )


            embedded_names = [
                name
                for name in names
                if "/embeddings/" in name.lower()
            ]


            media_names = [
                name
                for name in names
                if "/media/" in name.lower()
            ]


            properties[
                "embedded_objects"
            ] = len(
                embedded_names
            )


            properties[
                "media_files"
            ] = len(
                media_names
            )


            for name in (
                embedded_names[:50]
            ):

                embedded_objects.append(
                    {
                        "type":
                            "embedded_object",

                        "name":
                            name,
                    }
                )


            core_properties = (
                _read_core_properties(
                    archive
                )
            )


            properties.update(
                core_properties
            )


            app_properties = (
                _read_app_properties(
                    archive
                )
            )


            properties.update(
                app_properties
            )


            external_relationships = (
                _find_external_relationships(
                    archive,
                    names,
                )
            )


            properties[
                "external_relationships"
            ] = len(
                external_relationships
            )


            for relationship in (
                external_relationships[:50]
            ):

                embedded_objects.append(
                    {
                        "type":
                            "external_relationship",

                        "name":
                            relationship,
                    }
                )


            if external_relationships:

                observations.append(
                    {
                        "severity": "info",
                        "title": (
                            "External relationships "
                            "present"
                        ),
                        "message": (
                            f"{len(external_relationships)} "
                            "external Office relationship(s) "
                            "were identified."
                        ),
                    }
                )


            if embedded_names:

                observations.append(
                    {
                        "severity": "info",
                        "title": "Embedded objects present",
                        "message": (
                            f"{len(embedded_names)} embedded "
                            "object(s) were identified."
                        ),
                    }
                )


    except zipfile.BadZipFile:

        return {
            "format": office_type,
            "status": "error",
            "properties": {},
            "observations": [
                {
                    "severity": "warning",
                    "title": "Malformed Office package",
                    "message": (
                        "The file resembles an Office package "
                        "but could not be parsed as a valid ZIP."
                    ),
                }
            ],
            "embedded_objects": [],
        }


    return {
        "format":
            office_type,

        "status":
            "ok",

        "properties":
            properties,

        "observations":
            observations,

        "embedded_objects":
            embedded_objects,

        "limitations": [
            (
                "Office package contents are inspected "
                "without opening or executing embedded files."
            )
        ],
    }


def _safe_read(
    archive: zipfile.ZipFile,
    name: str,
) -> bytes | None:

    try:

        info = archive.getinfo(
            name
        )


        if (
            info.file_size
            > MAX_XML_BYTES
        ):

            return None


        return archive.read(
            name
        )


    except (
        KeyError,
        RuntimeError,
        zipfile.BadZipFile,
    ):

        return None


def _read_core_properties(
    archive: zipfile.ZipFile,
) -> dict:

    data = _safe_read(
        archive,
        "docProps/core.xml",
    )


    if not data:

        return {}


    try:

        root = ET.fromstring(
            data
        )


    except ET.ParseError:

        return {}


    mappings = {
        "title":
            "dc:title",

        "subject":
            "dc:subject",

        "author":
            "dc:creator",

        "description":
            "dc:description",

        "last_modified_by":
            "cp:lastModifiedBy",

        "revision":
            "cp:revision",

        "created":
            "dcterms:created",

        "modified":
            "dcterms:modified",
    }


    result = {}


    for (
        output_name,
        xpath,
    ) in mappings.items():

        element = root.find(
            xpath,
            CORE_NAMESPACES,
        )


        if (
            element is not None
            and element.text
        ):

            result[
                output_name
            ] = element.text


    return result


def _read_app_properties(
    archive: zipfile.ZipFile,
) -> dict:

    data = _safe_read(
        archive,
        "docProps/app.xml",
    )


    if not data:

        return {}


    try:

        root = ET.fromstring(
            data
        )


    except ET.ParseError:

        return {}


    result = {}


    for element in root:

        name = (
            element.tag
            .split("}")[-1]
        )


        if name in (
            "Application",
            "AppVersion",
            "Company",
            "Manager",
            "Pages",
            "Words",
            "Slides",
        ):

            result[
                name.lower()
            ] = element.text


    return result


def _find_external_relationships(
    archive: zipfile.ZipFile,
    names: list[str],
) -> list[str]:

    external = []


    for name in names:

        if not name.lower().endswith(
            ".rels"
        ):

            continue


        data = _safe_read(
            archive,
            name,
        )


        if not data:

            continue


        try:

            root = ET.fromstring(
                data
            )


        except ET.ParseError:

            continue


        for relationship in root:

            if (
                relationship.attrib.get(
                    "TargetMode"
                )
                == "External"
            ):

                target = (
                    relationship.attrib.get(
                        "Target"
                    )
                )


                if target:

                    external.append(
                        target
                    )


    return external