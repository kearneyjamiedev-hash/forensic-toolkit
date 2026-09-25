from datetime import datetime, timezone
from pathlib import Path
import math
import struct


MACHINE_TYPES = {
    0x014C:
        "x86",

    0x8664:
        "x64",

    0x01C0:
        "ARM",

    0xAA64:
        "ARM64",
}


def analyze_pe(
    file_path: Path,
) -> dict:

    observations = []
    sections = []


    try:

        with file_path.open("rb") as file:
            data = file.read()


        if (
            len(data) < 64
            or not data.startswith(
                b"MZ"
            )
        ):

            raise ValueError(
                "Invalid DOS header."
            )


        pe_offset = struct.unpack_from(
            "<I",
            data,
            0x3C,
        )[0]


        if (
            pe_offset + 24
            > len(data)
        ):

            raise ValueError(
                "PE header offset is outside file."
            )


        if (
            data[
                pe_offset:
                pe_offset + 4
            ]
            != b"PE\x00\x00"
        ):

            raise ValueError(
                "PE signature not found."
            )


        coff_offset = (
            pe_offset + 4
        )


        (
            machine,
            section_count,
            timestamp,
            pointer_symbols,
            number_symbols,
            optional_size,
            characteristics,
        ) = struct.unpack_from(
            "<HHIIIHH",
            data,
            coff_offset,
        )


        optional_offset = (
            coff_offset + 20
        )


        optional_magic = (
            struct.unpack_from(
                "<H",
                data,
                optional_offset,
            )[0]
        )


        if optional_magic == 0x10B:

            pe_type = "PE32"
            architecture = "32-bit"

            data_directory_offset = (
                optional_offset
                + 96
            )


        elif optional_magic == 0x20B:

            pe_type = "PE32+"
            architecture = "64-bit"

            data_directory_offset = (
                optional_offset
                + 112
            )


        else:

            pe_type = (
                f"Unknown "
                f"0x{optional_magic:04X}"
            )

            architecture = "Unknown"

            data_directory_offset = None


        certificate_table_present = False


        if (
            data_directory_offset
            is not None
            and (
                data_directory_offset
                + (8 * 5)
            )
            <= len(data)
        ):

            security_offset = (
                data_directory_offset
                + (8 * 4)
            )


            (
                certificate_file_offset,
                certificate_size,
            ) = struct.unpack_from(
                "<II",
                data,
                security_offset,
            )


            certificate_table_present = (
                certificate_file_offset > 0
                and certificate_size > 0
            )


        section_table_offset = (
            optional_offset
            + optional_size
        )


        for index in range(
            section_count
        ):

            offset = (
                section_table_offset
                + index * 40
            )


            if (
                offset + 40
                > len(data)
            ):

                observations.append(
                    {
                        "severity": "warning",
                        "title": (
                            "Truncated section table"
                        ),
                        "message": (
                            "The PE section table ended "
                            "before all declared sections "
                            "could be parsed."
                        ),
                    }
                )

                break


            raw_name = data[
                offset:
                offset + 8
            ]


            section_name = (
                raw_name
                .split(
                    b"\x00",
                    1,
                )[0]
                .decode(
                    "ascii",
                    errors="replace",
                )
            )


            (
                virtual_size,
                virtual_address,
                raw_size,
                raw_pointer,
            ) = struct.unpack_from(
                "<IIII",
                data,
                offset + 8,
            )


            section_data = b""


            if (
                raw_pointer
                < len(data)
            ):

                section_data = data[
                    raw_pointer:
                    raw_pointer
                    + raw_size
                ]


            entropy = (
                _entropy(
                    section_data
                )
                if section_data
                else 0
            )


            sections.append(
                {
                    "type":
                        "pe_section",

                    "name":
                        section_name,

                    "virtual_size":
                        virtual_size,

                    "raw_size":
                        raw_size,

                    "entropy":
                        round(
                            entropy,
                            3,
                        ),
                }
            )


            if entropy >= 7.2:

                observations.append(
                    {
                        "severity": "info",
                        "title": (
                            f"High entropy section "
                            f"{section_name}"
                        ),
                        "message": (
                            "High section entropy may "
                            "result from compression, "
                            "packing, encryption or "
                            "ordinary binary data."
                        ),
                    }
                )


        compile_time = None


        if timestamp:

            try:

                compile_time = (
                    datetime
                    .fromtimestamp(
                        timestamp,
                        tz=timezone.utc,
                    )
                    .isoformat()
                    .replace(
                        "+00:00",
                        "Z",
                    )
                )


            except (
                ValueError,
                OSError,
                OverflowError,
            ):

                compile_time = None


        return {
            "format": "pe",

            "status": "ok",

            "properties": {
                "pe_type":
                    pe_type,

                "architecture":
                    architecture,

                "machine":
                    MACHINE_TYPES.get(
                        machine,
                        f"0x{machine:04X}",
                    ),

                "section_count":
                    section_count,

                "compile_timestamp":
                    compile_time,

                "characteristics":
                    f"0x{characteristics:04X}",

                "certificate_table_present":
                    certificate_table_present,
            },

            "observations":
                observations,

            "embedded_objects":
                sections,

            "limitations": [
                (
                    "PE analysis is static. "
                    "The executable is never run."
                ),
                (
                    "Compile timestamps are metadata "
                    "and can be modified."
                ),
            ],
        }


    except (
        OSError,
        ValueError,
        struct.error,
    ) as error:

        return {
            "format": "pe",

            "status": "error",

            "properties": {},

            "observations": [
                {
                    "severity": "warning",
                    "title": "Malformed PE file",
                    "message": str(
                        error
                    ),
                }
            ],

            "embedded_objects": [],
        }


def _entropy(
    data: bytes,
) -> float:

    if not data:

        return 0.0


    counts = [
        0
    ] * 256


    for byte in data:

        counts[
            byte
        ] += 1


    length = len(
        data
    )


    entropy = 0.0


    for count in counts:

        if not count:

            continue


        probability = (
            count
            / length
        )


        entropy -= (
            probability
            * math.log2(
                probability
            )
        )


    return entropy