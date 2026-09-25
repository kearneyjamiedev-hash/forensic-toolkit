from pathlib import Path
import struct


def analyze_image(
    file_path: Path,
) -> dict:

    with file_path.open("rb") as file:
        data = file.read()


    if data.startswith(
        b"\x89PNG\r\n\x1a\n"
    ):

        return _analyze_png(
            data
        )


    if data.startswith(
        b"\xff\xd8"
    ):

        return _analyze_jpeg(
            data
        )


    return {
        "format": "image",
        "status": "not_supported",
        "properties": {},
        "observations": [],
        "embedded_objects": [],
    }


def _analyze_png(
    data: bytes,
) -> dict:

    properties = {
        "image_format":
            "PNG",

        "chunk_count":
            0,

        "text_chunks":
            0,

        "exif_chunks":
            0,

        "icc_profiles":
            0,
    }


    observations = []

    offset = 8
    iend_end = None


    while (
        offset + 12
        <= len(data)
    ):

        length = struct.unpack(
            ">I",
            data[
                offset:
                offset + 4
            ],
        )[0]


        chunk_type = data[
            offset + 4:
            offset + 8
        ]


        end = (
            offset
            + 12
            + length
        )


        if end > len(data):

            observations.append(
                {
                    "severity": "warning",
                    "title": "Truncated PNG chunk",
                    "message": (
                        "A PNG chunk extends beyond "
                        "the available file data."
                    ),
                }
            )

            break


        payload = data[
            offset + 8:
            offset + 8 + length
        ]


        properties[
            "chunk_count"
        ] += 1


        if (
            chunk_type
            == b"IHDR"
            and len(payload) >= 13
        ):

            (
                width,
                height,
                bit_depth,
                colour_type,
                compression,
                filter_method,
                interlace,
            ) = struct.unpack(
                ">IIBBBBB",
                payload[:13],
            )


            properties.update(
                {
                    "width":
                        width,

                    "height":
                        height,

                    "bit_depth":
                        bit_depth,

                    "colour_type":
                        colour_type,

                    "interlaced":
                        bool(
                            interlace
                        ),
                }
            )


        elif chunk_type in (
            b"tEXt",
            b"zTXt",
            b"iTXt",
        ):

            properties[
                "text_chunks"
            ] += 1


        elif chunk_type == b"eXIf":

            properties[
                "exif_chunks"
            ] += 1


        elif chunk_type == b"iCCP":

            properties[
                "icc_profiles"
            ] += 1


        elif chunk_type == b"IEND":

            iend_end = end

            break


        offset = end


    trailing_bytes = 0


    if iend_end is not None:

        trailing = (
            data[
                iend_end:
            ]
            .strip(
                b"\x00"
                b"\x09"
                b"\x0a"
                b"\x0d"
                b"\x20"
            )
        )


        trailing_bytes = len(
            trailing
        )


    properties[
        "trailing_bytes_after_iend"
    ] = trailing_bytes


    if trailing_bytes:

        observations.append(
            {
                "severity": "warning",
                "title": "Data after PNG IEND",
                "message": (
                    f"{trailing_bytes} non-whitespace "
                    "bytes were found after the IEND chunk."
                ),
            }
        )


    return {
        "format": "png",
        "status": "ok",
        "properties": properties,
        "observations": observations,
        "embedded_objects": [],
    }


def _analyze_jpeg(
    data: bytes,
) -> dict:

    properties = {
        "image_format":
            "JPEG",

        "app_segments":
            0,

        "comment_segments":
            0,

        "exif_present":
            False,

        "xmp_present":
            False,
    }


    observations = []

    position = 2
    eoi_position = None


    while (
        position + 1
        < len(data)
    ):

        if (
            data[position]
            != 0xFF
        ):

            position += 1

            continue


        while (
            position < len(data)
            and data[position] == 0xFF
        ):

            position += 1


        if (
            position
            >= len(data)
        ):

            break


        marker = data[
            position
        ]

        position += 1


        if marker == 0xD9:

            eoi_position = position

            break


        if marker in (
            0x01,
            0xD0,
            0xD1,
            0xD2,
            0xD3,
            0xD4,
            0xD5,
            0xD6,
            0xD7,
            0xD8,
        ):

            continue


        if (
            position + 2
            > len(data)
        ):

            break


        segment_length = struct.unpack(
            ">H",
            data[
                position:
                position + 2
            ],
        )[0]


        if segment_length < 2:

            break


        segment_end = (
            position
            + segment_length
        )


        if segment_end > len(data):

            observations.append(
                {
                    "severity": "warning",
                    "title": "Truncated JPEG segment",
                    "message": (
                        "A JPEG segment extends beyond "
                        "the available file data."
                    ),
                }
            )

            break


        payload = data[
            position + 2:
            segment_end
        ]


        if (
            0xE0
            <= marker
            <= 0xEF
        ):

            properties[
                "app_segments"
            ] += 1


        if marker == 0xE1:

            if payload.startswith(
                b"Exif\x00\x00"
            ):

                properties[
                    "exif_present"
                ] = True


            if (
                b"http://ns.adobe.com/xap/"
                in payload
            ):

                properties[
                    "xmp_present"
                ] = True


        if marker == 0xFE:

            properties[
                "comment_segments"
            ] += 1


        if marker in (
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        ):

            if len(payload) >= 6:

                properties[
                    "precision"
                ] = payload[0]


                properties[
                    "height"
                ] = struct.unpack(
                    ">H",
                    payload[
                        1:3
                    ],
                )[0]


                properties[
                    "width"
                ] = struct.unpack(
                    ">H",
                    payload[
                        3:5
                    ],
                )[0]


        position = (
            segment_end
        )


    trailing_bytes = 0


    if eoi_position is not None:

        trailing = (
            data[
                eoi_position:
            ]
            .strip(
                b"\x00"
                b"\x09"
                b"\x0a"
                b"\x0d"
                b"\x20"
            )
        )


        trailing_bytes = len(
            trailing
        )


    properties[
        "trailing_bytes_after_eoi"
    ] = trailing_bytes


    if trailing_bytes:

        observations.append(
            {
                "severity": "warning",
                "title": "Data after JPEG EOI",
                "message": (
                    f"{trailing_bytes} non-whitespace "
                    "bytes were found after the JPEG "
                    "end marker."
                ),
            }
        )


    return {
        "format": "jpeg",
        "status": "ok",
        "properties": properties,
        "observations": observations,
        "embedded_objects": [],
    }