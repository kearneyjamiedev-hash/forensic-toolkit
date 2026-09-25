from __future__ import annotations

import ipaddress
import re
from pathlib import Path


MIN_STRING_LENGTH = 4
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_ITEMS_PER_CATEGORY = 200
MAX_OFFSETS_PER_ITEM = 5


ASCII_RE = re.compile(
    rb"[\x20-\x7e]{4,}"
)

UTF16LE_RE = re.compile(
    rb"(?:[\x20-\x7e]\x00){4,}"
)


URL_RE = re.compile(
    r'\bhttps?://[^\s<>\'"()\[\]{}]+',
    re.IGNORECASE,
)


EMAIL_RE = re.compile(
    r"\b"
    r"[A-Z0-9._%+-]+"
    r"@"
    r"[A-Z0-9.-]+"
    r"\.[A-Z]{2,63}"
    r"\b",
    re.IGNORECASE,
)


IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}"
    r"\d{1,3}"
    r"(?![\d.])"
)


IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"[0-9A-Fa-f:]{3,39}"
    r"(?![0-9A-Fa-f:])"
)


DOMAIN_RE = re.compile(
    r"\b"
    r"(?:"
    r"[A-Z0-9]"
    r"(?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"\.)+"
    r"[A-Z]{2,24}"
    r"\b",
    re.IGNORECASE,
)


WINDOWS_PATH_RE = re.compile(
    r'\b'
    r'[A-Za-z]:\\'
    r'(?:'
    r'[^\\/:*?"<>|\r\n\t]+\\'
    r')*'
    r'[^\\/:*?"<>|\r\n\t]*'
)


UNIX_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9:/])"
    r"/"
    r"(?:"
    r"[A-Za-z0-9._~+-]+/"
    r")+"
    r"[A-Za-z0-9._~+-]+"
)


REGISTRY_RE = re.compile(
    r"\b(?:"
    r"HKEY_LOCAL_MACHINE|"
    r"HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|"
    r"HKEY_USERS|"
    r"HKEY_CURRENT_CONFIG|"
    r"HKLM|HKCU|HKCR|HKU|HKCC"
    r")\\"
    r"[A-Za-z0-9 _./{}()@%+-]+"
    r"(?:\\[A-Za-z0-9 _./{}()@%+-]+)*",
    re.IGNORECASE,
)


EXECUTABLE_RE = re.compile(
    r"\b"
    r"[A-Za-z0-9]"
    r"[A-Za-z0-9_.-]{1,80}"
    r"\."
    r"(?:"
    r"exe|dll|sys|scr|com|bat|cmd|"
    r"ps1|vbs|jse|wsf|msi|msp|"
    r"cpl|ocx|jar|py|sh"
    r")"
    r"\b",
    re.IGNORECASE,
)


USERNAME_CONTEXT_RE = re.compile(
    r"\b(?:"
    r"user(?:name)?|"
    r"account|"
    r"login"
    r")"
    r"\s*[:=]\s*"
    r"([A-Za-z0-9._$@\\-]{2,128})",
    re.IGNORECASE,
)


WINDOWS_USER_RE = re.compile(
    r"\b"
    r"[A-Za-z]:\\Users\\"
    r"([^\\\r\n\t]{1,128})",
    re.IGNORECASE,
)


UNIX_USER_RE = re.compile(
    r"(?:^|[\s\"'])"
    r"/home/"
    r"([^/\s\"']{1,128})/",
    re.IGNORECASE,
)


COMMAND_HINT_RE = re.compile(
    r"(?:^|\s)(?:"
    r"powershell(?:\.exe)?|"
    r"pwsh(?:\.exe)?|"
    r"cmd(?:\.exe)?|"
    r"rundll32(?:\.exe)?|"
    r"reg(?:\.exe)?|"
    r"certutil(?:\.exe)?|"
    r"wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|"
    r"mshta(?:\.exe)?|"
    r"curl(?:\.exe)?|"
    r"wget(?:\.exe)?|"
    r"python(?:3)?(?:\.exe)?|"
    r"bash|"
    r"sh"
    r")\b",
    re.IGNORECASE,
)


GENERIC_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "io",
    "dev",
    "app",
    "info",
    "biz",
    "cloud",
    "online",
    "site",
    "tech",
    "store",
    "xyz",
    "me",
    "ai",
}


COMMON_COUNTRY_TLDS = {
    "ie",
    "uk",
    "us",
    "ca",
    "au",
    "nz",
    "de",
    "fr",
    "nl",
    "be",
    "es",
    "it",
    "pt",
    "pl",
    "se",
    "no",
    "dk",
    "fi",
    "ch",
    "at",
    "cz",
    "jp",
    "kr",
    "sg",
    "in",
}


CATEGORY_LABELS = {
    "urls": "URLs",
    "email_addresses": "Email addresses",
    "ip_addresses": "IP addresses",
    "domains": "Domains",
    "usernames": "Usernames",
    "windows_paths": "Windows paths",
    "unix_paths": "Unix paths",
    "registry_paths": "Registry paths",
    "executables": "Executable / script references",
    "command_lines": "Command-like strings",
}


def extract_interesting_artefacts(
    file_path: Path,
) -> dict:
    with file_path.open("rb") as file:
        data = file.read(
            MAX_SCAN_BYTES + 1
        )

    truncated = (
        len(data)
        > MAX_SCAN_BYTES
    )

    if truncated:
        data = data[
            :MAX_SCAN_BYTES
        ]

    items = {
        category: {}
        for category
        in CATEGORY_LABELS
    }

    extracted_string_count = 0

    for (
        value,
        offset,
        encoding,
    ) in _iter_strings(data):
        extracted_string_count += 1

        _classify_string(
            value=value,
            offset=offset,
            encoding=encoding,
            items=items,
        )

    categories = {}
    total_found = 0

    for (
        category,
        label,
    ) in CATEGORY_LABELS.items():
        category_items = list(
            items[
                category
            ].values()
        )

        category_items.sort(
            key=lambda item: (
                item["offsets"][0]
                if item["offsets"]
                else 0,
                item["value"].lower(),
            )
        )

        category_items = (
            category_items[
                :MAX_ITEMS_PER_CATEGORY
            ]
        )

        categories[category] = {
            "label": label,
            "count": len(
                category_items
            ),
            "items": category_items,
        }

        total_found += len(
            category_items
        )

    return {
        "total_found":
            total_found,

        "extracted_string_count":
            extracted_string_count,

        "scanned_bytes":
            len(data),

        "scan_limit_bytes":
            MAX_SCAN_BYTES,

        "truncated":
            truncated,

        "minimum_string_length":
            MIN_STRING_LENGTH,

        "categories":
            categories,

        "limitations": [
            (
                "Extracted artefacts are "
                "investigative leads. Their presence "
                "does not by itself indicate "
                "malicious activity."
            ),
            (
                "Raw string scanning may not expose "
                "content stored inside compressed, "
                "encoded or encrypted containers."
            ),
        ],
    }


def _iter_strings(
    data: bytes,
):
    for match in ASCII_RE.finditer(
        data
    ):
        value = (
            match
            .group()
            .decode(
                "ascii",
                errors="ignore",
            )
        )

        if (
            len(value)
            >= MIN_STRING_LENGTH
        ):
            yield (
                value,
                match.start(),
                "ASCII",
            )

    for match in UTF16LE_RE.finditer(
        data
    ):
        value = (
            match
            .group()
            .decode(
                "utf-16le",
                errors="ignore",
            )
        )

        if (
            len(value)
            >= MIN_STRING_LENGTH
        ):
            yield (
                value,
                match.start(),
                "UTF-16LE",
            )


def _classify_string(
    *,
    value: str,
    offset: int,
    encoding: str,
    items: dict,
) -> None:
    value = value.strip()

    if not value:
        return

    url_matches = list(
        URL_RE.finditer(
            value
        )
    )

    email_matches = list(
        EMAIL_RE.finditer(
            value
        )
    )

    occupied_domain_spans = []

    for match in url_matches:
        cleaned = (
            _clean_trailing_punctuation(
                match.group()
            )
        )

        _add_item(
            items,
            "urls",
            cleaned,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

        occupied_domain_spans.append(
            match.span()
        )

    for match in email_matches:
        email = match.group()

        _add_item(
            items,
            "email_addresses",
            email,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

        occupied_domain_spans.append(
            match.span()
        )

    for match in IPV4_RE.finditer(
        value
    ):
        candidate = (
            match.group()
        )

        try:
            parsed = (
                ipaddress
                .ip_address(candidate)
            )

        except ValueError:
            continue

        if parsed.version == 4:
            _add_item(
                items,
                "ip_addresses",
                candidate,
                _match_offset(
                    offset,
                    match.start(),
                    encoding,
                ),
                encoding,
            )

    for match in (
        IPV6_CANDIDATE_RE
        .finditer(value)
    ):
        candidate = (
            match.group()
        )

        # Avoid tiny IPv6-looking fragments that commonly
        # occur by chance in compressed/binary data.
        if len(candidate) < 7:
            continue

        if candidate.count(":") < 2:
            continue

        # "::" and similarly tiny compressed forms may be
        # technically valid syntax but are too weak to treat
        # as useful forensic artefacts on their own.
        if candidate in (
            "::",
            "::0",
            "::1",
        ):
            continue

        try:
            parsed = (
                ipaddress
                .ip_address(candidate)
            )

        except ValueError:
            continue

        if parsed.version == 6:
            _add_item(
                items,
                "ip_addresses",
                candidate,
                _match_offset(
                    offset,
                    match.start(),
                    encoding,
                ),
                encoding,
            )

    for match in DOMAIN_RE.finditer(
        value
    ):
        candidate = (
            match
            .group()
            .lower()
        )

        if _span_overlaps(
            match.span(),
            occupied_domain_spans,
        ):
            continue

        if not _is_plausible_domain(
            candidate
        ):
            continue

        _add_item(
            items,
            "domains",
            candidate,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

    for match in (
        WINDOWS_PATH_RE
        .finditer(value)
    ):
        candidate = (
            _clean_trailing_punctuation(
                match.group()
            )
        )

        if not _is_plausible_path(
            candidate
        ):
            continue

        _add_item(
            items,
            "windows_paths",
            candidate,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

    for match in UNIX_PATH_RE.finditer(
        value
    ):
        candidate = (
            _clean_trailing_punctuation(
                match.group()
            )
        )

        if not _is_plausible_path(
            candidate
        ):
            continue

        _add_item(
            items,
            "unix_paths",
            candidate,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

    for match in REGISTRY_RE.finditer(
        value
    ):
        candidate = (
            _clean_trailing_punctuation(
                match.group()
            )
        )

        _add_item(
            items,
            "registry_paths",
            candidate,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

    for match in (
        EXECUTABLE_RE
        .finditer(value)
    ):
        candidate = (
            match.group()
        )

        if not _is_plausible_executable(
            candidate
        ):
            continue

        _add_item(
            items,
            "executables",
            candidate,
            _match_offset(
                offset,
                match.start(),
                encoding,
            ),
            encoding,
        )

    for regex in (
        USERNAME_CONTEXT_RE,
        WINDOWS_USER_RE,
        UNIX_USER_RE,
    ):
        for match in regex.finditer(
            value
        ):
            username = (
                match
                .group(1)
                .strip()
            )

            if not _is_plausible_username(
                username
            ):
                continue

            _add_item(
                items,
                "usernames",
                username,
                _match_offset(
                    offset,
                    match.start(1),
                    encoding,
                ),
                encoding,
            )

    if _looks_like_command_line(
        value
    ):
        leading_spaces = (
            len(value)
            - len(
                value.lstrip()
            )
        )

        command_value = (
            value
            .strip()[:1000]
        )

        _add_item(
            items,
            "command_lines",
            command_value,
            _match_offset(
                offset,
                leading_spaces,
                encoding,
            ),
            encoding,
        )


def _is_plausible_domain(
    value: str,
) -> bool:
    if len(value) < 6:
        return False

    if len(value) > 253:
        return False

    if _looks_like_ip(
        value
    ):
        return False

    labels = value.split(".")

    if len(labels) < 2:
        return False

    if any(
        not label
        for label in labels
    ):
        return False

    if any(
        len(label) > 63
        for label in labels
    ):
        return False

    tld = labels[-1]

    if (
        tld not in GENERIC_TLDS
        and tld not in COMMON_COUNTRY_TLDS
    ):
        return False

    main_label = labels[-2]

    if len(main_label) < 2:
        return False

    if (
        not any(
            character.isalpha()
            for character in main_label
        )
    ):
        return False

    if (
        value.count("-")
        > 5
    ):
        return False

    return True


def _is_plausible_path(
    value: str,
) -> bool:
    if len(value) < 4:
        return False

    if len(value) > 300:
        return False

    if (
        value.count("\\") == 0
        and value.count("/") < 2
    ):
        return False

    alphanumeric_count = sum(
        character.isalnum()
        for character in value
    )

    if (
        alphanumeric_count
        < 3
    ):
        return False

    return True


def _is_plausible_executable(
    value: str,
) -> bool:
    basename = (
        value
        .rsplit(
            ".",
            1,
        )[0]
    )

    if len(basename) < 2:
        return False

    if not any(
        character.isalpha()
        for character in basename
    ):
        return False

    return True


def _is_plausible_username(
    value: str,
) -> bool:
    if len(value) < 2:
        return False

    if len(value) > 128:
        return False

    if value in (
        ".",
        "..",
    ):
        return False

    return any(
        character.isalnum()
        for character in value
    )


def _looks_like_command_line(
    value: str,
) -> bool:

    value = value.strip()


    if len(value) < 8:
        return False


    if len(value) > 2000:
        return False


    match = COMMAND_HINT_RE.search(
        value
    )


    if not match:
        return False


    command = (
        match.group()
        .strip()
        .lower()
    )


    strong_markers = (
        " -",
        " /",
        " --",
        "-enc",
        "-encodedcommand",
        "-command",
        "/c ",
        "/k ",
        "|",
        ">",
        "&&",
        "http://",
        "https://",
    )


    if any(
        marker in value.lower()
        for marker in strong_markers
    ):
        return True


    # Shell names such as "sh" or "bash" are too common
    # in arbitrary binary strings to trust without clear
    # command syntax.
    if command in (
        "sh",
        "bash",
    ):
        return False


    # For named executables, require enough surrounding
    # text to look like an actual invocation rather than
    # an isolated filename.
    return (
        len(value.split()) >= 3
        and len(value) >= 12
    )


def _match_offset(
    base_offset: int,
    character_offset: int,
    encoding: str,
) -> int:
    multiplier = (
        2
        if encoding == "UTF-16LE"
        else 1
    )

    return (
        base_offset
        + character_offset
        * multiplier
    )


def _add_item(
    items: dict,
    category: str,
    value: str,
    offset: int,
    encoding: str,
) -> None:
    value = value.strip()

    if not value:
        return

    if len(value) > 1000:
        value = value[:1000]

    key = value.casefold()

    existing = (
        items[
            category
        ].get(key)
    )

    if existing is None:
        items[
            category
        ][key] = {
            "value":
                value,

            "occurrences":
                1,

            "offsets": [
                offset
            ],

            "offsets_hex": [
                f"0x{offset:08X}"
            ],

            "encodings": [
                encoding
            ],
        }

        return

    existing[
        "occurrences"
    ] += 1

    if (
        offset
        not in existing[
            "offsets"
        ]
        and len(
            existing[
                "offsets"
            ]
        )
        < MAX_OFFSETS_PER_ITEM
    ):
        existing[
            "offsets"
        ].append(
            offset
        )

        existing[
            "offsets_hex"
        ].append(
            f"0x{offset:08X}"
        )

    if (
        encoding
        not in existing[
            "encodings"
        ]
    ):
        existing[
            "encodings"
        ].append(
            encoding
        )


def _clean_trailing_punctuation(
    value: str,
) -> str:
    return value.rstrip(
        ".,;:!?)]}'\""
    )


def _looks_like_ip(
    value: str,
) -> bool:
    try:
        ipaddress.ip_address(
            value
        )

        return True

    except ValueError:
        return False


def _span_overlaps(
    span: tuple[int, int],
    occupied: list[
        tuple[int, int]
    ],
) -> bool:
    start, end = span

    for (
        occupied_start,
        occupied_end,
    ) in occupied:
        if (
            start < occupied_end
            and end > occupied_start
        ):
            return True

    return False