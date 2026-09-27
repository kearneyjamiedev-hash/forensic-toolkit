from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request


HEALTH_URL = "http://127.0.0.1:8000/api/health"


def main() -> int:
    request = urllib.request.Request(
        HEALTH_URL,
        headers={
            "Host": "127.0.0.1:8000",
            "User-Agent": "forensic-toolkit-healthcheck/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=3,
        ) as response:
            if response.status != 200:
                return 1

            payload = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

    except (
        urllib.error.URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError,
    ):
        return 1

    return (
        0
        if payload.get("status") == "ok"
        else 1
    )


if __name__ == "__main__":
    sys.exit(
        main()
    )
