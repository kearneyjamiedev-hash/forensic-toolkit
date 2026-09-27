from __future__ import annotations

from urllib.parse import urlsplit

from starlette.datastructures import (
    Headers,
    MutableHeaders,
)

from starlette.responses import (
    JSONResponse,
)

from app.config import (
    HTTP_ALLOWED_HOSTS,
    HTTP_ALLOWED_ORIGIN_HOSTS,
)


UNSAFE_METHODS = {
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
}

API_PREFIX = "/api/"


CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
    ]
)


class HttpSecurityMiddleware:
    """
    Security controls for the local forensic web application.

    The application is designed to be accessed through loopback addresses.
    This middleware:
    - restricts Host headers to configured local names;
    - rejects cross-site state-changing API requests;
    - adds browser security headers;
    - prevents API/evidence responses from being cached.
    """

    def __init__(
        self,
        app,
        *,
        allowed_hosts: tuple[str, ...] | None = None,
        allowed_origin_hosts: tuple[str, ...] | None = None,
    ):
        self.app = app

        self.allowed_hosts = {
            host.casefold()
            for host in (
                allowed_hosts
                or HTTP_ALLOWED_HOSTS
            )
        }

        self.allowed_origin_hosts = {
            host.casefold()
            for host in (
                allowed_origin_hosts
                or HTTP_ALLOWED_ORIGIN_HOSTS
            )
        }

    async def __call__(
        self,
        scope,
        receive,
        send,
    ):

        if scope.get(
            "type"
        ) != "http":

            await self.app(
                scope,
                receive,
                send,
            )

            return

        method = str(
            scope.get(
                "method",
                "GET",
            )
        ).upper()

        path = str(
            scope.get(
                "path",
                "/",
            )
        )

        request_headers = Headers(
            scope=scope
        )

        async def secure_send(
            message,
        ):
            if (
                message.get(
                    "type"
                )
                == "http.response.start"
            ):
                headers = (
                    MutableHeaders(
                        scope=message
                    )
                )

                _apply_security_headers(
                    headers,
                    api_response=(
                        path.startswith(
                            API_PREFIX
                        )
                    ),
                )

            await send(
                message
            )

        host = _hostname_from_host_header(
            request_headers.get(
                "host"
            )
        )

        if (
            host is not None
            and host.casefold()
            not in self.allowed_hosts
        ):
            response = JSONResponse(
                status_code=400,
                content={
                    "detail":
                        "Invalid host header."
                },
            )

            await response(
                scope,
                receive,
                secure_send,
            )

            return

        if (
            path.startswith(
                API_PREFIX
            )
            and method
            in UNSAFE_METHODS
        ):

            fetch_site = (
                request_headers.get(
                    "sec-fetch-site",
                    "",
                )
                .strip()
                .casefold()
            )

            if (
                fetch_site
                == "cross-site"
            ):
                response = JSONResponse(
                    status_code=403,
                    content={
                        "detail":
                            (
                                "Cross-site API requests "
                                "are not permitted."
                            )
                    },
                )

                await response(
                    scope,
                    receive,
                    secure_send,
                )

                return

            origin = (
                request_headers.get(
                    "origin"
                )
            )

            if (
                origin
                and not _origin_is_allowed(
                    origin,
                    self.allowed_origin_hosts,
                )
            ):
                response = JSONResponse(
                    status_code=403,
                    content={
                        "detail":
                            (
                                "The request origin is "
                                "not permitted."
                            )
                    },
                )

                await response(
                    scope,
                    receive,
                    secure_send,
                )

                return

        await self.app(
            scope,
            receive,
            secure_send,
        )


def _hostname_from_host_header(
    value: str | None,
) -> str | None:

    if not value:
        return None

    try:
        return (
            urlsplit(
                "//"
                + value
            )
            .hostname
        )

    except ValueError:
        return None


def _origin_is_allowed(
    origin: str,
    allowed_hosts: set[str],
) -> bool:

    try:
        parsed = urlsplit(
            origin
        )

    except ValueError:
        return False

    if (
        parsed.scheme.casefold()
        not in {
            "http",
            "https",
        }
    ):
        return False

    hostname = (
        parsed.hostname
    )

    if not hostname:
        return False

    return (
        hostname.casefold()
        in allowed_hosts
    )


def _apply_security_headers(
    headers: MutableHeaders,
    *,
    api_response: bool,
) -> None:

    headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    headers[
        "X-Frame-Options"
    ] = "DENY"

    headers[
        "Referrer-Policy"
    ] = "no-referrer"

    headers[
        "Permissions-Policy"
    ] = (
        "camera=(), microphone=(), "
        "geolocation=(), payment=(), "
        "usb=()"
    )

    headers[
        "Cross-Origin-Opener-Policy"
    ] = "same-origin"

    headers[
        "Cross-Origin-Resource-Policy"
    ] = "same-origin"

    headers[
        "X-Permitted-Cross-Domain-Policies"
    ] = "none"

    headers[
        "X-Robots-Tag"
    ] = (
        "noindex, nofollow, noarchive"
    )

    headers[
        "Content-Security-Policy"
    ] = CONTENT_SECURITY_POLICY

    if api_response:
        headers[
            "Cache-Control"
        ] = (
            "no-store, max-age=0"
        )

        headers[
            "Pragma"
        ] = "no-cache"
