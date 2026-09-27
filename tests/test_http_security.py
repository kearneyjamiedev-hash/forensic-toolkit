from fastapi import FastAPI
from fastapi.testclient import TestClient

import pytest

from app.http_security import (
    CONTENT_SECURITY_POLICY,
    HttpSecurityMiddleware,
)


pytestmark = pytest.mark.unit


def build_app() -> FastAPI:

    app = FastAPI()

    app.add_middleware(
        HttpSecurityMiddleware,
        allowed_hosts=(
            "127.0.0.1",
            "localhost",
            "testserver",
        ),
        allowed_origin_hosts=(
            "127.0.0.1",
            "localhost",
            "testserver",
        ),
    )

    @app.get("/")
    async def index():
        return {
            "status": "ok",
        }

    @app.get("/api/value")
    async def api_value():
        return {
            "value": 1,
        }

    @app.post("/api/action")
    async def api_action():
        return {
            "status": "accepted",
        }

    return app


def test_security_headers_are_added():

    client = TestClient(
        build_app()
    )

    response = client.get(
        "/",
        headers={
            "Host":
                "127.0.0.1:8000",
        },
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "x-content-type-options"
        ]
        == "nosniff"
    )

    assert (
        response.headers[
            "x-frame-options"
        ]
        == "DENY"
    )

    assert (
        response.headers[
            "referrer-policy"
        ]
        == "no-referrer"
    )

    assert (
        response.headers[
            "content-security-policy"
        ]
        == CONTENT_SECURITY_POLICY
    )


def test_api_responses_are_not_cached():

    client = TestClient(
        build_app()
    )

    response = client.get(
        "/api/value",
        headers={
            "Host":
                "127.0.0.1:8000",
        },
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "cache-control"
        ]
        == "no-store, max-age=0"
    )

    assert (
        response.headers[
            "pragma"
        ]
        == "no-cache"
    )


def test_untrusted_host_is_rejected():

    client = TestClient(
        build_app()
    )

    response = client.get(
        "/",
        headers={
            "Host":
                "evil.example",
        },
    )

    assert response.status_code == 400

    assert (
        response.json()["detail"]
        == "Invalid host header."
    )


def test_cross_site_api_post_is_rejected():

    client = TestClient(
        build_app()
    )

    response = client.post(
        "/api/action",
        headers={
            "Host":
                "127.0.0.1:8000",

            "Origin":
                "https://evil.example",

            "Sec-Fetch-Site":
                "cross-site",
        },
    )

    assert response.status_code == 403


def test_foreign_origin_api_post_is_rejected_without_fetch_metadata():

    client = TestClient(
        build_app()
    )

    response = client.post(
        "/api/action",
        headers={
            "Host":
                "127.0.0.1:8000",

            "Origin":
                "https://evil.example",
        },
    )

    assert response.status_code == 403

    assert (
        response.json()["detail"]
        == (
            "The request origin is "
            "not permitted."
        )
    )


def test_local_origin_api_post_is_allowed():

    client = TestClient(
        build_app()
    )

    response = client.post(
        "/api/action",
        headers={
            "Host":
                "127.0.0.1:8000",

            "Origin":
                "http://127.0.0.1:8000",

            "Sec-Fetch-Site":
                "same-origin",
        },
    )

    assert response.status_code == 200


def test_api_post_without_origin_is_allowed_for_local_cli_use():

    client = TestClient(
        build_app()
    )

    response = client.post(
        "/api/action",
        headers={
            "Host":
                "127.0.0.1:8000",
        },
    )

    assert response.status_code == 200
