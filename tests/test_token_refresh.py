# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for per-caller access token refresh (broker + ASGI middleware)."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock

import httpx
import jwt
import pytest
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from okta_mcp_server import server as server_module
from okta_mcp_server.utils.auth.token_refresh import (
    REFRESH_TOKEN_HEADER,
    OktaRefreshTokenBroker,
    OktaRefreshTokenMiddleware,
    RefreshedToken,
)

ORG_URL = "https://test.okta.com"
CLIENT_ID = "mcp-client-id"
CLIENT_SECRET = "mcp-client-secret"
REFRESH_TOKEN = "rt-original"


def _jwt(age_seconds: int) -> str:
    return jwt.encode({"exp": int(time.time()) + age_seconds}, "test-secret", algorithm="HS256")


# Built once at import so it stays comfortably unexpired for the whole test run.
VALID_BEARER_TOKEN = _jwt(3600)


def _token_response(
    access_token: str = "at-new", expires_in: int = 3600, refresh_token: str | None = None
) -> httpx.Response:
    body = {"access_token": access_token, "expires_in": expires_in, "token_type": "Bearer"}
    if refresh_token is not None:
        body["refresh_token"] = refresh_token
    return httpx.Response(200, json=body)


def _refreshed(access_token: str, rotated: str | None = None) -> RefreshedToken:
    return RefreshedToken(access_token=access_token, rotated_refresh_token=rotated)


def _broker(handler) -> tuple[OktaRefreshTokenBroker, list[httpx.Request]]:
    """Broker wired to a mock transport, plus the list every request is appended to."""
    requests: list[httpx.Request] = []

    async def recording_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        result = handler(request)
        return await result if asyncio.iscoroutine(result) else result

    client = httpx.AsyncClient(transport=httpx.MockTransport(recording_handler))
    return OktaRefreshTokenBroker(ORG_URL, CLIENT_ID, CLIENT_SECRET, http_client=client), requests


class TestBroker:
    @pytest.mark.asyncio
    async def test_runs_the_refresh_token_grant(self):
        broker, requests = _broker(lambda r: _token_response())

        result = await broker.access_token_for(REFRESH_TOKEN)

        assert result is not None
        assert result.access_token == "at-new"
        assert result.rotated_refresh_token is None
        assert requests[0].url == f"{ORG_URL}/oauth2/v1/token"
        form = httpx.QueryParams(requests[0].read().decode())
        assert form["grant_type"] == "refresh_token"
        assert form["refresh_token"] == REFRESH_TOKEN
        assert form["client_id"] == CLIENT_ID
        assert form["client_secret"] == CLIENT_SECRET

    @pytest.mark.asyncio
    async def test_reuses_the_cached_token_until_near_expiry(self):
        broker, requests = _broker(lambda r: _token_response(expires_in=3600))

        first = await broker.access_token_for(REFRESH_TOKEN)
        second = await broker.access_token_for(REFRESH_TOKEN)

        assert first.access_token == second.access_token == "at-new"
        assert len(requests) == 1

    @pytest.mark.asyncio
    async def test_refreshes_again_inside_the_safety_margin(self):
        handler = AsyncMock(side_effect=[_token_response("at-1", expires_in=30), _token_response("at-2")])
        broker, requests = _broker(handler)

        await broker.access_token_for(REFRESH_TOKEN)
        second = await broker.access_token_for(REFRESH_TOKEN)

        assert second.access_token == "at-2"
        assert len(requests) == 2

    @pytest.mark.asyncio
    async def test_returns_and_indexes_a_rotated_refresh_token(self):
        broker, requests = _broker(lambda r: _token_response(refresh_token="rt-rotated"))

        result = await broker.access_token_for(REFRESH_TOKEN)
        presented_rotated = await broker.access_token_for("rt-rotated")

        assert result.rotated_refresh_token == "rt-rotated"
        assert presented_rotated.access_token == "at-new"
        assert len(requests) == 1

    @pytest.mark.asyncio
    async def test_a_stale_refresh_token_still_resolves_to_the_session(self):
        broker, requests = _broker(lambda r: _token_response(refresh_token="rt-rotated"))
        await broker.access_token_for(REFRESH_TOKEN)

        # The caller never learned about the rotation and presents the value it already rotated away.
        result = await broker.access_token_for(REFRESH_TOKEN)

        assert result.access_token == "at-new"
        assert len(requests) == 1

    @pytest.mark.asyncio
    async def test_the_next_refresh_grant_uses_the_rotated_token(self):
        handler = AsyncMock(
            side_effect=[
                _token_response("at-1", expires_in=30, refresh_token="rt-rotated"),
                _token_response("at-2"),
            ]
        )
        broker, requests = _broker(handler)
        await broker.access_token_for(REFRESH_TOKEN)

        await broker.access_token_for(REFRESH_TOKEN)

        assert httpx.QueryParams(requests[1].read().decode())["refresh_token"] == "rt-rotated"

    @pytest.mark.asyncio
    async def test_one_caller_does_not_refresh_twice_at_once(self):
        async def slow_handler(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.05)
            return _token_response()

        broker, requests = _broker(slow_handler)

        first, second = await asyncio.gather(
            broker.access_token_for(REFRESH_TOKEN), broker.access_token_for(REFRESH_TOKEN)
        )

        assert first.access_token == second.access_token == "at-new"
        assert len(requests) == 1

    @pytest.mark.asyncio
    async def test_okta_refusal_returns_none_and_forgets_the_session(self):
        broker, requests = _broker(lambda r: httpx.Response(400, json={"error": "invalid_grant"}))

        assert await broker.access_token_for(REFRESH_TOKEN) is None
        assert await broker.access_token_for(REFRESH_TOKEN) is None
        assert len(requests) == 2

    @pytest.mark.asyncio
    async def test_response_without_an_access_token_returns_none(self):
        broker, _ = _broker(lambda r: httpx.Response(200, json={"token_type": "Bearer"}))

        assert await broker.access_token_for(REFRESH_TOKEN) is None

    @pytest.mark.asyncio
    async def test_transport_error_returns_none(self):
        def refuse(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom", request=request)

        broker, _ = _broker(refuse)

        assert await broker.access_token_for(REFRESH_TOKEN) is None


def _scope(headers: dict[str, str], scope_type: str = "http") -> dict:
    return {
        "type": scope_type,
        "headers": [(name.lower().encode(), value.encode()) for name, value in headers.items()],
    }


def _headers_of(scope: dict) -> dict[str, str]:
    return {name.decode(): value.decode() for name, value in scope["headers"]}


class _RecordingApp:
    """Inner ASGI app that records what it was handed and answers 200."""

    def __init__(self):
        self.scopes: list[dict] = []
        self.broker = AsyncMock()

    async def __call__(self, scope, receive, send):
        self.scopes.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"{}"})


async def _receive() -> dict:  # noqa: RUF029 - the ASGI protocol requires an awaitable
    return {"type": "http.request", "body": b"", "more_body": False}


async def _call(middleware: OktaRefreshTokenMiddleware, scope: dict) -> list[dict]:
    messages: list[dict] = []

    async def send(message: dict) -> None:  # noqa: RUF029 - the ASGI protocol requires an awaitable
        messages.append(message)

    await middleware(scope, _receive, send)
    return messages


class TestMiddleware:
    def setup_method(self):
        self.app = _RecordingApp()

    def _middleware(self, broker=None) -> OktaRefreshTokenMiddleware:
        return OktaRefreshTokenMiddleware(self.app, broker=broker or self.app.broker)

    @pytest.mark.asyncio
    async def test_requests_without_the_header_pass_through_untouched(self):
        messages = await _call(self._middleware(), _scope({"authorization": "Bearer expired-token"}))

        assert _headers_of(self.app.scopes[0]) == {"authorization": "Bearer expired-token"}
        assert messages[0]["type"] == "http.response.start"
        self.app.broker.access_token_for.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_still_valid_bearer_token_never_reaches_the_token_endpoint(self):
        bearer = f"Bearer {_jwt(3600)}"
        scope = _scope({"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(self._middleware(), scope)

        assert _headers_of(self.app.scopes[0]) == {"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN}
        self.app.broker.access_token_for.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_an_expired_bearer_token_is_replaced(self):
        self.app.broker.access_token_for.return_value = _refreshed("at-new")
        scope = _scope({"authorization": f"Bearer {_jwt(-10)}", REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(self._middleware(), scope)

        self.app.broker.access_token_for.assert_awaited_once_with(REFRESH_TOKEN)
        assert _headers_of(self.app.scopes[0])["authorization"] == "Bearer at-new"

    @pytest.mark.asyncio
    async def test_a_request_with_no_bearer_token_is_still_served(self):
        self.app.broker.access_token_for.return_value = _refreshed("at-new")
        scope = _scope({REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(self._middleware(), scope)

        assert _headers_of(self.app.scopes[0])["authorization"] == "Bearer at-new"

    @pytest.mark.asyncio
    async def test_a_refused_refresh_leaves_the_request_as_it_arrived(self):
        self.app.broker.access_token_for.return_value = None
        bearer = f"Bearer {_jwt(-10)}"
        scope = _scope({"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(self._middleware(), scope)

        assert _headers_of(self.app.scopes[0]) == {"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN}

    @pytest.mark.asyncio
    async def test_a_rotated_refresh_token_is_returned_to_the_caller(self):
        self.app.broker.access_token_for.return_value = _refreshed("at-new", rotated="rt-rotated")
        scope = _scope({"authorization": f"Bearer {_jwt(-10)}", REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        messages = await _call(self._middleware(), scope)

        start = messages[0]
        assert dict(start["headers"])[REFRESH_TOKEN_HEADER.encode()] == b"rt-rotated"

    @pytest.mark.asyncio
    async def test_no_response_header_without_rotation(self):
        self.app.broker.access_token_for.return_value = _refreshed("at-new")
        scope = _scope({"authorization": f"Bearer {_jwt(-10)}", REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        messages = await _call(self._middleware(), scope)

        assert REFRESH_TOKEN_HEADER.encode() not in dict(messages[0]["headers"])

    @pytest.mark.asyncio
    async def test_without_a_broker_the_request_passes_through_and_warns_once(self):
        middleware = OktaRefreshTokenMiddleware(self.app, broker=None)
        bearer = f"Bearer {_jwt(-10)}"
        scope = _scope({"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(middleware, _scope({"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN}))
        await _call(middleware, scope)

        assert _headers_of(self.app.scopes[-1]) == {"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN}
        assert middleware._warned_without_broker is True

    @pytest.mark.asyncio
    async def test_non_http_scopes_pass_straight_through(self):
        await _call(self._middleware(), _scope({}, scope_type="lifespan"))

        assert self.app.scopes[0]["type"] == "lifespan"
        self.app.broker.access_token_for.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_original_scope_is_not_mutated(self):
        self.app.broker.access_token_for.return_value = _refreshed("at-new")
        bearer = f"Bearer {_jwt(-10)}"
        scope = _scope({"authorization": bearer, REFRESH_TOKEN_HEADER: REFRESH_TOKEN})

        await _call(self._middleware(), scope)

        assert _headers_of(scope)["authorization"] == bearer


class TestOutsideTheMcpAuthMiddleware:
    """The rewritten bearer token must reach FastMCP's verifier, not just our own code.

    FastMCP builds its Starlette middleware stack itself with no hook for adding to it, so
    ``server.py`` serves the app behind this middleware with ``add_middleware()``. These tests
    pin that ordering against the real ``BearerAuthBackend``: if the wrapper ever ended up
    inside the auth middleware, the verifier would see the expired token and every refresh
    would 401.
    """

    def _app(self, broker, seen: list[str]) -> Starlette:
        class _StubVerifier:
            async def verify_token(self, token: str) -> AccessToken | None:
                seen.append(token)
                if token != "at-new" and token != VALID_BEARER_TOKEN:
                    return None
                return AccessToken(
                    token=token, client_id=CLIENT_ID, scopes=["openid"], expires_at=int(time.time()) + 3600
                )

        async def endpoint(request):  # noqa: RUF029 - Starlette route handlers are awaited for us
            return PlainTextResponse("ok")

        app = Starlette(
            routes=[Route("/mcp", endpoint, methods=["POST"])],
            middleware=[
                Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(_StubVerifier())),
                Middleware(AuthContextMiddleware),
            ],
        )
        app.add_middleware(OktaRefreshTokenMiddleware, broker=broker)
        return app

    @pytest.mark.asyncio
    async def test_the_verifier_is_handed_the_minted_token(self):
        seen: list[str] = []
        broker = AsyncMock()
        broker.access_token_for.return_value = _refreshed("at-new", rotated="rt-2")
        app = self._app(broker, seen)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/mcp", headers={"Authorization": f"Bearer {_jwt(-10)}", REFRESH_TOKEN_HEADER: REFRESH_TOKEN}
            )

        assert response.status_code == 200
        assert seen == ["at-new"]
        assert response.headers[REFRESH_TOKEN_HEADER] == "rt-2"

    @pytest.mark.asyncio
    async def test_a_request_the_middleware_should_not_touch_is_verified_as_is(self):
        seen: list[str] = []
        broker = AsyncMock()
        app = self._app(broker, seen)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post("/mcp", headers={"Authorization": f"Bearer {VALID_BEARER_TOKEN}"})

        assert response.status_code == 200
        assert seen == [VALID_BEARER_TOKEN]
        broker.access_token_for.assert_not_awaited()


class TestServerWiring:
    """The streamable-http app must really be served behind the middleware."""

    def _fake_mcp(self, monkeypatch) -> MagicMock:
        fake = MagicMock()
        fake.settings.host = "0.0.0.0"
        fake.settings.port = 8000
        monkeypatch.setattr(server_module, "mcp", fake)
        return fake

    def test_the_broker_needs_the_client_secret(self, monkeypatch):
        monkeypatch.setenv("OKTA_ORG_URL", ORG_URL)
        monkeypatch.setenv("OKTA_CLIENT_ID", CLIENT_ID)
        monkeypatch.delenv("OKTA_CLIENT_SECRET", raising=False)

        assert server_module._refresh_broker() is None

        monkeypatch.setenv("OKTA_CLIENT_SECRET", CLIENT_SECRET)
        broker = server_module._refresh_broker()
        assert broker is not None
        assert broker.token_url == f"{ORG_URL}/oauth2/v1/token"

    def test_user_mode_serves_the_wrapped_app(self, monkeypatch):
        app = MagicMock()
        self._fake_mcp(monkeypatch).streamable_http_app.return_value = app
        broker = OktaRefreshTokenBroker(ORG_URL, CLIENT_ID, CLIENT_SECRET)
        served: dict = {}
        monkeypatch.setattr(server_module, "AUTH_MODE", "user")
        monkeypatch.setattr(server_module, "_refresh_broker", lambda: broker)
        monkeypatch.setattr("uvicorn.run", lambda served_app, **kwargs: served.update(app=served_app, kwargs=kwargs))

        server_module._run_http()

        assert app.add_middleware.call_args.args == (OktaRefreshTokenMiddleware,)
        assert app.add_middleware.call_args.kwargs == {"broker": broker}
        assert served["app"] is app
        assert served["kwargs"]["port"] == 8000

    def test_service_mode_adds_no_middleware(self, monkeypatch):
        app = MagicMock()
        self._fake_mcp(monkeypatch).streamable_http_app.return_value = app
        monkeypatch.setattr(server_module, "AUTH_MODE", "service")
        monkeypatch.setattr("uvicorn.run", lambda *args, **kwargs: None)

        server_module._run_http()

        app.add_middleware.assert_not_called()
