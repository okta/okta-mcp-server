# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# Per-caller access token refresh for user auth mode (OKTA_AUTH_MODE=user).
#
# Okta org authorization server access tokens are short-lived (one hour by default), so a
# caller whose token expires mid-session starts getting 401s even though its refresh token is
# still valid. Okta honors a refresh_token grant only from the client the token was issued to,
# so the server runs the grant itself using OKTA_CLIENT_SECRET.
#
# A client that can refresh on its own should keep doing that; this path is opt-in per request,
# taken only when the request carries REFRESH_TOKEN_HEADER and the bearer token is no longer
# usable.

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from loguru import logger
from starlette.datastructures import Headers, MutableHeaders

from okta_mcp_server.utils.auth.auth_manager import token_is_unexpired

REFRESH_TOKEN_HEADER = "x-okta-refresh-token"
"""Header a client may send alongside its bearer token to enable server-side refresh.

Sent back on the response when Okta rotates the refresh token, so a client that stores what it
is given stays in sync. Clients that ignore it keep working too: the server holds the rotated
value for the caller's session.
"""

_DEFAULT_EXPIRES_IN_SECONDS = 3600.0
_REFRESH_MARGIN_SECONDS = 60
_MAX_SESSIONS = 1024

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], Receive, Send], Awaitable[None]]


def _cache_key(token: str) -> str:
    """Hash a token so refresh tokens are not held as dict keys in plain text."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class RefreshedToken:
    """A freshly minted access token, plus the caller's new refresh token if Okta rotated it."""

    access_token: str
    rotated_refresh_token: str | None = None


@dataclass
class _Session:
    """One caller's refresh token and the access token last minted from it."""

    refresh_token: str
    access_token: str | None = None
    expires_at: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class OktaRefreshTokenBroker:
    """Mints Okta access tokens from callers' refresh tokens, caching one per caller.

    Sessions are keyed by the refresh token the caller presents, so the same caller reuses one
    session. When Okta rotates the refresh token the session keeps the newest value and is also
    indexed under it: a caller that keeps presenting a value it already rotated still resolves
    to the same session and is handed the still-unexpired access token instead of failing with
    ``invalid_grant``.
    """

    def __init__(
        self,
        org_url: str,
        client_id: str,
        client_secret: str,
        *,
        http_client: httpx.AsyncClient | None = None,
    ):
        self.token_url = f"{org_url.rstrip('/')}/oauth2/v1/token"
        self.client_id = client_id
        self.client_secret = client_secret
        self._http_client = http_client
        self._sessions: dict[str, _Session] = {}

    async def access_token_for(self, refresh_token: str) -> RefreshedToken | None:
        """Return a usable access token for ``refresh_token``, or None if Okta refuses it.

        Concurrent requests from one caller share a single token endpoint call: the second
        waiter finds the access token the first stored rather than refreshing again, which
        would burn a rotated refresh token.
        """
        session = self._sessions.get(_cache_key(refresh_token)) or self._new_session(refresh_token)
        async with session.lock:
            if session.access_token and session.expires_at > time.time() + _REFRESH_MARGIN_SECONDS:
                logger.debug("Reusing an access token already minted for this caller")
                return RefreshedToken(access_token=session.access_token)
            return await self._refresh(session)

    def _new_session(self, refresh_token: str) -> _Session:
        if len(self._sessions) >= _MAX_SESSIONS:
            self._evict()
        session = _Session(refresh_token=refresh_token)
        self._sessions[_cache_key(refresh_token)] = session
        return session

    def _evict(self) -> None:
        now = time.time()
        self._sessions = {k: v for k, v in self._sessions.items() if v.expires_at > now}
        if len(self._sessions) >= _MAX_SESSIONS:
            logger.warning(f"Refresh token cache full ({_MAX_SESSIONS} callers); clearing it")
            self._sessions.clear()

    def _drop(self, session: _Session) -> None:
        self._sessions = {k: v for k, v in self._sessions.items() if v is not session}

    async def _refresh(self, session: _Session) -> RefreshedToken | None:
        payload = await self._post_for_token(session.refresh_token)
        if payload is None:
            self._drop(session)
            return None

        access_token = payload.get("access_token")
        if not access_token:
            logger.warning("Okta refresh response carried no access_token; dropping the caller session")
            self._drop(session)
            return None

        session.access_token = access_token
        session.expires_at = time.time() + float(payload.get("expires_in") or _DEFAULT_EXPIRES_IN_SECONDS)

        rotated = payload.get("refresh_token")
        is_rotated = bool(rotated) and rotated != session.refresh_token
        if is_rotated:
            session.refresh_token = rotated
            self._sessions[_cache_key(rotated)] = session
            logger.debug("Stored rotated refresh token for this caller")

        logger.info("Minted a fresh Okta access token for a caller")
        return RefreshedToken(access_token=access_token, rotated_refresh_token=rotated if is_rotated else None)

    async def _post_for_token(self, refresh_token: str) -> dict | None:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        client = self._http_client or httpx.AsyncClient(timeout=10)
        try:
            response = await client.post(self.token_url, data=data, headers={"Accept": "application/json"})
        except httpx.HTTPError as e:
            logger.error(f"Okta token endpoint unreachable while refreshing a caller token: {e}")
            return None
        finally:
            if self._http_client is None:
                await client.aclose()

        if response.status_code != 200:
            logger.warning(
                f"Okta rejected the refresh_token grant (HTTP {response.status_code} "
                f"{response.json().get('error', '')}); dropping the caller session"
            )
            return None
        return response.json()


class OktaRefreshTokenMiddleware:
    """Swap an unusable bearer token for a freshly minted one before the request is verified.

    Pure ASGI middleware added outside the MCP auth middleware, so by the time FastMCP verifies
    the bearer token the request genuinely carries a valid one and everything downstream —
    verification, scope pruning, the forwarded Okta client — sees the fresh token unchanged.

    A request is left exactly as it arrived unless it opts in: no refresh header, or a bearer
    token that is still unexpired, or a refresh Okta refused. That keeps the common path free of
    token endpoint calls and keeps clients that refresh on their own unaffected.
    """

    def __init__(self, app: ASGIApp, broker: OktaRefreshTokenBroker | None = None):
        self.app = app
        self.broker = broker
        self._warned_without_broker = False

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        refresh_token = headers.get(REFRESH_TOKEN_HEADER)
        if not refresh_token:
            await self.app(scope, receive, send)
            return

        bearer = _bearer_token(headers.get("authorization"))
        if bearer and token_is_unexpired(bearer):
            await self.app(scope, receive, send)
            return

        if self.broker is None:
            if not self._warned_without_broker:
                logger.warning(
                    f"Received {REFRESH_TOKEN_HEADER} but OKTA_CLIENT_SECRET is not set, so expired "
                    "caller tokens cannot be refreshed server-side"
                )
                self._warned_without_broker = True
            await self.app(scope, receive, send)
            return

        refreshed = await self.broker.access_token_for(refresh_token)
        if refreshed is None:
            await self.app(scope, receive, send)
            return

        scope = dict(scope)
        scope["headers"] = _replace_header(scope["headers"], "authorization", f"Bearer {refreshed.access_token}")

        if refreshed.rotated_refresh_token is None:
            await self.app(scope, receive, send)
            return

        rotated = refreshed.rotated_refresh_token

        async def send_with_rotated_token(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)[REFRESH_TOKEN_HEADER] = rotated
            await send(message)

        await self.app(scope, receive, send_with_rotated_token)


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, credentials = authorization.partition(" ")
    return credentials.strip() or None if scheme.lower() == "bearer" else None


def _replace_header(headers: list[tuple[bytes, bytes]], name: str, value: str) -> list[tuple[bytes, bytes]]:
    name_bytes = name.lower().encode("utf-8")
    remaining = [(k, v) for k, v in headers if k.lower() != name_bytes]
    remaining.append((name_bytes, value.encode("utf-8")))
    return remaining
