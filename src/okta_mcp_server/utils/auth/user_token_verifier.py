# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# This module verifies per-user bearer tokens when the server runs in user auth mode
# (OKTA_AUTH_MODE=user). Each MCP request carries the caller's own Okta access token,
# issued by the org authorization server, and every Okta API call is made with it, so
# the caller can do only what their own Okta admin role allows.

import asyncio
import hashlib
import time

import httpx
import jwt
from loguru import logger
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

_MAX_CACHE_SECONDS = 300
_MAX_CACHE_ENTRIES = 1024
_REJECTION_CACHE_SECONDS = 60
_LOOKUP_BURST = 30
_LOOKUPS_PER_SECOND = 5.0
_REFUSED = object()
"""Returned by the userinfo call when Okta definitively rejected the token."""


class _LookupBudget:
    """Token bucket capping how often unverified tokens are sent to Okta.

    Claims are checked before the signature is (Okta does that), so anyone can mint a token that
    passes them. Without a cap, a stream of such tokens turns into a stream of userinfo calls that
    drains the org's rate limit for every other app using it.
    """

    def __init__(self, rate: float, burst: int):
        self.rate = rate
        self.burst = burst
        self._available = float(burst)
        self._updated = time.monotonic()

    def try_acquire(self) -> bool:
        now = time.monotonic()
        self._available = min(self.burst, self._available + (now - self._updated) * self.rate)
        self._updated = now
        if self._available < 1:
            return False
        self._available -= 1
        return True


class OktaUserTokenVerifier:
    """Verify Okta org authorization server access tokens presented to the MCP server.

    Org authorization server access tokens are meant to be treated as opaque by resource
    servers, so validity is confirmed by Okta itself: the token is presented to the org
    ``/oauth2/v1/userinfo`` endpoint, which rejects expired, revoked, or forged tokens.
    Only after Okta accepts the token are its (unverified) claims trusted. The ``cid``
    claim must match ``OKTA_CLIENT_ID`` so tokens minted for other apps are rejected.

    Results are cached per token for up to five minutes (never past the token's expiry), and
    tokens Okta rejects are remembered for a minute, to stay well under the userinfo rate limit.
    Concurrent requests carrying the same new token share one userinfo call, and calls for tokens
    not yet seen are capped overall, so forged tokens cannot exhaust the org's rate limit: past
    the cap, new tokens are rejected until it refills while already verified ones keep working.
    """

    def __init__(
        self,
        org_url: str,
        client_id: str,
        *,
        lookups_per_second: float = _LOOKUPS_PER_SECOND,
        lookup_burst: int = _LOOKUP_BURST,
    ):
        self.org_url = org_url.rstrip("/")
        self.client_id = client_id
        self._cache: dict[str, tuple[float, AccessToken]] = {}
        self._rejected: dict[str, tuple[float, None]] = {}
        self._inflight: dict[str, asyncio.Future[AccessToken | None]] = {}
        self._lookups = _LookupBudget(lookups_per_second, lookup_burst)

    async def verify_token(self, token: str) -> AccessToken | None:
        cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = time.time()

        cached = self._cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]
        rejected = self._rejected.get(cache_key)
        if rejected and rejected[0] > now:
            logger.debug("Rejected bearer token: Okta rejected it within the last minute")
            return None

        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.DecodeError:
            logger.warning("Rejected bearer token: not a JWT")
            return None

        if claims.get("iss", "").rstrip("/") != self.org_url:
            logger.warning(f"Rejected bearer token: issuer {claims.get('iss')!r} is not the org authorization server")
            return None
        if claims.get("cid") != self.client_id:
            logger.warning(f"Rejected bearer token: issued to client {claims.get('cid')!r}, not OKTA_CLIENT_ID")
            return None

        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp <= now:
            logger.info("Rejected bearer token: expired or missing exp claim")
            return None

        inflight = self._inflight.get(cache_key)
        if inflight is None:
            inflight = asyncio.ensure_future(self._verify_with_okta(token, cache_key, claims, exp))
            self._inflight[cache_key] = inflight
            inflight.add_done_callback(lambda _: self._inflight.pop(cache_key, None))
        # Shielded so one caller disconnecting does not cancel the lookup the others are awaiting.
        return await asyncio.shield(inflight)

    async def _verify_with_okta(self, token: str, cache_key: str, claims: dict, exp: float) -> AccessToken | None:
        if not self._lookups.try_acquire():
            logger.warning("Rejected bearer token: Okta userinfo lookup budget exhausted, possible forged tokens")
            return None

        userinfo = await self._fetch_userinfo(token)
        now = time.time()
        if userinfo is _REFUSED:
            self._store(self._rejected, cache_key, now + _REJECTION_CACHE_SECONDS, None)
            return None
        if userinfo is None:
            return None

        if claims.get("uid") and userinfo.get("sub") != claims["uid"]:
            logger.warning("Rejected bearer token: userinfo subject does not match the token uid claim")
            self._store(self._rejected, cache_key, now + _REJECTION_CACHE_SECONDS, None)
            return None

        access_token = AccessToken(
            token=token,
            client_id=claims["cid"],
            scopes=claims.get("scp", []),
            expires_at=exp,
            subject=userinfo.get("sub"),
            claims={"iss": claims["iss"], "uid": claims.get("uid"), "sub": claims.get("sub")},
        )
        logger.info(f"Authenticated Okta user {claims.get('sub')} ({userinfo.get('sub')})")

        self._store(self._cache, cache_key, min(exp, now + _MAX_CACHE_SECONDS), access_token)
        return access_token

    async def _fetch_userinfo(self, token: str) -> dict | object | None:
        """The userinfo payload, ``_REFUSED`` if Okta rejected the token (HTTP 401 or 403), or None
        for any other failure (network error, rate limit, 5xx), which is not remembered.
        """
        url = f"{self.org_url}/oauth2/v1/userinfo"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(
                    url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
                )
        except httpx.HTTPError as e:
            logger.error(f"Failed to reach Okta userinfo endpoint: {e}")
            return None

        if response.status_code != 200:
            logger.warning(f"Rejected bearer token: userinfo returned HTTP {response.status_code}")
            return _REFUSED if response.status_code in (401, 403) else None
        return response.json()

    @staticmethod
    def _store(cache: dict[str, tuple[float, AccessToken | None]], cache_key: str, expires_at: float, value) -> None:
        if len(cache) >= _MAX_CACHE_ENTRIES:
            now = time.time()
            for key in [k for k, v in cache.items() if v[0] <= now]:
                del cache[key]
            if len(cache) >= _MAX_CACHE_ENTRIES:
                cache.clear()
        cache[cache_key] = (expires_at, value)


def build_user_auth(
    org_url: str, client_id: str, scopes: list[str], public_url: str | None
) -> tuple[AuthSettings, OktaUserTokenVerifier]:
    """Build the FastMCP auth settings and token verifier for user auth mode.

    ``openid`` plus the configured Okta API scopes are both advertised in the protected
    resource metadata and required on every token, so a client that requests only some
    of them is rejected with ``insufficient_scope`` rather than failing tool by tool.
    """
    org_url = org_url.rstrip("/")
    if not org_url.startswith("https://"):
        org_url = "https://" + org_url

    required_scopes = ["openid", *(s for s in scopes if s != "openid")]
    settings = AuthSettings(
        issuer_url=org_url,
        resource_server_url=public_url,
        required_scopes=required_scopes,
    )
    return settings, OktaUserTokenVerifier(org_url, client_id)
