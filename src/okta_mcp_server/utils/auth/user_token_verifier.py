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

import hashlib
import time

import httpx
import jwt
from loguru import logger
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings

_MAX_CACHE_SECONDS = 300
_MAX_CACHE_ENTRIES = 1024


class OktaUserTokenVerifier:
    """Verify Okta org authorization server access tokens presented to the MCP server.

    Org authorization server access tokens are meant to be treated as opaque by resource
    servers, so validity is confirmed by Okta itself: the token is presented to the org
    ``/oauth2/v1/userinfo`` endpoint, which rejects expired, revoked, or forged tokens.
    Only after Okta accepts the token are its (unverified) claims trusted. The ``cid``
    claim must match ``OKTA_CLIENT_ID`` so tokens minted for other apps are rejected.

    Results are cached per token for up to five minutes (never past the token's expiry)
    to stay well under the userinfo rate limit.
    """

    def __init__(self, org_url: str, client_id: str):
        self.org_url = org_url.rstrip("/")
        self.client_id = client_id
        self._cache: dict[str, tuple[float, AccessToken]] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        cache_key = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = time.time()

        cached = self._cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

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

        userinfo = await self._fetch_userinfo(token)
        if userinfo is None:
            return None

        if claims.get("uid") and userinfo.get("sub") != claims["uid"]:
            logger.warning("Rejected bearer token: userinfo subject does not match the token uid claim")
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

        self._store(cache_key, min(exp, now + _MAX_CACHE_SECONDS), access_token)
        return access_token

    async def _fetch_userinfo(self, token: str) -> dict | None:
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
            return None
        return response.json()

    def _store(self, cache_key: str, expires_at: float, access_token: AccessToken) -> None:
        if len(self._cache) >= _MAX_CACHE_ENTRIES:
            now = time.time()
            self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            if len(self._cache) >= _MAX_CACHE_ENTRIES:
                self._cache.clear()
        self._cache[cache_key] = (expires_at, access_token)


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
