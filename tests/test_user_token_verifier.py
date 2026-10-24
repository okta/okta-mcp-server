# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the per-user bearer token verifier used in user auth mode."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest

from okta_mcp_server.utils.auth.user_token_verifier import OktaUserTokenVerifier, build_user_auth

ORG_URL = "https://test.okta.com"
CLIENT_ID = "mcp-client-id"
USER_ID = "00u123"


def _token(**overrides) -> str:
    claims = {
        "iss": ORG_URL,
        "aud": ORG_URL,
        "cid": CLIENT_ID,
        "uid": USER_ID,
        "sub": "admin@example.com",
        "scp": ["openid", "okta.users.read"],
        "exp": int(time.time()) + 3600,
    }
    claims.update(overrides)
    return jwt.encode(claims, "test-secret", algorithm="HS256")


def _userinfo_response(status_code: int = 200, sub: str = USER_ID) -> MagicMock:
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = {"sub": sub}
    return response


def _patch_userinfo(response=None, side_effect=None):
    client = MagicMock()
    client.get = AsyncMock(return_value=response, side_effect=side_effect)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return patch("okta_mcp_server.utils.auth.user_token_verifier.httpx.AsyncClient", return_value=client), client


class TestVerifyToken:
    @pytest.mark.asyncio
    async def test_accepts_token_that_okta_accepts(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        token = _token()
        patcher, client = _patch_userinfo(_userinfo_response())
        with patcher:
            result = await verifier.verify_token(token)

        assert result is not None
        assert result.token == token
        assert result.client_id == CLIENT_ID
        assert result.subject == USER_ID
        assert result.scopes == ["openid", "okta.users.read"]
        client.get.assert_awaited_once()
        assert client.get.await_args.args[0] == f"{ORG_URL}/oauth2/v1/userinfo"
        assert client.get.await_args.kwargs["headers"]["Authorization"] == f"Bearer {token}"

    @pytest.mark.asyncio
    async def test_caches_successful_verification(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        token = _token()
        patcher, client = _patch_userinfo(_userinfo_response())
        with patcher:
            await verifier.verify_token(token)
            await verifier.verify_token(token)
        client.get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rejects_when_userinfo_rejects(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        patcher, _ = _patch_userinfo(_userinfo_response(status_code=401))
        with patcher:
            assert await verifier.verify_token(_token()) is None

    @pytest.mark.asyncio
    async def test_does_not_cache_rejections(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        token = _token()
        patcher, client = _patch_userinfo(_userinfo_response(status_code=401))
        with patcher:
            await verifier.verify_token(token)
            await verifier.verify_token(token)
        assert client.get.await_count == 2

    @pytest.mark.asyncio
    async def test_rejects_when_userinfo_unreachable(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        patcher, _ = _patch_userinfo(side_effect=httpx.ConnectError("boom"))
        with patcher:
            assert await verifier.verify_token(_token()) is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "token",
        [
            pytest.param("not-a-jwt", id="opaque"),
            pytest.param(_token(cid="some-other-app"), id="other-client"),
            pytest.param(_token(iss=f"{ORG_URL}/oauth2/default"), id="custom-auth-server"),
            pytest.param(_token(exp=int(time.time()) - 10), id="expired"),
            pytest.param(_token(exp=None), id="no-exp"),
        ],
    )
    async def test_rejects_without_calling_okta(self, token):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        patcher, client = _patch_userinfo(_userinfo_response())
        with patcher:
            assert await verifier.verify_token(token) is None
        client.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_rejects_when_userinfo_subject_does_not_match_uid(self):
        verifier = OktaUserTokenVerifier(ORG_URL, CLIENT_ID)
        patcher, _ = _patch_userinfo(_userinfo_response(sub="00uSOMEONEELSE"))
        with patcher:
            assert await verifier.verify_token(_token()) is None

    @pytest.mark.asyncio
    async def test_tolerates_trailing_slash_on_org_url(self):
        verifier = OktaUserTokenVerifier(f"{ORG_URL}/", CLIENT_ID)
        patcher, _ = _patch_userinfo(_userinfo_response())
        with patcher:
            assert await verifier.verify_token(_token()) is not None


class TestBuildUserAuth:
    def test_requires_openid_and_configured_scopes(self):
        settings, verifier = build_user_auth(
            "test.okta.com/", CLIENT_ID, ["okta.users.read", "openid", "okta.groups.read"], "https://mcp.example.com/mcp"
        )
        assert settings.required_scopes == ["openid", "okta.users.read", "okta.groups.read"]
        assert str(settings.issuer_url).rstrip("/") == ORG_URL
        assert str(settings.resource_server_url) == "https://mcp.example.com/mcp"
        assert verifier.org_url == ORG_URL
        assert verifier.client_id == CLIENT_ID

    def test_public_url_is_optional(self):
        settings, _ = build_user_auth(ORG_URL, CLIENT_ID, [], None)
        assert settings.resource_server_url is None
        assert settings.required_scopes == ["openid"]
