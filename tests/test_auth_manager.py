# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for OktaAuthManager scope-aware token validation."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest

from okta_mcp_server.utils.auth import auth_manager
from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager


def _token(scp):
    """Build an unsigned-readable JWT carrying the given scopes."""
    return jwt.encode({"scp": scp}, "test-secret", algorithm="HS256")


@pytest.fixture
def manager(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "0oaclient")
    monkeypatch.setenv("OKTA_SCOPES", "")
    return OktaAuthManager()


def _patch_token(monkeypatch, api_token):
    monkeypatch.setattr(
        auth_manager.keyring,
        "get_password",
        lambda service, key: api_token if key == "api_token" else None,
    )


class TestTokenHasRequiredScopes:
    def test_returns_true_when_token_covers_requested_scopes(self, manager):
        manager.scopes = "okta.users.read"
        assert manager._token_has_required_scopes(_token(["okta.users.read", "okta.groups.read"])) is True

    def test_returns_false_when_a_scope_is_missing(self, manager):
        manager.scopes = "okta.users.read okta.groups.manage"
        assert manager._token_has_required_scopes(_token(["okta.users.read"])) is False

    def test_space_delimited_scope_string_claim_is_handled(self, manager):
        manager.scopes = "okta.users.read okta.groups.read"
        token = jwt.encode({"scope": "okta.users.read okta.groups.read"}, "s", algorithm="HS256")
        assert manager._token_has_required_scopes(token) is True

    def test_oidc_base_scopes_are_ignored(self, manager):
        # openid/profile/email/offline_access are never echoed in the access token's
        # scope claim, so they must not trigger a re-auth.
        manager.scopes = "openid profile email offline_access okta.users.read"
        assert manager._token_has_required_scopes(_token(["okta.users.read"])) is True

    def test_opaque_token_is_assumed_valid(self, manager):
        manager.scopes = "okta.users.read"
        assert manager._token_has_required_scopes("not-a-jwt") is True


class TestIsValidTokenScopeGate:
    @pytest.mark.asyncio
    async def test_forces_reauth_and_skips_refresh_when_scope_widened(self, manager, monkeypatch):
        manager.scopes = "okta.users.read okta.groups.manage"
        _patch_token(monkeypatch, _token(["okta.users.read"]))
        manager.token_timestamp = time.time()  # fresh token; only scopes are stale

        refresh_mock = MagicMock(return_value=True)
        auth_mock = AsyncMock()
        monkeypatch.setattr(manager, "refresh_access_token", refresh_mock)
        monkeypatch.setattr(manager, "authenticate", auth_mock)

        await manager.is_valid_token()

        auth_mock.assert_awaited_once()
        refresh_mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_valid_when_token_covers_scopes_and_is_fresh(self, manager, monkeypatch):
        manager.scopes = "okta.users.read"
        _patch_token(monkeypatch, _token(["okta.users.read", "okta.groups.read"]))
        manager.token_timestamp = time.time()

        refresh_mock = MagicMock()
        auth_mock = AsyncMock()
        monkeypatch.setattr(manager, "refresh_access_token", refresh_mock)
        monkeypatch.setattr(manager, "authenticate", auth_mock)

        assert await manager.is_valid_token() is True
        refresh_mock.assert_not_called()
        auth_mock.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_does_not_reprompt_after_first_scope_reauth_attempt(self, manager, monkeypatch):
        # A scope listed in OKTA_SCOPES but never granted to the Okta app stays
        # absent from every fresh token. After one re-auth attempt we must stop
        # forcing the device flow and let the API 401/403 path handle it.
        manager.scopes = "okta.users.read okta.groups.manage"
        _patch_token(monkeypatch, _token(["okta.users.read"]))
        manager.token_timestamp = time.time()

        refresh_mock = MagicMock(return_value=True)
        auth_mock = AsyncMock()
        monkeypatch.setattr(manager, "refresh_access_token", refresh_mock)
        monkeypatch.setattr(manager, "authenticate", auth_mock)

        # First call: scope mismatch triggers exactly one fresh grant.
        await manager.is_valid_token()
        assert auth_mock.await_count == 1
        assert manager._scope_reauth_attempted is True

        # Second call with the same still-insufficient token must NOT re-auth again.
        await manager.is_valid_token()
        assert auth_mock.await_count == 1

    @pytest.mark.asyncio
    async def test_expired_token_with_correct_scopes_refreshes(self, manager, monkeypatch):
        manager.scopes = "okta.users.read"
        _patch_token(monkeypatch, _token(["okta.users.read"]))
        manager.token_timestamp = time.time() - 7200  # well past the 3600s expiry

        refresh_mock = MagicMock(return_value=True)
        auth_mock = AsyncMock()
        monkeypatch.setattr(manager, "refresh_access_token", refresh_mock)
        monkeypatch.setattr(manager, "authenticate", auth_mock)

        await manager.is_valid_token()

        refresh_mock.assert_called_once()
        auth_mock.assert_not_awaited()
