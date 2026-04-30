# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the okta_authorisation_flow lifespan handler."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.server import OktaAppContext, okta_authorisation_flow


@pytest.fixture(autouse=True)
def _okta_env(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "test-client-id")
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)


def _make_manager_mock(*, is_valid: bool, has_token: bool = True) -> MagicMock:
    manager = MagicMock()
    manager.is_valid_token = AsyncMock(return_value=is_valid)
    manager.has_token = MagicMock(return_value=has_token)
    manager.authenticate = AsyncMock()
    manager.clear_tokens = MagicMock()
    return manager


class TestOktaAuthorisationFlow:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.server.OktaAuthManager")
    async def test_skips_authenticate_when_token_is_valid(self, mock_cls):
        manager = _make_manager_mock(is_valid=True)
        mock_cls.return_value = manager
        async with okta_authorisation_flow(MagicMock()) as ctx:
            assert isinstance(ctx, OktaAppContext)
            assert ctx.okta_auth_manager is manager
        manager.is_valid_token.assert_awaited_once()
        manager.authenticate.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.server.OktaAuthManager")
    async def test_yields_context_after_successful_reauth(self, mock_cls):
        manager = _make_manager_mock(is_valid=False, has_token=True)
        mock_cls.return_value = manager
        async with okta_authorisation_flow(MagicMock()) as ctx:
            assert ctx.okta_auth_manager is manager
        manager.is_valid_token.assert_awaited_once()
        manager.has_token.assert_called_once()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.server.OktaAuthManager")
    async def test_does_not_clear_tokens_on_teardown(self, mock_cls):
        manager = _make_manager_mock(is_valid=True)
        mock_cls.return_value = manager
        async with okta_authorisation_flow(MagicMock()):
            pass
        manager.clear_tokens.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.server.OktaAuthManager")
    async def test_exits_with_code_1_when_auth_fails(self, mock_cls):
        manager = _make_manager_mock(is_valid=False, has_token=False)
        mock_cls.return_value = manager
        with pytest.raises(SystemExit) as exc_info:
            async with okta_authorisation_flow(MagicMock()):
                pytest.fail("Lifespan must not yield when no token is available")
        assert exc_info.value.code == 1
        manager.is_valid_token.assert_awaited_once()
        manager.has_token.assert_called_once()
