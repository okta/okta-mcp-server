# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.client.get_okta_client."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
from okta_mcp_server.utils.client import get_okta_client


def _build_manager_mock() -> MagicMock:
    manager = MagicMock(spec=OktaAuthManager)
    manager.org_url = "https://test.okta.com"
    manager.authenticate = AsyncMock()
    return manager


class TestGetOktaClient:
    @pytest.mark.asyncio
    async def test_uses_freshly_refreshed_token_not_stale_pre_refresh_value(self):
        keyring_state = {"api_token": "stale-pre-refresh-token"}

        def refresh_then_return_true():
            keyring_state["api_token"] = "fresh-post-refresh-token"
            return True

        manager = _build_manager_mock()
        manager.is_valid_token = AsyncMock(side_effect=refresh_then_return_true)

        captured_config: dict = {}

        def fake_okta_client(config):
            captured_config.update(config)
            return MagicMock()

        with (
            patch("okta_mcp_server.utils.client.keyring") as mock_kr,
            patch("okta_mcp_server.utils.client.OktaClient", side_effect=fake_okta_client),
        ):
            mock_kr.get_password.side_effect = lambda _s, k: keyring_state.get(k)
            await get_okta_client(manager)

        assert captured_config["token"] == "fresh-post-refresh-token"

    @pytest.mark.asyncio
    async def test_uses_cached_token_when_already_valid(self):
        keyring_state = {"api_token": "valid-cached-token"}

        manager = _build_manager_mock()
        manager.is_valid_token = AsyncMock(return_value=True)

        captured_config: dict = {}

        def fake_okta_client(config):
            captured_config.update(config)
            return MagicMock()

        with (
            patch("okta_mcp_server.utils.client.keyring") as mock_kr,
            patch("okta_mcp_server.utils.client.OktaClient", side_effect=fake_okta_client),
        ):
            mock_kr.get_password.side_effect = lambda _s, k: keyring_state.get(k)
            await get_okta_client(manager)

        assert captured_config["token"] == "valid-cached-token"
        manager.authenticate.assert_not_awaited()
