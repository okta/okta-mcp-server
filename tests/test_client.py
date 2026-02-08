# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.client"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager


# We need to mock okta.client.Client since it may not be installed
@pytest.fixture
def mock_okta_client():
    with patch.dict(
        "sys.modules",
        {
            "okta": MagicMock(),
            "okta.client": MagicMock(),
        },
    ):
        from okta_mcp_server.utils.client import get_okta_client

        yield get_okta_client


class TestGetOktaClient:
    async def test_creates_client_with_valid_token(self, mock_okta_client, monkeypatch):
        monkeypatch.setenv("OKTA_ORG_URL", "https://dev.okta.com")
        monkeypatch.setenv("OKTA_CLIENT_ID", "client123")

        manager = OktaAuthManager()
        manager.org_url = "https://dev.okta.com"

        with (
            patch("keyring.get_password", return_value="valid_api_token"),
            patch.object(manager, "is_valid_token", new_callable=AsyncMock, return_value=True),
        ):
            client = await mock_okta_client(manager)
            assert client is not None

    async def test_reauthenticates_on_invalid_token(self, mock_okta_client, monkeypatch):
        monkeypatch.setenv("OKTA_ORG_URL", "https://dev.okta.com")
        monkeypatch.setenv("OKTA_CLIENT_ID", "client123")

        manager = OktaAuthManager()
        manager.org_url = "https://dev.okta.com"

        with (
            patch("keyring.get_password", return_value="new_token"),
            patch.object(manager, "is_valid_token", new_callable=AsyncMock, return_value=False),
            patch.object(manager, "authenticate", new_callable=AsyncMock) as mock_auth,
        ):
            client = await mock_okta_client(manager)
            mock_auth.assert_called_once()
