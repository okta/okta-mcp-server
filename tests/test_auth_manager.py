# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for okta_mcp_server.utils.auth.auth_manager"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager, SERVICE_NAME


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env_vars(monkeypatch):
    """Set required env vars for OktaAuthManager."""
    monkeypatch.setenv("OKTA_ORG_URL", "https://dev-123456.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "0oa1abcdef")
    # Clear optional browserless vars
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)
    monkeypatch.delenv("OKTA_SCOPES", raising=False)


@pytest.fixture
def browserless_env(monkeypatch, env_vars):
    """Set env vars for browserless auth."""
    monkeypatch.setenv("OKTA_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----")
    monkeypatch.setenv("OKTA_KEY_ID", "kid123")


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestOktaAuthManagerInit:
    def test_init_with_required_vars(self, env_vars):
        manager = OktaAuthManager()
        assert manager.org_url == "https://dev-123456.okta.com"
        assert manager.client_id == "0oa1abcdef"
        assert manager.use_browserless_auth is False

    def test_adds_https_prefix(self, monkeypatch):
        monkeypatch.setenv("OKTA_ORG_URL", "dev-123456.okta.com")
        monkeypatch.setenv("OKTA_CLIENT_ID", "0oa1abcdef")
        manager = OktaAuthManager()
        assert manager.org_url == "https://dev-123456.okta.com"

    def test_exits_without_org_url(self, monkeypatch):
        monkeypatch.delenv("OKTA_ORG_URL", raising=False)
        monkeypatch.setenv("OKTA_CLIENT_ID", "0oa1abcdef")
        with pytest.raises(SystemExit):
            OktaAuthManager()

    def test_exits_without_client_id(self, monkeypatch):
        monkeypatch.setenv("OKTA_ORG_URL", "https://dev.okta.com")
        monkeypatch.delenv("OKTA_CLIENT_ID", raising=False)
        with pytest.raises(SystemExit):
            OktaAuthManager()

    def test_browserless_auth_detected(self, browserless_env):
        manager = OktaAuthManager()
        assert manager.use_browserless_auth is True

    def test_private_key_without_key_id_falls_back(self, monkeypatch, env_vars):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", "somekey")
        monkeypatch.delenv("OKTA_KEY_ID", raising=False)
        manager = OktaAuthManager()
        assert manager.use_browserless_auth is False

    def test_custom_scopes(self, monkeypatch, env_vars):
        monkeypatch.setenv("OKTA_SCOPES", "okta.users.read")
        manager = OktaAuthManager()
        assert "okta.users.read" in manager.scopes

    def test_private_key_newline_processing(self, monkeypatch, env_vars):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", "line1\\nline2")
        monkeypatch.setenv("OKTA_KEY_ID", "kid123")
        manager = OktaAuthManager()
        assert "\n" in manager.private_key
        assert "\\n" not in manager.private_key


# ---------------------------------------------------------------------------
# Token validation
# ---------------------------------------------------------------------------


class TestIsValidToken:
    async def test_valid_token(self, env_vars):
        manager = OktaAuthManager()
        manager.token_timestamp = int(time.time())

        with patch("keyring.get_password", return_value="valid_token"):
            assert await manager.is_valid_token() is True

    async def test_expired_token_triggers_refresh(self, env_vars):
        manager = OktaAuthManager()
        manager.token_timestamp = int(time.time()) - 7200  # 2 hours ago

        with (
            patch("keyring.get_password", return_value="old_token"),
            patch.object(manager, "refresh_access_token", return_value=True) as mock_refresh,
        ):
            await manager.is_valid_token()
            mock_refresh.assert_called_once()

    async def test_missing_token(self, env_vars):
        manager = OktaAuthManager()
        manager.token_timestamp = 0

        with (
            patch("keyring.get_password", return_value=None),
            patch.object(manager, "refresh_access_token", return_value=False),
            patch.object(manager, "authenticate", new_callable=AsyncMock) as mock_auth,
        ):
            await manager.is_valid_token()
            mock_auth.assert_called_once()


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------


class TestRefreshAccessToken:
    def test_no_refresh_token(self, env_vars):
        manager = OktaAuthManager()
        with patch("keyring.get_password", return_value=None):
            assert manager.refresh_access_token() is False

    def test_successful_refresh(self, env_vars):
        manager = OktaAuthManager()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_token",
            "refresh_token": "new_refresh",
        }

        with (
            patch("keyring.get_password", return_value="old_refresh_token"),
            patch("keyring.set_password") as mock_set,
            patch("requests.post", return_value=mock_response),
        ):
            assert manager.refresh_access_token() is True
            assert mock_set.call_count == 2  # access + refresh

    def test_failed_refresh(self, env_vars):
        manager = OktaAuthManager()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "invalid_grant"

        with (
            patch("keyring.get_password", return_value="old_refresh"),
            patch("requests.post", return_value=mock_response),
        ):
            assert manager.refresh_access_token() is False


# ---------------------------------------------------------------------------
# Clear tokens
# ---------------------------------------------------------------------------


class TestClearTokens:
    def test_clears_all_tokens(self, env_vars):
        manager = OktaAuthManager()
        manager.token_timestamp = 12345

        with patch("keyring.delete_password") as mock_delete:
            manager.clear_tokens()
            assert mock_delete.call_count == 2
            assert manager.token_timestamp == 0

    def test_handles_keyring_errors(self, env_vars):
        from keyring.errors import KeyringError

        manager = OktaAuthManager()

        with patch(
            "keyring.delete_password",
            side_effect=KeyringError("not found"),
        ):
            # Should not raise
            manager.clear_tokens()
            assert manager.token_timestamp == 0


# ---------------------------------------------------------------------------
# Device authorization
# ---------------------------------------------------------------------------


class TestDeviceAuthorization:
    def test_initiate_device_authorization_success(self, env_vars):
        manager = OktaAuthManager()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "device_code": "dc_123",
            "user_code": "ABCD-EFGH",
            "verification_uri_complete": "https://dev.okta.com/activate?user_code=ABCD",
            "expires_in": 600,
            "interval": 5,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = manager._initiate_device_authorization()
            assert result["device_code"] == "dc_123"
            assert "start_time" in result

    def test_initiate_device_authorization_failure_exits(self, env_vars):
        import requests as req

        manager = OktaAuthManager()

        with patch("requests.post", side_effect=req.RequestException("fail")):
            with pytest.raises(SystemExit):
                manager._initiate_device_authorization()
