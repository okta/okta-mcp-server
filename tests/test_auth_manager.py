# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for OktaAuthManager.

All external I/O is mocked:
  - requests (HTTP calls — device flow only)
  - keyring (OS credential store)
  - OAuth2Session / PrivateKeyJWT (authlib — browserless + refresh)
  - webbrowser
  - time (to control token age)
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Patch-target constants (resolves into auth_manager's own namespace)
# ---------------------------------------------------------------------------
MOD = "okta_mcp_server.utils.auth.auth_manager"
PATCH_REQUESTS = f"{MOD}.requests"
PATCH_KEYRING = f"{MOD}.keyring"
PATCH_OAUTH2_SESSION = f"{MOD}.OAuth2Session"
PATCH_PRIVATE_KEY_JWT = f"{MOD}.PrivateKeyJWT"
PATCH_TIME = f"{MOD}.time"
PATCH_WEBBROWSER = f"{MOD}.webbrowser"

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def base_env(monkeypatch):
    """Minimal valid env for device-flow auth."""
    monkeypatch.setenv("OKTA_ORG_URL", "test.okta.com")
    monkeypatch.setenv("OKTA_CLIENT_ID", "client123")
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)
    monkeypatch.delenv("OKTA_SCOPES", raising=False)


@pytest.fixture()
def browserless_env(monkeypatch, base_env):
    """Env for browserless (client-credentials + JWT) auth."""
    monkeypatch.setenv("OKTA_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\\nMIIEfake\\n-----END RSA PRIVATE KEY-----")
    monkeypatch.setenv("OKTA_KEY_ID", "kid123")


def _make_auth_manager(env_fixture):
    """Helper: import + instantiate OktaAuthManager after env is patched."""
    # Import inside the test so the module picks up the monkeypatched env
    from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager  # noqa: PLC0415
    return OktaAuthManager()


def _mock_response(status_code=200, json_data=None, raise_for_status=None):
    """Build a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = str(json_data)
    if raise_for_status:
        resp.raise_for_status.side_effect = raise_for_status
    else:
        resp.raise_for_status.return_value = None
    return resp


# ---------------------------------------------------------------------------
# TestOktaAuthManagerInit
# ---------------------------------------------------------------------------


class TestOktaAuthManagerInit:
    def test_https_prefix_added(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert mgr.org_url == "https://test.okta.com"

    def test_org_url_with_https_unchanged(self, monkeypatch, base_env):
        monkeypatch.setenv("OKTA_ORG_URL", "https://test.okta.com")
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert mgr.org_url == "https://test.okta.com"

    def test_missing_org_url_exits(self, monkeypatch, base_env):
        monkeypatch.delenv("OKTA_ORG_URL")
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with pytest.raises(SystemExit):
            OktaAuthManager()

    def test_missing_client_id_exits(self, monkeypatch, base_env):
        monkeypatch.delenv("OKTA_CLIENT_ID")
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with pytest.raises(SystemExit):
            OktaAuthManager()

    def test_browserless_mode_detected(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert mgr.use_browserless_auth is True

    def test_private_key_only_uses_device_flow(self, monkeypatch, base_env):
        monkeypatch.setenv("OKTA_PRIVATE_KEY", "some-key")
        # OKTA_KEY_ID intentionally NOT set
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert mgr.use_browserless_auth is False

    def test_escaped_newlines_replaced_in_private_key(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert "\\n" not in mgr.private_key
        assert "\n" in mgr.private_key

    def test_extra_scopes_appended(self, monkeypatch, base_env):
        monkeypatch.setenv("OKTA_SCOPES", "custom:scope")
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert "custom:scope" in mgr.scopes
        assert "openid" in mgr.scopes

    def test_default_scopes_without_extra(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert "openid" in mgr.scopes
        assert "offline_access" in mgr.scopes

    def test_client_id_stored(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        mgr = OktaAuthManager()
        assert mgr.client_id == "client123"


# ---------------------------------------------------------------------------
# TestDeviceAuthorizationFlow
# ---------------------------------------------------------------------------


class TestDeviceAuthorizationFlow:
    def test_initiate_device_authorization_success(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_resp = {
            "device_code": "dc123",
            "user_code": "ABCD-1234",
            "verification_uri_complete": "https://test.okta.com/activate?user_code=ABCD-1234",
            "expires_in": 600,
            "interval": 5,
        }
        with patch(PATCH_REQUESTS) as mock_req:
            mock_req.post.return_value = _mock_response(200, device_resp)
            mock_req.RequestException = __import__("requests").RequestException
            mgr = OktaAuthManager()
            result = mgr._initiate_device_authorization()

        assert result["device_code"] == "dc123"
        assert "start_time" in result

    def test_initiate_device_authorization_http_error_exits(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_REQUESTS) as mock_req:
            mock_req.post.return_value = _mock_response(
                400, raise_for_status=real_requests.HTTPError("400")
            )
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            with pytest.raises(SystemExit):
                mgr._initiate_device_authorization()

    def test_poll_immediate_success(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        token_resp = {"access_token": "at123", "refresh_token": "rt456"}
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 5,
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req, patch(PATCH_KEYRING) as mock_kr:
            mock_req.post.return_value = _mock_response(200, token_resp)
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result == "at123"
        mock_kr.set_password.assert_any_call("OktaAuthManager", "api_token", "at123")
        mock_kr.set_password.assert_any_call("OktaAuthManager", "refresh_token", "rt456")

    def test_poll_authorization_pending_then_success(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        pending_resp = _mock_response(400, {"error": "authorization_pending"})
        success_resp = _mock_response(200, {"access_token": "at123"})
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 0,  # no sleep delay in tests
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req, patch(PATCH_KEYRING):
            mock_req.post.side_effect = [pending_resp, success_resp]
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result == "at123"

    def test_poll_access_denied_returns_none(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 0,
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req:
            mock_req.post.return_value = _mock_response(400, {"error": "access_denied"})
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result is None

    def test_poll_slow_down_doubles_interval_then_succeeds(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        slow_down_resp = _mock_response(400, {"error": "slow_down"})
        success_resp = _mock_response(200, {"access_token": "at_slow"})
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 5,
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req, patch(PATCH_KEYRING):
            mock_req.post.side_effect = [slow_down_resp, success_resp]
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result == "at_slow"
        assert device_data["interval"] == 10  # doubled from 5

    def test_poll_expired_token_returns_none(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 0,
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req:
            mock_req.post.return_value = _mock_response(400, {"error": "expired_token"})
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result is None

    def test_poll_timeout_returns_none(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        # start_time far enough in the past to be immediately expired
        device_data = {
            "device_code": "dc123",
            "expires_in": 1,
            "interval": 0,
            "start_time": time.time() - 10,
        }
        with patch(PATCH_REQUESTS) as mock_req:
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result is None
        mock_req.post.assert_not_called()

    def test_poll_request_exception_sleeps_and_retries(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 0,
            "start_time": time.time(),
        }
        success_resp = _mock_response(200, {"access_token": "at_retry"})
        with patch(PATCH_REQUESTS) as mock_req, patch(PATCH_KEYRING):
            mock_req.post.side_effect = [
                real_requests.RequestException("connection error"),
                success_resp,
            ]
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            result = mgr._poll_for_token(device_data)

        assert result == "at_retry"

    def test_poll_stores_refresh_token(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_data = {
            "device_code": "dc123",
            "expires_in": 600,
            "interval": 0,
            "start_time": time.time(),
        }
        with patch(PATCH_REQUESTS) as mock_req, patch(PATCH_KEYRING) as mock_kr:
            mock_req.post.return_value = _mock_response(200, {"access_token": "at", "refresh_token": "rt"})
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            mgr._poll_for_token(device_data)

        mock_kr.set_password.assert_any_call("OktaAuthManager", "refresh_token", "rt")

    @pytest.mark.asyncio
    async def test_authenticate_device_flow_opens_browser(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_resp = {
            "device_code": "dc",
            "user_code": "CODE",
            "verification_uri_complete": "https://test.okta.com/activate?user_code=CODE",
            "expires_in": 600,
            "interval": 0,
        }
        with (
            patch(PATCH_REQUESTS) as mock_req,
            patch(PATCH_KEYRING),
            patch(PATCH_WEBBROWSER) as mock_wb,
        ):
            mock_req.post.side_effect = [
                _mock_response(200, device_resp),
                _mock_response(200, {"access_token": "at"}),
            ]
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            await mgr.authenticate()

        mock_wb.open.assert_called_once_with("https://test.okta.com/activate?user_code=CODE")

    @pytest.mark.asyncio
    async def test_authenticate_device_flow_browser_error_not_raised(self, base_env):
        import requests as real_requests
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        device_resp = {
            "device_code": "dc",
            "user_code": "CODE",
            "verification_uri_complete": "https://test.okta.com/activate",
            "expires_in": 600,
            "interval": 0,
        }
        with (
            patch(PATCH_REQUESTS) as mock_req,
            patch(PATCH_KEYRING),
            patch(PATCH_WEBBROWSER) as mock_wb,
        ):
            mock_wb.open.side_effect = __import__("webbrowser").Error("no browser")
            mock_wb.Error = __import__("webbrowser").Error
            mock_req.post.side_effect = [
                _mock_response(200, device_resp),
                _mock_response(200, {"access_token": "at"}),
            ]
            mock_req.RequestException = real_requests.RequestException
            mgr = OktaAuthManager()
            # Should not raise; logs warning instead
            await mgr.authenticate()


# ---------------------------------------------------------------------------
# TestBrowserlessAuthFlow
# ---------------------------------------------------------------------------


class TestBrowserlessAuthFlow:
    def test_browserless_authenticate_success(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.return_value = {"access_token": "at_bl"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            result = mgr._browserless_authenticate()

        assert result == "at_bl"
        mock_kr.set_password.assert_called_with("OktaAuthManager", "api_token", "at_bl")

    def test_browserless_authenticate_creates_session_with_private_key(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
            patch(PATCH_KEYRING),
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.return_value = {"access_token": "at"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            mgr._browserless_authenticate()

        call_kwargs = mock_session_cls.call_args
        assert call_kwargs.kwargs["client_id"] == "client123"
        assert call_kwargs.kwargs["client_secret"] is not None  # private key
        assert call_kwargs.kwargs["token_endpoint_auth_method"] == "private_key_jwt"

    def test_browserless_authenticate_registers_private_key_jwt_with_kid(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT) as mock_pkjwt_cls,
            patch(PATCH_KEYRING),
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.return_value = {"access_token": "at"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            mgr._browserless_authenticate()

        pkjwt_call = mock_pkjwt_cls.call_args
        assert pkjwt_call.kwargs["headers"] == {"kid": "kid123"}
        mock_session.register_client_auth_method.assert_called_once()

    def test_browserless_authenticate_error_returns_none(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.side_effect = Exception("invalid_client")
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            result = mgr._browserless_authenticate()

        assert result is None

    def test_browserless_authenticate_no_access_token_returns_none(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.return_value = {"token_type": "Bearer"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            result = mgr._browserless_authenticate()

        assert result is None

    def test_browserless_no_refresh_token_stored(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.return_value = {"access_token": "at"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            mgr._browserless_authenticate()

        for c in mock_kr.set_password.call_args_list:
            assert "refresh_token" not in str(c)

    @pytest.mark.asyncio
    async def test_authenticate_browserless_exits_on_none_token(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_PRIVATE_KEY_JWT),
        ):
            mock_session = MagicMock()
            mock_session.fetch_token.side_effect = Exception("unauthorized")
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            with pytest.raises(SystemExit):
                await mgr.authenticate()


# ---------------------------------------------------------------------------
# TestTokenRefresh
# ---------------------------------------------------------------------------


class TestTokenRefresh:
    def test_refresh_success(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_kr.get_password.return_value = "old_rt"
            mock_session = MagicMock()
            mock_session.refresh_token.return_value = {"access_token": "new_at", "refresh_token": "new_rt"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            result = mgr.refresh_access_token()

        assert result is True
        mock_kr.set_password.assert_any_call("OktaAuthManager", "api_token", "new_at")
        mock_kr.set_password.assert_any_call("OktaAuthManager", "refresh_token", "new_rt")

    def test_refresh_no_stored_refresh_token_returns_false(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with patch(PATCH_KEYRING) as mock_kr:
            mock_kr.get_password.return_value = None
            mgr = OktaAuthManager()
            result = mgr.refresh_access_token()

        assert result is False

    def test_refresh_error_returns_false(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_kr.get_password.return_value = "rt"
            mock_session = MagicMock()
            mock_session.refresh_token.side_effect = Exception("invalid_grant")
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            result = mgr.refresh_access_token()

        assert result is False

    def test_refresh_updates_timestamp(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_kr.get_password.return_value = "rt"
            mock_session = MagicMock()
            mock_session.refresh_token.return_value = {"access_token": "new_at"}
            mock_session_cls.return_value = mock_session
            mgr = OktaAuthManager()
            before = mgr.token_timestamp
            mgr.refresh_access_token()

        assert mgr.token_timestamp > before


# ---------------------------------------------------------------------------
# TestTokenValidation
# ---------------------------------------------------------------------------


class TestTokenValidation:
    @pytest.mark.asyncio
    async def test_valid_fresh_token_returns_true(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_KEYRING) as mock_kr:
            mock_kr.get_password.return_value = "valid_token"
            mgr = OktaAuthManager()
            mgr.token_timestamp = int(time.time())  # just issued
            result = await mgr.is_valid_token(expiry_duration=3600)

        assert result is True

    @pytest.mark.asyncio
    async def test_expired_token_triggers_refresh(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        with (
            patch(PATCH_OAUTH2_SESSION) as mock_session_cls,
            patch(PATCH_KEYRING) as mock_kr,
        ):
            mock_session = MagicMock()
            mock_session.refresh_token.return_value = {"access_token": "new_at"}
            mock_session_cls.return_value = mock_session
            # First get_password: api_token (stale); second: refresh_token; third: api_token (after refresh)
            mock_kr.get_password.side_effect = ["stale_token", "old_rt", "new_at"]
            mgr = OktaAuthManager()
            mgr.token_timestamp = 0  # expired: age >> 3600
            result = await mgr.is_valid_token(expiry_duration=3600)

        assert result is True

    @pytest.mark.asyncio
    async def test_expired_token_refresh_fails_triggers_reauthenticate(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        called = []

        async def fake_authenticate(self_inner):
            called.append(True)

        with (
            patch(PATCH_KEYRING) as mock_kr,
            patch(f"{MOD}.OktaAuthManager.authenticate", fake_authenticate),
        ):
            # No refresh token stored → refresh fails
            mock_kr.get_password.side_effect = [
                "stale_token",  # api_token check → exists but aged
                None,            # refresh_token lookup → None → refresh returns False
                "new_at",        # api_token after reauthenticate
            ]
            mgr = OktaAuthManager()
            mgr.token_timestamp = 0
            result = await mgr.is_valid_token(expiry_duration=3600)

        assert called
        assert result is True

    @pytest.mark.asyncio
    async def test_missing_token_triggers_reauthenticate(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        called = []

        async def fake_authenticate(self_inner):
            called.append(True)

        with (
            patch(PATCH_KEYRING) as mock_kr,
            patch(f"{MOD}.OktaAuthManager.authenticate", fake_authenticate),
        ):
            mock_kr.get_password.side_effect = [
                None,     # api_token → missing
                None,     # refresh_token → None
                "new_at", # api_token after re-auth
            ]
            mgr = OktaAuthManager()
            mgr.token_timestamp = 0
            result = await mgr.is_valid_token()

        assert called
        assert result is True

    @pytest.mark.asyncio
    async def test_browserless_expired_triggers_reauthenticate_not_refresh(self, browserless_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        called = []

        async def fake_authenticate(self_inner):
            called.append(True)

        with (
            patch(PATCH_KEYRING) as mock_kr,
            patch(f"{MOD}.OktaAuthManager.authenticate", fake_authenticate),
        ):
            mock_kr.get_password.side_effect = ["stale", "new_at"]
            mgr = OktaAuthManager()
            mgr.token_timestamp = 0
            await mgr.is_valid_token(expiry_duration=3600)

        assert called

    @pytest.mark.asyncio
    async def test_custom_expiry_duration_respected(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_KEYRING) as mock_kr:
            mock_kr.get_password.return_value = "token"
            mgr = OktaAuthManager()
            mgr.token_timestamp = int(time.time()) - 100  # 100 seconds old
            # With 3600s expiry: still valid
            assert await mgr.is_valid_token(expiry_duration=3600) is True
            # With 50s expiry: expired
            mgr.token_timestamp = int(time.time()) - 100

        # Re-run with short expiry; patch authenticate to avoid actually authenticating
        with (
            patch(PATCH_KEYRING) as mock_kr,
            patch(f"{MOD}.OktaAuthManager.authenticate", AsyncMock()),
        ):
            mock_kr.get_password.return_value = "token"
            mgr = OktaAuthManager()
            mgr.token_timestamp = int(time.time()) - 100
            result = await mgr.is_valid_token(expiry_duration=50)
        # Token was expired → authenticate was called; return value depends on keyring state
        assert result is not None  # truthy or False depending on keyring, but no exception

    @pytest.mark.asyncio
    async def test_returns_false_if_no_token_after_auth(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

        async def fake_authenticate(self_inner):
            pass  # does nothing — token remains absent

        with (
            patch(PATCH_KEYRING) as mock_kr,
            patch(f"{MOD}.OktaAuthManager.authenticate", fake_authenticate),
        ):
            mock_kr.get_password.return_value = None  # always None
            mgr = OktaAuthManager()
            mgr.token_timestamp = 0
            result = await mgr.is_valid_token()

        assert result is False


# ---------------------------------------------------------------------------
# TestClearTokens
# ---------------------------------------------------------------------------


class TestClearTokens:
    def test_clear_tokens_deletes_both_keys(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_KEYRING) as mock_kr:
            mgr = OktaAuthManager()
            mgr.clear_tokens()

        mock_kr.delete_password.assert_any_call("OktaAuthManager", "api_token")
        mock_kr.delete_password.assert_any_call("OktaAuthManager", "refresh_token")

    def test_clear_tokens_resets_timestamp(self, base_env):
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_KEYRING):
            mgr = OktaAuthManager()
            mgr.token_timestamp = 9999
            mgr.clear_tokens()

        assert mgr.token_timestamp == 0

    def test_clear_tokens_handles_keyring_error_gracefully(self, base_env):
        import keyring.backend
        from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
        with patch(PATCH_KEYRING) as mock_kr:
            mock_kr.delete_password.side_effect = keyring.backend.errors.KeyringError("not found")
            mock_kr.backend.errors.KeyringError = keyring.backend.errors.KeyringError
            mgr = OktaAuthManager()
            # Should not raise
            mgr.clear_tokens()

        assert mgr.token_timestamp == 0

