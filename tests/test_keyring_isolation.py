# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Two server configs (e.g. sandbox and production orgs) must not share keyring entries (#95)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager


class _MemoryKeyring:
    """Stand-in for the OS keyring: one secret per (service, username), like the real backends."""

    def __init__(self):
        self.store: dict[tuple[str, str], str] = {}

    def set_password(self, service, username, password):
        self.store[service, username] = password

    def get_password(self, service, username):
        return self.store.get((service, username))

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


def _manager(monkeypatch, org_url: str, client_id: str) -> OktaAuthManager:
    monkeypatch.setenv("OKTA_ORG_URL", org_url)
    monkeypatch.setenv("OKTA_CLIENT_ID", client_id)
    monkeypatch.delenv("OKTA_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OKTA_KEY_ID", raising=False)
    monkeypatch.delenv("OKTA_SCOPES", raising=False)
    return OktaAuthManager()


def _token_response(access_token: str, refresh_token: str) -> MagicMock:
    response = MagicMock(status_code=200)
    response.json.return_value = {"access_token": access_token, "refresh_token": refresh_token}
    return response


@pytest.fixture
def memory_keyring():
    kr = _MemoryKeyring()
    with patch("okta_mcp_server.utils.auth.auth_manager.keyring", kr):
        yield kr


def _device_login(manager: OktaAuthManager, access_token: str, refresh_token: str) -> None:
    device_data = {"device_code": "dc", "start_time": 0, "expires_in": 10**12, "interval": 0}
    response = _token_response(access_token, refresh_token)
    with patch("okta_mcp_server.utils.auth.auth_manager.requests.post", return_value=response):
        assert manager._poll_for_token(device_data) == access_token


def test_sandbox_refresh_is_not_sent_the_production_refresh_token(monkeypatch, memory_keyring):
    """The reported bug, through public behaviour only: log in to sandbox, then production,
    then refresh sandbox. Sandbox must send its own refresh token to its own org."""
    sandbox = _manager(monkeypatch, "https://sandbox.oktapreview.com", "sandbox-client")
    production = _manager(monkeypatch, "https://prod.okta.com", "prod-client")
    _device_login(sandbox, "sandbox-access", "sandbox-refresh")
    _device_login(production, "prod-access", "prod-refresh")

    with patch(
        "okta_mcp_server.utils.auth.auth_manager.requests.post",
        return_value=_token_response("sandbox-access-2", "sandbox-refresh-2"),
    ) as post:
        sandbox.refresh_access_token()

    assert post.call_args.kwargs["data"]["refresh_token"] == "sandbox-refresh"


def test_two_orgs_keep_their_own_tokens(monkeypatch, memory_keyring):
    sandbox = _manager(monkeypatch, "https://sandbox.oktapreview.com", "sandbox-client")
    production = _manager(monkeypatch, "https://prod.okta.com", "prod-client")

    _device_login(sandbox, "sandbox-access", "sandbox-refresh")
    _device_login(production, "prod-access", "prod-refresh")

    assert memory_keyring.get_password(sandbox.keyring_service, "api_token") == "sandbox-access"
    assert memory_keyring.get_password(sandbox.keyring_service, "refresh_token") == "sandbox-refresh"
    assert memory_keyring.get_password(production.keyring_service, "api_token") == "prod-access"
    assert memory_keyring.get_password(production.keyring_service, "refresh_token") == "prod-refresh"


def test_refresh_uses_this_orgs_refresh_token(monkeypatch, memory_keyring):
    sandbox = _manager(monkeypatch, "https://sandbox.oktapreview.com", "sandbox-client")
    production = _manager(monkeypatch, "https://prod.okta.com", "prod-client")
    _device_login(sandbox, "sandbox-access", "sandbox-refresh")
    _device_login(production, "prod-access", "prod-refresh")

    with patch(
        "okta_mcp_server.utils.auth.auth_manager.requests.post",
        return_value=_token_response("sandbox-access-2", "sandbox-refresh-2"),
    ) as post:
        assert sandbox.refresh_access_token() is True

    assert post.call_args.kwargs["data"]["refresh_token"] == "sandbox-refresh"
    assert post.call_args.args[0] == "https://sandbox.oktapreview.com/oauth2/v1/token"
    assert memory_keyring.get_password(production.keyring_service, "api_token") == "prod-access"


def test_clear_tokens_only_clears_this_org(monkeypatch, memory_keyring):
    sandbox = _manager(monkeypatch, "https://sandbox.oktapreview.com", "sandbox-client")
    production = _manager(monkeypatch, "https://prod.okta.com", "prod-client")
    _device_login(sandbox, "sandbox-access", "sandbox-refresh")
    _device_login(production, "prod-access", "prod-refresh")

    sandbox.clear_tokens()

    assert memory_keyring.get_password(sandbox.keyring_service, "api_token") is None
    assert memory_keyring.get_password(production.keyring_service, "api_token") == "prod-access"


def test_same_org_and_client_share_the_cache(monkeypatch):
    first = _manager(monkeypatch, "https://prod.okta.com/", "prod-client")
    second = _manager(monkeypatch, "prod.okta.com", "prod-client")
    assert first.keyring_service == second.keyring_service


def test_same_org_different_clients_do_not_share(monkeypatch):
    a = _manager(monkeypatch, "https://prod.okta.com", "client-a")
    b = _manager(monkeypatch, "https://prod.okta.com", "client-b")
    assert a.keyring_service != b.keyring_service
