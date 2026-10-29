# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the Host / Origin validation applied to the streamable-http transport."""

from __future__ import annotations

import pytest
from mcp.server.transport_security import TransportSecurityMiddleware
from starlette.requests import Request

from okta_mcp_server.server import _server_options, _transport_security


def _request(host: str, origin: str | None = None) -> Request:
    headers = [(b"host", host.encode()), (b"content-type", b"application/json")]
    if origin:
        headers.append((b"origin", origin.encode()))
    return Request({"type": "http", "method": "POST", "path": "/mcp", "headers": headers})


async def _status(settings, host: str, origin: str | None = None) -> int:
    response = await TransportSecurityMiddleware(settings).validate_request(_request(host, origin), is_post=True)
    return 200 if response is None else response.status_code


@pytest.fixture(autouse=True)
def _no_extra_hosts(monkeypatch):
    monkeypatch.delenv("OKTA_MCP_ALLOWED_HOSTS", raising=False)


class TestTransportSecurity:
    @pytest.mark.asyncio
    async def test_accepts_the_public_host_a_reverse_proxy_forwards(self):
        settings = _transport_security("https://okta-mcp.example.com/mcp")
        assert await _status(settings, "okta-mcp.example.com") == 200

    @pytest.mark.asyncio
    async def test_accepts_localhost_for_direct_access(self):
        settings = _transport_security("https://okta-mcp.example.com/mcp")
        assert await _status(settings, "localhost:8010") == 200
        assert await _status(settings, "127.0.0.1:8010") == 200

    @pytest.mark.asyncio
    async def test_rejects_other_hosts(self):
        settings = _transport_security("https://okta-mcp.example.com/mcp")
        assert await _status(settings, "attacker.example.net") == 421
        assert await _status(settings, "okta-mcp.example.com.attacker.example.net") == 421

    @pytest.mark.asyncio
    async def test_rejects_browser_origins_other_than_the_public_one(self):
        settings = _transport_security("https://okta-mcp.example.com/mcp")
        assert await _status(settings, "okta-mcp.example.com", "https://okta-mcp.example.com") == 200
        assert await _status(settings, "okta-mcp.example.com", "https://attacker.example.net") == 403

    @pytest.mark.asyncio
    async def test_keeps_a_port_in_the_public_url(self):
        settings = _transport_security("http://localhost:8010/mcp")
        assert await _status(settings, "localhost:8010", "http://localhost:8010") == 200

    @pytest.mark.asyncio
    async def test_extra_hosts_come_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("OKTA_MCP_ALLOWED_HOSTS", "okta-mcp.internal:8010 10.0.0.5:*")
        settings = _transport_security(None)
        assert await _status(settings, "okta-mcp.internal:8010") == 200
        assert await _status(settings, "10.0.0.5:8010") == 200
        assert await _status(settings, "okta-mcp.internal") == 421

    def test_is_on_even_when_bound_to_all_interfaces(self, monkeypatch):
        monkeypatch.setenv("OKTA_MCP_HOST", "0.0.0.0")
        monkeypatch.setenv("OKTA_MCP_PUBLIC_URL", "https://okta-mcp.example.com/mcp")
        monkeypatch.delenv("OKTA_AUTH_MODE", raising=False)
        settings = _server_options()["transport_security"]
        assert settings.enable_dns_rebinding_protection
        assert "okta-mcp.example.com" in settings.allowed_hosts
