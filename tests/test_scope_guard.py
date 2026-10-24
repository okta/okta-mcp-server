# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for require_scopes error handling and prune_tools_by_scope bookkeeping."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from okta.exceptions.exceptions import ForbiddenException

from okta_mcp_server.utils.scope_guard import get_disabled_tools, prune_tools_by_scope, require_scopes


def _ctx(*, user_auth: bool):
    manager = SimpleNamespace(scopes="openid okta.users.read", use_user_auth=user_auth)
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=SimpleNamespace(okta_auth_manager=manager)))


@require_scopes("okta.users.read")
async def _forbidden_tool(ctx=None):  # noqa: RUF029
    raise ForbiddenException(status=403)


class TestRequireScopesForbidden:
    @pytest.mark.asyncio
    async def test_user_mode_points_at_the_callers_admin_role(self):
        result = await _forbidden_tool(ctx=_ctx(user_auth=True))
        assert "admin role" in result["error"]
        assert "HTTP 403" in result["error"]

    @pytest.mark.asyncio
    async def test_service_mode_keeps_the_scope_message(self):
        result = await _forbidden_tool(ctx=_ctx(user_auth=False))
        assert "missing required scope" in result["error"]
        assert "admin role" not in result["error"]


class _FakeToolManager:
    def __init__(self, names):
        self._names = set(names)

    def list_tools(self):
        return [SimpleNamespace(name=n) for n in self._names]

    def remove_tool(self, name):
        self._names.remove(name)


class TestPruneAcrossSessions:
    def test_second_session_still_reports_tools_removed_by_the_first(self):
        registry = {"list_users": "okta.users.read", "create_user": "okta.users.manage"}
        server = MagicMock()
        server._tool_manager = _FakeToolManager(registry)
        manager = SimpleNamespace(scopes="openid okta.users.read")

        with patch("okta_mcp_server.utils.scope_registry.TOOL_SCOPE_REGISTRY", registry):
            prune_tools_by_scope(server, manager)
            assert get_disabled_tools() == {"create_user": "okta.users.manage"}

            prune_tools_by_scope(server, manager)
            assert get_disabled_tools() == {"create_user": "okta.users.manage"}

        assert {t.name for t in server._tool_manager.list_tools()} == {"list_users"}
