# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for assign_user_to_app / assign_group_to_app."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import AppUserAssignRequest

from okta_mcp_server.tools.applications.applications import assign_group_to_app, assign_user_to_app


APP_ID = "0oaTESTAPP0000001"
USER_ID = "00uTESTUSER000001"
GROUP_ID = "00gTESTGROUP00001"


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


class TestAssignUserToApp:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_success_sends_assign_request_and_returns_assignment(self, mock_get_client):
        app_user = MagicMock()
        client = AsyncMock()
        client.assign_user_to_application.return_value = (app_user, MagicMock(), None)
        mock_get_client.return_value = client

        result = await assign_user_to_app(ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID)

        assert result == [app_user]
        call_args = client.assign_user_to_application.call_args[0]
        assert call_args[0] == APP_ID
        assert isinstance(call_args[1], AppUserAssignRequest)
        assert call_args[1].id == USER_ID
        assert call_args[1].scope == "USER"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client = AsyncMock()
        client.assign_user_to_application.return_value = (None, None, "404 user not found")
        mock_get_client.return_value = client

        result = await assign_user_to_app(ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID)

        assert result == ["Error: 404 user not found"]

    @pytest.mark.asyncio
    async def test_invalid_id_rejected_before_api_call(self):
        result = await assign_user_to_app(ctx=_make_ctx(), app_id="../../etc", user_id=USER_ID)

        assert len(result) == 1
        assert result[0].startswith("Error:")


class TestAssignGroupToApp:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_success_returns_assignment(self, mock_get_client):
        assignment = MagicMock()
        client = AsyncMock()
        client.assign_group_to_application.return_value = (assignment, MagicMock(), None)
        mock_get_client.return_value = client

        result = await assign_group_to_app(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        assert result == [assignment]
        client.assign_group_to_application.assert_awaited_once_with(APP_ID, GROUP_ID)

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client = AsyncMock()
        client.assign_group_to_application.return_value = (None, None, "403 forbidden")
        mock_get_client.return_value = client

        result = await assign_group_to_app(ctx=_make_ctx(), app_id=APP_ID, group_id=GROUP_ID)

        assert result == ["Error: 403 forbidden"]
