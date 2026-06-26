# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for user_resources tools — list_user_groups."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.user_resources.user_resources import list_user_groups


USER_ID = "00uTEST000000001"


def _make_ctx():
    """Build a minimal fake Context (no elicitation needed for read-only tools)."""
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _make_group_mock(group_id: str, name: str):
    group = MagicMock()
    group.id = group_id
    group.profile = MagicMock()
    group.profile.name = name
    return group


class TestListUserGroups:
    """Tests for list_user_groups tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client")
    async def test_returns_groups_for_user(self, mock_get_client):
        """A valid user_id should return the list of groups the user belongs to."""
        client = AsyncMock()
        groups = [
            _make_group_mock("00gTEST0000001", "Engineering"),
            _make_group_mock("00gTEST0000002", "Everyone"),
        ]
        client.list_user_groups.return_value = (groups, MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_user_groups(user_id=USER_ID, ctx=_make_ctx())

        client.list_user_groups.assert_called_once_with(USER_ID)
        assert len(result) == 2
        assert result[0].profile.name == "Engineering"
        assert result[1].profile.name == "Everyone"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client")
    async def test_returns_empty_list_when_user_has_no_groups(self, mock_get_client):
        """A user with no group memberships should return an empty list."""
        client = AsyncMock()
        client.list_user_groups.return_value = ([], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_user_groups(user_id=USER_ID, ctx=_make_ctx())

        assert result == []

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client")
    async def test_returns_empty_list_when_api_returns_none(self, mock_get_client):
        """A None groups response (no memberships) should return an empty list."""
        client = AsyncMock()
        client.list_user_groups.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_user_groups(user_id=USER_ID, ctx=_make_ctx())

        assert result == []

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client")
    async def test_okta_api_error_is_surfaced(self, mock_get_client):
        """An Okta API error should be returned as an error string in the list."""
        client = AsyncMock()
        client.list_user_groups.return_value = (None, None, "Error: user not found")
        mock_get_client.return_value = client

        result = await list_user_groups(user_id=USER_ID, ctx=_make_ctx())

        assert len(result) == 1
        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client")
    async def test_exception_is_surfaced(self, mock_get_client):
        """An unexpected exception should be returned as an Exception string."""
        mock_get_client.side_effect = Exception("Connection refused")

        result = await list_user_groups(user_id=USER_ID, ctx=_make_ctx())

        assert len(result) == 1
        assert "Exception" in result[0]

    @pytest.mark.asyncio
    async def test_invalid_user_id_rejected_before_api_call(self):
        """A user_id with path traversal characters should be rejected without hitting the API."""
        result = await list_user_groups(user_id="../admin", ctx=_make_ctx())

        assert len(result) == 1
        assert "Error" in result[0]

    @pytest.mark.asyncio
    async def test_login_shortname_accepted(self):
        """A login shortname (valid Okta ID format) should pass validation."""
        with patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client") as mock_get_client:
            client = AsyncMock()
            client.list_user_groups.return_value = ([], MagicMock(), None)
            mock_get_client.return_value = client

            result = await list_user_groups(user_id="jdoe", ctx=_make_ctx())

            client.list_user_groups.assert_called_once_with("jdoe")
            assert result == []

    @pytest.mark.asyncio
    async def test_email_login_accepted(self):
        """An email address used as login should pass validation."""
        with patch("okta_mcp_server.tools.user_resources.user_resources.get_okta_client") as mock_get_client:
            client = AsyncMock()
            client.list_user_groups.return_value = ([], MagicMock(), None)
            mock_get_client.return_value = client

            result = await list_user_groups(user_id="jdoe@example.com", ctx=_make_ctx())

            client.list_user_groups.assert_called_once_with("jdoe@example.com")
            assert result == []
