# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for create_user — activate parameter behaviour."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import CreateUserRequest

from okta_mcp_server.tools.users.users import create_user


PROFILE = {
    "firstName": "Test",
    "lastName": "User",
    "email": "test.user@example.com",
    "login": "test.user@example.com",
}


def _make_ctx():
    """Build a minimal fake Context (no elicitation needed for create_user)."""
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _make_user_mock(status: str = "PROVISIONED"):
    user = MagicMock()
    user.id = "00uTESTUSER0000001"
    user.status = status
    user.profile = MagicMock()
    user.profile.email = PROFILE["email"]
    return user


class TestCreateUserActivateParam:
    """Verify that the activate query param is forwarded correctly to the Okta SDK."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_default_activate_true_sends_true(self, mock_get_client):
        """Calling create_user without activate should pass activate=true."""
        client = AsyncMock()
        client.create_user.return_value = (_make_user_mock("PROVISIONED"), None, None)
        mock_get_client.return_value = client

        result = await create_user(profile=PROFILE, ctx=_make_ctx())

        call_args = client.create_user.call_args[0]
        assert isinstance(call_args[0], CreateUserRequest)
        assert call_args[0].profile.email == PROFILE["email"]
        assert call_args[1] == True
        assert result[0].status == "PROVISIONED"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_explicit_activate_true_sends_true(self, mock_get_client):
        """Passing activate=True explicitly should pass activate=true."""
        client = AsyncMock()
        client.create_user.return_value = (_make_user_mock("PROVISIONED"), None, None)
        mock_get_client.return_value = client

        result = await create_user(profile=PROFILE, activate=True, ctx=_make_ctx())

        call_args = client.create_user.call_args[0]
        assert isinstance(call_args[0], CreateUserRequest)
        assert call_args[0].profile.email == PROFILE["email"]
        assert call_args[1] == True
        assert result[0].status == "PROVISIONED"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_activate_false_sends_false_and_returns_staged_user(self, mock_get_client):
        """Passing activate=False should pass activate=false, creating a STAGED user."""
        client = AsyncMock()
        client.create_user.return_value = (_make_user_mock("STAGED"), None, None)
        mock_get_client.return_value = client

        result = await create_user(profile=PROFILE, activate=False, ctx=_make_ctx())

        call_args = client.create_user.call_args[0]
        assert isinstance(call_args[0], CreateUserRequest)
        assert call_args[0].profile.email == PROFILE["email"]
        assert call_args[1] == False
        assert result[0].status == "STAGED"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_okta_api_error_is_returned(self, mock_get_client):
        """An Okta API error should be surfaced in the returned list."""
        client = AsyncMock()
        client.create_user.return_value = (None, None, "Error: login already exists")
        mock_get_client.return_value = client

        result = await create_user(profile=PROFILE, ctx=_make_ctx())

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_during_create_is_returned(self, mock_get_client):
        """An unexpected exception should be surfaced as an Exception string."""
        mock_get_client.side_effect = Exception("Connection refused")

        result = await create_user(profile=PROFILE, ctx=_make_ctx())

        assert "Exception" in result[0]
