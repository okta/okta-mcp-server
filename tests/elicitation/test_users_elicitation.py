# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for user lifecycle operations including unlock, deactivation, and deletion."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.users.users import (
    deactivate_user,
    delete_deactivated_user,
    unlock_user,
)


USER_ID = "00u1234567890ABCDEF"


# ===================================================================
# unlock_user
# ===================================================================

class TestUnlockUser:
    """Tests for unlock_user (non-destructive, no elicitation required)."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_unlock_success(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        """Unlock succeeds and returns a success message."""
        mock_get_client.return_value = mock_okta_client

        result = await unlock_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.unlock_user.assert_awaited_once_with(USER_ID)
        assert "unlocked successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_unlock_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        """Okta API error is surfaced to the caller."""
        client = AsyncMock()
        client.unlock_user.return_value = (None, "API Error: user is not locked out")
        mock_get_client.return_value = client

        result = await unlock_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_unlock_exception(self, mock_get_client, ctx_elicit_accept_true):
        """Generic exception is surfaced to the caller."""
        mock_get_client.side_effect = Exception("Connection refused")

        result = await unlock_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Exception" in result[0]


# ===================================================================
# deactivate_user — elicitation flows
# ===================================================================

class TestDeactivateUserElicitation:
    """Tests for deactivate_user when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_confirmed_deactivates(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.deactivate_user.return_value = (None, "API Error: user not found")
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_during_deactivate(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Exception" in result[0]


# ===================================================================
# deactivate_user — fallback flows
# ===================================================================

class TestDeactivateUserFallback:
    """Tests for deactivate_user when the client does NOT support elicitation.

    Pre-elicitation behaviour: the operation proceeds directly without
    confirmation because there was never a separate confirm tool for users.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_fallback_proceeds_with_deactivation(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_no_elicitation)

        mock_okta_client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_fallback_proceeds_with_deactivation(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_exception)

        mock_okta_client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]


# ===================================================================
# delete_deactivated_user — elicitation flows
# ===================================================================

class TestDeleteDeactivatedUserElicitation:
    """Tests for delete_deactivated_user when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_confirmed_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.deactivate_or_delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.deactivate_or_delete_user.return_value = (None, "API Error: user not found")
        mock_get_client.return_value = client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Exception" in result[0]


# ===================================================================
# delete_deactivated_user — fallback flows
# ===================================================================

class TestDeleteDeactivatedUserFallback:
    """Tests for delete_deactivated_user when the client does NOT support elicitation.

    Pre-elicitation behaviour: the operation proceeds directly without
    confirmation because there was never a separate confirm tool for users.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_fallback_proceeds_with_deletion(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_no_elicitation)

        mock_okta_client.deactivate_or_delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_fallback_proceeds_with_deletion(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_exception)

        mock_okta_client.deactivate_or_delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]
