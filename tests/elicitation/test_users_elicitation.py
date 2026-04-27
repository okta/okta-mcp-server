# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for user deactivation and deletion with elicitation support."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.users.users import (
    deactivate_user,
    delete_deactivated_user,
)


USER_ID = "00u1234567890ABCDEF"


# ===================================================================
# deactivate_user — status guard (DEPROVISIONED pre-check)
# ===================================================================

def _make_active_client():
    """Return an AsyncMock client whose get_user returns an ACTIVE user."""
    client = AsyncMock()
    active_user = MagicMock()
    active_user.status = "ACTIVE"
    client.get_user.return_value = (active_user, None, None)
    client.deactivate_user.return_value = (None, None)
    return client


class TestDeactivateUserStatusGuard:
    """Tests for the status pre-check added to deactivate_user.

    Calling deactivate_user on a DEPROVISIONED user would result in a 404
    from the Okta API because the lifecycle endpoint is unavailable for users
    in that state.  The guard detects this early and returns clear guidance.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_deprovisioned_user_returns_guidance_without_deactivating(
        self, mock_get_client, ctx_elicit_accept_true
    ):
        """Calling the tool on a DEPROVISIONED user must return guidance, never deactivate."""
        client = AsyncMock()
        deprovisioned_user = MagicMock()
        deprovisioned_user.status = "DEPROVISIONED"
        client.get_user.return_value = (deprovisioned_user, None, None)
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.deactivate_user.assert_not_awaited()
        assert "DEPROVISIONED" in result[0]
        assert "delete_deactivated_user" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_get_user_api_error_returns_error_without_deactivating(
        self, mock_get_client, ctx_elicit_accept_true
    ):
        """If get_user returns an API error the tool surfaces it without deactivating."""
        client = AsyncMock()
        client.get_user.return_value = (None, None, "API Error: user not found")
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.deactivate_user.assert_not_awaited()
        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_get_user_exception_returns_exception(self, mock_get_client, ctx_elicit_accept_true):
        """If get_user raises an exception the tool propagates it gracefully."""
        mock_get_client.side_effect = Exception("Connection refused")

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Exception" in result[0]


# ===================================================================
# deactivate_user — elicitation flows
# ===================================================================

class TestDeactivateUserElicitation:
    """Tests for deactivate_user when the client supports elicitation.

    All tests supply an ACTIVE user via get_user so the status guard passes
    and execution reaches the elicitation / deactivation logic.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_confirmed_deactivates(self, mock_get_client, ctx_elicit_accept_true):
        client = _make_active_client()
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_not_confirmed_cancels(self, mock_get_client, ctx_elicit_accept_false):
        mock_get_client.return_value = _make_active_client()

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_decline_cancels(self, mock_get_client, ctx_elicit_decline):
        mock_get_client.return_value = _make_active_client()

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_cancel_cancels(self, mock_get_client, ctx_elicit_cancel):
        mock_get_client.return_value = _make_active_client()

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = _make_active_client()
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
    async def test_fallback_proceeds_with_deactivation(self, mock_get_client, ctx_no_elicitation):
        client = _make_active_client()
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_no_elicitation)

        client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_fallback_proceeds_with_deactivation(self, mock_get_client, ctx_elicit_exception):
        client = _make_active_client()
        mock_get_client.return_value = client

        result = await deactivate_user(user_id=USER_ID, ctx=ctx_elicit_exception)

        client.deactivate_user.assert_awaited_once_with(USER_ID)
        assert "deactivated successfully" in result[0]


# ===================================================================
# delete_deactivated_user — status guard (new behaviour)
# ===================================================================

class TestDeleteDeactivatedUserStatusGuard:
    """Tests for the status pre-check introduced to fix the two-call bug.

    The Okta API's DELETE endpoint transitions active users to DEPROVISIONED
    instead of permanently deleting them.  The tool must therefore verify the
    user is already DEPROVISIONED before proceeding so it never returns a
    misleading 'deleted successfully' message for a non-deleted user.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_active_user_returns_error_without_deleting(self, mock_get_client, ctx_elicit_accept_true):
        """Calling the tool on an ACTIVE user must return an error, never delete."""
        client = AsyncMock()
        active_user = MagicMock()
        active_user.status = "ACTIVE"
        client.get_user.return_value = (active_user, None, None)
        mock_get_client.return_value = client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.delete_user.assert_not_awaited()
        assert "Error" in result[0]
        assert "ACTIVE" in result[0]
        assert "deactivate" in result[0].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    @pytest.mark.parametrize("status", ["STAGED", "PROVISIONED", "LOCKED_OUT", "PASSWORD_EXPIRED", "RECOVERY", "SUSPENDED"])
    async def test_non_deprovisioned_status_returns_error(self, mock_get_client, status, ctx_elicit_accept_true):
        """Any status other than DEPROVISIONED must be rejected."""
        client = AsyncMock()
        user = MagicMock()
        user.status = status
        client.get_user.return_value = (user, None, None)
        mock_get_client.return_value = client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.delete_user.assert_not_awaited()
        assert "Error" in result[0]
        assert status in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_get_user_api_error_returns_error(self, mock_get_client, ctx_elicit_accept_true):
        """If get_user returns an API error the tool should surface it without deleting."""
        client = AsyncMock()
        client.get_user.return_value = (None, None, "API Error: user not found")
        mock_get_client.return_value = client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.delete_user.assert_not_awaited()
        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_get_user_exception_returns_exception(self, mock_get_client, ctx_elicit_accept_true):
        """If get_user raises an exception the tool should propagate it gracefully."""
        client = AsyncMock()
        client.get_user.side_effect = Exception("Connection refused")
        mock_get_client.return_value = client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        client.delete_user.assert_not_awaited()
        assert "Exception" in result[0]


# ===================================================================
# delete_deactivated_user — elicitation flows
# ===================================================================

class TestDeleteDeactivatedUserElicitation:
    """Tests for delete_deactivated_user when the client supports elicitation.

    All tests supply a DEPROVISIONED user via get_user so the status guard
    passes and execution reaches the elicitation / deletion logic.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_confirmed_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_accept_not_confirmed_cancels(self, mock_get_client, ctx_elicit_accept_false, mock_okta_client):
        # get_user must be reachable (status check happens before elicitation).
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_false)

        mock_okta_client.delete_user.assert_not_awaited()
        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_decline_cancels(self, mock_get_client, ctx_elicit_decline, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_decline)

        mock_okta_client.delete_user.assert_not_awaited()
        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_cancel_cancels(self, mock_get_client, ctx_elicit_cancel, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_cancel)

        mock_okta_client.delete_user.assert_not_awaited()
        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_delete_api_error_after_status_check(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        """delete_user API error is surfaced correctly when the user is DEPROVISIONED."""
        mock_okta_client.delete_user.return_value = (None, "API Error: delete failed")
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_accept_true)

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        """Exception raised by delete_user (not get_user) is handled gracefully."""
        client = AsyncMock()
        deprovisioned_user = MagicMock()
        deprovisioned_user.status = "DEPROVISIONED"
        client.get_user.return_value = (deprovisioned_user, None, None)
        client.delete_user.side_effect = Exception("Connection refused")
        mock_get_client.return_value = client

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

        mock_okta_client.delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_exception_fallback_proceeds_with_deletion(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_deactivated_user(user_id=USER_ID, ctx=ctx_elicit_exception)

        mock_okta_client.delete_user.assert_awaited_once_with(USER_ID)
        assert "deleted successfully" in result[0]
