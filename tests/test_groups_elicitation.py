# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for group deletion with elicitation support."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.groups.groups import delete_group, confirm_delete_group


GROUP_ID = "00g1234567890ABCDEF"


# ---------------------------------------------------------------------------
# delete_group — elicitation flows
# ---------------------------------------------------------------------------

class TestDeleteGroupElicitation:
    """Tests for delete_group when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_accept_confirmed_deletes_group(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_group(GROUP_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.delete_group.assert_awaited_once_with(GROUP_ID)
        assert result[0]["message"] == f"Group {GROUP_ID} deleted successfully"

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await delete_group(GROUP_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await delete_group(GROUP_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await delete_group(GROUP_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group.return_value = (None, "API Error: group not found")
        mock_get_client.return_value = client

        result = await delete_group(GROUP_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await delete_group(GROUP_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result[0]


# ---------------------------------------------------------------------------
# delete_group — fallback flows
# ---------------------------------------------------------------------------

class TestDeleteGroupFallback:
    """Tests for delete_group when the client does NOT support elicitation.

    Pre-elicitation behaviour: the tool returns a payload directing the LLM
    to call ``confirm_delete_group`` (the legacy two-tool flow).
    """

    @pytest.mark.asyncio
    async def test_returns_confirmation_with_confirm_tool(self, ctx_no_elicitation):
        result = await delete_group(GROUP_ID, ctx=ctx_no_elicitation)

        payload = result[0]
        assert payload["confirmation_required"] is True
        assert payload["tool_to_use"] == "confirm_delete_group"
        assert GROUP_ID in payload["message"]
        assert "confirm_delete_group" in payload["message"]

    @pytest.mark.asyncio
    async def test_exception_returns_confirmation_with_confirm_tool(self, ctx_elicit_exception):
        result = await delete_group(GROUP_ID, ctx=ctx_elicit_exception)

        payload = result[0]
        assert payload["confirmation_required"] is True
        assert payload["tool_to_use"] == "confirm_delete_group"


# ---------------------------------------------------------------------------
# confirm_delete_group — deprecated legacy flow
# ---------------------------------------------------------------------------

class TestConfirmDeleteGroupDeprecated:
    """Tests for the deprecated confirm_delete_group tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_correct_confirmation_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await confirm_delete_group(GROUP_ID, "DELETE", ctx=ctx_elicit_accept_true)

        mock_okta_client.delete_group.assert_awaited_once_with(GROUP_ID)
        assert result[0]["message"] == f"Group {GROUP_ID} deleted successfully"

    @pytest.mark.asyncio
    async def test_incorrect_confirmation_cancels(self, ctx_elicit_accept_true):
        result = await confirm_delete_group(GROUP_ID, "wrong", ctx=ctx_elicit_accept_true)

        assert "error" in result[0]
        assert "cancelled" in result[0]["error"].lower() or "Deletion cancelled" in result[0]["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.groups.groups.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group.return_value = (None, "API Error")
        mock_get_client.return_value = client

        result = await confirm_delete_group(GROUP_ID, "DELETE", ctx=ctx_elicit_accept_true)

        assert "error" in result[0]
