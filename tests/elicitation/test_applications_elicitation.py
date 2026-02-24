# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for application deletion and deactivation with elicitation support."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import (
    confirm_delete_application,
    deactivate_application,
    delete_application,
)


APP_ID = "0oa1234567890ABCDEF"


# ---------------------------------------------------------------------------
# delete_application — elicitation flows
# ---------------------------------------------------------------------------

class TestDeleteApplicationElicitation:
    """Tests for delete_application when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_accept_confirmed_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        mock_okta_client.delete_application.assert_awaited_once_with(APP_ID)
        assert result[0]["message"] == f"Application {APP_ID} deleted successfully"

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await delete_application(ctx=ctx_elicit_accept_false, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await delete_application(ctx=ctx_elicit_decline, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await delete_application(ctx=ctx_elicit_cancel, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_application.return_value = (None, "API Error: app not found")
        mock_get_client.return_value = client

        result = await delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        assert "error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        assert "error" in result[0]


# ---------------------------------------------------------------------------
# delete_application — fallback flows
# ---------------------------------------------------------------------------

class TestDeleteApplicationFallback:
    """Tests for delete_application when the client does NOT support elicitation.

    Pre-elicitation behaviour: the tool returns a payload directing the LLM
    to call ``confirm_delete_application`` (the legacy two-tool flow).
    """

    @pytest.mark.asyncio
    async def test_returns_confirmation_with_confirm_tool(self, ctx_no_elicitation):
        result = await delete_application(ctx=ctx_no_elicitation, app_id=APP_ID)

        payload = result[0]
        assert payload["confirmation_required"] is True
        assert payload["tool_to_use"] == "confirm_delete_application"
        assert APP_ID in payload["message"]
        assert "confirm_delete_application" in payload["message"]

    @pytest.mark.asyncio
    async def test_exception_returns_confirmation_with_confirm_tool(self, ctx_elicit_exception):
        result = await delete_application(ctx=ctx_elicit_exception, app_id=APP_ID)

        payload = result[0]
        assert payload["confirmation_required"] is True
        assert payload["tool_to_use"] == "confirm_delete_application"


# ---------------------------------------------------------------------------
# confirm_delete_application — deprecated legacy flow
# ---------------------------------------------------------------------------

class TestConfirmDeleteApplicationDeprecated:
    """Tests for the deprecated confirm_delete_application tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_correct_confirmation_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await confirm_delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID, confirmation="DELETE")

        mock_okta_client.delete_application.assert_awaited_once_with(APP_ID)
        assert "deleted successfully" in result[0]

    @pytest.mark.asyncio
    async def test_incorrect_confirmation_cancels(self, ctx_elicit_accept_true):
        result = await confirm_delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID, confirmation="wrong")

        assert "cancelled" in result[0].lower() or "Deletion cancelled" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_application.return_value = (None, "API Error")
        mock_get_client.return_value = client

        result = await confirm_delete_application(ctx=ctx_elicit_accept_true, app_id=APP_ID, confirmation="DELETE")

        assert "Error" in result[0]


# ---------------------------------------------------------------------------
# deactivate_application — elicitation flows
# ---------------------------------------------------------------------------

class TestDeactivateApplicationElicitation:
    """Tests for deactivate_application when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_accept_confirmed_deactivates(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        mock_okta_client.deactivate_application.assert_awaited_once_with(APP_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await deactivate_application(ctx=ctx_elicit_accept_false, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await deactivate_application(ctx=ctx_elicit_decline, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await deactivate_application(ctx=ctx_elicit_cancel, app_id=APP_ID)

        assert "cancelled" in result[0]["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.deactivate_application.return_value = (None, "API Error: app not found")
        mock_get_client.return_value = client

        result = await deactivate_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        assert "Error" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_exception_during_deactivation(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await deactivate_application(ctx=ctx_elicit_accept_true, app_id=APP_ID)

        assert "Exception" in result[0]


# ---------------------------------------------------------------------------
# deactivate_application — fallback flows (auto-confirm)
# ---------------------------------------------------------------------------

class TestDeactivateApplicationFallback:
    """Tests for deactivate_application when the client does NOT support elicitation.

    Pre-elicitation behaviour: the operation proceeds directly without
    confirmation (auto_confirm_on_fallback=True).
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fallback_auto_confirms(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_application(ctx=ctx_no_elicitation, app_id=APP_ID)

        mock_okta_client.deactivate_application.assert_awaited_once_with(APP_ID)
        assert "deactivated successfully" in result[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_exception_fallback_auto_confirms(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_application(ctx=ctx_elicit_exception, app_id=APP_ID)

        mock_okta_client.deactivate_application.assert_awaited_once_with(APP_ID)
        assert "deactivated successfully" in result[0]
