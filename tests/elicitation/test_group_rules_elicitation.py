# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for group rule delete and deactivate with elicitation support."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.group_rules.group_rules import deactivate_group_rule, delete_group_rule

RULE_ID = "0qr1a2b3c4D5E6F7G8H9"


# ---------------------------------------------------------------------------
# delete_group_rule — elicitation flows
# ---------------------------------------------------------------------------


class TestDeleteGroupRuleElicitation:
    """Tests for delete_group_rule when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_accept_confirmed_deletes_rule(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.delete_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["message"] == f"Group rule {RULE_ID} deleted successfully"
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_remove_users_passed_to_api(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_accept_true, remove_users=True)

        mock_okta_client.delete_group_rule.assert_awaited_once_with(RULE_ID, remove_users=True)
        assert "also be removed" in ctx_elicit_accept_true.elicit.call_args.kwargs["message"]
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_group_rule.return_value = (None, "API Error: rule not found")
        mock_get_client.return_value = client

        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result


# ---------------------------------------------------------------------------
# delete_group_rule — fallback flows (auto_confirm_on_fallback=True)
# ---------------------------------------------------------------------------


class TestDeleteGroupRuleFallback:
    """Tests for delete_group_rule when the client does NOT support elicitation.

    With auto_confirm_on_fallback=True, the operation proceeds automatically.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_no_elicitation_auto_confirms(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        mock_okta_client.delete_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_exception_fallback_auto_confirms(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_group_rule(RULE_ID, ctx=ctx_elicit_exception)

        mock_okta_client.delete_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# deactivate_group_rule — elicitation flows
# ---------------------------------------------------------------------------


class TestDeactivateGroupRuleElicitation:
    """Tests for deactivate_group_rule when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_accept_confirmed_deactivates_rule(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        mock_okta_client.deactivate_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["message"] == f"Group rule {RULE_ID} deactivated successfully"
        assert result["success"] is True

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_accept_false)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_decline)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_cancel)

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.deactivate_group_rule.return_value = (None, "API Error: rule not found")
        mock_get_client.return_value = client

        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_exception_during_deactivate(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_accept_true)

        assert "error" in result


# ---------------------------------------------------------------------------
# deactivate_group_rule — fallback flows (auto_confirm_on_fallback=True)
# ---------------------------------------------------------------------------


class TestDeactivateGroupRuleFallback:
    """Tests for deactivate_group_rule when the client does NOT support elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_no_elicitation_auto_confirms(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        mock_okta_client.deactivate_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.group_rules.group_rules.get_okta_client")
    async def test_exception_fallback_auto_confirms(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await deactivate_group_rule(RULE_ID, ctx=ctx_elicit_exception)

        mock_okta_client.deactivate_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["success"] is True
