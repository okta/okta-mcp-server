# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the non-destructive group rule tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.group_rules.group_rules import (
    activate_group_rule,
    create_group_rule,
    get_group_rule,
    list_group_rules,
    update_group_rule,
)

RULE_ID = "0pr1a2b3c4D5E6F7G8H9"
PATCH_CLIENT = "okta_mcp_server.tools.group_rules.group_rules.get_okta_client"

RULE_DATA = {
    "type": "group_rule",
    "name": "Engineering department",
    "conditions": {"expression": {"type": "urn:okta:expression:1.0", "value": 'user.department=="Engineering"'}},
    "actions": {"assignUserToGroups": {"groupIds": ["00g1a2b3c4D5E6F7G8H9"]}},
}


def _make_rule(rule_id: str = RULE_ID) -> MagicMock:
    rule = MagicMock()
    rule.id = rule_id
    rule.as_dict.return_value = {"id": rule_id, "name": RULE_DATA["name"]}
    return rule


def _make_response(has_next: bool = False) -> MagicMock:
    response = MagicMock()
    response.has_next.return_value = has_next
    response.headers = {}
    return response


# ---------------------------------------------------------------------------
# list_group_rules
# ---------------------------------------------------------------------------


class TestListGroupRules:
    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_passes_query_params(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_group_rules.return_value = ([_make_rule()], _make_response(), None)
        mock_get_client.return_value = client

        result = await list_group_rules(
            ctx_no_elicitation, search="Engineering", expand="groupIdToGroupNameMap", limit=50
        )

        client.list_group_rules.assert_awaited_once_with(
            {"search": "Engineering", "limit": "50", "expand": "groupIdToGroupNameMap"}
        )
        assert result["total_fetched"] == 1

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_limit_is_clamped(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_group_rules.return_value = ([], _make_response(), None)
        mock_get_client.return_value = client

        await list_group_rules(ctx_no_elicitation, limit=500)

        client.list_group_rules.assert_awaited_once_with({"limit": "100"})

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_empty_result(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_group_rules.return_value = ([], _make_response(), None)
        mock_get_client.return_value = client

        result = await list_group_rules(ctx_no_elicitation)

        assert result["items"] == []
        assert result["total_fetched"] == 0

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_okta_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_group_rules.return_value = (None, None, "API Error")
        mock_get_client.return_value = client

        result = await list_group_rules(ctx_no_elicitation)

        assert result == {"error": "Error: API Error"}

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_exception_returns_error(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await list_group_rules(ctx_no_elicitation, search="Engineering")

        assert result == {"error": "Exception: Connection refused"}


# ---------------------------------------------------------------------------
# get_group_rule
# ---------------------------------------------------------------------------


class TestGetGroupRule:
    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_returns_rule(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_group_rule.return_value = (_make_rule(), None, None)
        mock_get_client.return_value = client

        result = await get_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        client.get_group_rule.assert_awaited_once_with(RULE_ID, {})
        assert result["id"] == RULE_ID

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_passes_expand(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_group_rule.return_value = (_make_rule(), None, None)
        mock_get_client.return_value = client

        await get_group_rule(RULE_ID, ctx=ctx_no_elicitation, expand="groupIdToGroupNameMap")

        client.get_group_rule.assert_awaited_once_with(RULE_ID, {"expand": "groupIdToGroupNameMap"})

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_okta_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_group_rule.return_value = (None, None, "Not found")
        mock_get_client.return_value = client

        result = await get_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        assert result == {"error": "Error: Not found"}

    @pytest.mark.asyncio
    async def test_invalid_id_rejected(self, ctx_no_elicitation):
        result = await get_group_rule("../users", ctx=ctx_no_elicitation)

        assert "error" in result


# ---------------------------------------------------------------------------
# create_group_rule
# ---------------------------------------------------------------------------


class TestCreateGroupRule:
    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_creates_and_activates(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.create_group_rule.return_value = (_make_rule(), None, None)
        client.activate_group_rule.return_value = (None, None)
        mock_get_client.return_value = client

        result = await create_group_rule(RULE_DATA, ctx=ctx_no_elicitation)

        client.create_group_rule.assert_awaited_once_with(RULE_DATA)
        client.activate_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["id"] == RULE_ID

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_create_without_activate(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.create_group_rule.return_value = (_make_rule(), None, None)
        mock_get_client.return_value = client

        result = await create_group_rule(RULE_DATA, ctx=ctx_no_elicitation, activate=False)

        client.activate_group_rule.assert_not_awaited()
        assert result["id"] == RULE_ID

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_activation_failure_returns_warning(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.create_group_rule.return_value = (_make_rule(), None, None)
        client.activate_group_rule.return_value = (None, "Activation failed")
        mock_get_client.return_value = client

        result = await create_group_rule(RULE_DATA, ctx=ctx_no_elicitation)

        assert result["rule"]["id"] == RULE_ID
        assert "Activation failed" in result["warning"]

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_okta_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.create_group_rule.return_value = (None, None, "Invalid expression")
        mock_get_client.return_value = client

        result = await create_group_rule(RULE_DATA, ctx=ctx_no_elicitation)

        client.activate_group_rule.assert_not_awaited()
        assert result == {"error": "Error: Invalid expression"}


# ---------------------------------------------------------------------------
# update_group_rule
# ---------------------------------------------------------------------------


class TestUpdateGroupRule:
    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_updates_rule(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.update_group_rule.return_value = (_make_rule(), None, None)
        mock_get_client.return_value = client

        result = await update_group_rule(RULE_ID, RULE_DATA, ctx=ctx_no_elicitation)

        client.update_group_rule.assert_awaited_once_with(RULE_ID, RULE_DATA)
        assert result["id"] == RULE_ID

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_okta_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.update_group_rule.return_value = (None, None, "Rule is active")
        mock_get_client.return_value = client

        result = await update_group_rule(RULE_ID, RULE_DATA, ctx=ctx_no_elicitation)

        assert result == {"error": "Error: Rule is active"}


# ---------------------------------------------------------------------------
# activate_group_rule
# ---------------------------------------------------------------------------


class TestActivateGroupRule:
    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_activates_rule(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.activate_group_rule.return_value = (None, None)
        mock_get_client.return_value = client

        result = await activate_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        client.activate_group_rule.assert_awaited_once_with(RULE_ID)
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch(PATCH_CLIENT)
    async def test_okta_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.activate_group_rule.return_value = (None, "Invalid rule")
        mock_get_client.return_value = client

        result = await activate_group_rule(RULE_ID, ctx=ctx_no_elicitation)

        assert result == {"error": "Error: Invalid rule"}
