# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Regression tests for Policies API payloads rejected by the generated SDK."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.policies.policies import (
    _safe_parse_policy,
    _safe_parse_policy_rule,
    get_policy,
    get_policy_rule,
    list_policies,
    list_policy_rules,
)

POLICY_ID = "rstABCDEfghIJKLmnop1"
RULE_ID = "rulABCDEfghIJKLmnop1"

ACCESS_POLICY_WITH_STRING_RESOURCE_TYPE = {
    "id": POLICY_ID,
    "name": "Example Access Policy",
    "priority": 1,
    "status": "ACTIVE",
    "system": False,
    "type": "ACCESS_POLICY",
    "_embedded": {"resourceType": "APP"},
}

ACCESS_POLICY_RULE_WITH_NULL_EXCLUDE = {
    "id": RULE_ID,
    "name": "Example Access Policy Rule",
    "priority": 4,
    "status": "ACTIVE",
    "system": False,
    "type": "ACCESS_POLICY",
    "conditions": {
        "userType": {
            "include": ["STANDARD"],
            "exclude": None,
        }
    },
    "actions": {"appSignOn": {"access": "ALLOW"}},
}


def _make_ctx():
    manager = MagicMock()
    ctx = MagicMock()
    ctx.request_context.lifespan_context.okta_auth_manager = manager
    return ctx


def _client_returning(*bodies):
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET"}, None))
    executor.execute = AsyncMock(
        side_effect=[(MagicMock(headers={}), json.dumps(body), None) for body in bodies]
    )
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestSafePolicyParsing:
    def test_string_resource_type_falls_back_to_raw_policy(self):
        result = _safe_parse_policy(ACCESS_POLICY_WITH_STRING_RESOURCE_TYPE)

        assert isinstance(result, dict)
        assert result["id"] == POLICY_ID
        assert "_embedded.resourceType" in result["_deserialization_warning"]

    def test_null_user_type_exclude_falls_back_to_raw_rule(self):
        result = _safe_parse_policy_rule(ACCESS_POLICY_RULE_WITH_NULL_EXCLUDE)

        assert isinstance(result, dict)
        assert result["id"] == RULE_ID
        assert "exclude" in result["_deserialization_warning"]


class TestPolicyReadToolsUseRawResponses:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_list_policies_salvages_non_conforming_policy(self, mock_get_client):
        client = _client_returning([ACCESS_POLICY_WITH_STRING_RESOURCE_TYPE])
        mock_get_client.return_value = client

        result = await list_policies(
            ctx=_make_ctx(), type="ACCESS_POLICY", q="Example Access Policy"
        )

        assert result["total_fetched"] == 1
        assert result["items"][0]["id"] == POLICY_ID
        assert "_deserialization_warning" in result["items"][0]
        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert "/api/v1/policies" in url
        assert "type=ACCESS_POLICY" in url
        assert "q=Example+Access+Policy" in url

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_get_policy_salvages_non_conforming_policy(self, mock_get_client):
        client = _client_returning(ACCESS_POLICY_WITH_STRING_RESOURCE_TYPE)
        mock_get_client.return_value = client

        result = await get_policy(ctx=_make_ctx(), policy_id=POLICY_ID)

        assert result["id"] == POLICY_ID
        assert result["_embedded"]["resourceType"] == "APP"
        assert "_deserialization_warning" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_list_policy_rules_salvages_non_conforming_rule(self, mock_get_client):
        client = _client_returning([ACCESS_POLICY_RULE_WITH_NULL_EXCLUDE])
        mock_get_client.return_value = client

        result = await list_policy_rules(ctx=_make_ctx(), policy_id=POLICY_ID)

        assert result["total_fetched"] == 1
        assert result["items"][0]["conditions"]["userType"]["exclude"] is None
        assert "_deserialization_warning" in result["items"][0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_get_policy_rule_salvages_non_conforming_rule(self, mock_get_client):
        client = _client_returning(ACCESS_POLICY_RULE_WITH_NULL_EXCLUDE)
        mock_get_client.return_value = client

        result = await get_policy_rule(
            ctx=_make_ctx(), policy_id=POLICY_ID, rule_id=RULE_ID
        )

        assert result["id"] == RULE_ID
        assert result["conditions"]["userType"]["exclude"] is None
        assert "_deserialization_warning" in result
        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert url == f"/api/v1/policies/{POLICY_ID}/rules/{RULE_ID}"
