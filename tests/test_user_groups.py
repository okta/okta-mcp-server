# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.users.users import get_user_groups
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

USER_ID = "00u1exampleUserId"


def _raw_client(payload, *, err=None):
    response = MagicMock()
    response.status = 200

    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=("request", None))
    executor.execute = AsyncMock(return_value=(response, json.dumps(payload) if err is None else "", err))

    client = MagicMock()
    client.get_base_url.return_value = "https://test.okta.com"
    client.get_request_executor.return_value = executor
    return client, executor


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_get_user_groups_uses_exact_user_membership_endpoint(mock_get_client, ctx_no_elicitation):
    payload = [
        {
            "id": "00gExampleProd",
            "type": "OKTA_GROUP",
            "profile": {
                "name": "example_app_prod",
                "description": None,
            },
            "_links": {"users": {"href": "large-unused-link"}},
        },
        {
            "id": "00gEveryone",
            "type": "BUILT_IN",
            "profile": None,
        },
    ]
    client, executor = _raw_client(payload)
    mock_get_client.return_value = client

    result = await get_user_groups(USER_ID, ctx=ctx_no_elicitation)

    assert result == {
        "user_id": USER_ID,
        "groups": [
            {
                "id": "00gExampleProd",
                "name": "example_app_prod",
                "description": None,
                "type": "OKTA_GROUP",
            },
            {
                "id": "00gEveryone",
                "name": None,
                "description": None,
                "type": "BUILT_IN",
            },
        ],
        "total_groups": 2,
    }
    executor.create_request.assert_awaited_once_with(
        "GET",
        f"https://test.okta.com/api/v1/users/{USER_ID}/groups",
        {},
        {},
    )
    executor.execute.assert_awaited_once_with("request")
    assert "_links" not in result["groups"][0]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_get_user_groups_surfaces_api_errors(mock_get_client, ctx_no_elicitation):
    client, _ = _raw_client([], err=RuntimeError("forbidden"))
    mock_get_client.return_value = client

    result = await get_user_groups(USER_ID, ctx=ctx_no_elicitation)

    assert result == {"error": "Error: forbidden"}


@pytest.mark.asyncio
async def test_get_user_groups_rejects_unsafe_user_id(ctx_no_elicitation):
    result = await get_user_groups("../groups/00gExampleProd", ctx=ctx_no_elicitation)

    assert "error" in result


def test_get_user_groups_scope_registry_entry():
    assert TOOL_SCOPE_REGISTRY["get_user_groups"] == "okta.users.read"
