# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for application-to-group assignment inspection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models.application_group_assignment import ApplicationGroupAssignment

from okta_mcp_server.tools.applications.applications import list_application_groups
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

APP_ID = "0oa12345678901234567"
GROUP_ID = "00g12345678901234567"


def _response(after_cursor: str | None = None):
    response = MagicMock()
    del response.has_next
    del response.next
    if after_cursor:
        response.headers = {
            "Link": (
                f"<https://test.okta.com/api/v1/apps/{APP_ID}/groups"
                f'?after={after_cursor}&limit=200&expand=group>; rel="next"'
            )
        }
    else:
        response.headers = {}
    return response


def _response_with_link(link: str):
    response = _response()
    response.headers = {"Link": link}
    return response


def _assignment(group_id: str = GROUP_ID, group_name: str = "example_app_prod"):
    return ApplicationGroupAssignment.model_validate(
        {
            "id": group_id,
            "lastUpdated": "2026-07-15T04:11:57.000Z",
            "priority": 1,
            "profile": {"example_app_role": "Reader"},
            "_embedded": {
                "group": {
                    "id": group_id,
                    "type": "OKTA_GROUP",
                    "profile": {"name": group_name},
                }
            },
        }
    )


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_expanded_application_group_is_normalized(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        return_value=([_assignment()], _response(), None)
    )
    mock_get_client.return_value = client

    result = await list_application_groups(
        ctx_no_elicitation,
        app_id=APP_ID,
        expand_group=True,
    )

    client.list_application_group_assignments.assert_awaited_once_with(
        APP_ID,
        limit=200,
        expand="group",
    )
    assert result["success"] is True
    assert result["app_id"] == APP_ID
    assert result["total_fetched"] == 1
    assert result["has_more"] is False
    assert result["next_cursor"] is None
    assert result["expand_group_used"] is True
    assert result["items"][0] == {
        "group_id": GROUP_ID,
        "group_name": "example_app_prod",
        "group_type": "OKTA_GROUP",
        "assignment_profile": {"example_app_role": "Reader"},
        "priority": 1,
        "lastUpdated": "2026-07-15T04:11:57.000Z",
        "raw": {
            "id": GROUP_ID,
            "lastUpdated": "2026-07-15T04:11:57.000Z",
            "priority": 1,
            "profile": {"example_app_role": "Reader"},
            "_embedded": {
                "group": {
                    "id": GROUP_ID,
                    "type": "OKTA_GROUP",
                    "profile": {"name": "example_app_prod"},
                }
            },
        },
    }


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_expand_group_false_omits_expand_query(
    mock_get_client,
    ctx_no_elicitation,
):
    assignment = ApplicationGroupAssignment.model_validate(
        {
            "id": GROUP_ID,
            "profile": {"example_app_role": "Reader"},
        }
    )
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        return_value=([assignment], _response(), None)
    )
    mock_get_client.return_value = client

    result = await list_application_groups(
        ctx_no_elicitation,
        app_id=APP_ID,
        expand_group=False,
    )

    client.list_application_group_assignments.assert_awaited_once_with(
        APP_ID,
        limit=200,
    )
    assert result["success"] is True
    assert result["expand_group_used"] is False
    assert result["items"][0]["group_id"] == GROUP_ID
    assert result["items"][0]["group_name"] is None
    assert result["items"][0]["group_type"] is None
    assert result["items"][0]["assignment_profile"] == {
        "example_app_role": "Reader"
    }
    assert result["items"][0]["raw"] == {
        "id": GROUP_ID,
        "profile": {"example_app_role": "Reader"},
    }


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_application_groups_fetches_every_page(mock_get_client, ctx_no_elicitation):
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        side_effect=[
            ([_assignment()], _response(after_cursor="NEXT1"), None),
            (
                [_assignment("00g76543210987654321", "example_app_stage")],
                _response(),
                None,
            ),
        ]
    )
    mock_get_client.return_value = client

    result = await list_application_groups(ctx_no_elicitation, app_id=APP_ID)
    assert client.list_application_group_assignments.await_args_list == [
        ((APP_ID,), {"limit": 200, "expand": "group"}),
        ((APP_ID,), {"limit": 200, "expand": "group", "after": "NEXT1"}),
    ]
    assert result["success"] is True
    assert result["total_fetched"] == 2
    assert [item["group_name"] for item in result["items"]] == [
        "example_app_prod",
        "example_app_stage",
    ]
    assert result["has_more"] is False
    assert result["next_cursor"] is None


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_application_groups_reports_incomplete_pagination(
    mock_get_client,
    ctx_no_elicitation,
):
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        side_effect=[
            ([_assignment()], _response(after_cursor="NEXT1"), None),
            (None, _response(), RuntimeError("rate limited")),
        ]
    )
    mock_get_client.return_value = client

    result = await list_application_groups(ctx_no_elicitation, app_id=APP_ID)
    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["total_fetched"] == 1
    assert result["items"][0]["group_name"] == "example_app_prod"
    assert result["has_more"] is True
    assert "rate limited" in result["error"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_empty_page_with_next_link_is_incomplete(
    mock_get_client,
    ctx_no_elicitation,
):
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        side_effect=[
            ([_assignment()], _response(after_cursor="NEXT1"), None),
            ([], _response(after_cursor="NEXT2"), None),
        ]
    )
    mock_get_client.return_value = client

    result = await list_application_groups(ctx_no_elicitation, app_id=APP_ID)
    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["total_fetched"] == 1
    assert result["has_more"] is True
    assert "empty page" in result["error"].lower()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_next_link_without_after_cursor_is_incomplete(
    mock_get_client,
    ctx_no_elicitation,
):
    response = _response_with_link(
        f'<https://test.okta.com/api/v1/apps/{APP_ID}/groups?limit=200>; rel="next"'
    )
    client = AsyncMock()
    client.list_application_group_assignments = AsyncMock(
        return_value=([_assignment()], response, None)
    )
    mock_get_client.return_value = client

    result = await list_application_groups(ctx_no_elicitation, app_id=APP_ID)
    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["total_fetched"] == 1
    assert result["has_more"] is True
    assert "cursor" in result["error"].lower()


def test_list_application_groups_scope_registry_entry():
    assert TOOL_SCOPE_REGISTRY["list_application_groups"] == "okta.apps.read"