# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for minimized, complete application-user assignment evidence."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications import applications
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY


def _response(next_cursor: str | None = None):
    response = MagicMock()
    del response.has_next
    del response.next
    if next_cursor:
        response.headers = {
            "Link": (
                "<https://test.okta.com/api/v1/apps/0oa1/users"
                f"?after={next_cursor}&limit=500&expand=user>; rel=\"next\""
            )
        }
    else:
        response.headers = {}
    return response


def _client_with_raw_pages(raw_pages):
    client = AsyncMock()
    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()
    executor.create_request = AsyncMock(
        return_value=({"method": "GET", "url": "https://test.okta.com"}, None)
    )
    executor.execute = AsyncMock(side_effect=raw_pages)
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_application_users_filters_suffixes_and_excludes_full_profiles(
    mock_get_client, ctx_no_elicitation
):
    list_application_users = getattr(applications, "list_application_users", None)
    assert list_application_users is not None, "list_application_users tool is missing"

    assignments = [
        {
            "id": "00u1",
            "scope": "GROUP",
            "status": "PROVISIONED",
            "syncState": "SYNCHRONIZED",
            "credentials": {"userName": "alice@example-app.com"},
            "profile": {
                "userName": "alice@example-app.com",
                "customSecret": "must-not-be-returned",
            },
            "_embedded": {
                "user": {
                    "id": "00u1",
                    "status": "ACTIVE",
                    "profile": {
                        "login": "alice@example.com",
                        "apiToken": "must-not-be-returned",
                    },
                }
            },
        },
        {
            "id": "00u2",
            "scope": "USER",
            "status": "PROVISIONED",
            "credentials": {"userName": "bob@example.com"},
            "_embedded": {
                "user": {
                    "id": "00u2",
                    "status": "ACTIVE",
                    "profile": {"login": "bob@example.com"},
                }
            },
        },
    ]
    client = _client_with_raw_pages(
        [(_response(), json.dumps(assignments), None)]
    )
    mock_get_client.return_value = client

    result = await list_application_users(
        ctx_no_elicitation,
        "0oa1",
        okta_login_suffix="@example.com",
        app_username_suffix="@example-app.com",
    )

    assert result["success"] is True
    assert result["assignments_scanned"] == 2
    assert result["matches_returned"] == 1
    assert result["items"] == [
        {
            "app_user_id": "00u1",
            "user_id": "00u1",
            "scope": "GROUP",
            "assignment_status": "PROVISIONED",
            "sync_state": "SYNCHRONIZED",
            "app_username": "alice@example-app.com",
            "okta_login": "alice@example.com",
            "okta_user_status": "ACTIVE",
        }
    ]
    serialized = json.dumps(result)
    assert "customSecret" not in serialized
    assert "apiToken" not in serialized
    request_url = client._executor.create_request.await_args.args[1]
    assert request_url == (
        "https://test.okta.com/api/v1/apps/0oa1/users?limit=500&expand=user"
    )


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_application_users_fails_closed_on_next_link_without_cursor(
    mock_get_client, ctx_no_elicitation
):
    response = MagicMock()
    del response.has_next
    del response.next
    response.headers = {
        "Link": (
            "<https://test.okta.com/api/v1/apps/0oa1/users?limit=500>; "
            'rel="next"'
        )
    }
    assignments = [
        {
            "id": "00u1",
            "credentials": {"userName": "alice@example-app.com"},
            "_embedded": {
                "user": {
                    "id": "00u1",
                    "status": "ACTIVE",
                    "profile": {"login": "alice@example.com"},
                }
            },
        }
    ]
    client = _client_with_raw_pages(
        [(response, json.dumps(assignments), None)]
    )
    mock_get_client.return_value = client

    result = await applications.list_application_users(ctx_no_elicitation, "0oa1")

    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["has_more"] is True
    assert "without an extractable after cursor" in result["error"]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_application_users_fails_closed_on_empty_next_linked_page(
    mock_get_client, ctx_no_elicitation
):
    first_assignments = [
        {
            "id": "00u1",
            "credentials": {"userName": "alice@example-app.com"},
            "_embedded": {
                "user": {
                    "id": "00u1",
                    "status": "ACTIVE",
                    "profile": {"login": "alice@example.com"},
                }
            },
        }
    ]
    client = _client_with_raw_pages(
        [
            (_response("CURSOR1"), json.dumps(first_assignments), None),
            (_response("CURSOR2"), json.dumps([]), None),
        ]
    )
    mock_get_client.return_value = client

    result = await applications.list_application_users(ctx_no_elicitation, "0oa1")

    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["has_more"] is True
    assert result["assignments_scanned"] == 1
    assert "empty page with a next link" in result["error"]


def test_list_application_users_scope_registry_entry():
    assert TOOL_SCOPE_REGISTRY["list_application_users"] == "okta.apps.read"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_application_users_follows_all_pages_and_matches_case_insensitively(
    mock_get_client, ctx_no_elicitation
):
    first = [
        {
            "id": "00u1",
            "scope": "GROUP",
            "credentials": {"userName": "alice@example-app.com"},
            "_embedded": {
                "user": {"id": "00u1", "profile": {"login": "alice@example.com"}}
            },
        }
    ]
    second = [
        {
            "id": "00u2",
            "scope": "USER",
            "credentials": {"userName": "BOB@EXAMPLE-APP.COM"},
            "_embedded": {
                "user": {"id": "00u2", "profile": {"login": "BOB@EXAMPLE.COM"}}
            },
        }
    ]
    client = _client_with_raw_pages(
        [
            (_response("CURSOR1"), json.dumps(first), None),
            (_response(), json.dumps(second), None),
        ]
    )
    mock_get_client.return_value = client

    result = await applications.list_application_users(
        ctx_no_elicitation,
        "0oa1",
        okta_login_suffix="@example.com",
        app_username_suffix="@example-app.com",
    )

    assert result["success"] is True
    assert result["partial"] is False
    assert result["assignments_scanned"] == 2
    assert result["matches_returned"] == 2
    assert result["has_more"] is False
    urls = [call.args[1] for call in client._executor.create_request.await_args_list]
    assert urls == [
        "https://test.okta.com/api/v1/apps/0oa1/users?limit=500&expand=user",
        "https://test.okta.com/api/v1/apps/0oa1/users?limit=500&expand=user&after=CURSOR1",
    ]


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_list_application_users_reports_later_page_error_as_partial(
    mock_get_client, ctx_no_elicitation
):
    first = [
        {
            "id": "00u1",
            "credentials": {"userName": "alice@example-app.com"},
            "_embedded": {
                "user": {"id": "00u1", "profile": {"login": "alice@example.com"}}
            },
        }
    ]
    client = _client_with_raw_pages(
        [
            (_response("CURSOR1"), json.dumps(first), None),
            (_response(), "", RuntimeError("upstream page failed")),
        ]
    )
    mock_get_client.return_value = client

    result = await applications.list_application_users(ctx_no_elicitation, "0oa1")

    assert result["success"] is False
    assert result["partial"] is True
    assert result["error_type"] == "pagination_incomplete"
    assert result["assignments_scanned"] == 1
    assert result["has_more"] is True
    assert "upstream page failed" in result["error"]
