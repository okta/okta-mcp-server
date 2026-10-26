# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the read-only Governance (Access Requests) tools and the shared raw-request helper."""

from __future__ import annotations

import json
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.errors.http_error import HTTPError
from okta.errors.okta_api_error import OktaAPIError

from okta_mcp_server.tools.applications.applications import get_catalog_app
from okta_mcp_server.tools.governance.governance import (
    get_app_request_condition,
    list_app_request_conditions,
    list_catalog_entries,
)
from okta_mcp_server.utils.raw_request import ScopeDeniedError, okta_raw_request
from okta_mcp_server.utils.scope_guard import build_scope_error
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

CONDITION_SCOPE = "okta.accessRequests.condition.read"
CATALOG_SCOPE = "okta.accessRequests.catalog.read"
GOVERNANCE_MODULE = "okta_mcp_server.tools.governance.governance"
APP_ID = "0oa1abc2DEF3ghi4J5d7"

ACTIVE_CONDITION = {
    "id": "rc1active",
    "resourceId": APP_ID,
    "name": "Engineering can request",
    "status": "ACTIVE",
    "priority": 0,
    "requesterSettings": {"type": "GROUPS", "groups": [{"id": "00g1eng"}]},
    "approvalSequenceId": "aps1mgr",
}
INACTIVE_CONDITION = {
    "id": "rc2inactive",
    "resourceId": APP_ID,
    "name": "Contractors (paused)",
    "status": "INACTIVE",
    "priority": 1,
    "requesterSettings": {"type": "EVERYONE"},
}
INVALID_CONDITION = {
    "id": "rc3invalid",
    "resourceId": APP_ID,
    "name": "Sales (deleted group)",
    "status": "INVALID",
    "priority": 2,
    "requesterSettings": {"type": "GROUPS", "groups": [{"id": "00g1gone"}]},
}


def _make_ctx(scopes: str | None = None):
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    manager = FakeOktaAuthManager()
    if scopes is not None:
        manager.scopes = scopes
    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(okta_auth_manager=manager)
    ctx = MagicMock()
    ctx.request_context = request_context
    ctx.info = AsyncMock()
    return ctx


def _client_paged(pages):
    """Client whose executor returns one result per successive execute call.

    Each entry is a body (dict/list, JSON-encoded here), or a pre-built
    (response, body, err) tuple for error pages.
    """
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "X"}, None))
    executor.execute = AsyncMock(
        side_effect=[p if isinstance(p, tuple) else (MagicMock(), json.dumps(p), None) for p in pages]
    )
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


def _requested_urls(client):
    return [c.kwargs["url"] for c in client.get_request_executor.return_value.create_request.call_args_list]


def _envelope(items, next_after=None):
    links = {"self": {"href": "https://test.okta.com/governance/api/v2/x"}}
    if next_after:
        links["next"] = {"href": f"https://test.okta.com/governance/api/v2/x?after={next_after}&limit=2"}
    return {"data": items, "_links": links}


@dataclass
class _ResponseDetails:
    status: int
    headers: dict


def _okta_api_error(status: int, code: str = "E0000006"):
    return OktaAPIError(
        "https://test.okta.com/governance/api/v2/x",
        _ResponseDetails(status=status, headers={}),
        {"errorCode": code, "errorSummary": "You do not have permission to perform the requested action"},
    )


def _error_result(err):
    return (None, None, err)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_tools_declared_in_scope_registry(self):
        assert TOOL_SCOPE_REGISTRY["list_app_request_conditions"] == CONDITION_SCOPE
        assert TOOL_SCOPE_REGISTRY["get_app_request_condition"] == CONDITION_SCOPE
        assert TOOL_SCOPE_REGISTRY["list_catalog_entries"] == CATALOG_SCOPE

    def test_tools_registered_on_server(self):
        from okta_mcp_server.server import mcp

        registered = {t.name for t in mcp._tool_manager.list_tools()}
        assert {"list_app_request_conditions", "get_app_request_condition", "list_catalog_entries"} <= registered


# ---------------------------------------------------------------------------
# Request conditions
# ---------------------------------------------------------------------------


class TestListAppRequestConditions:
    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_returns_active_inactive_and_invalid_conditions(self, mock_get_client):
        conditions = [ACTIVE_CONDITION, INACTIVE_CONDITION, INVALID_CONDITION]
        client = _client_paged([_envelope(conditions)])
        mock_get_client.return_value = client

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID)

        assert result["items"] == conditions
        assert result["total_fetched"] == 3
        assert result["status_summary"] == {"ACTIVE": 1, "INACTIVE": 1, "INVALID": 1}
        assert result["has_more"] is False
        assert result["next_cursor"] is None
        assert _requested_urls(client) == [f"/governance/api/v2/resources/{APP_ID}/request-conditions"]

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_no_conditions_returns_empty_summary(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_envelope([])])

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID)

        assert result["items"] == []
        assert result["status_summary"] == {}

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_403_returns_canonical_scope_error(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_error_result(_okta_api_error(403))])

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID)

        assert result == build_scope_error([CONDITION_SCOPE])

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_non_scope_error_passes_through(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_error_result(_okta_api_error(404, "E0000007"))])

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID)

        assert "404" in result["error"]
        assert "missing required scope" not in result["error"]

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_invalid_app_id_rejected_before_request(self, mock_get_client):
        result = await list_app_request_conditions(ctx=_make_ctx(), app_id="../../api/v1/users")

        assert "error" in result
        mock_get_client.assert_not_called()

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_missing_configured_scope_blocks_before_request(self, mock_get_client):
        ctx = _make_ctx(scopes="okta.apps.read okta.accessRequests.catalog.read")

        result = await list_app_request_conditions(ctx=ctx, app_id=APP_ID)

        assert result == build_scope_error([CONDITION_SCOPE])
        mock_get_client.assert_not_called()


class TestGetAppRequestCondition:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("condition", [ACTIVE_CONDITION, INACTIVE_CONDITION, INVALID_CONDITION])
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_returns_condition_for_each_status(self, mock_get_client, condition):
        client = _client_paged([condition])
        mock_get_client.return_value = client

        result = await get_app_request_condition(ctx=_make_ctx(), app_id=APP_ID, condition_id=condition["id"])

        assert result == condition
        assert _requested_urls(client) == [
            f"/governance/api/v2/resources/{APP_ID}/request-conditions/{condition['id']}"
        ]

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_403_returns_canonical_scope_error(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_error_result(_okta_api_error(403))])

        result = await get_app_request_condition(ctx=_make_ctx(), app_id=APP_ID, condition_id="rc1active")

        assert result == build_scope_error([CONDITION_SCOPE])

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_empty_body_returns_error(self, mock_get_client):
        executor = MagicMock()
        executor.create_request = AsyncMock(return_value=({"method": "X"}, None))
        executor.execute = AsyncMock(return_value=(MagicMock(), "", None))
        client = MagicMock()
        client.get_request_executor = MagicMock(return_value=executor)
        mock_get_client.return_value = client

        result = await get_app_request_condition(ctx=_make_ctx(), app_id=APP_ID, condition_id="rc1active")

        assert "empty response" in result["error"]

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_invalid_condition_id_rejected_before_request(self, mock_get_client):
        result = await get_app_request_condition(ctx=_make_ctx(), app_id=APP_ID, condition_id="rc1/../x")

        assert "error" in result
        mock_get_client.assert_not_called()


# ---------------------------------------------------------------------------
# Catalog entries
# ---------------------------------------------------------------------------


class TestListCatalogEntries:
    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_sends_top_level_filter_and_match(self, mock_get_client):
        entries = [{"id": "cen1sfdc", "label": "Salesforce", "requestable": True}]
        client = _client_paged([_envelope(entries)])
        mock_get_client.return_value = client

        result = await list_catalog_entries(ctx=_make_ctx(), app_name="Sales force")

        assert result["items"] == entries
        (url,) = _requested_urls(client)
        assert url.startswith("/governance/api/v2/catalogs/default/entries?")
        assert "filter=not%28parent%20pr%29" in url
        assert "match=Sales%20force" in url

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_without_app_name_sends_no_match(self, mock_get_client):
        client = _client_paged([_envelope([])])
        mock_get_client.return_value = client

        await list_catalog_entries(ctx=_make_ctx())

        (url,) = _requested_urls(client)
        assert "match=" not in url

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_401_returns_canonical_scope_error(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_error_result(_okta_api_error(401, "E0000011"))])

        result = await list_catalog_entries(ctx=_make_ctx())

        assert result == build_scope_error([CATALOG_SCOPE])


# ---------------------------------------------------------------------------
# Pagination (_links.next cursor in the body, not a Link header)
# ---------------------------------------------------------------------------


class TestGovernancePagination:
    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_next_cursor_read_from_links_next(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_envelope([{"id": "a"}, {"id": "b"}], next_after="cur2")])

        result = await list_catalog_entries(ctx=_make_ctx(), limit=2)

        assert result["has_more"] is True
        assert result["next_cursor"] == "cur2"

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_after_and_limit_passed_through(self, mock_get_client):
        client = _client_paged([_envelope([])])
        mock_get_client.return_value = client

        await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID, after="cur2", limit=500)

        (url,) = _requested_urls(client)
        assert "after=cur2" in url
        assert "limit=200" in url  # clamped

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_fetch_all_follows_cursor_until_no_next_link(self, mock_get_client):
        client = _client_paged(
            [
                _envelope([ACTIVE_CONDITION], next_after="cur2"),
                _envelope([INACTIVE_CONDITION], next_after="cur3"),
                _envelope([INVALID_CONDITION]),
            ]
        )
        mock_get_client.return_value = client

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID, fetch_all=True)

        assert [c["id"] for c in result["items"]] == ["rc1active", "rc2inactive", "rc3invalid"]
        assert result["status_summary"] == {"ACTIVE": 1, "INACTIVE": 1, "INVALID": 1}
        assert result["fetch_all_used"] is True
        assert result["has_more"] is False
        assert result["pagination_info"]["pages_fetched"] == 3
        assert result["pagination_info"]["stopped_early"] is False
        urls = _requested_urls(client)
        assert "after=" not in urls[0]
        assert "after=cur2" in urls[1]
        assert "after=cur3" in urls[2]
        # The next href's host/path is never followed — only its cursor.
        assert all(u.startswith(f"/governance/api/v2/resources/{APP_ID}/request-conditions") for u in urls)

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_fetch_all_keeps_filter_on_every_page(self, mock_get_client):
        client = _client_paged([_envelope([{"id": "a"}], next_after="cur2"), _envelope([{"id": "b"}])])
        mock_get_client.return_value = client

        result = await list_catalog_entries(ctx=_make_ctx(), app_name="sf", fetch_all=True)

        assert [e["id"] for e in result["items"]] == ["a", "b"]
        assert all("filter=not%28parent%20pr%29" in u and "match=sf" in u for u in _requested_urls(client))

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_fetch_all_error_mid_walk_returns_partial_with_resume_cursor(self, mock_get_client):
        mock_get_client.return_value = _client_paged(
            [
                _envelope([{"id": "a"}], next_after="cur2"),
                _error_result(_okta_api_error(500, "E0000009")),
            ]
        )

        result = await list_catalog_entries(ctx=_make_ctx(), fetch_all=True)

        assert [e["id"] for e in result["items"]] == ["a"]
        assert result["pagination_info"]["stopped_early"] is True
        assert "API error" in result["pagination_info"]["stop_reason"]
        assert result["has_more"] is True
        assert result["next_cursor"] == "cur2"

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_fetch_all_stops_when_cursor_does_not_advance(self, mock_get_client):
        mock_get_client.return_value = _client_paged(
            [
                _envelope([{"id": "a"}], next_after="cur2"),
                _envelope([{"id": "a"}], next_after="cur2"),
            ]
        )

        result = await list_catalog_entries(ctx=_make_ctx(), fetch_all=True)

        assert [e["id"] for e in result["items"]] == ["a"]
        assert result["pagination_info"]["stop_reason"] == "Pagination cursor did not advance"

    @pytest.mark.asyncio
    @patch(f"{GOVERNANCE_MODULE}.get_okta_client")
    async def test_bare_array_body_treated_as_final_page(self, mock_get_client):
        mock_get_client.return_value = _client_paged([[ACTIVE_CONDITION]])

        result = await list_app_request_conditions(ctx=_make_ctx(), app_id=APP_ID)

        assert result["items"] == [ACTIVE_CONDITION]
        assert result["has_more"] is False


# ---------------------------------------------------------------------------
# Shared raw-request helper
# ---------------------------------------------------------------------------


class TestOktaRawRequest:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [401, 403])
    async def test_auth_statuses_become_scope_denied(self, status):
        cause = _okta_api_error(status)
        client = _client_paged([_error_result(cause)])

        response, body, err = await okta_raw_request(client, "GET", "/governance/api/v2/x", scopes=[CATALOG_SCOPE])

        assert response is None and body is None
        assert isinstance(err, ScopeDeniedError)
        assert err.status == status
        assert err.cause is cause
        assert {"error": str(err)} == build_scope_error([CATALOG_SCOPE])

    @pytest.mark.asyncio
    async def test_non_json_403_also_becomes_scope_denied(self):
        cause = HTTPError(
            "https://test.okta.com/x", _ResponseDetails(status=403, headers={}), "<html>Forbidden</html>"
        )
        client = _client_paged([_error_result(cause)])

        _, _, err = await okta_raw_request(client, "GET", "/x", scopes=[CATALOG_SCOPE])

        assert isinstance(err, ScopeDeniedError)

    @pytest.mark.asyncio
    async def test_other_errors_returned_unchanged(self):
        cause = _okta_api_error(429, "E0000047")
        client = _client_paged([_error_result(cause)])

        _, _, err = await okta_raw_request(client, "GET", "/x", scopes=[CATALOG_SCOPE])

        assert err is cause

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_applications_catalog_tool_gets_scope_error_on_403(self, mock_get_client):
        mock_get_client.return_value = _client_paged([_error_result(_okta_api_error(403))])

        result = await get_catalog_app(ctx=_make_ctx(), app_name="scim2testapp")

        assert result == build_scope_error(["okta.apps.read"])
