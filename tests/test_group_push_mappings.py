# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the Group Push Mapping tools.

Covers ``list_group_push_mappings`` (direct per-app listing, SDK happy path plus
the raw-fetch fallback) and ``find_apps_pushing_group`` (the source-group → apps
finder used to answer "is this group pushed to any app?").
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from okta_mcp_server.tools.group_push.group_push import (
    find_apps_pushing_group,
    list_group_push_mappings,
)

APP_ID = "0oa11app22bb33cc44d"
GROUP_ID = "00g11w9tu8yc5jSI81e8"
OTHER_GROUP_ID = "00g99zzzzzzzzzzzz999"


def _make_validation_error() -> ValidationError:
    class _M(BaseModel):
        x: int

    try:
        _M(x="nope")
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a ValidationError")


def _make_response(after_cursor: str | None = None):
    response = MagicMock()
    del response.has_next
    del response.next
    if after_cursor:
        response.headers = {
            "Link": f'<https://test.okta.com/x?after={after_cursor}&limit=200>; rel="next"'
        }
    else:
        response.headers = {}
    return response


def _make_aiohttp_response(after_cursor: str | None = None, status: int = 200):
    """Build a response whose headers behave like aiohttp's CIMultiDictProxy.

    Okta returns the self and next links as two SEPARATE Link headers, which is
    the real-world shape that regressed cursor extraction. ``status`` lets a test
    simulate a stale app instance returning 404.
    """
    from multidict import CIMultiDict, CIMultiDictProxy

    headers = CIMultiDict()
    headers.add("Link", '<https://test.okta.com/api/v1/apps?limit=200>; rel="self"')
    if after_cursor:
        headers.add(
            "Link",
            f'<https://test.okta.com/api/v1/apps?after={after_cursor}&limit=200>; rel="next"',
        )
    response = MagicMock()
    del response.has_next
    del response.next
    response.headers = CIMultiDictProxy(headers)
    response.status = status
    return response


def _client_with_executor(*, sdk_side_effect=None, sdk_return=None, execute_pages=None):
    client = AsyncMock()
    if sdk_side_effect is not None:
        client.list_group_push_mappings = AsyncMock(side_effect=sdk_side_effect)
    elif sdk_return is not None:
        client.list_group_push_mappings = AsyncMock(return_value=sdk_return)

    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET", "url": "u"}, None))
    if execute_pages is not None:
        executor.execute = AsyncMock(side_effect=execute_pages)
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    return client


# ---------------------------------------------------------------------------
# list_group_push_mappings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_list_mappings_happy_path(mock_get_client, ctx_no_elicitation):
    mapping = MagicMock(id="gpm1", source_group_id=GROUP_ID)
    client = _client_with_executor(sdk_return=([mapping], _make_response(), None))
    mock_get_client.return_value = client

    result = await list_group_push_mappings(APP_ID, ctx=ctx_no_elicitation)

    assert "raw_fallback" not in result
    assert result["total_fetched"] == 1
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_list_mappings_validation_error_falls_back_to_raw(mock_get_client, ctx_no_elicitation):
    raw_mappings = [
        {"id": "gpm1", "sourceGroupId": GROUP_ID, "targetGroupId": "tg1", "status": "ACTIVE"},
    ]
    client = _client_with_executor(
        sdk_side_effect=_make_validation_error(),
        execute_pages=[(_make_response(), json.dumps(raw_mappings), None)],
    )
    mock_get_client.return_value = client

    result = await list_group_push_mappings(APP_ID, ctx=ctx_no_elicitation)

    assert result.get("raw_fallback") is True
    assert result["total_fetched"] == 1
    assert result["items"][0]["sourceGroupId"] == GROUP_ID
    client._executor.create_request.assert_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_list_mappings_non_deserialization_error_surfaces(mock_get_client, ctx_no_elicitation):
    client = _client_with_executor(sdk_side_effect=ConnectionError("boom"))
    mock_get_client.return_value = client

    result = await list_group_push_mappings(APP_ID, ctx=ctx_no_elicitation)

    assert "error" in result
    assert "boom" in result["error"]
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
async def test_list_mappings_invalid_status_rejected(ctx_no_elicitation):
    result = await list_group_push_mappings(APP_ID, ctx=ctx_no_elicitation, status="BOGUS")
    assert "error" in result
    assert "Invalid status" in result["error"]


@pytest.mark.asyncio
async def test_list_mappings_invalid_app_id_rejected(ctx_no_elicitation):
    result = await list_group_push_mappings("../evil", ctx=ctx_no_elicitation)
    assert "error" in result


# ---------------------------------------------------------------------------
# find_apps_pushing_group
# ---------------------------------------------------------------------------

def _find_client(apps_pages, mappings_by_app):
    """Build a client whose raw executor serves an app list then per-app mappings.

    apps_pages: list of (response, json_body, err) tuples for GET /api/v1/apps.
    mappings_by_app: dict app_id -> (response, json_body, err) for the mappings GET.
    """
    client = AsyncMock()
    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()

    # create_request records the URL so execute() can route to the right payload.
    state = {"url": None}

    async def _create_request(method, url, body, headers):
        state["url"] = url
        return ({"method": method, "url": url}, None)

    async def _execute(request):
        url = state["url"]
        if "/group-push/mappings" in url:
            # Extract appId from .../apps/{appId}/group-push/mappings
            app_id = url.split("/apps/")[1].split("/group-push")[0]
            return mappings_by_app.get(app_id, (_make_response(), json.dumps([]), None))
        # Otherwise it's the apps listing; pop pages in order.
        return apps_pages.pop(0)

    executor.create_request = AsyncMock(side_effect=_create_request)
    executor.execute = AsyncMock(side_effect=_execute)
    client.get_request_executor = MagicMock(return_value=executor)
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_match(mock_get_client, ctx_no_elicitation):
    apps = [
        {"id": "0oaPUSH1", "label": "SCIM App", "features": ["GROUP_PUSH", "PUSH_NEW_USERS"]},
        {"id": "0oaSSO1", "label": "SSO Only", "features": ["SSO"]},
    ]
    mappings_by_app = {
        "0oaPUSH1": (
            _make_response(),
            json.dumps([
                {"id": "gpm1", "sourceGroupId": GROUP_ID, "targetGroupId": "t1", "status": "ACTIVE"}
            ]),
            None,
        ),
    }
    client = _find_client([(_make_response(), json.dumps(apps), None)], mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["is_pushed_to_any_app"] is True
    assert result["apps_scanned"] == 2
    assert result["push_enabled_apps_checked"] == 1
    assert len(result["matches"]) == 1
    assert result["matches"][0]["app_id"] == "0oaPUSH1"
    assert result["matches"][0]["mappings"][0]["sourceGroupId"] == GROUP_ID


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_no_match(mock_get_client, ctx_no_elicitation):
    apps = [{"id": "0oaPUSH1", "label": "SCIM App", "features": ["GROUP_PUSH"]}]
    # The push app only has a mapping for a DIFFERENT source group.
    mappings_by_app = {
        "0oaPUSH1": (
            _make_response(),
            json.dumps([
                {"id": "gpm9", "sourceGroupId": OTHER_GROUP_ID, "targetGroupId": "t9", "status": "ACTIVE"}
            ]),
            None,
        ),
    }
    client = _find_client([(_make_response(), json.dumps(apps), None)], mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["is_pushed_to_any_app"] is False
    assert result["matches"] == []
    assert result["push_enabled_apps_checked"] == 1


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_skips_non_push_apps(mock_get_client, ctx_no_elicitation):
    apps = [
        {"id": "0oaSSO1", "label": "SSO Only", "features": ["SSO"]},
        {"id": "0oaNONE", "label": "No features"},
    ]
    client = _find_client([(_make_response(), json.dumps(apps), None)], {})
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["is_pushed_to_any_app"] is False
    assert result["apps_scanned"] == 2
    assert result["push_enabled_apps_checked"] == 0


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_paginates_all_app_pages(mock_get_client, ctx_no_elicitation):
    """Regression: the app list must be fully paginated across real (multi-header) Link pages.

    Page 1 of /api/v1/apps carries the next cursor in a SEPARATE ``Link`` header
    (aiohttp/CIMultiDictProxy shape). The only GROUP_PUSH app lives on page 2, so
    it is found ONLY if cursor extraction follows ``rel="next"`` correctly. Before
    the fix the scan stopped at page 1 (apps_scanned stuck at one page).
    """
    page1_apps = [{"id": "0oaSSO1", "label": "SSO Only", "features": ["SSO"]}]
    page2_apps = [{"id": "0oaPUSH1", "label": "SCIM App", "features": ["GROUP_PUSH"]}]
    apps_pages = [
        (_make_aiohttp_response(after_cursor="PAGE2"), json.dumps(page1_apps), None),
        (_make_aiohttp_response(), json.dumps(page2_apps), None),
    ]
    mappings_by_app = {
        "0oaPUSH1": (
            _make_response(),
            json.dumps([
                {"id": "gpm1", "sourceGroupId": GROUP_ID, "targetGroupId": "t1", "status": "ACTIVE"}
            ]),
            None,
        ),
    }
    client = _find_client(apps_pages, mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["apps_scanned"] == 2
    assert result["scan_complete"] is True
    assert result["is_pushed_to_any_app"] is True
    assert result["matches"][0]["app_id"] == "0oaPUSH1"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_404_app_is_skipped_not_incomplete(
    mock_get_client, ctx_no_elicitation
):
    """A push app whose mappings endpoint 404s (stale instance) is reported as
    skipped, and must NOT flip ``scan_complete`` to False."""
    apps = [{"id": "0oaSTALE", "label": "Stale App", "features": ["GROUP_PUSH"]}]
    err = Exception("Okta HTTP 404 Not Found: resource not found")
    mappings_by_app = {
        "0oaSTALE": (_make_aiohttp_response(status=404), None, err),
    }
    client = _find_client([(_make_response(), json.dumps(apps), None)], mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["is_pushed_to_any_app"] is False
    assert result["scan_complete"] is True
    assert "skipped_apps" in result
    assert result["skipped_apps"][0]["app_id"] == "0oaSTALE"
    assert result["skipped_apps"][0]["reason"] == "not found (404)"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_non_404_error_marks_incomplete(
    mock_get_client, ctx_no_elicitation
):
    """A non-404 read error (e.g. 500) is a real coverage gap → scan_complete False."""
    apps = [{"id": "0oaPUSH1", "label": "SCIM App", "features": ["GROUP_PUSH"]}]
    err = Exception("Okta HTTP 500 Internal Server Error")
    bad_resp = _make_aiohttp_response(status=500)
    mappings_by_app = {
        "0oaPUSH1": (bad_resp, None, err),
    }
    client = _find_client([(_make_response(), json.dumps(apps), None)], mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert result["scan_complete"] is False
    assert "skipped_apps" not in result
    assert any("0oaPUSH1" in n for n in result.get("notes", []))


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.group_push.group_push.get_okta_client")
async def test_find_apps_pushing_group_handles_null_labels_and_descriptions(
    mock_get_client, ctx_no_elicitation
):
    apps = [
        {
            "id": "0oaNULLTEXT",
            "label": None,
            "name": None,
            "description": None,
            "features": ["GROUP_PUSH"],
        }
    ]
    mappings_by_app = {
        "0oaNULLTEXT": (
            _make_response(),
            json.dumps(
                [
                    {
                        "id": "gpm-null-text",
                        "sourceGroupId": GROUP_ID,
                        "sourceGroupName": None,
                        "targetGroupId": "target-group",
                        "targetGroupName": None,
                        "description": None,
                        "status": "ACTIVE",
                    }
                ]
            ),
            None,
        ),
    }
    client = _find_client([(_make_response(), json.dumps(apps), None)], mappings_by_app)
    mock_get_client.return_value = client

    result = await find_apps_pushing_group(GROUP_ID, ctx=ctx_no_elicitation)

    assert "error" not in result
    assert result["is_pushed_to_any_app"] is True
    assert result["matches"][0]["app_label"] == "0oaNULLTEXT"
    assert result["matches"][0]["mappings"][0]["sourceGroupName"] is None
    assert result["matches"][0]["mappings"][0]["description"] is None


@pytest.mark.asyncio
async def test_find_apps_pushing_group_invalid_group_id(ctx_no_elicitation):
    result = await find_apps_pushing_group("bad/id", ctx=ctx_no_elicitation)
    assert "error" in result
