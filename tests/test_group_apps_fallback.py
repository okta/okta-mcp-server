# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the raw-API fallback in ``list_group_apps``.

The bundled Okta SDK parses the group-apps response into strict Pydantic
``Application`` models. A single app whose schema has drifted from the bundled
OpenAPI spec raises a ``ValidationError`` that aborts the entire call, so the
caller gets nothing. ``list_group_apps`` must detect that failure and fall back
to a raw fetch that returns plain dicts, preserving a complete list.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from okta_mcp_server.tools.groups.groups import _is_deserialization_error, list_group_apps

GROUP_ID = "00g11w9tu8yc5jSI81e8"


def _make_validation_error() -> ValidationError:
    """Produce a genuine Pydantic ``ValidationError`` instance."""

    class _M(BaseModel):
        x: int

    try:
        _M(x="not-an-int")
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a ValidationError")


def _make_raw_response(after_cursor: str | None = None):
    """Return a minimal response object exposing only a ``headers`` mapping."""
    response = MagicMock()
    # The raw fallback relies on the Link header, never has_next()/next().
    del response.has_next
    del response.next
    if after_cursor:
        response.headers = {
            "Link": (
                f'<https://test.okta.com/api/v1/groups/{GROUP_ID}/apps'
                f'?after={after_cursor}&limit=200>; rel="next"'
            )
        }
    else:
        response.headers = {}
    return response


def _build_client(*, sdk_side_effect=None, sdk_return=None, raw_pages=None):
    """Construct a mock Okta client with SDK + raw-executor behaviour."""
    client = AsyncMock()

    if sdk_side_effect is not None:
        client.list_assigned_applications_for_group = AsyncMock(side_effect=sdk_side_effect)
    else:
        client.list_assigned_applications_for_group = AsyncMock(return_value=sdk_return)

    client.get_base_url = MagicMock(return_value="https://test.okta.com")

    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET", "url": "https://test.okta.com"}, None))
    if raw_pages is not None:
        executor.execute = AsyncMock(side_effect=raw_pages)
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    return client


def test_is_deserialization_error_detects_validation_error():
    assert _is_deserialization_error(_make_validation_error()) is True
    assert _is_deserialization_error(Exception("ValidationError: bad")) is True
    assert _is_deserialization_error(ConnectionError("network down")) is False


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_validation_error_triggers_raw_fallback(mock_get_client, ctx_no_elicitation):
    apps = [
        {"id": "0oa1", "label": "App One", "signOnMode": "SAML_2_0", "features": ["GROUP_PUSH"]},
        {"id": "0oa2", "label": "App Two", "signOnMode": "OPENID_CONNECT", "features": []},
    ]
    response = _make_raw_response()
    client = _build_client(
        sdk_side_effect=_make_validation_error(),
        raw_pages=[(response, json.dumps(apps), None)],
    )
    mock_get_client.return_value = client

    result = await list_group_apps(GROUP_ID, ctx=ctx_no_elicitation)

    assert result.get("raw_fallback") is True
    assert result["total_fetched"] == 2
    assert {a["id"] for a in result["items"]} == {"0oa1", "0oa2"}
    # The problematic group-push app is included instead of aborting the call.
    assert result["items"][0]["features"] == ["GROUP_PUSH"]
    client._executor.create_request.assert_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_happy_path_does_not_use_raw_fallback(mock_get_client, ctx_no_elicitation):
    sdk_response = _make_raw_response()
    sdk_apps = [MagicMock(id="0oa1")]
    client = _build_client(sdk_return=(sdk_apps, sdk_response, None))
    mock_get_client.return_value = client

    result = await list_group_apps(GROUP_ID, ctx=ctx_no_elicitation)

    assert "raw_fallback" not in result
    assert result["total_fetched"] == 1
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_non_deserialization_exception_returns_error(mock_get_client, ctx_no_elicitation):
    client = _build_client(sdk_side_effect=ConnectionError("network down"))
    mock_get_client.return_value = client

    result = await list_group_apps(GROUP_ID, ctx=ctx_no_elicitation)

    assert "error" in result
    assert "network down" in result["error"]
    # A genuine transport error must NOT silently trigger the raw fallback.
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.groups.groups.get_okta_client")
async def test_raw_fallback_paginates_with_fetch_all(mock_get_client, ctx_no_elicitation):
    page1 = [{"id": "0oa1", "label": "A", "features": ["GROUP_PUSH"]}]
    page2 = [{"id": "0oa2", "label": "B", "features": []}]
    raw_pages = [
        (_make_raw_response(after_cursor="CURSOR1"), json.dumps(page1), None),
        (_make_raw_response(), json.dumps(page2), None),
    ]
    client = _build_client(sdk_side_effect=_make_validation_error(), raw_pages=raw_pages)
    mock_get_client.return_value = client

    result = await list_group_apps(GROUP_ID, ctx=ctx_no_elicitation, fetch_all=True)

    assert result.get("raw_fallback") is True
    assert result["total_fetched"] == 2
    assert {a["id"] for a in result["items"]} == {"0oa1", "0oa2"}
    assert result["fetch_all_used"] is True
