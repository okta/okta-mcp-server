# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the raw-API fallback in ``list_applications``."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

from okta_mcp_server.tools.applications.applications import get_application, list_applications


class _SdkApp(BaseModel):
    id: str


def _make_validation_error() -> ValidationError:
    """Produce a genuine Pydantic ``ValidationError`` instance."""
    class _Model(BaseModel):
        required_field: str

    try:
        _Model.model_validate({"required_field": None})
    except ValidationError as exc:
        return exc
    raise AssertionError("expected a ValidationError")


def _make_raw_response(after_cursor: str | None = None):
    response = MagicMock()
    del response.has_next
    del response.next
    if after_cursor:
        response.headers = {
            "Link": (f'<https://test.okta.com/api/v1/apps?after={after_cursor}&limit=100>; rel="next"')
        }
    else:
        response.headers = {}
    return response


def _build_client(*, sdk_side_effect=None, sdk_return=None, raw_pages=None):
    client = AsyncMock()
    if sdk_side_effect is not None:
        client.list_applications = AsyncMock(side_effect=sdk_side_effect)
    else:
        client.list_applications = AsyncMock(return_value=sdk_return)

    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET", "url": "https://test.okta.com"}, None))
    if raw_pages is not None:
        executor.execute = AsyncMock(side_effect=raw_pages)
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_validation_error_triggers_raw_fallback_with_search_query(mock_get_client, ctx_no_elicitation):
    apps = [
        {
            "id": "0oa1",
            "label": "Example",
            "signOnMode": "SAML_2_0",
            "settings": {"app": {"nullableField": None}},
        }
    ]
    response = _make_raw_response()
    client = _build_client(
        sdk_side_effect=_make_validation_error(),
        raw_pages=[(response, json.dumps(apps), None)],
    )
    mock_get_client.return_value = client

    result = await list_applications(ctx_no_elicitation, q="Example")

    assert result.get("raw_fallback") is True
    assert result["total_fetched"] == 1
    assert result["items"] == apps
    request_url = client._executor.create_request.await_args.args[1]
    assert request_url == "https://test.okta.com/api/v1/apps?q=Example"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_validation_error_on_later_page_uses_raw_fallback(mock_get_client, ctx_no_elicitation):
    sdk_app = _SdkApp(id="0oa1")
    first_response = _make_raw_response(after_cursor="CURSOR1")
    raw_apps = [{"id": "0oa2", "label": "Example SAML", "signOnMode": "SAML_2_0"}]
    raw_response = _make_raw_response()
    client = _build_client(
        sdk_side_effect=[
            ([sdk_app], first_response, None),
            _make_validation_error(),
        ],
        raw_pages=[(raw_response, json.dumps(raw_apps), None)],
    )
    mock_get_client.return_value = client

    result = await list_applications(ctx_no_elicitation, q="Example", fetch_all=True)

    assert result.get("raw_fallback") is True
    assert result["total_fetched"] == 2
    assert result["items"] == [{"id": "0oa1"}, *raw_apps]
    request_url = client._executor.create_request.await_args.args[1]
    assert request_url == "https://test.okta.com/api/v1/apps?q=Example&after=CURSOR1"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_happy_path_does_not_use_raw_fallback(mock_get_client, ctx_no_elicitation):
    response = _make_raw_response()
    sdk_apps = [_SdkApp(id="0oa1")]
    client = _build_client(sdk_return=(sdk_apps, response, None))
    mock_get_client.return_value = client

    result = await list_applications(ctx_no_elicitation, q="Example")

    assert "raw_fallback" not in result
    assert result["items"] == [{"id": "0oa1"}]
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_non_deserialization_exception_does_not_use_raw_fallback(mock_get_client, ctx_no_elicitation):
    client = _build_client(sdk_side_effect=ConnectionError("network down"))
    mock_get_client.return_value = client

    result = await list_applications(ctx_no_elicitation, q="Example")

    assert "network down" in result["error"]
    client._executor.create_request.assert_not_awaited()


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.applications.applications.get_okta_client")
async def test_get_application_validation_error_uses_raw_single_resource_fallback(
    mock_get_client, ctx_no_elicitation
):
    raw_app = {
        "id": "0oa-salesforce",
        "name": "salesforce",
        "label": "Salesforce.com",
        "signOnMode": "SAML_2_0",
        "settings": {
            "app": {
                "integrationType": "STANDARD",
                "instanceType": "PRODUCTION",
            },
            "signOn": {"defaultRelayState": None, "attributeStatements": []},
        },
    }
    response = _make_raw_response()
    client = AsyncMock()
    client.get_application = AsyncMock(side_effect=_make_validation_error())
    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()
    executor.create_request = AsyncMock(
        return_value=(
            {
                "method": "GET",
                "url": "https://test.okta.com/api/v1/apps/0oa-salesforce",
            },
            None,
        )
    )
    executor.execute = AsyncMock(
        return_value=(response, json.dumps(raw_app), None)
    )
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    mock_get_client.return_value = client

    result = await get_application(ctx_no_elicitation, "0oa-salesforce")

    assert result["id"] == "0oa-salesforce"
    assert result["name"] == "salesforce"
    assert result["raw_fallback"] is True
    assert "schema drift" in result["notice"]
    request_url = executor.create_request.await_args.args[1]
    assert request_url == "https://test.okta.com/api/v1/apps/0oa-salesforce"