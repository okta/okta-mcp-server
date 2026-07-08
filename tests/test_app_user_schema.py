# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for app user-profile schema tools (Profile Editor parity)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import (
    add_app_user_schema_attribute,
    get_app_user_schema,
)


APP_ID = "0oaSCHEMAAPP0001"


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


class TestGetAppUserSchema:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_schema_dict(self, mock_get_client):
        schema = MagicMock()
        schema.to_dict.return_value = {"definitions": {"custom": {"properties": {}}}}
        client = AsyncMock()
        client.get_application_user_schema.return_value = (schema, None, None)
        mock_get_client.return_value = client

        result = await get_app_user_schema(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"definitions": {"custom": {"properties": {}}}}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client = AsyncMock()
        client.get_application_user_schema.return_value = (None, None, "404 not found")
        mock_get_client.return_value = client

        result = await get_app_user_schema(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "404 not found"}


def _client_posting(body, execute_error=None):
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "POST"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(MagicMock(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestAddAppUserSchemaAttribute:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_posts_custom_property_to_schema_endpoint(self, mock_get_client):
        returned = {"definitions": {"custom": {"properties": {"employeeNumber": {"title": "Employee Number"}}}}}
        client = _client_posting(json.dumps(returned))
        mock_get_client.return_value = client

        result = await add_app_user_schema_attribute(
            ctx=_make_ctx(),
            app_id=APP_ID,
            variable_name="employeeNumber",
            title="Employee Number",
        )

        assert result == returned

        create_kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert create_kwargs["method"] == "POST"
        assert create_kwargs["url"].endswith(f"/api/v1/meta/schemas/apps/{APP_ID}/default")
        prop = create_kwargs["body"]["definitions"]["custom"]["properties"]["employeeNumber"]
        assert prop == {"title": "Employee Number", "type": "string"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_merges_attribute_definition_and_type_description(self, mock_get_client):
        client = _client_posting(json.dumps({}))
        mock_get_client.return_value = client

        await add_app_user_schema_attribute(
            ctx=_make_ctx(),
            app_id=APP_ID,
            variable_name="startDate",
            title="Start Date",
            attribute_type="string",
            description="Employment start date",
            attribute_definition={"permissions": [{"principal": "SELF", "action": "READ_WRITE"}]},
        )

        body = client.get_request_executor.return_value.create_request.call_args.kwargs["body"]
        prop = body["definitions"]["custom"]["properties"]["startDate"]
        assert prop["title"] == "Start Date"
        assert prop["type"] == "string"
        assert prop["description"] == "Employment start date"
        assert prop["permissions"] == [{"principal": "SELF", "action": "READ_WRITE"}]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client = _client_posting(None, execute_error="403 forbidden")
        mock_get_client.return_value = client

        result = await add_app_user_schema_attribute(
            ctx=_make_ctx(), app_id=APP_ID, variable_name="x", title="X"
        )

        assert result == {"error": "403 forbidden"}
