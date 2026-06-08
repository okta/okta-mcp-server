# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for get_application — raw read-back keeps SAML attribute statements legible."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import get_application


APP_ID = "0oaSAMLAPP000001"

APP_JSON = {
    "id": APP_ID,
    "label": "HR SAML App",
    "status": "ACTIVE",
    "signOnMode": "SAML_2_0",
    "settings": {
        "signOn": {
            "ssoAcsUrl": "https://sp.example.com/acs",
            "attributeStatements": [
                {
                    "type": "EXPRESSION",
                    "name": "email",
                    "namespace": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                    "values": ["user.email"],
                }
            ],
        }
    },
    "_links": {"metadata": {"href": "https://test.okta.com/api/v1/apps/0oaSAMLAPP000001/sso/saml/metadata"}},
}


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _client_returning(body, execute_error=None):
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(MagicMock(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestGetApplication:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_raw_json_with_legible_attribute_statements(self, mock_get_client):
        mock_get_client.return_value = _client_returning(json.dumps(APP_JSON))

        result = await get_application(ctx=_make_ctx(), app_id=APP_ID)

        assert result["id"] == APP_ID
        stmts = result["settings"]["signOn"]["attributeStatements"]
        assert stmts[0]["name"] == "email"
        assert stmts[0]["type"] == "EXPRESSION"
        assert stmts[0]["values"] == ["user.email"]
        # The opaque anyOf-wrapper internals must not leak through.
        assert "actual_instance" not in stmts[0]
        assert "any_of_schemas" not in stmts[0]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_expand_is_sent_as_query_param(self, mock_get_client):
        client = _client_returning(json.dumps(APP_JSON))
        mock_get_client.return_value = client

        await get_application(ctx=_make_ctx(), app_id=APP_ID, expand="user")

        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert url.endswith(f"/api/v1/apps/{APP_ID}?expand=user")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="Error: 404 not found")

        result = await get_application(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "Error: 404 not found"}

    @pytest.mark.asyncio
    async def test_invalid_id_rejected_before_api_call(self):
        result = await get_application(ctx=_make_ctx(), app_id="../../etc")

        assert isinstance(result, dict)
        assert "error" in result
