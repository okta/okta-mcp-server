# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for OIN catalog browse + install tools."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import (
    get_catalog_app,
    install_oin_app,
    list_catalog_apps,
)


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
    executor.create_request = AsyncMock(return_value=({"method": "X"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(MagicMock(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestListCatalogApps:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_catalog_apps_and_passes_query(self, mock_get_client):
        catalog = [{"name": "scim2testapp", "displayName": "SCIM 2.0 Test App", "features": ["IMPORT_NEW_USERS"]}]
        client = _client_returning(json.dumps(catalog))
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), q="scim")

        assert result == {"catalog_apps": catalog}
        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert kwargs["method"] == "GET"
        assert "/api/v1/catalog/apps?q=scim" in kwargs["url"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="403 forbidden")

        result = await list_catalog_apps(ctx=_make_ctx())

        assert result == {"error": "403 forbidden"}


class TestGetCatalogApp:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_app_definition_with_schema_expand(self, mock_get_client):
        client = _client_returning(json.dumps({"name": "scim2testapp", "status": "ACTIVE"}))
        mock_get_client.return_value = client

        result = await get_catalog_app(ctx=_make_ctx(), app_name="scim2testapp")

        assert result["name"] == "scim2testapp"
        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert url.endswith("/api/v1/catalog/apps/scim2testapp?expand=schema")


class TestInstallOinApp:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_posts_body_with_name_preserved(self, mock_get_client):
        created = {"id": "0oaNEW0000001", "name": "scim2testapp", "label": "HR Directory Sync", "status": "ACTIVE"}
        client = _client_returning(json.dumps(created))
        mock_get_client.return_value = client

        result = await install_oin_app(
            ctx=_make_ctx(), name="scim2testapp", label="HR Directory Sync", sign_on_mode="SAML_2_0"
        )

        assert result == created
        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert kwargs["method"] == "POST"
        assert kwargs["url"].startswith("/api/v1/apps?")
        assert "activate=true" in kwargs["url"]
        # The catalog `name` MUST be in the body — the whole point (the typed SDK path drops it).
        assert kwargs["body"] == {"name": "scim2testapp", "label": "HR Directory Sync", "signOnMode": "SAML_2_0"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_settings_and_activate_false_forwarded(self, mock_get_client):
        client = _client_returning(json.dumps({}))
        mock_get_client.return_value = client

        await install_oin_app(
            ctx=_make_ctx(), name="scim2testapp", label="X", sign_on_mode="SAML_2_0",
            settings={"app": {"acsUrl": "https://x"}}, activate=False,
        )

        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert "activate=false" in kwargs["url"]
        assert kwargs["body"]["settings"] == {"app": {"acsUrl": "https://x"}}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="400 invalid app name")

        result = await install_oin_app(
            ctx=_make_ctx(), name="bogus", label="X", sign_on_mode="SAML_2_0"
        )

        assert result == {"error": "400 invalid app name"}
