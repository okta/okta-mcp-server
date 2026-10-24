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


class _ExplodingCtx:
    """A ctx whose request_context access raises, escaping the tool body's
    own try/except so the exception reaches @json_response."""

    @property
    def request_context(self):
        raise RuntimeError("boom")


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


def _client_paged(pages):
    """Client whose executor returns one result per successive execute call.

    Each entry is a JSON body string, or a pre-built (response, body, err)
    tuple for error pages.
    """
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "X"}, None))
    executor.execute = AsyncMock(
        side_effect=[p if isinstance(p, tuple) else (MagicMock(), p, None) for p in pages]
    )
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestListCatalogApps:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_items_and_passes_query(self, mock_get_client):
        catalog = [{"name": "scim2testapp", "displayName": "SCIM 2.0 Test App", "features": ["IMPORT_NEW_USERS"]}]
        client = _client_returning(json.dumps(catalog))
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), q="scim")

        assert result["items"] == catalog
        assert result["total_fetched"] == 1
        # One item is a short page (server default 20), so the catalog is exhausted.
        assert result["has_more"] is False
        assert result["next_cursor"] is None
        assert result["fetch_all_used"] is False
        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert kwargs["method"] == "GET"
        assert "/api/v1/catalog/apps?q=scim" in kwargs["url"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_full_page_synthesizes_next_cursor_from_last_name(self, mock_get_client):
        # The catalog endpoint sends no Link header; a full page means "maybe
        # more" and the cursor is the last entry's name.
        catalog = [{"name": "app_a"}, {"name": "app_b"}]
        client = _client_returning(json.dumps(catalog))
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), limit=2)

        assert result["has_more"] is True
        assert result["next_cursor"] == "app_b"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_after_cursor_passed_through(self, mock_get_client):
        client = _client_returning(json.dumps([]))
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), after="app_b", limit=2)

        assert result["items"] == []
        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert "after=app_b" in url

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_follows_cursor_until_short_page(self, mock_get_client):
        pages = [
            [{"name": "app_a"}, {"name": "app_b"}],
            [{"name": "app_c"}, {"name": "app_d"}],
            [{"name": "app_e"}],
        ]
        client = _client_paged([json.dumps(p) for p in pages])
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), q="scim", limit=2, fetch_all=True)

        assert [a["name"] for a in result["items"]] == ["app_a", "app_b", "app_c", "app_d", "app_e"]
        assert result["total_fetched"] == 5
        assert result["fetch_all_used"] is True
        assert result["has_more"] is False
        assert result["pagination_info"]["pages_fetched"] == 3
        assert result["pagination_info"]["stopped_early"] is False
        urls = [
            c.kwargs["url"]
            for c in client.get_request_executor.return_value.create_request.call_args_list
        ]
        assert len(urls) == 3
        assert "after" not in urls[0]
        assert "after=app_b" in urls[1] and "q=scim" in urls[1]
        assert "after=app_d" in urls[2]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_error_mid_walk_surfaces_resume_cursor(self, mock_get_client):
        pages = [
            json.dumps([{"name": "app_a"}, {"name": "app_b"}]),
            (None, None, "429 too many requests"),
        ]
        mock_get_client.return_value = _client_paged(pages)

        result = await list_catalog_apps(ctx=_make_ctx(), limit=2, fetch_all=True)

        assert [a["name"] for a in result["items"]] == ["app_a", "app_b"]
        assert result["pagination_info"]["stopped_early"] is True
        assert "429" in result["pagination_info"]["stop_reason"]
        # Partial result must not claim completeness — surface the resume point.
        assert result["has_more"] is True
        assert result["next_cursor"] == "app_b"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_single_short_page_still_includes_pagination_info(self, mock_get_client):
        client = _client_returning(json.dumps([{"name": "only"}]))
        mock_get_client.return_value = client

        result = await list_catalog_apps(ctx=_make_ctx(), q="only", fetch_all=True)

        assert result["fetch_all_used"] is True
        assert result["pagination_info"]["pages_fetched"] == 1
        assert result["pagination_info"]["total_items"] == 1
        assert result["pagination_info"]["stopped_early"] is False
        assert result["has_more"] is False
        assert client.get_request_executor.return_value.execute.await_count == 1

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_duplicate_page_stops_without_duplicating_items(self, mock_get_client):
        same_page = json.dumps([{"name": "app_a"}, {"name": "app_b"}])
        mock_get_client.return_value = _client_paged([same_page, same_page])

        result = await list_catalog_apps(ctx=_make_ctx(), limit=2, fetch_all=True)

        assert [a["name"] for a in result["items"]] == ["app_a", "app_b"]
        assert result["pagination_info"]["stopped_early"] is True
        assert "did not advance" in result["pagination_info"]["stop_reason"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_keeps_paginating_when_server_caps_limit(self, mock_get_client):
        # Requested limit=50, but the server caps pages at its default of 20:
        # a 20-item page is NOT proof of exhaustion and the walk must continue.
        page1 = [{"name": f"app_{i:02d}"} for i in range(20)]
        page2 = [{"name": "app_20"}, {"name": "app_21"}, {"name": "app_22"}]
        mock_get_client.return_value = _client_paged([json.dumps(page1), json.dumps(page2)])

        result = await list_catalog_apps(ctx=_make_ctx(), limit=50, fetch_all=True)

        assert result["total_fetched"] == 23
        assert result["pagination_info"]["pages_fetched"] == 2
        assert result["has_more"] is False

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_fetch_all_phantom_cursor_empty_page_terminates_cleanly(self, mock_get_client):
        # A final page that is exactly full yields a phantom cursor; the empty
        # next page must end the walk without reporting an early stop.
        pages = [json.dumps([{"name": "app_a"}, {"name": "app_b"}]), json.dumps([])]
        mock_get_client.return_value = _client_paged(pages)

        result = await list_catalog_apps(ctx=_make_ctx(), limit=2, fetch_all=True)

        assert [a["name"] for a in result["items"]] == ["app_a", "app_b"]
        assert result["has_more"] is False
        assert result["next_cursor"] is None
        assert result["pagination_info"]["stopped_early"] is False
        assert result["pagination_info"]["pages_fetched"] == 1

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="403 forbidden")

        result = await list_catalog_apps(ctx=_make_ctx())

        assert result == {"error": "403 forbidden"}

    @pytest.mark.asyncio
    async def test_exception_outside_try_returns_failure_envelope(self):
        result = await list_catalog_apps(ctx=_ExplodingCtx())

        assert result["ok"] is False
        assert result["error"]["type"] == "RuntimeError"
        assert result["error"]["message"] == "boom"
        assert result["error"]["tool"] == "list_catalog_apps"


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

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_path_traversal_app_name_rejected_before_api_call(self, mock_get_client):
        result = await get_catalog_app(ctx=_make_ctx(), app_name="../admin")

        assert "error" in result
        assert "app_name" in result["error"]
        mock_get_client.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_empty_body_returns_none_body_error(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None)

        result = await get_catalog_app(ctx=_make_ctx(), app_name="scim2testapp")

        assert "error" in result
        assert "empty response" in result["error"]


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
        # Settings must be forwarded verbatim — without this the SDK prunes
        # legitimately-empty values from the body (clear_empty_params).
        assert kwargs["keep_empty_params"] is True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_settings_and_activate_false_forwarded(self, mock_get_client):
        client = _client_returning(json.dumps({"id": "0oaX"}))
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
    async def test_path_traversal_name_rejected_before_api_call(self, mock_get_client):
        result = await install_oin_app(
            ctx=_make_ctx(), name="../evil", label="X", sign_on_mode="SAML_2_0"
        )

        assert "error" in result
        assert "name" in result["error"]
        mock_get_client.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="400 invalid app name")

        result = await install_oin_app(
            ctx=_make_ctx(), name="bogus", label="X", sign_on_mode="SAML_2_0"
        )

        assert result == {"error": "400 invalid app name"}
