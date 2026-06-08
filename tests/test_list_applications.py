# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for list_applications — resilient per-item parsing of the apps page."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.applications import _safe_parse_app, list_applications


# A bookmark app parses cleanly into a typed model.
GOOD_BOOKMARK = {
    "id": "0oaBOOKMARK001",
    "label": "Bookmark App",
    "name": "bookmark",
    "signOnMode": "BOOKMARK",
    "settings": {"app": {"url": "https://example.com"}},
}

# A SAML app with a partial settings.signOn fails strict SDK validation
# (the model marks ~15 signOn fields required). This is the record that
# previously aborted the whole listing.
BAD_SPARSE_SAML = {
    "id": "0oaSAML0001",
    "label": "Sparse SAML",
    "name": "sparsesaml",
    "signOnMode": "SAML_2_0",
    "settings": {"signOn": {"defaultRelayState": ""}},
}


class _Resp:
    """Minimal stand-in for the executor response (only headers are read)."""

    def __init__(self, headers=None):
        self.headers = headers or {}


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _client_returning(body, response=None, execute_error=None):
    """Build a fake Okta client whose request executor returns the given page body."""
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(response or _Resp(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestSafeParseApp:
    def test_good_record_parses_to_model(self):
        result = _safe_parse_app(GOOD_BOOKMARK)
        assert isinstance(result, okta_models.BookmarkApplication)

    def test_bad_record_falls_back_to_raw_dict(self):
        result = _safe_parse_app(BAD_SPARSE_SAML)
        assert isinstance(result, dict)
        assert result["id"] == "0oaSAML0001"
        assert "_deserialization_warning" in result


class TestListApplicationsResilientParsing:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_one_bad_app_does_not_abort_the_listing(self, mock_get_client):
        body = json.dumps([GOOD_BOOKMARK, BAD_SPARSE_SAML])
        mock_get_client.return_value = _client_returning(body)

        result = await list_applications(ctx=_make_ctx())

        assert result["total_fetched"] == 2
        items = result["items"]

        bad = [i for i in items if isinstance(i, dict) and "_deserialization_warning" in i]
        assert len(bad) == 1
        assert bad[0]["id"] == "0oaSAML0001"

        good = [i for i in items if not isinstance(i, dict)]
        assert len(good) == 1
        assert isinstance(good[0], okta_models.BookmarkApplication)

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_executor_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="Error: 403 forbidden")

        result = await list_applications(ctx=_make_ctx())

        assert result == {"error": "Error: 403 forbidden"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_empty_page_returns_empty_envelope(self, mock_get_client):
        mock_get_client.return_value = _client_returning("[]")

        result = await list_applications(ctx=_make_ctx())

        assert result["total_fetched"] == 0
        assert result["items"] == []

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_snake_case_params_are_sent_as_camel_case(self, mock_get_client):
        client = _client_returning("[]")
        mock_get_client.return_value = client

        await list_applications(ctx=_make_ctx(), include_non_deleted=True)

        executor = client.get_request_executor.return_value
        url = executor.create_request.call_args.kwargs["url"]
        assert "includeNonDeleted=true" in url
        assert "include_non_deleted" not in url
