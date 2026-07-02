# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for get_application — resilient parsing of a single app record (#48)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.applications import get_application


# A bookmark app parses cleanly into a typed model.
GOOD_BOOKMARK = {
    "id": "0oaBOOKMARK001",
    "label": "Bookmark App",
    "name": "bookmark",
    "signOnMode": "BOOKMARK",
    "settings": {"app": {"url": "https://example.com"}},
}

# An App Catalog SAML app with a partial settings.signOn fails strict SDK
# validation (the model marks ~15 signOn fields required) — the record that
# previously made get_application fail outright (#48).
BAD_SPARSE_SAML = {
    "id": "0oaSAML0001",
    "label": "Sparse SAML",
    "name": "sparsesaml",
    "signOnMode": "SAML_2_0",
    "settings": {"signOn": {"defaultRelayState": ""}},
}


def _make_ctx():
    manager = MagicMock()
    ctx = MagicMock()
    ctx.request_context.lifespan_context.okta_auth_manager = manager
    return ctx


def _client_returning(body, execute_error=None):
    """Build a fake Okta client whose request executor returns the given record."""
    executor = MagicMock()
    executor.create_request = AsyncMock(return_value=({"method": "GET"}, None))
    if execute_error is not None:
        executor.execute = AsyncMock(return_value=(None, None, execute_error))
    else:
        executor.execute = AsyncMock(return_value=(MagicMock(), body, None))
    client = MagicMock()
    client.get_request_executor = MagicMock(return_value=executor)
    return client


class TestGetApplicationResilientParsing:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_good_app_returns_typed_model(self, mock_get_client):
        mock_get_client.return_value = _client_returning(json.dumps(GOOD_BOOKMARK))

        result = await get_application(_make_ctx(), "0oaBOOKMARK001")

        assert isinstance(result, okta_models.BookmarkApplication)

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_non_conforming_app_falls_back_to_raw_dict(self, mock_get_client):
        mock_get_client.return_value = _client_returning(json.dumps(BAD_SPARSE_SAML))

        result = await get_application(_make_ctx(), "0oaSAML0001")

        assert isinstance(result, dict)
        assert result["id"] == "0oaSAML0001"
        assert "_deserialization_warning" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_executor_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="Error: 404 not found")

        result = await get_application(_make_ctx(), "0oaMISSING")

        assert result == {"error": "Error: 404 not found"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_expand_is_sent_as_query_param(self, mock_get_client):
        client = _client_returning(json.dumps(GOOD_BOOKMARK))
        mock_get_client.return_value = client

        await get_application(_make_ctx(), "0oaBOOKMARK001", expand="user/abc")

        url = client.get_request_executor.return_value.create_request.call_args.kwargs["url"]
        assert "/api/v1/apps/0oaBOOKMARK001" in url
        assert "expand=user" in url
