# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for create_application — error handling when the SDK returns no app."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.applications.applications import create_application


SAML_CONFIG = {
    "signOnMode": "SAML_2_0",
    "label": "Test SAML App",
    "name": "testorg_testsamlapp_1",
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


class TestCreateApplicationEmptyResponse:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_empty_response_returns_explicit_error(self, mock_get_client):
        """SDK returning no app and no error must surface a clear error, not an empty result."""
        client = AsyncMock()
        client.create_application.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_application(ctx=_make_ctx(), app_config=SAML_CONFIG)

        assert isinstance(result, dict)
        assert "error" in result
        assert "empty response" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_passed_through(self, mock_get_client):
        client = AsyncMock()
        client.create_application.return_value = (None, None, "Error: invalid config")
        mock_get_client.return_value = client

        result = await create_application(ctx=_make_ctx(), app_config=SAML_CONFIG)

        assert result == {"error": "Error: invalid config"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_success_returns_app_and_sends_typed_model(self, mock_get_client):
        app = MagicMock()
        app.id = "0oaTESTAPP0000001"
        client = AsyncMock()
        client.create_application.return_value = (app, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_application(ctx=_make_ctx(), app_config=SAML_CONFIG, activate=True)

        assert result is app
        call_args = client.create_application.call_args[0]
        assert isinstance(call_args[0], okta_models.SamlApplication)
        assert call_args[1] is True
