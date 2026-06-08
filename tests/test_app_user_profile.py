# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for app-user profile tools (per-assignment attribute values)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.applications.applications import get_app_user, update_app_user_profile


APP_ID = "0oaHRAPP00000001"
USER_ID = "00uJANE000000001"


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


class TestGetAppUser:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_app_user_json(self, mock_get_client):
        app_user = {"id": USER_ID, "scope": "USER", "status": "ACTIVE",
                    "profile": {"employeeNumber": "E-12345"}}
        client = _client_returning(json.dumps(app_user))
        mock_get_client.return_value = client

        result = await get_app_user(ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID)

        assert result["id"] == USER_ID
        assert result["profile"]["employeeNumber"] == "E-12345"
        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert kwargs["method"] == "GET"
        assert kwargs["url"].endswith(f"/api/v1/apps/{APP_ID}/users/{USER_ID}")

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="404 not found")

        result = await get_app_user(ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID)

        assert result == {"error": "404 not found"}


class TestUpdateAppUserProfile:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_posts_profile_to_app_user_endpoint(self, mock_get_client):
        returned = {"id": USER_ID, "profile": {"employeeNumber": "E-12345"}}
        client = _client_returning(json.dumps(returned))
        mock_get_client.return_value = client

        profile = {"employeeNumber": "E-12345", "employmentStartDate": "2026-01-01"}
        result = await update_app_user_profile(
            ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID, profile=profile
        )

        assert result == returned
        kwargs = client.get_request_executor.return_value.create_request.call_args.kwargs
        assert kwargs["method"] == "POST"
        assert kwargs["url"].endswith(f"/api/v1/apps/{APP_ID}/users/{USER_ID}")
        assert kwargs["body"] == {"profile": profile}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        mock_get_client.return_value = _client_returning(None, execute_error="400 bad profile")

        result = await update_app_user_profile(
            ctx=_make_ctx(), app_id=APP_ID, user_id=USER_ID, profile={"x": 1}
        )

        assert result == {"error": "400 bad profile"}

    @pytest.mark.asyncio
    async def test_invalid_id_rejected_before_api_call(self):
        result = await update_app_user_profile(
            ctx=_make_ctx(), app_id=APP_ID, user_id="../../etc", profile={"x": 1}
        )

        assert isinstance(result, dict)
        assert "error" in result
