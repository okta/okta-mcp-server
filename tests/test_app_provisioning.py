# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for application provisioning (outbound SCIM / directory sync) tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import (
    ApplicationFeatureType,
    UpdateDefaultProvisioningConnectionForApplicationRequest,
    UpdateFeatureForApplicationRequest,
)

from okta_mcp_server.tools.applications.applications import (
    activate_app_provisioning_connection,
    deactivate_app_provisioning_connection,
    get_app_provisioning_connection,
    list_app_features,
    set_app_provisioning_connection,
    update_app_feature,
)


APP_ID = "0oaSCIMAPP000001"
BASE_URL = "https://scim.vendor.com/scim/v2"
TOKEN = "scim-bearer-secret"


def _make_ctx():
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _model(d):
    obj = MagicMock()
    obj.to_dict.return_value = d
    return obj


_UNKNOWN_BODY = {"profile": {"authScheme": "UNKNOWN"}, "status": "UNKNOWN"}


class TestGetProvisioningConnection:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_connection_dict(self, mock_get_client):
        conn = _model({"baseUrl": BASE_URL, "authScheme": "TOKEN", "status": "ENABLED"})
        client = AsyncMock()
        client.get_default_provisioning_connection_for_application.return_value = (conn, None, None)
        mock_get_client.return_value = client

        result = await get_app_provisioning_connection(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"baseUrl": BASE_URL, "authScheme": "TOKEN", "status": "ENABLED"}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_unknown_status_surfaces_unsupported_error(self, mock_get_client):
        client = AsyncMock()
        client.get_default_provisioning_connection_for_application.return_value = (_model(_UNKNOWN_BODY), None, None)
        mock_get_client.return_value = client

        result = await get_app_provisioning_connection(ctx=_make_ctx(), app_id=APP_ID)

        assert "error" in result
        assert "not enabled or supported" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_api_error_is_returned(self, mock_get_client):
        client = AsyncMock()
        client.get_default_provisioning_connection_for_application.return_value = (None, None, "404 not found")
        mock_get_client.return_value = client

        result = await get_app_provisioning_connection(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "404 not found"}


class TestSetProvisioningConnection:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_unknown_status_surfaces_unsupported_error(self, mock_get_client):
        # Okta returns 200 + status/authScheme UNKNOWN (no error) on an app that
        # doesn't support provisioning — must surface a clear error, not "success".
        client = AsyncMock()
        client.update_default_provisioning_connection_for_application.return_value = (_model(_UNKNOWN_BODY), None, None)
        mock_get_client.return_value = client

        result = await set_app_provisioning_connection(
            ctx=_make_ctx(), app_id=APP_ID, base_url=BASE_URL, token=TOKEN
        )

        assert "error" in result
        assert "not enabled or supported" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_sends_token_request_with_base_url_and_token(self, mock_get_client):
        conn = _model({"baseUrl": BASE_URL, "authScheme": "TOKEN", "status": "ENABLED"})
        client = AsyncMock()
        client.update_default_provisioning_connection_for_application.return_value = (conn, None, None)
        mock_get_client.return_value = client

        result = await set_app_provisioning_connection(
            ctx=_make_ctx(), app_id=APP_ID, base_url=BASE_URL, token=TOKEN
        )

        assert result == {"baseUrl": BASE_URL, "authScheme": "TOKEN", "status": "ENABLED"}

        call_args = client.update_default_provisioning_connection_for_application.call_args[0]
        assert call_args[0] == APP_ID
        request = call_args[1]
        assert isinstance(request, UpdateDefaultProvisioningConnectionForApplicationRequest)
        # The oneOf union must have bound to the token variant and carry the real
        # base URL + token (the regression that bit attribute statements in #9).
        assert request.to_dict() == {
            "baseUrl": BASE_URL,
            "profile": {"authScheme": "TOKEN", "token": TOKEN},
        }
        assert call_args[2] is True  # activate defaults to True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_activate_false_is_forwarded(self, mock_get_client):
        client = AsyncMock()
        client.update_default_provisioning_connection_for_application.return_value = (_model({}), None, None)
        mock_get_client.return_value = client

        await set_app_provisioning_connection(
            ctx=_make_ctx(), app_id=APP_ID, base_url=BASE_URL, token=TOKEN, activate=False
        )

        assert client.update_default_provisioning_connection_for_application.call_args[0][2] is False


class TestProvisioningConnectionLifecycle:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_activate_empty_body_returns_message(self, mock_get_client):
        client = AsyncMock()
        client.activate_default_provisioning_connection_for_application.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await activate_app_provisioning_connection(ctx=_make_ctx(), app_id=APP_ID)

        assert "message" in result
        assert APP_ID in result["message"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_deactivate_error_is_returned(self, mock_get_client):
        client = AsyncMock()
        client.deactivate_default_provisioning_connection_for_application.return_value = (None, None, "403 forbidden")
        mock_get_client.return_value = client

        result = await deactivate_app_provisioning_connection(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"error": "403 forbidden"}


class TestListAppFeatures:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_returns_feature_dicts(self, mock_get_client):
        f1 = _model({"name": "USER_PROVISIONING", "status": "ENABLED"})
        client = AsyncMock()
        client.list_features_for_application.return_value = ([f1], None, None)
        mock_get_client.return_value = client

        result = await list_app_features(ctx=_make_ctx(), app_id=APP_ID)

        assert result == {"features": [{"name": "USER_PROVISIONING", "status": "ENABLED"}]}


class TestUpdateAppFeature:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_sends_capabilities_and_feature_type(self, mock_get_client):
        feature = _model({"name": "USER_PROVISIONING", "status": "ENABLED"})
        client = AsyncMock()
        client.update_feature_for_application.return_value = (feature, None, None)
        mock_get_client.return_value = client

        caps = {
            "create": {"lifecycleCreate": {"status": "ENABLED"}},
            "update": {"lifecycleDeactivate": {"status": "ENABLED"}, "profile": {"status": "ENABLED"}},
        }
        result = await update_app_feature(
            ctx=_make_ctx(), app_id=APP_ID, feature_name="USER_PROVISIONING", capabilities=caps
        )

        assert result == {"name": "USER_PROVISIONING", "status": "ENABLED"}

        call_args = client.update_feature_for_application.call_args[0]
        assert call_args[0] == APP_ID
        assert call_args[1] == ApplicationFeatureType.USER_PROVISIONING
        request = call_args[2]
        assert isinstance(request, UpdateFeatureForApplicationRequest)
        assert request.to_dict() == caps

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.applications.applications.get_okta_client")
    async def test_invalid_feature_name_rejected_before_api_call(self, mock_get_client):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await update_app_feature(
            ctx=_make_ctx(), app_id=APP_ID, feature_name="BOGUS", capabilities={}
        )

        assert "error" in result
        assert "Invalid feature_name" in result["error"]
        client.update_feature_for_application.assert_not_called()
