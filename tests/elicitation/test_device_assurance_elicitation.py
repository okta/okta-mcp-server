# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for device assurance policy deletion with elicitation support."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from okta_mcp_server.tools.device_assurance.device_assurance import delete_device_assurance_policy


DEVICE_ASSURANCE_ID = "da01234567890ABCDE"


# ===================================================================
# delete_device_assurance_policy — elicitation flows
# ===================================================================

class TestDeleteDeviceAssurancePolicyElicitation:
    """Tests for delete_device_assurance_policy when the client supports elicitation."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_accept_confirmed_deletes(self, mock_get_client, ctx_elicit_accept_true, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_accept_true, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        mock_okta_client.delete_device_assurance_policy.assert_awaited_once_with(DEVICE_ASSURANCE_ID)
        assert result["success"] is True
        assert DEVICE_ASSURANCE_ID in result["message"]

    @pytest.mark.asyncio
    async def test_accept_not_confirmed_cancels(self, ctx_elicit_accept_false):
        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_accept_false, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_decline_cancels(self, ctx_elicit_decline):
        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_decline, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_cancel_cancels(self, ctx_elicit_cancel):
        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_cancel, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "cancelled" in result["message"].lower()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_okta_api_error(self, mock_get_client, ctx_elicit_accept_true):
        client = AsyncMock()
        client.delete_device_assurance_policy.return_value = (None, "API Error: policy not found")
        mock_get_client.return_value = client

        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_accept_true, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_exception_during_delete(self, mock_get_client, ctx_elicit_accept_true):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_accept_true, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "error" in result


# ===================================================================
# delete_device_assurance_policy — fallback flows
# ===================================================================

class TestDeleteDeviceAssurancePolicyFallback:
    """Tests for delete_device_assurance_policy when the client does NOT support elicitation.

    Pre-elicitation behaviour: the operation proceeds directly without
    confirmation because there was never a separate confirm tool for device assurance policies.
    """

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_fallback_proceeds_with_deletion(self, mock_get_client, ctx_no_elicitation, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        mock_okta_client.delete_device_assurance_policy.assert_awaited_once_with(DEVICE_ASSURANCE_ID)
        assert result["success"] is True

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_exception_fallback_proceeds_with_deletion(self, mock_get_client, ctx_elicit_exception, mock_okta_client):
        mock_get_client.return_value = mock_okta_client

        result = await delete_device_assurance_policy(
            ctx=ctx_elicit_exception, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        mock_okta_client.delete_device_assurance_policy.assert_awaited_once_with(DEVICE_ASSURANCE_ID)
        assert result["success"] is True
