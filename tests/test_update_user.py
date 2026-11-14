# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for update_user — partial profile serialization."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from okta.models import UpdateUserRequest

from okta_mcp_server.tools.users.users import _profile_for_partial_update, update_user


def _make_ctx():
    """Build a minimal fake Context for update_user."""
    from tests.conftest import FakeLifespanContext, FakeOktaAuthManager

    request_context = MagicMock()
    request_context.lifespan_context = FakeLifespanContext(
        okta_auth_manager=FakeOktaAuthManager()
    )
    ctx = MagicMock()
    ctx.request_context = request_context
    return ctx


def _make_user_mock():
    user = MagicMock()
    user.id = "00uTESTUSER0000001"
    user.profile = MagicMock()
    user.profile.email = "test.user@example.com"
    user.to_dict.return_value = {
        "id": "00uTESTUSER0000001",
        "profile": {"email": "test.user@example.com", "title": "Engineer"},
    }
    return user


class TestProfileForPartialUpdate:
    """Verify omitted profile fields are not serialized as JSON null."""

    def test_only_supplied_standard_fields_are_serialized(self):
        profile = _profile_for_partial_update(
            {"title": "Engineer", "department": "Engineering"}
        )
        serialized = profile.to_dict()

        assert serialized == {"title": "Engineer", "department": "Engineering"}
        assert "firstName" not in serialized
        assert "email" not in serialized
        assert None not in serialized.values()

    def test_custom_attributes_are_preserved(self):
        profile = _profile_for_partial_update(
            {"title": "Engineer", "workgroup": "Platform"}
        )
        serialized = profile.to_dict()

        assert serialized["title"] == "Engineer"
        assert serialized["workgroup"] == "Platform"

    def test_camel_case_aliases_are_accepted(self):
        profile = _profile_for_partial_update({"displayName": "Test User"})
        serialized = profile.to_dict()

        assert serialized == {"displayName": "Test User"}

    def test_from_dict_path_emits_nulls_for_omitted_fields(self):
        """Document the SDK pitfall this helper avoids."""
        request = UpdateUserRequest.from_dict(
            {"profile": {"title": "Engineer", "department": "Engineering"}}
        )
        null_fields = [k for k, v in request.to_dict()["profile"].items() if v is None]

        assert len(null_fields) > 0


class TestUpdateUserPartialPayload:
    """Verify update_user sends a partial UpdateUserRequest to the SDK."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.users.users.get_okta_client")
    async def test_update_user_sends_only_provided_profile_keys(self, mock_get_client):
        client = AsyncMock()
        client.update_user.return_value = (_make_user_mock(), None, None)
        mock_get_client.return_value = client

        result = await update_user(
            user_id="00uTESTUSER0000001",
            profile={"title": "Engineer", "workgroup": "Platform"},
            ctx=_make_ctx(),
        )

        call_args = client.update_user.call_args[0]
        assert call_args[0] == "00uTESTUSER0000001"
        assert isinstance(call_args[1], UpdateUserRequest)

        serialized_profile = call_args[1].to_dict()["profile"]
        assert serialized_profile == {"title": "Engineer", "workgroup": "Platform"}
        assert None not in serialized_profile.values()
        assert result[0]["id"] == "00uTESTUSER0000001"
