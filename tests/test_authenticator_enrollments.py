# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use
# this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for secret-minimized user authenticator enrollment operations."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.users import users
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

USER_ID = "00u12345678901234567"
ENROLLMENT_ID = "fwf1exampleEnrollment"


def _client_with_raw_responses(raw_responses):
    client = AsyncMock()
    client.get_base_url = MagicMock(return_value="https://test.okta.com")
    executor = MagicMock()
    executor.create_request = AsyncMock(
        return_value=({"method": "GET", "url": "https://test.okta.com"}, None)
    )
    executor.execute = AsyncMock(side_effect=raw_responses)
    client.get_request_executor = MagicMock(return_value=executor)
    client._executor = executor
    return client


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_list_user_authenticator_enrollments_returns_minimized_inventory(
    mock_get_client, ctx_no_elicitation
):
    list_enrollments = getattr(users, "list_user_authenticator_enrollments", None)
    assert list_enrollments is not None, "list_user_authenticator_enrollments tool is missing"

    enrollments = [
        {
            "id": ENROLLMENT_ID,
            "key": "okta_verify",
            "type": "app",
            "name": "Okta Verify",
            "status": "ACTIVE",
            "created": "2026-01-02T03:04:05.000Z",
            "lastUpdated": "2026-01-02T03:04:06.000Z",
            "profile": {
                "deviceName": "Sample phone",
                "credentialId": "must-not-be-returned",
            },
            "methods": [{"type": "push", "secret": "must-not-be-returned"}],
            "_links": {"self": {"href": "https://test.okta.com/private"}},
        }
    ]
    client = _client_with_raw_responses(
        [(MagicMock(headers={}), json.dumps(enrollments), None)]
    )
    mock_get_client.return_value = client

    result = await list_enrollments(ctx_no_elicitation, USER_ID)

    assert result == {
        "success": True,
        "user_id": USER_ID,
        "count": 1,
        "items": [
            {
                "enrollment_id": ENROLLMENT_ID,
                "key": "okta_verify",
                "type": "app",
                "name": "Okta Verify",
                "status": "ACTIVE",
                "created": "2026-01-02T03:04:05.000Z",
                "last_updated": "2026-01-02T03:04:06.000Z",
            }
        ],
    }
    serialized = json.dumps(result)
    assert "credentialId" not in serialized
    assert "must-not-be-returned" not in serialized
    assert "deviceName" not in serialized
    request_url = client._executor.create_request.await_args.args[1]
    assert request_url == (
        f"https://test.okta.com/api/v1/users/{USER_ID}/authenticator-enrollments"
    )


def test_list_user_authenticator_enrollments_scope_registry_entry():
    assert TOOL_SCOPE_REGISTRY["list_user_authenticator_enrollments"] == "okta.users.read"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_unenroll_user_authenticator_requires_exact_confirmation_after_preflight(
    mock_get_client, ctx_no_elicitation
):
    unenroll = getattr(users, "unenroll_user_authenticator", None)
    assert unenroll is not None, "unenroll_user_authenticator tool is missing"

    user = {
        "id": USER_ID,
        "status": "ACTIVE",
        "profile": {"login": "alex@example.com", "secret": "hidden"},
    }
    enrollment = {
        "id": ENROLLMENT_ID,
        "key": "okta_verify",
        "type": "app",
        "name": "Okta Verify",
        "status": "ACTIVE",
    }
    client = _client_with_raw_responses(
        [
            (MagicMock(headers={}), json.dumps(user), None),
            (MagicMock(headers={}), json.dumps([enrollment]), None),
        ]
    )
    mock_get_client.return_value = client

    result = await unenroll(
        ctx_no_elicitation,
        USER_ID,
        ENROLLMENT_ID,
        expected_login="alex@example.com",
        expected_key="okta_verify",
        expected_type="app",
        expected_status="ACTIVE",
        confirmation="",
    )

    assert result["success"] is False
    assert result["confirmation_required"] is True
    assert result["required_confirmation"] == (
        f"UNENROLL alex@example.com {ENROLLMENT_ID}"
    )
    assert result["preflight"] == {
        "user_id": USER_ID,
        "login": "alex@example.com",
        "user_status": "ACTIVE",
        "enrollment": {
            "enrollment_id": ENROLLMENT_ID,
            "key": "okta_verify",
            "type": "app",
            "name": "Okta Verify",
            "status": "ACTIVE",
            "created": None,
            "last_updated": None,
        },
        "preserved_enrollment_ids": [],
    }
    assert client._executor.create_request.await_count == 2


def test_unenroll_user_authenticator_scope_registry_entry():
    assert TOOL_SCOPE_REGISTRY["unenroll_user_authenticator"] == "okta.users.manage"


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_unenroll_user_authenticator_deletes_exact_enrollment_and_verifies_preservation(
    mock_get_client, ctx_no_elicitation
):
    preserved_id = "fwf1preservedEnrollment"
    user = {
        "id": USER_ID,
        "status": "ACTIVE",
        "profile": {"login": "alex@example.com"},
    }
    target = {
        "id": ENROLLMENT_ID,
        "key": "okta_verify",
        "type": "app",
        "name": "Okta Verify",
        "status": "ACTIVE",
    }
    preserved = {
        "id": preserved_id,
        "key": "webauthn",
        "type": "security_key",
        "name": "Security Key or Biometric Authenticator",
        "status": "ACTIVE",
    }
    delete_response = MagicMock(headers={}, status=204)
    client = _client_with_raw_responses(
        [
            (MagicMock(headers={}), json.dumps(user), None),
            (MagicMock(headers={}), json.dumps([target, preserved]), None),
            (delete_response, "", None),
            (MagicMock(headers={}), json.dumps([preserved]), None),
            (MagicMock(headers={}), json.dumps(user), None),
        ]
    )
    mock_get_client.return_value = client

    result = await users.unenroll_user_authenticator(
        ctx_no_elicitation,
        USER_ID,
        ENROLLMENT_ID,
        expected_login="alex@example.com",
        expected_key="okta_verify",
        expected_type="app",
        expected_status="ACTIVE",
        confirmation=f"UNENROLL alex@example.com {ENROLLMENT_ID}",
    )

    assert result["success"] is True
    assert result["http_status"] == 204
    assert result["removed_enrollment_id"] == ENROLLMENT_ID
    assert result["preserved_enrollment_ids"] == [preserved_id]
    assert result["post_enrollment_count"] == 1
    assert result["login"] == "alex@example.com"
    assert result["user_status"] == "ACTIVE"
    methods = [call.args[0] for call in client._executor.create_request.await_args_list]
    assert methods == ["GET", "GET", "DELETE", "GET", "GET"]
    delete_url = client._executor.create_request.await_args_list[2].args[1]
    assert delete_url == (
        f"https://test.okta.com/api/v1/users/{USER_ID}/authenticator-enrollments/"
        f"{ENROLLMENT_ID}"
    )


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_unenroll_user_authenticator_fails_closed_on_guard_mismatch(
    mock_get_client, ctx_no_elicitation
):
    user = {
        "id": USER_ID,
        "status": "ACTIVE",
        "profile": {"login": "alex@example.com"},
    }
    enrollment = {
        "id": ENROLLMENT_ID,
        "key": "webauthn",
        "type": "security_key",
        "name": "Security Key or Biometric Authenticator",
        "status": "ACTIVE",
    }
    client = _client_with_raw_responses(
        [
            (MagicMock(headers={}), json.dumps(user), None),
            (MagicMock(headers={}), json.dumps([enrollment]), None),
        ]
    )
    mock_get_client.return_value = client

    result = await users.unenroll_user_authenticator(
        ctx_no_elicitation,
        USER_ID,
        ENROLLMENT_ID,
        expected_login="alex@example.com",
        expected_key="okta_verify",
        expected_type="app",
        expected_status="ACTIVE",
        confirmation=f"UNENROLL alex@example.com {ENROLLMENT_ID}",
    )

    assert result["success"] is False
    assert result["error_type"] == "enrollment_guard_mismatch"
    assert result["actual"] == {
        "key": "webauthn",
        "type": "security_key",
        "status": "ACTIVE",
    }
    assert client._executor.create_request.await_count == 2


@pytest.mark.asyncio
@patch("okta_mcp_server.tools.users.users.get_okta_client")
async def test_unenroll_user_authenticator_reports_missing_preserved_enrollment(
    mock_get_client, ctx_no_elicitation
):
    preserved_id = "fwf1preservedEnrollment"
    user = {
        "id": USER_ID,
        "status": "ACTIVE",
        "profile": {"login": "alex@example.com"},
    }
    target = {
        "id": ENROLLMENT_ID,
        "key": "okta_verify",
        "type": "app",
        "name": "Okta Verify",
        "status": "ACTIVE",
    }
    preserved = {
        "id": preserved_id,
        "key": "webauthn",
        "type": "security_key",
        "name": "Security Key or Biometric Authenticator",
        "status": "ACTIVE",
    }
    client = _client_with_raw_responses(
        [
            (MagicMock(headers={}), json.dumps(user), None),
            (MagicMock(headers={}), json.dumps([target, preserved]), None),
            (MagicMock(headers={}, status=204), "", None),
            (MagicMock(headers={}), json.dumps([]), None),
        ]
    )
    mock_get_client.return_value = client

    result = await users.unenroll_user_authenticator(
        ctx_no_elicitation,
        USER_ID,
        ENROLLMENT_ID,
        expected_login="alex@example.com",
        expected_key="okta_verify",
        expected_type="app",
        expected_status="ACTIVE",
        confirmation=f"UNENROLL alex@example.com {ENROLLMENT_ID}",
    )

    assert result["success"] is False
    assert result["error_type"] == "post_delete_verification_failed"
    assert result["target_still_present"] is False
    assert result["missing_preserved_enrollment_ids"] == [preserved_id]
    assert client._executor.create_request.await_count == 4
