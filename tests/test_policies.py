# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for policy rule ``type`` handling.

``_build_policy_rule_model`` picks the typed SDK model from ``rule_data["type"]``.
Before this fix, a missing ``type`` surfaced as a cryptic SDK discriminator
error, and a lowercase ``type`` was rejected by the typed model's enum even
though it selected the right class. These tests cover:

1. Every supported rule type maps to its typed model class.
2. ``type`` is matched case-insensitively and normalised before deserialising.
3. A missing / empty / unsupported ``type`` raises an actionable ``ValueError``
   that lists the valid values.
4. The create/update tools return that message as ``{"error": ...}`` and make
   no API call.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import okta.models as okta_models
import pytest

from okta_mcp_server.tools.policies.policies import (
    _POLICY_RULE_MODEL_MAP,
    _build_policy_rule_model,
    _requested_status,
    create_policy_rule,
    update_policy_rule,
)

POLICY_ID = "00p1a2b3c4d5e6f7g8h9"
RULE_ID = "0pr1a2b3c4d5e6f7g8h9"

VALID_TYPES = [
    "ACCESS_POLICY",
    "DEVICE_SIGNAL_COLLECTION",
    "ENTITY_RISK",
    "IDP_DISCOVERY",
    "MFA_ENROLL",
    "PASSWORD",
    "POST_AUTH_SESSION",
    "PROFILE_ENROLLMENT",
    "SIGN_ON",
]

EXPECTED_MODEL = {
    "ACCESS_POLICY": okta_models.AccessPolicyRule,
    "DEVICE_SIGNAL_COLLECTION": okta_models.DeviceSignalCollectionPolicyRule,
    "ENTITY_RISK": okta_models.EntityRiskPolicyRule,
    "IDP_DISCOVERY": okta_models.IdpDiscoveryPolicyRule,
    "MFA_ENROLL": okta_models.AuthenticatorEnrollmentPolicyRule,
    "PASSWORD": okta_models.PasswordPolicyRule,
    "POST_AUTH_SESSION": okta_models.PostAuthSessionPolicyRule,
    "PROFILE_ENROLLMENT": okta_models.ProfileEnrollmentPolicyRule,
    "SIGN_ON": okta_models.OktaSignOnPolicyRule,
}

PASSWORD_RULE = {
    "type": "PASSWORD",
    "name": "Allow self-service reset",
    "actions": {"passwordChange": {"access": "ALLOW"}},
}


class TestBuildPolicyRuleModel:
    def test_valid_types_match_the_model_map(self):
        """Guards the documented list of valid values against map drift."""
        assert sorted(_POLICY_RULE_MODEL_MAP) == VALID_TYPES

    @pytest.mark.parametrize("rule_type", VALID_TYPES)
    def test_each_type_maps_to_its_model(self, rule_type):
        model = _build_policy_rule_model({"type": rule_type, "name": "r"})
        assert type(model) is EXPECTED_MODEL[rule_type]

    @pytest.mark.parametrize("raw", ["password", "Password", "  PASSWORD  "])
    def test_type_is_case_insensitive_and_normalised(self, raw):
        model = _build_policy_rule_model({**PASSWORD_RULE, "type": raw})
        assert type(model) is okta_models.PasswordPolicyRule
        assert model.to_dict()["type"] == "PASSWORD"

    def test_actions_survive_the_round_trip(self):
        body = _build_policy_rule_model(PASSWORD_RULE).to_dict()
        assert body["actions"] == {"passwordChange": {"access": "ALLOW"}}

    def test_does_not_mutate_caller_dict(self):
        data = {**PASSWORD_RULE, "type": "password"}
        _build_policy_rule_model(data)
        assert data["type"] == "password"

    @pytest.mark.parametrize("data", [{"name": "r"}, {"type": "", "name": "r"}, {"type": None, "name": "r"}])
    def test_missing_type_raises_actionable_error(self, data):
        with pytest.raises(ValueError) as exc:
            _build_policy_rule_model(data)
        msg = str(exc.value)
        assert "missing the required 'type' field" in msg
        for rule_type in VALID_TYPES:
            assert rule_type in msg
        assert "discriminator" not in msg

    def test_unsupported_type_raises_actionable_error(self):
        with pytest.raises(ValueError) as exc:
            _build_policy_rule_model({"type": "OKTA_SIGN_ON", "name": "r"})
        msg = str(exc.value)
        assert "unsupported 'type' value 'OKTA_SIGN_ON'" in msg
        assert "SIGN_ON rules for an OKTA_SIGN_ON policy" in msg


class TestPolicyRuleToolsTypeValidation:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_create_without_type_returns_error_and_skips_api(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            rule_data={"name": "r", "actions": {"signon": {"access": "ALLOW"}}},
        )

        assert "error" in result
        assert "missing the required 'type' field" in result["error"]
        assert "SIGN_ON" in result["error"]
        client.create_policy_rule.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_update_with_invalid_type_returns_error_and_skips_api(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        mock_get_client.return_value = client

        result = await update_policy_rule(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            rule_id=RULE_ID,
            rule_data={"type": "NOT_A_TYPE", "name": "r"},
        )

        assert "error" in result
        assert "unsupported 'type' value 'NOT_A_TYPE'" in result["error"]
        client.replace_policy_rule.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_create_with_lowercase_type_sends_typed_model(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        created = MagicMock()
        created.to_dict.return_value = {"id": RULE_ID, "type": "PASSWORD"}
        client.create_policy_rule.return_value = (created, MagicMock(), None)
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation,
            policy_id=POLICY_ID,
            rule_data={**PASSWORD_RULE, "type": "password"},
        )

        assert result == {"id": RULE_ID, "type": "PASSWORD"}
        sent_policy_id, sent_rule = client.create_policy_rule.call_args.args
        assert sent_policy_id == POLICY_ID
        assert type(sent_rule) is okta_models.PasswordPolicyRule
        assert sent_rule.to_dict()["type"] == "PASSWORD"


# ---------------------------------------------------------------------------
# requested ``status`` is applied, not silently dropped
# ---------------------------------------------------------------------------
#
# Okta ignores ``status`` in a rule create/replace body. Create honours only
# the ``activate`` query parameter; replace keeps the rule's current status and
# needs a lifecycle call (activate / deactivate) to change it.


def _rule(status: str, rule_id: str = RULE_ID) -> okta_models.PasswordPolicyRule:
    return okta_models.PasswordPolicyRule.from_dict({**PASSWORD_RULE, "id": rule_id, "status": status})


def _status_client(*, created=None, replaced=None, fetched=None, lifecycle_err=None, get_err=None) -> AsyncMock:
    client = AsyncMock()
    client.create_policy_rule.return_value = (created, MagicMock(), None)
    client.replace_policy_rule.return_value = (replaced, MagicMock(), None)
    client.activate_policy_rule.return_value = (MagicMock(), lifecycle_err)
    client.deactivate_policy_rule.return_value = (MagicMock(), lifecycle_err)
    client.get_policy_rule.return_value = (fetched, MagicMock(), get_err)
    return client


class TestRequestedStatus:
    @pytest.mark.parametrize(
        "raw, expected",
        [("ACTIVE", "ACTIVE"), ("INACTIVE", "INACTIVE"), ("inactive", "INACTIVE"), (" Active ", "ACTIVE")],
    )
    def test_normalises_valid_values(self, raw, expected):
        assert _requested_status({"status": raw}) == expected

    def test_omitted_is_none(self):
        assert _requested_status({}) is None
        assert _requested_status({"status": None}) is None

    def test_invalid_value_raises_actionable_error(self):
        with pytest.raises(ValueError, match=r"unsupported 'status' value 'DISABLED'.*ACTIVE, INACTIVE"):
            _requested_status({"status": "DISABLED"})

    def test_lowercase_status_reaches_the_model_normalised(self):
        model = _build_policy_rule_model({**PASSWORD_RULE, "status": "inactive"})
        assert model.to_dict()["status"] == "INACTIVE"


class TestCreatePolicyRuleStatus:
    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_inactive_creates_with_activate_false(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(created=_rule("INACTIVE"))
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation, policy_id=POLICY_ID, rule_data={**PASSWORD_RULE, "status": "INACTIVE"}
        )

        assert client.create_policy_rule.call_args.kwargs == {"activate": False}
        assert result["status"] == "INACTIVE"
        assert "warning" not in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    @pytest.mark.parametrize("status", [None, "ACTIVE"])
    async def test_active_or_omitted_keeps_default_create(self, mock_get_client, status, ctx_no_elicitation):
        client = _status_client(created=_rule("ACTIVE"))
        mock_get_client.return_value = client
        data = dict(PASSWORD_RULE) if status is None else {**PASSWORD_RULE, "status": status}

        result = await create_policy_rule(ctx=ctx_no_elicitation, policy_id=POLICY_ID, rule_data=data)

        assert client.create_policy_rule.call_args.kwargs == {}
        assert result["status"] == "ACTIVE"
        assert "warning" not in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_mismatch_after_create_returns_warning(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(created=_rule("ACTIVE"))
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation, policy_id=POLICY_ID, rule_data={**PASSWORD_RULE, "status": "INACTIVE"}
        )

        assert result["status"] == "ACTIVE"
        assert "Requested status INACTIVE but the rule is ACTIVE" in result["warning"]
        assert "deactivate_policy_rule" in result["warning"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_invalid_status_returns_error_and_skips_api(self, mock_get_client, ctx_no_elicitation):
        client = _status_client()
        mock_get_client.return_value = client

        result = await create_policy_rule(
            ctx=ctx_no_elicitation, policy_id=POLICY_ID, rule_data={**PASSWORD_RULE, "status": "DISABLED"}
        )

        assert "unsupported 'status' value 'DISABLED'" in result["error"]
        client.create_policy_rule.assert_not_called()


class TestUpdatePolicyRuleStatus:
    async def _update(self, ctx, status):
        data = dict(PASSWORD_RULE) if status is None else {**PASSWORD_RULE, "status": status}
        return await update_policy_rule(ctx=ctx, policy_id=POLICY_ID, rule_id=RULE_ID, rule_data=data)

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_deactivates_and_refetches_when_replace_keeps_active(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(replaced=_rule("ACTIVE"), fetched=_rule("INACTIVE"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "INACTIVE")

        client.deactivate_policy_rule.assert_awaited_once_with(POLICY_ID, RULE_ID)
        client.activate_policy_rule.assert_not_called()
        client.get_policy_rule.assert_awaited_once_with(POLICY_ID, RULE_ID)
        assert result["status"] == "INACTIVE"
        assert "warning" not in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_activates_when_replace_keeps_inactive(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(replaced=_rule("INACTIVE"), fetched=_rule("ACTIVE"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "active")

        client.activate_policy_rule.assert_awaited_once_with(POLICY_ID, RULE_ID)
        client.deactivate_policy_rule.assert_not_called()
        assert result["status"] == "ACTIVE"
        assert "warning" not in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    @pytest.mark.parametrize("status, current", [(None, "ACTIVE"), (None, "INACTIVE"), ("ACTIVE", "ACTIVE")])
    async def test_no_lifecycle_call_when_status_omitted_or_already_matches(
        self, mock_get_client, status, current, ctx_no_elicitation
    ):
        client = _status_client(replaced=_rule(current))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, status)

        client.activate_policy_rule.assert_not_called()
        client.deactivate_policy_rule.assert_not_called()
        client.get_policy_rule.assert_not_called()
        assert result["status"] == current
        assert "warning" not in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_lifecycle_error_returns_rule_with_warning(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(replaced=_rule("ACTIVE"), lifecycle_err=Exception("E0000006 forbidden"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "INACTIVE")

        client.get_policy_rule.assert_not_called()
        assert result["status"] == "ACTIVE"
        assert "Requested status INACTIVE but the rule is ACTIVE" in result["warning"]
        assert "E0000006 forbidden" in result["warning"]
        assert "deactivate_policy_rule" in result["warning"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_refetch_still_mismatched_returns_warning(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(replaced=_rule("ACTIVE"), fetched=_rule("ACTIVE"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "INACTIVE")

        assert result["status"] == "ACTIVE"
        assert "Requested status INACTIVE but the rule is ACTIVE" in result["warning"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_refetch_failure_reports_requested_status_with_warning(self, mock_get_client, ctx_no_elicitation):
        client = _status_client(replaced=_rule("ACTIVE"), get_err=Exception("timeout"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "INACTIVE")

        assert result["status"] == "INACTIVE"
        assert "re-reading the rule failed" in result["warning"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_replace_error_skips_lifecycle(self, mock_get_client, ctx_no_elicitation):
        client = _status_client()
        client.replace_policy_rule.return_value = (None, MagicMock(), Exception("E0000001 bad"))
        mock_get_client.return_value = client

        result = await self._update(ctx_no_elicitation, "INACTIVE")

        assert result == {"error": "E0000001 bad"}
        client.deactivate_policy_rule.assert_not_called()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.policies.policies.get_okta_client")
    async def test_deactivation_does_not_prompt_for_confirmation(self, mock_get_client, ctx_elicit_accept_true):
        client = _status_client(replaced=_rule("ACTIVE"), fetched=_rule("INACTIVE"))
        mock_get_client.return_value = client

        await self._update(ctx_elicit_accept_true, "INACTIVE")

        ctx_elicit_accept_true.elicit.assert_not_called()
