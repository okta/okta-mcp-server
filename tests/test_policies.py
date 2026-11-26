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
