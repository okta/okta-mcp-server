# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Regression tests for the SDK model workarounds applied on import of
``okta_mcp_server.tools.policies.policies``.

Both bugs were observed against a live Okta for Government tenant and reproduce on
every request, not just as flakes: a single ACCESS_POLICY or MFA_ENROLL policy of
the affected shape poisons the entire `list_policies` page.
"""

from __future__ import annotations

from okta.models.access_policy import AccessPolicy
from okta.models.authenticator_enrollment_policy_authenticator_settings import (
    AuthenticatorEnrollmentPolicyAuthenticatorSettings,
)

# Importing the tools module applies both workarounds as an import-time side effect,
# exactly like the existing LogSecurityContext workaround in system_logs.py.
import okta_mcp_server.tools.policies.policies  # noqa: F401


class TestAccessPolicyEmbeddedWorkaround:
    """`_embedded` on an ACCESS_POLICY mapped to an app is a flat string value,
    not a nested dict — e.g. ``{"resourceType": "APP"}``."""

    def test_flat_string_value_no_longer_raises(self):
        policy = AccessPolicy.from_dict(
            {
                "id": "rst1abcdefghij0000",
                "name": "Test Access Policy",
                "status": "ACTIVE",
                "type": "ACCESS_POLICY",
                "_embedded": {"resourceType": "APP"},
            }
        )
        assert policy.embedded == {"resourceType": "APP"}

    def test_nested_dict_values_still_supported(self):
        """Backward compatibility: `_embedded` entries that ARE nested objects
        (the shape the original, stricter annotation assumed) must still work."""
        policy = AccessPolicy.from_dict(
            {
                "id": "rst1abcdefghij0001",
                "name": "Test Access Policy",
                "status": "ACTIVE",
                "type": "ACCESS_POLICY",
                "_embedded": {"someResource": {"id": "abc123"}},
            }
        )
        assert policy.embedded == {"someResource": {"id": "abc123"}}

    def test_no_embedded_field_still_supported(self):
        policy = AccessPolicy.from_dict(
            {
                "id": "rst1abcdefghij0002",
                "name": "Test Access Policy",
                "status": "ACTIVE",
                "type": "ACCESS_POLICY",
            }
        )
        assert policy.embedded is None


class TestAuthenticatorEnrollmentSmartCardIdpWorkaround:
    """`AuthenticatorEnrollmentPolicyAuthenticatorType` doesn't include
    `smart_card_idp`, even though the SDK's own `AuthenticatorKeyEnum` does —
    common on Okta for Government tenants that enable PIV/CAC authentication."""

    def test_smart_card_idp_no_longer_raises(self):
        settings = AuthenticatorEnrollmentPolicyAuthenticatorSettings.from_dict(
            {"key": "smart_card_idp"}
        )
        assert settings.key == "smart_card_idp"

    def test_previously_valid_key_still_supported(self):
        """Backward compatibility: keys that were already valid enum members
        must continue to validate identically after the relaxation."""
        settings = AuthenticatorEnrollmentPolicyAuthenticatorSettings.from_dict(
            {"key": "okta_verify"}
        )
        assert settings.key == "okta_verify"

    def test_unknown_junk_key_is_also_accepted(self):
        """Documents the accepted tradeoff of relaxing `key` to `str`: any string
        Okta returns is now passed through rather than raising, in exchange for
        no longer silently dropping the whole page on an unrecognized authenticator."""
        settings = AuthenticatorEnrollmentPolicyAuthenticatorSettings.from_dict(
            {"key": "not_a_real_authenticator_key"}
        )
        assert settings.key == "not_a_real_authenticator_key"
