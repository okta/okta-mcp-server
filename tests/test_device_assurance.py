# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests for device assurance policy tools and helper functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.tools.device_assurance.device_assurance import (
    _compute_policy_diff,
    _enrich_policy_with_attribute_status,
    _get_implication,
    _validate_os_version,
    create_device_assurance_policy,
    get_device_assurance_policy,
    list_device_assurance_policies,
    replace_device_assurance_policy,
)


DEVICE_ASSURANCE_ID = "da01234567890ABCDE"

MACOS_POLICY_DICT = {
    "id": DEVICE_ASSURANCE_ID,
    "name": "MacOS Compliance",
    "platform": "MACOS",
    "osVersion": {"minimum": "14.0.0"},
    "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
    "screenLockType": {"include": ["BIOMETRIC"]},
    "secureHardwarePresent": True,
}

IOS_POLICY_DICT = {
    "id": DEVICE_ASSURANCE_ID,
    "name": "iOS Compliance",
    "platform": "IOS",
    "osVersion": {"minimum": "17.0.0"},
    "jailbreak": False,
    "screenLockType": {"include": ["BIOMETRIC"]},
}


def _make_policy_model(policy_dict: dict) -> MagicMock:
    """Return a mock Okta SDK model whose to_dict() returns a copy of policy_dict."""
    mock = MagicMock()
    mock.to_dict.return_value = policy_dict.copy()
    return mock


# ===========================================================================
# _validate_os_version
# ===========================================================================

class TestValidateOsVersion:
    """Tests for the _validate_os_version helper."""

    def test_returns_none_when_no_os_version_key(self):
        assert _validate_os_version({}) is None

    def test_returns_none_when_os_version_is_none(self):
        assert _validate_os_version({"osVersion": None}) is None

    def test_returns_none_when_minimum_is_absent(self):
        assert _validate_os_version({"osVersion": {}}) is None

    def test_returns_none_when_minimum_is_empty_string(self):
        assert _validate_os_version({"osVersion": {"minimum": ""}}) is None

    def test_valid_xyz_passes(self):
        assert _validate_os_version({"osVersion": {"minimum": "14.2.1"}}) is None

    def test_valid_xyzw_passes(self):
        assert _validate_os_version({"osVersion": {"minimum": "14.2.1.0"}}) is None

    def test_valid_xy_normalises_in_place_to_xyz(self):
        data = {"osVersion": {"minimum": "14.2"}}
        assert _validate_os_version(data) is None
        assert data["osVersion"]["minimum"] == "14.2.0"

    def test_single_component_returns_error(self):
        error = _validate_os_version({"osVersion": {"minimum": "14"}})
        assert error is not None
        assert "Invalid" in error
        assert "14" in error

    def test_alpha_component_returns_error(self):
        error = _validate_os_version({"osVersion": {"minimum": "14.2.alpha"}})
        assert error is not None

    def test_version_with_leading_dot_returns_error(self):
        error = _validate_os_version({"osVersion": {"minimum": ".14.2.1"}})
        assert error is not None

    def test_snake_case_os_version_key_accepted(self):
        assert _validate_os_version({"os_version": {"minimum": "14.2.1"}}) is None

    def test_snake_case_xy_normalises_in_place(self):
        data = {"os_version": {"minimum": "17.0"}}
        assert _validate_os_version(data) is None
        assert data["os_version"]["minimum"] == "17.0.0"

    def test_error_message_contains_valid_format_hint(self):
        error = _validate_os_version({"osVersion": {"minimum": "abc"}})
        assert error is not None
        assert "X.Y" in error


# ===========================================================================
# _enrich_policy_with_attribute_status
# ===========================================================================

class TestEnrichPolicyWithAttributeStatus:
    """Tests for the _enrich_policy_with_attribute_status helper."""

    def test_macos_all_attributes_configured(self):
        result = _enrich_policy_with_attribute_status(MACOS_POLICY_DICT.copy())
        status = result["securityAttributeStatus"]
        assert status["osVersion"] == "configured"
        assert status["diskEncryptionType"] == "configured"
        assert status["screenLockType"] == "configured"
        assert status["secureHardwarePresent"] == "configured"

    def test_macos_missing_attributes_are_not_configured(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS", "osVersion": {"minimum": "14.0.0"}}
        result = _enrich_policy_with_attribute_status(policy)
        status = result["securityAttributeStatus"]
        assert status["osVersion"] == "configured"
        assert status["diskEncryptionType"] == "not_configured"
        assert status["screenLockType"] == "not_configured"
        assert status["secureHardwarePresent"] == "not_configured"

    def test_macos_status_keys_match_expected_attributes(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy)
        assert set(result["securityAttributeStatus"].keys()) == {
            "osVersion", "diskEncryptionType", "screenLockType", "secureHardwarePresent"
        }

    def test_ios_all_attributes_configured(self):
        result = _enrich_policy_with_attribute_status(IOS_POLICY_DICT.copy())
        status = result["securityAttributeStatus"]
        assert status["osVersion"] == "configured"
        # jailbreak=False is still "configured" — the setting exists, it's just set to False
        assert status["jailbreak"] == "configured"
        assert status["screenLockType"] == "configured"

    def test_ios_missing_attributes_are_not_configured(self):
        policy = {"id": "x", "name": "test", "platform": "IOS"}
        result = _enrich_policy_with_attribute_status(policy)
        status = result["securityAttributeStatus"]
        assert status["osVersion"] == "not_configured"
        assert status["jailbreak"] == "not_configured"
        assert status["screenLockType"] == "not_configured"

    def test_android_expected_attributes(self):
        policy = {"id": "x", "name": "test", "platform": "ANDROID", "osVersion": {"minimum": "12.0.0"}}
        result = _enrich_policy_with_attribute_status(policy)
        status = result["securityAttributeStatus"]
        assert status["osVersion"] == "configured"
        assert status["jailbreak"] == "not_configured"
        assert status["screenLockType"] == "not_configured"
        # ANDROID does not include diskEncryptionType or secureHardwarePresent
        assert "diskEncryptionType" not in status
        assert "secureHardwarePresent" not in status

    def test_windows_expected_attributes(self):
        policy = {"id": "x", "name": "test", "platform": "WINDOWS"}
        result = _enrich_policy_with_attribute_status(policy)
        assert set(result["securityAttributeStatus"].keys()) == {
            "osVersion", "diskEncryptionType", "screenLockType", "secureHardwarePresent"
        }

    def test_chromeos_only_os_version(self):
        policy = {"id": "x", "name": "test", "platform": "CHROMEOS", "osVersion": {"minimum": "115.0.0"}}
        result = _enrich_policy_with_attribute_status(policy)
        status = result["securityAttributeStatus"]
        assert set(status.keys()) == {"osVersion"}
        assert status["osVersion"] == "configured"

    def test_no_platform_key_returns_policy_unchanged(self):
        policy = {"id": "x", "name": "test"}
        result = _enrich_policy_with_attribute_status(policy)
        assert "securityAttributeStatus" not in result

    def test_unknown_platform_adds_empty_status(self):
        policy = {"id": "x", "name": "test", "platform": "UNKNOWN"}
        result = _enrich_policy_with_attribute_status(policy)
        assert result["securityAttributeStatus"] == {}

    def test_original_dict_is_mutated_in_place(self):
        """The helper mutates and returns the same dict object."""
        policy = {"id": "x", "name": "test", "platform": "CHROMEOS"}
        result = _enrich_policy_with_attribute_status(policy)
        assert result is policy


# ===========================================================================
# _compute_policy_diff
# ===========================================================================

class TestComputePolicyDiff:
    """Tests for the _compute_policy_diff helper."""

    def test_identical_policies_return_empty_list(self):
        policy = {"name": "Test", "platform": "MACOS"}
        assert _compute_policy_diff(policy, policy.copy()) == []

    def test_name_change_is_detected(self):
        before = {"name": "Old Name", "platform": "MACOS"}
        after = {"name": "New Name", "platform": "MACOS"}
        diff = _compute_policy_diff(before, after)
        assert len(diff) == 1
        change = diff[0]
        assert change["attribute"] == "name"
        assert change["before"] == "Old Name"
        assert change["after"] == "New Name"
        assert "implication" in change

    def test_metadata_keys_are_excluded(self):
        before = {"name": "Test", "id": "old", "createdBy": "admin", "_links": {}, "lastUpdate": "2024"}
        after = {"name": "Test", "id": "new", "createdBy": "user", "_links": {"self": "x"}, "lastUpdate": "2025"}
        diff = _compute_policy_diff(before, after)
        assert diff == []

    def test_security_attribute_status_is_excluded(self):
        before = {"name": "Test", "securityAttributeStatus": {"osVersion": "configured"}}
        after = {"name": "Test", "securityAttributeStatus": {"osVersion": "not_configured"}}
        diff = _compute_policy_diff(before, after)
        assert diff == []

    def test_multiple_changes_sorted_alphabetically(self):
        before = {"name": "Old", "osVersion": {"minimum": "14.0.0"}}
        after = {"name": "New", "osVersion": {"minimum": "15.0.0"}}
        diff = _compute_policy_diff(before, after)
        assert len(diff) == 2
        assert diff[0]["attribute"] == "name"
        assert diff[1]["attribute"] == "osVersion"

    def test_added_attribute_shows_none_before(self):
        before = {"name": "Test", "platform": "MACOS"}
        after = {"name": "Test", "platform": "MACOS", "secureHardwarePresent": True}
        diff = _compute_policy_diff(before, after)
        assert len(diff) == 1
        assert diff[0]["attribute"] == "secureHardwarePresent"
        assert diff[0]["before"] is None
        assert diff[0]["after"] is True

    def test_removed_attribute_shows_none_after(self):
        before = {"name": "Test", "platform": "MACOS", "secureHardwarePresent": True}
        after = {"name": "Test", "platform": "MACOS"}
        diff = _compute_policy_diff(before, after)
        assert len(diff) == 1
        assert diff[0]["attribute"] == "secureHardwarePresent"
        assert diff[0]["before"] is True
        assert diff[0]["after"] is None

    def test_each_change_contains_required_fields(self):
        before = {"name": "Old"}
        after = {"name": "New"}
        diff = _compute_policy_diff(before, after)
        assert len(diff) == 1
        assert {"attribute", "before", "after", "implication"} == set(diff[0].keys())


# ===========================================================================
# _get_implication
# ===========================================================================

class TestGetImplication:
    """Tests for the _get_implication helper."""

    def test_os_version_mentions_requirement(self):
        result = _get_implication("osVersion", {"minimum": "13.0.0"}, {"minimum": "14.0.0"})
        assert "OS version" in result

    def test_jailbreak_enabled_mentions_blocked(self):
        result = _get_implication("jailbreak", False, True)
        assert "blocked" in result.lower()

    def test_jailbreak_disabled_mentions_no_longer(self):
        result = _get_implication("jailbreak", True, False)
        assert "no longer" in result.lower()

    def test_disk_encryption_mentions_encryption(self):
        result = _get_implication("diskEncryptionType", None, {"include": ["ALL_INTERNAL_VOLUMES"]})
        assert "encryption" in result.lower()

    def test_screen_lock_mentions_screen_lock(self):
        result = _get_implication("screenLockType", None, {"include": ["BIOMETRIC"]})
        assert "screen lock" in result.lower()

    def test_secure_hardware_enabled_mentions_hardware(self):
        result = _get_implication("secureHardwarePresent", False, True)
        assert "hardware" in result.lower() or "secure" in result.lower()

    def test_secure_hardware_disabled_mentions_no_longer(self):
        result = _get_implication("secureHardwarePresent", True, False)
        assert "no longer" in result.lower()

    def test_name_change_mentions_name(self):
        result = _get_implication("name", "Old", "New")
        assert "name" in result.lower()

    def test_platform_change_mentions_platform(self):
        result = _get_implication("platform", "MACOS", "WINDOWS")
        assert "platform" in result.lower()

    def test_unknown_attribute_includes_attr_name_in_message(self):
        result = _get_implication("someCustomField", "a", "b")
        assert "someCustomField" in result


# ===========================================================================
# list_device_assurance_policies
# ===========================================================================

class TestListDeviceAssurancePolicies:
    """Tests for the list_device_assurance_policies tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_enriched_list_of_policies(self, mock_get_client, ctx_no_elicitation):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = ([mock_policy], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "policies" in result
        assert len(result["policies"]) == 1
        assert "securityAttributeStatus" in result["policies"][0]
        assert result["policies"][0]["platform"] == "MACOS"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_multiple_policies(self, mock_get_client, ctx_no_elicitation):
        mock_policies = [
            _make_policy_model(MACOS_POLICY_DICT),
            _make_policy_model(IOS_POLICY_DICT),
        ]
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = (mock_policies, MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert len(result["policies"]) == 2

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_empty_list_when_no_policies(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = ([], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert result == {"policies": []}

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = (None, MagicMock(), "API Error: forbidden")
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_exception(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = Exception("Connection refused")

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result


# ===========================================================================
# get_device_assurance_policy
# ===========================================================================

class TestGetDeviceAssurancePolicy:
    """Tests for the get_device_assurance_policy tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_enriched_policy(self, mock_get_client, ctx_no_elicitation):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (mock_policy, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert result["id"] == DEVICE_ASSURANCE_ID
        assert "securityAttributeStatus" in result
        client.get_device_assurance_policy.assert_awaited_once_with(DEVICE_ASSURANCE_ID)

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_none_when_policy_not_found(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client

        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert result is None

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_api_error(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (None, MagicMock(), "Not Found")
        mock_get_client.return_value = client

        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_exception(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = Exception("Timeout")

        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_id_returns_error_without_api_call(self, ctx_no_elicitation):
        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id="../evil/path"
        )

        assert "error" in result


# ===========================================================================
# create_device_assurance_policy
# ===========================================================================

class TestCreateDeviceAssurancePolicy:
    """Tests for the create_device_assurance_policy tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_creates_policy_and_returns_dict(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.create_device_assurance_policy.return_value = (mock_policy, MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test MacOS Policy", "platform": "MACOS", "osVersion": {"minimum": "14.0.0"}},
        )

        assert result["id"] == DEVICE_ASSURANCE_ID
        client.create_device_assurance_policy.assert_awaited_once()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_two_component_version_normalised_before_api_call(
        self, mock_get_client, mock_da_cls, ctx_no_elicitation
    ):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.create_device_assurance_policy.return_value = (mock_policy, MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        policy_data = {"name": "Test", "platform": "MACOS", "osVersion": {"minimum": "14.2"}}
        await create_device_assurance_policy(ctx=ctx_no_elicitation, policy_data=policy_data)

        # Confirms normalisation mutated the dict before the model was built
        assert policy_data["osVersion"]["minimum"] == "14.2.0"

    @pytest.mark.asyncio
    async def test_invalid_os_version_returns_error_before_api_call(self, ctx_no_elicitation):
        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS", "osVersion": {"minimum": "14"}},
        )

        assert "error" in result
        assert "Invalid" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_api_error(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        client = AsyncMock()
        client.create_device_assurance_policy.return_value = (None, MagicMock(), "Validation Error")
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_exception(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = Exception("Connection error")

        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_none_when_api_returns_no_policy(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        client = AsyncMock()
        client.create_device_assurance_policy.return_value = (None, MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert result is None


# ===========================================================================
# replace_device_assurance_policy
# ===========================================================================

class TestReplaceDeviceAssurancePolicy:
    """Tests for the replace_device_assurance_policy tool."""

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_before_after_and_changes(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        before_dict = {**MACOS_POLICY_DICT, "name": "Old Name"}
        after_dict = {**MACOS_POLICY_DICT, "name": "New Name"}
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (_make_policy_model(before_dict), MagicMock(), None)
        client.replace_device_assurance_policy.return_value = (_make_policy_model(after_dict), MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "New Name", "platform": "MACOS"},
        )

        assert "before" in result
        assert "after" in result
        assert "changes" in result
        assert result["before"]["name"] == "Old Name"
        assert result["after"]["name"] == "New Name"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_changes_list_includes_name_change(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        before_dict = {**MACOS_POLICY_DICT, "name": "Old Name"}
        after_dict = {**MACOS_POLICY_DICT, "name": "New Name"}
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (_make_policy_model(before_dict), MagicMock(), None)
        client.replace_device_assurance_policy.return_value = (_make_policy_model(after_dict), MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "New Name", "platform": "MACOS"},
        )

        name_changes = [c for c in result["changes"] if c["attribute"] == "name"]
        assert len(name_changes) == 1
        assert name_changes[0]["before"] == "Old Name"
        assert name_changes[0]["after"] == "New Name"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_before_after_both_contain_security_attribute_status(
        self, mock_get_client, mock_da_cls, ctx_no_elicitation
    ):
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (_make_policy_model(MACOS_POLICY_DICT), MagicMock(), None)
        client.replace_device_assurance_policy.return_value = (_make_policy_model(MACOS_POLICY_DICT), MagicMock(), None)
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "MacOS Compliance", "platform": "MACOS"},
        )

        assert "securityAttributeStatus" in result["before"]
        assert "securityAttributeStatus" in result["after"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_when_fetch_fails(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (None, MagicMock(), "Not Found")
        mock_get_client.return_value = client

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result
        client.replace_device_assurance_policy.assert_not_awaited()

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.DeviceAssurance")
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_when_replace_api_fails(self, mock_get_client, mock_da_cls, ctx_no_elicitation):
        client = AsyncMock()
        client.get_device_assurance_policy.return_value = (_make_policy_model(MACOS_POLICY_DICT), MagicMock(), None)
        client.replace_device_assurance_policy.return_value = (None, MagicMock(), "Conflict")
        mock_get_client.return_value = client
        mock_da_cls.from_dict.return_value = MagicMock()

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_os_version_returns_error_before_api_call(self, ctx_no_elicitation):
        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS", "osVersion": {"minimum": "bad-version"}},
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_invalid_id_returns_error_without_api_call(self, ctx_no_elicitation):
        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id="../../etc/passwd",
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_error_dict_on_exception(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = Exception("Timeout")

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result
