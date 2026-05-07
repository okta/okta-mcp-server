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
from okta.exceptions.exceptions import ForbiddenException, UnauthorizedException

from okta_mcp_server.tools.device_assurance.device_assurance import (
    _build_scope_error,
    _compute_policy_diff,
    _detect_unverifiable_attributes,
    _enrich_policy_with_attribute_status,
    _get_implication,
    _validate_platform_attributes,
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


def _make_forbidden_exception(status: int = 403) -> ForbiddenException:
    """Create a minimal ForbiddenException / UnauthorizedException for testing."""
    exc = ForbiddenException.__new__(ForbiddenException)
    exc.status = status
    exc.reason = "Forbidden" if status == 403 else "Unauthorized"
    exc.body = None
    exc.data = None
    exc.headers = None
    return exc


# ===========================================================================
# Tool docstring contract tests (AC2 / AC3 guard rails)
# ===========================================================================

class TestToolDocstringContracts:
    """Guard-rail tests that ensure critical LLM instruction text is present in
    the tool docstrings / response bodies.  If these fail it means a refactor
    accidentally removed text the LLM relies on to behave correctly."""

    def test_list_tool_exposes_version_threshold_parameter(self):
        """AC2: list_device_assurance_policies must declare a version_threshold
        parameter so the validate_os_version_params decorator can intercept
        incomplete versions before the tool body runs."""
        import inspect
        sig = inspect.signature(list_device_assurance_policies)
        assert "version_threshold" in sig.parameters, (
            "list_device_assurance_policies is missing the 'version_threshold' parameter "
            "required for pre-call OS version validation"
        )

    def test_list_tool_version_threshold_defaults_to_none(self):
        import inspect
        sig = inspect.signature(list_device_assurance_policies)
        default = sig.parameters["version_threshold"].default
        assert default is None

    def test_replace_docstring_mandatory_block_at_top(self):
        """AC3: The MANDATORY RESPONSE FORMAT block must appear before the
        'Platform-specific attribute support' section."""
        doc = replace_device_assurance_policy.__doc__ or ""
        mandatory_pos = doc.find("MANDATORY RESPONSE FORMAT")
        platform_pos = doc.find("Platform-specific attribute support")
        assert mandatory_pos != -1, "MANDATORY RESPONSE FORMAT block is missing from replace docstring"
        assert mandatory_pos < platform_pos, (
            "MANDATORY RESPONSE FORMAT block must come before the platform attributes section"
        )

    def test_replace_docstring_says_never_reply_done(self):
        """AC3: The docstring must explicitly forbid a 'Done' response."""
        doc = replace_device_assurance_policy.__doc__ or ""
        assert "Done" in doc

    # --- AC2: list tool must have the MANDATORY version-threshold block ---

    def test_list_docstring_contains_mandatory_version_block(self):
        """AC2: The list docstring must have a MANDATORY block calling out that
        version_threshold MUST be passed — not filtered locally."""
        doc = list_device_assurance_policies.__doc__ or ""
        assert "MANDATORY" in doc, (
            "list_device_assurance_policies docstring is missing the MANDATORY "
            "version threshold block"
        )

    def test_list_docstring_prohibits_self_filtering(self):
        """AC2: The docstring must explicitly tell the LLM never to filter locally."""
        doc = list_device_assurance_policies.__doc__ or ""
        assert "NEVER call this tool with no arguments" in doc, (
            "list docstring must contain 'NEVER call this tool with no arguments' "
            "to prevent the LLM from bypassing version_threshold validation"
        )

    def test_list_docstring_shows_wrong_and_right_call_examples(self):
        """AC2: The docstring must include both a WRONG and RIGHT call example
        so the LLM has a concrete pattern to follow."""
        doc = list_device_assurance_policies.__doc__ or ""
        assert "WRONG" in doc
        assert "RIGHT" in doc

    # --- AC2 / AC3: replace tool must forbid invented versions ---

    def test_replace_docstring_says_never_invent_version(self):
        """AC2/AC3: The replace docstring must tell the LLM never to complete or guess a version."""
        doc = replace_device_assurance_policy.__doc__ or ""
        assert "NEVER invent" in doc, (
            "replace_device_assurance_policy docstring is missing the "
            "'NEVER invent' instruction that prevents invented/normalized version numbers"
        )
        assert "NOT the same" in doc, (
            "replace docstring must make clear that X.Y and X.Y.0 are different versions"
        )
        assert "user_stated_os_version" in doc, (
            "replace docstring must mention user_stated_os_version as the required "
            "channel for OS version changes"
        )

    def test_replace_docstring_instructs_to_ask_for_version(self):
        """AC2: If the user hasn't confirmed an exact version, the LLM must ask."""
        doc = replace_device_assurance_policy.__doc__ or ""
        assert "STOP and ask" in doc, (
            "replace docstring must tell the LLM to STOP and ask when no "
            "explicit version has been confirmed"
        )


# ===========================================================================
# _build_scope_error
# ===========================================================================

class TestBuildScopeError:
    """Tests for the _build_scope_error helper."""

    def test_read_operation_mentions_read_scope(self):
        result = _build_scope_error("list")
        assert "okta.deviceAssurance.read" in result["error"]

    def test_write_operation_mentions_manage_scope(self):
        for op in ("create", "replace", "delete"):
            result = _build_scope_error(op)
            assert "okta.deviceAssurance.manage" in result["error"], f"Failed for operation: {op}"

    def test_status_code_is_included_in_message(self):
        result = _build_scope_error("list", status=401)
        assert "401" in result["error"]

    def test_mentions_permissions_blocked(self):
        result = _build_scope_error("list", status=403)
        assert "blocked by permissions" in result["error"].lower()

    def test_mentions_device_assurance(self):
        result = _build_scope_error("list", status=403)
        assert "device assurance" in result["error"].lower()

    def test_mentions_mcp_config_scopes(self):
        result = _build_scope_error("list", status=403)
        assert "mcp.json" in result["error"].lower()
        assert "okta_scopes" in result["error"].lower()

    def test_returns_dict_with_error_key(self):
        result = _build_scope_error("list")
        assert "error" in result
        assert isinstance(result["error"], str)


# ===========================================================================
# _validate_platform_attributes
# ===========================================================================

class TestValidatePlatformAttributes:
    """Tests for the _validate_platform_attributes helper."""

    # --- Valid combinations should return None ---

    def test_returns_none_when_no_platform(self):
        assert _validate_platform_attributes({"diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}}) is None

    def test_returns_none_for_macos_with_valid_attributes(self):
        data = {
            "platform": "MACOS",
            "osVersion": {"minimum": "14.0.0"},
            "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
            "screenLockType": {"include": ["BIOMETRIC"]},
            "secureHardwarePresent": True,
        }
        assert _validate_platform_attributes(data) is None

    def test_returns_none_for_android_with_jailbreak_false(self):
        data = {"platform": "ANDROID", "jailbreak": False, "screenLockType": {"include": ["BIOMETRIC"]}}
        assert _validate_platform_attributes(data) is None

    def test_returns_none_for_ios_with_jailbreak_false(self):
        data = {"platform": "IOS", "jailbreak": False}
        assert _validate_platform_attributes(data) is None

    def test_returns_none_for_chromeos_with_only_os_version(self):
        assert _validate_platform_attributes({"platform": "CHROMEOS", "osVersion": {"minimum": "115.0.0"}}) is None

    # --- Platform/attribute incompatibilities ---

    def test_chromeos_with_disk_encryption_returns_error(self):
        data = {"platform": "CHROMEOS", "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "diskEncryptionType" in error
        assert "CHROMEOS" in error

    def test_macos_with_jailbreak_returns_error(self):
        data = {"platform": "MACOS", "jailbreak": False}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "jailbreak" in error
        assert "MACOS" in error

    def test_android_with_disk_encryption_returns_error(self):
        data = {"platform": "ANDROID", "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "diskEncryptionType" in error

    def test_ios_with_secure_hardware_returns_error(self):
        data = {"platform": "IOS", "secureHardwarePresent": True}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "secureHardwarePresent" in error

    def test_windows_with_jailbreak_returns_error(self):
        data = {"platform": "WINDOWS", "jailbreak": False}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "jailbreak" in error

    def test_error_message_includes_supported_platforms(self):
        data = {"platform": "CHROMEOS", "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]}}
        error = _validate_platform_attributes(data)
        assert "MACOS" in error
        assert "WINDOWS" in error

    def test_error_message_includes_remove_hint(self):
        data = {"platform": "IOS", "secureHardwarePresent": True}
        error = _validate_platform_attributes(data)
        assert "Remove" in error

    # --- jailbreak=True validation ---

    def test_jailbreak_true_on_android_returns_error(self):
        data = {"platform": "ANDROID", "jailbreak": True}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "jailbreak" in error
        assert "false" in error.lower()

    def test_jailbreak_true_on_ios_returns_error(self):
        data = {"platform": "IOS", "jailbreak": True}
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "jailbreak" in error
        assert "false" in error.lower()

    def test_jailbreak_false_on_android_is_valid(self):
        # False is the only accepted value — must not be rejected
        assert _validate_platform_attributes({"platform": "ANDROID", "jailbreak": False}) is None

    def test_multiple_invalid_attributes_returns_combined_error(self):
        data = {
            "platform": "CHROMEOS",
            "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
            "secureHardwarePresent": True,
        }
        error = _validate_platform_attributes(data)
        assert error is not None
        assert "diskEncryptionType" in error
        assert "secureHardwarePresent" in error


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

    # --- AC1: Policy status field ---

    def test_status_field_preserved_when_present(self):
        policy = {**MACOS_POLICY_DICT.copy(), "status": "ACTIVE"}
        result = _enrich_policy_with_attribute_status(policy)
        assert result["status"] == "ACTIVE"

    def test_inactive_status_is_preserved(self):
        policy = {**MACOS_POLICY_DICT.copy(), "status": "INACTIVE"}
        result = _enrich_policy_with_attribute_status(policy)
        assert result["status"] == "INACTIVE"

    def test_status_field_set_to_unknown_when_absent(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy)
        assert result["status"] == "UNKNOWN"

    def test_no_platform_key_does_not_add_status(self):
        """When there is no platform, the function returns early without touching status."""
        policy = {"id": "x", "name": "test"}
        result = _enrich_policy_with_attribute_status(policy)
        assert "status" not in result
        assert "securityAttributeStatus" not in result

    # --- AC4: Partial failure / unverifiable attributes ---

    def test_unverifiable_attrs_marked_as_unverifiable(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS", "osVersion": {"minimum": "14.0.0"}}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs={"diskEncryptionType"})
        assert result["securityAttributeStatus"]["diskEncryptionType"] == "unverifiable"

    def test_unverifiable_attrs_do_not_affect_configured_attrs(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS", "osVersion": {"minimum": "14.0.0"}}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs={"diskEncryptionType"})
        assert result["securityAttributeStatus"]["osVersion"] == "configured"

    def test_non_unverifiable_absent_attrs_remain_not_configured(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS", "osVersion": {"minimum": "14.0.0"}}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs={"diskEncryptionType"})
        assert result["securityAttributeStatus"]["screenLockType"] == "not_configured"

    def test_partial_failure_section_added_when_unverifiable(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs={"diskEncryptionType"})
        assert "partial_failure" in result
        assert "diskEncryptionType" in result["partial_failure"]["unverifiable_attributes"]
        assert "message" in result["partial_failure"]

    def test_partial_failure_message_says_not_treat_as_not_configured(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs={"diskEncryptionType"})
        assert "not configured" in result["partial_failure"]["message"].lower()

    def test_no_partial_failure_section_when_no_unverifiable_attrs(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy)
        assert "partial_failure" not in result

    def test_empty_unverifiable_attrs_set_does_not_add_partial_failure(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(policy, unverifiable_attrs=set())
        assert "partial_failure" not in result

    def test_all_unverifiable_attrs_listed_in_partial_failure(self):
        policy = {"id": "x", "name": "test", "platform": "MACOS"}
        result = _enrich_policy_with_attribute_status(
            policy, unverifiable_attrs={"diskEncryptionType", "screenLockType"}
        )
        listed = result["partial_failure"]["unverifiable_attributes"]
        assert "diskEncryptionType" in listed
        assert "screenLockType" in listed


# ===========================================================================
# _compute_policy_diff
# ===========================================================================

class TestDetectUnverifiableAttributes:
    """Tests for the _detect_unverifiable_attributes helper."""

    def test_returns_empty_set_when_resp_is_none(self):
        assert _detect_unverifiable_attributes({}, None) == set()

    def test_returns_empty_set_for_200_response(self):
        resp = MagicMock()
        resp.status_code = 200
        assert _detect_unverifiable_attributes({"platform": "MACOS"}, resp) == set()

    def test_returns_empty_set_for_201_response(self):
        resp = MagicMock()
        resp.status_code = 201
        assert _detect_unverifiable_attributes({"platform": "MACOS"}, resp) == set()

    def test_returns_missing_attrs_for_207_response(self):
        resp = MagicMock()
        resp.status_code = 207
        policy = {"platform": "MACOS", "osVersion": {"minimum": "14.0.0"}}
        result = _detect_unverifiable_attributes(policy, resp)
        assert "diskEncryptionType" in result
        assert "screenLockType" in result
        assert "secureHardwarePresent" in result
        assert "osVersion" not in result  # present in the policy dict

    def test_returns_empty_set_for_207_when_all_attrs_present(self):
        resp = MagicMock()
        resp.status_code = 207
        policy = {
            "platform": "MACOS",
            "osVersion": {"minimum": "14.0.0"},
            "diskEncryptionType": {"include": ["ALL_INTERNAL_VOLUMES"]},
            "screenLockType": {"include": ["BIOMETRIC"]},
            "secureHardwarePresent": True,
        }
        result = _detect_unverifiable_attributes(policy, resp)
        assert result == set()

    def test_unknown_platform_returns_empty_set_for_207(self):
        resp = MagicMock()
        resp.status_code = 207
        result = _detect_unverifiable_attributes({"platform": "UNKNOWN"}, resp)
        assert result == set()

    def test_resp_without_status_code_returns_empty_set(self):
        """When resp has neither status_code nor status, no partial failure is assumed."""
        resp = object()  # bare object — no status attributes
        result = _detect_unverifiable_attributes({"platform": "MACOS"}, resp)
        assert result == set()

    def test_ios_missing_attrs_for_207(self):
        resp = MagicMock()
        resp.status_code = 207
        policy = {"platform": "IOS"}
        result = _detect_unverifiable_attributes(policy, resp)
        assert "jailbreak" in result
        assert "screenLockType" in result
        assert "osVersion" in result


# ===========================================================================
# _compute_policy_diff
# ===========================================================================
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
        assert "retrieved_at" in result
        assert "note" in result

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
        assert "retrieved_at" in result
        assert "note" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_returns_empty_list_when_no_policies(self, mock_get_client, ctx_no_elicitation):
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = ([], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert result["policies"] == []
        assert "retrieved_at" in result
        assert "note" in result

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_none_policies_transient_returns_warning_with_metadata(
        self, mock_get_client, ctx_no_elicitation
    ):
        """When the SDK returns (None, 2xx_resp, None), the response must include
        the transient-retry warning, retrieved_at, and note fields."""
        client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        client.list_device_assurance_policies.return_value = (None, mock_resp, None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert result["policies"] == []
        assert "warning" in result
        assert "retrieved_at" in result
        assert "note" in result

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

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_forbidden_exception_returns_scope_error(self, mock_get_client, ctx_no_elicitation):
        """A ForbiddenException (403 with JSON body) should surface a clear scope error."""
        mock_get_client.side_effect = _make_forbidden_exception(403)

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result
        assert "403" in result["error"]
        assert "okta.deviceAssurance.read" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_unauthorised_exception_returns_scope_error(self, mock_get_client, ctx_no_elicitation):
        """An UnauthorizedException (401) should also surface a clear scope error."""
        exc = ForbiddenException.__new__(UnauthorizedException)
        exc.status = 401
        exc.reason = "Unauthorized"
        exc.body = None
        exc.data = None
        exc.headers = None
        mock_get_client.side_effect = exc

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result
        assert "401" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_none_policies_with_403_response_returns_scope_error(
        self, mock_get_client, ctx_no_elicitation
    ):
        """When the SDK returns (None, resp, None) with a 403 status (empty 403 body),
        the tool must return a scope error rather than the transient-retry warning."""
        client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        client.list_device_assurance_policies.return_value = (None, mock_resp, None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result
        assert "403" in result["error"]
        assert "okta.deviceAssurance.read" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_none_policies_with_401_response_returns_scope_error(
        self, mock_get_client, ctx_no_elicitation
    ):
        client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        client.list_device_assurance_policies.return_value = (None, mock_resp, None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result
        assert "401" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_scope_precheck_short_circuits_without_api_call(
        self, mock_get_client, ctx_no_elicitation
    ):
        """If the cached token clearly lacks okta.policies.read, the tool should return
        the scope error immediately and not attempt any API call.
        """
        # Configure the fake auth manager to expose a scopes string
        # that is missing okta.deviceAssurance.read.
        ctx_no_elicitation.request_context.lifespan_context.okta_auth_manager.scopes = "okta.users.read"

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)

        assert "error" in result
        assert "okta.deviceAssurance.read" in result["error"]
        mock_get_client.assert_not_called()

    # --- AC2: version_threshold pre-validation ---

    @pytest.mark.asyncio
    async def test_two_component_version_threshold_rejected_before_api_call(
        self, ctx_no_elicitation
    ):
        """AC2: passing version_threshold='14.2' must be rejected by the
        validate_os_version_params decorator before the tool body runs."""
        result = await list_device_assurance_policies(
            ctx=ctx_no_elicitation, version_threshold="14.2"
        )
        assert "error" in result
        assert "Incomplete" in result["error"]
        assert "14.2.0" in result["error"]

    @pytest.mark.asyncio
    async def test_incomplete_threshold_error_warns_not_to_assume(
        self, ctx_no_elicitation
    ):
        result = await list_device_assurance_policies(
            ctx=ctx_no_elicitation, version_threshold="10.15"
        )
        assert "error" in result
        assert "Do NOT assume" in result["error"]

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_valid_three_component_threshold_passes_through(
        self, mock_get_client, ctx_no_elicitation
    ):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = ([mock_policy], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(
            ctx=ctx_no_elicitation, version_threshold="14.2.1"
        )
        assert "error" not in result
        assert result["version_threshold"] == "14.2.1"

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_none_version_threshold_omitted_from_response(
        self, mock_get_client, ctx_no_elicitation
    ):
        mock_policy = _make_policy_model(MACOS_POLICY_DICT)
        client = AsyncMock()
        client.list_device_assurance_policies.return_value = ([mock_policy], MagicMock(), None)
        mock_get_client.return_value = client

        result = await list_device_assurance_policies(ctx=ctx_no_elicitation)
        assert "error" not in result
        assert "version_threshold" not in result

    @pytest.mark.asyncio
    async def test_invalid_format_threshold_rejected(
        self, ctx_no_elicitation
    ):
        result = await list_device_assurance_policies(
            ctx=ctx_no_elicitation, version_threshold="notaversion"
        )
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
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_forbidden_exception_returns_scope_error(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = _make_forbidden_exception(403)

        result = await get_device_assurance_policy(
            ctx=ctx_no_elicitation, device_assurance_id=DEVICE_ASSURANCE_ID
        )

        assert "error" in result
        assert "403" in result["error"]
        assert "okta.deviceAssurance.read" in result["error"]


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
            policy_data={"name": "Test MacOS Policy", "platform": "MACOS"},
            user_stated_os_version="14.0.0",
        )

        assert result["id"] == DEVICE_ASSURANCE_ID
        client.create_device_assurance_policy.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_two_component_version_rejected_before_api_call(
        self, ctx_no_elicitation
    ):
        # AC2: X.Y in user_stated_os_version must be rejected before the API is called.
        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
            user_stated_os_version="14.2",
        )

        assert "error" in result
        assert "Incomplete" in result["error"]
        assert "14.2.0" in result["error"]

    @pytest.mark.asyncio
    async def test_invalid_os_version_returns_error_before_api_call(self, ctx_no_elicitation):
        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
            user_stated_os_version="14",
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
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_forbidden_exception_returns_scope_error(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = _make_forbidden_exception(403)

        result = await create_device_assurance_policy(
            ctx=ctx_no_elicitation,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result
        assert "403" in result["error"]
        assert "okta.deviceAssurance.manage" in result["error"]

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
        assert "_display_required" in result
        assert result["_display_required"]  # must be a non-empty instruction string
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
            policy_data={"name": "Test", "platform": "MACOS"},
            user_stated_os_version="bad-version",
        )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_os_version_in_policy_data_without_user_stated_rejected(
        self, ctx_no_elicitation
    ):
        """AC2: If policy_data contains osVersion but user_stated_os_version is absent,
        the tool must refuse — forcing the LLM to always use the verbatim channel."""
        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS", "osVersion": {"minimum": "13.2.0"}},
        )
        assert "error" in result
        assert "osVersion must NOT be included" in result["error"]

    @pytest.mark.asyncio
    async def test_xy_in_user_stated_os_version_rejected(self, ctx_no_elicitation):
        """AC2: A two-component version in user_stated_os_version must be rejected
        by the decorator before the tool body or API call runs."""
        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS"},
            user_stated_os_version="13.2",
        )
        assert "error" in result
        assert "Incomplete" in result["error"]

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

    @pytest.mark.asyncio
    @patch("okta_mcp_server.tools.device_assurance.device_assurance.get_okta_client")
    async def test_forbidden_exception_returns_scope_error(self, mock_get_client, ctx_no_elicitation):
        mock_get_client.side_effect = _make_forbidden_exception(403)

        result = await replace_device_assurance_policy(
            ctx=ctx_no_elicitation,
            device_assurance_id=DEVICE_ASSURANCE_ID,
            policy_data={"name": "Test", "platform": "MACOS"},
        )

        assert "error" in result
        assert "403" in result["error"]
        assert "okta.deviceAssurance.manage" in result["error"]
