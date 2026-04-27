# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
Unit tests for the validation module.

These tests verify that the validate_okta_id function properly blocks
path traversal and injection attacks while allowing valid Okta IDs.
"""

import pytest

from okta_mcp_server.utils.validation import (
    InvalidOktaIdError,
    _validate_os_version_string,
    validate_okta_id,
    validate_os_version_params,
)


class TestValidateOktaId:
    """Tests for the validate_okta_id function."""

    def test_valid_okta_user_id(self):
        """Test that valid Okta user IDs are accepted."""
        valid_ids = [
            "00u1234567890ABCDEF",
            "00uabcdefghijklmnop",
            "00u123ABC456DEF789",
        ]
        for id_value in valid_ids:
            result = validate_okta_id(id_value, "user_id")
            assert result == id_value

    def test_valid_okta_group_id(self):
        """Test that valid Okta group IDs are accepted."""
        valid_ids = [
            "00g1234567890ABCDEF",
            "00gabcdefghijklmnop",
        ]
        for id_value in valid_ids:
            result = validate_okta_id(id_value, "group_id")
            assert result == id_value

    def test_valid_email_as_user_id(self):
        """Test that email addresses are accepted as user IDs (Okta supports this)."""
        valid_emails = [
            "user@example.com",
            "john.doe@company.org",
            "user+tag@example.com",
        ]
        for email in valid_emails:
            result = validate_okta_id(email, "user_id")
            assert result == email

    def test_path_traversal_with_forward_slash(self):
        """Test that path traversal using forward slashes is blocked."""
        malicious_ids = [
            "../groups/00g123",
            "00u123/../../groups/00g456",
            "/api/v1/groups",
            "00u123/../00g456",
        ]
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidOktaIdError) as exc_info:
                validate_okta_id(malicious_id, "user_id")
            assert "forbidden" in str(exc_info.value).lower()

    def test_path_traversal_with_backslash(self):
        """Test that path traversal using backslashes is blocked."""
        malicious_ids = [
            "..\\groups\\00g123",
            "00u123\\..\\..\\groups",
        ]
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidOktaIdError) as exc_info:
                validate_okta_id(malicious_id, "user_id")
            assert "forbidden" in str(exc_info.value).lower()

    def test_path_traversal_with_dot_dot(self):
        """Test that .. sequences are blocked even without slashes."""
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id("00u123..00g456", "user_id")
        assert "forbidden" in str(exc_info.value).lower()

    def test_url_encoded_path_traversal(self):
        """Test that URL-encoded path traversal attempts are blocked."""
        malicious_ids = [
            "%2f..%2fgroups%2f00g123",  # URL-encoded forward slashes
            "%2F..%2Fgroups%2F00g123",  # URL-encoded forward slashes (uppercase)
            "%5c..%5cgroups",  # URL-encoded backslashes
            "%2e%2e%2fgroups",  # URL-encoded ..
        ]
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidOktaIdError) as exc_info:
                validate_okta_id(malicious_id, "user_id")
            assert "forbidden" in str(exc_info.value).lower()

    def test_query_string_injection(self):
        """Test that query string injection attempts are blocked."""
        malicious_ids = [
            "00u123?admin=true",
            "00u123?filter=all",
        ]
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidOktaIdError) as exc_info:
                validate_okta_id(malicious_id, "user_id")
            assert "forbidden" in str(exc_info.value).lower()

    def test_fragment_injection(self):
        """Test that fragment injection attempts are blocked."""
        malicious_ids = [
            "00u123#section",
            "00u123#admin",
        ]
        for malicious_id in malicious_ids:
            with pytest.raises(InvalidOktaIdError) as exc_info:
                validate_okta_id(malicious_id, "user_id")
            assert "forbidden" in str(exc_info.value).lower()

    def test_empty_id(self):
        """Test that empty IDs are rejected."""
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id("", "user_id")
        assert "empty" in str(exc_info.value).lower()

    def test_non_string_id(self):
        """Test that non-string IDs are rejected."""
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id(12345, "user_id")
        assert "string" in str(exc_info.value).lower()

    def test_id_with_spaces(self):
        """Test that IDs with spaces are rejected."""
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id("00u123 00g456", "user_id")
        assert "invalid" in str(exc_info.value).lower()

    def test_id_type_in_error_message(self):
        """Test that the ID type appears in error messages."""
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id("../bad", "policy_id")
        assert "policy_id" in str(exc_info.value)

    def test_valid_ids_with_hyphens_and_underscores(self):
        """Test that IDs with hyphens and underscores are accepted."""
        valid_ids = [
            "00u-123-456",
            "00u_123_456",
            "00u-abc_def",
        ]
        for id_value in valid_ids:
            result = validate_okta_id(id_value, "user_id")
            assert result == id_value

    def test_ssrf_attack_vector(self):
        """Test the specific SSRF attack vector from the security report."""
        # This is the exact attack vector from the security ticket
        malicious_id = "../groups/00gegmsyuRJro9LWi0w6"
        with pytest.raises(InvalidOktaIdError) as exc_info:
            validate_okta_id(malicious_id, "user_id")
        assert "forbidden" in str(exc_info.value).lower()


# ===========================================================================
# _validate_os_version_string
# ===========================================================================

class TestValidateOsVersionString:
    """Tests for the _validate_os_version_string helper in validation.py."""

    # --- Valid versions ---

    def test_valid_xyz_returns_none(self):
        assert _validate_os_version_string("14.2.1") is None

    def test_valid_xyzw_returns_none(self):
        assert _validate_os_version_string("14.2.1.0") is None

    def test_empty_string_returns_none(self):
        assert _validate_os_version_string("") is None

    def test_android_single_component_accepted(self):
        assert _validate_os_version_string("12", "ANDROID") is None

    def test_android_single_component_zero_accepted(self):
        assert _validate_os_version_string("9", "ANDROID") is None

    def test_android_platform_case_insensitive(self):
        assert _validate_os_version_string("12", "android") is None

    # --- Two-component X.Y — must be rejected ---

    def test_xy_returns_error(self):
        error = _validate_os_version_string("14.2")
        assert error is not None
        assert "Incomplete" in error
        assert "14.2" in error
        assert "14.2.0" in error

    def test_xy_error_warns_not_to_assume_patch(self):
        error = _validate_os_version_string("14.2")
        assert "Do NOT assume" in error

    def test_xy_rejected_for_non_android_platform(self):
        error = _validate_os_version_string("14.2", "MACOS")
        assert error is not None
        assert "Incomplete" in error

    def test_xy_rejected_even_for_android(self):
        # Two-component versions are not accepted for Android either —
        # Android uses single major version only.
        error = _validate_os_version_string("12.0", "ANDROID")
        assert error is not None
        assert "Incomplete" in error

    def test_snake_case_not_applicable_to_string_helper(self):
        # The string helper does not deal with dict keys; just validates the value.
        assert _validate_os_version_string("14.2.1") is None

    # --- Single-component for non-Android ---

    def test_single_component_rejected_without_platform(self):
        error = _validate_os_version_string("14")
        assert error is not None
        assert "Invalid" in error
        assert "14" in error

    def test_single_component_rejected_for_macos(self):
        error = _validate_os_version_string("14", "MACOS")
        assert error is not None
        assert "Invalid" in error

    # --- Garbage / alpha versions ---

    def test_alpha_component_returns_error(self):
        error = _validate_os_version_string("14.2.alpha")
        assert error is not None

    def test_leading_dot_returns_error(self):
        error = _validate_os_version_string(".14.2.1")
        assert error is not None

    def test_completely_non_numeric_returns_error(self):
        error = _validate_os_version_string("notaversion")
        assert error is not None

    def test_error_message_contains_xyz_format_hint(self):
        error = _validate_os_version_string("abc")
        assert error is not None
        assert "X.Y.Z" in error

    def test_error_message_mentions_android_exception(self):
        error = _validate_os_version_string("14", "MACOS")
        assert error is not None
        assert "Android" in error


# ===========================================================================
# validate_os_version_params (decorator)
# ===========================================================================

class TestValidateOsVersionParams:
    """Tests for the validate_os_version_params decorator in validation.py."""

    # --- Direct string parameter ---

    @pytest.mark.asyncio
    async def test_valid_xyz_string_param_passes(self):
        @validate_os_version_params("ver")
        async def tool(ver=None):
            return {"ok": True}
        result = await tool(ver="14.2.1")
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_xy_string_param_rejected(self):
        @validate_os_version_params("ver")
        async def tool(ver=None):
            return {"ok": True}
        result = await tool(ver="14.2")
        assert "error" in result
        assert "Incomplete" in result["error"]
        assert "14.2.0" in result["error"]

    @pytest.mark.asyncio
    async def test_none_string_param_skipped(self):
        @validate_os_version_params("ver")
        async def tool(ver=None):
            return {"ok": True}
        result = await tool(ver=None)
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_invalid_string_param_rejected(self):
        @validate_os_version_params("ver")
        async def tool(ver=None):
            return {"ok": True}
        result = await tool(ver="notaversion")
        assert "error" in result

    # --- Dict / policy_data parameter ---

    @pytest.mark.asyncio
    async def test_valid_policy_data_version_passes(self):
        @validate_os_version_params("policy_data")
        async def tool(policy_data):
            return {"ok": True}
        result = await tool(policy_data={"platform": "MACOS", "osVersion": {"minimum": "14.2.1"}})
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_xy_policy_data_version_rejected(self):
        @validate_os_version_params("policy_data")
        async def tool(policy_data):
            return {"ok": True}
        result = await tool(policy_data={"platform": "MACOS", "osVersion": {"minimum": "14.2"}})
        assert "error" in result
        assert "Incomplete" in result["error"]
        assert "Do NOT assume" in result["error"]

    @pytest.mark.asyncio
    async def test_snake_case_os_version_key_in_dict_rejected(self):
        @validate_os_version_params("policy_data")
        async def tool(policy_data):
            return {"ok": True}
        result = await tool(policy_data={"platform": "MACOS", "os_version": {"minimum": "17.0"}})
        assert "error" in result
        assert "Incomplete" in result["error"]

    @pytest.mark.asyncio
    async def test_policy_data_without_os_version_passes(self):
        @validate_os_version_params("policy_data")
        async def tool(policy_data):
            return {"ok": True}
        result = await tool(policy_data={"platform": "MACOS", "name": "My Policy"})
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_android_single_component_in_policy_data_passes(self):
        @validate_os_version_params("policy_data")
        async def tool(policy_data):
            return {"ok": True}
        result = await tool(policy_data={"platform": "ANDROID", "osVersion": {"minimum": "12"}})
        assert result == {"ok": True}

    # --- error_return_type="list" ---

    @pytest.mark.asyncio
    async def test_list_return_type_on_error(self):
        @validate_os_version_params("ver", error_return_type="list")
        async def tool(ver=None):
            return ["ok"]
        result = await tool(ver="14.2")
        assert isinstance(result, list)
        assert result[0].startswith("Error:")

    # --- Sync function support ---

    def test_sync_function_xy_rejected(self):
        @validate_os_version_params("ver")
        def tool(ver=None):
            return {"ok": True}
        result = tool(ver="14.2")
        assert "error" in result
        assert "Incomplete" in result["error"]

    def test_sync_function_valid_version_passes(self):
        @validate_os_version_params("ver")
        def tool(ver=None):
            return {"ok": True}
        result = tool(ver="14.2.1")
        assert result == {"ok": True}

    # --- Parameter not present in call ---

    @pytest.mark.asyncio
    async def test_missing_param_name_skipped(self):
        @validate_os_version_params("nonexistent")
        async def tool(ver=None):
            return {"ok": True}
        result = await tool(ver="14.2")
        assert result == {"ok": True}

