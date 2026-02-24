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

from okta_mcp_server.utils.validation import InvalidOktaIdError, validate_okta_id


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
