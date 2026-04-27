# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
Unit tests for the validation module.

These tests verify that the validate_okta_id function properly blocks
path traversal and injection attacks while allowing valid Okta IDs,
and that validate_file_path blocks access to OS system paths
and path traversal sequences.
"""

import os

import pytest

from okta_mcp_server.utils.validation import (
    InvalidFilePathError,
    InvalidOktaIdError,
    validate_file_path,
    validate_okta_id,
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


class TestValidateFilePath:
    """Tests for the validate_file_path function."""

    # ------------------------------------------------------------------
    # Absolute system path rejection
    # ------------------------------------------------------------------

    def test_rejects_etc_passwd(self):
        """: /etc/passwd must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/etc/passwd", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_rejects_etc_hosts(self):
        """: /etc/hosts must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/etc/hosts", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_rejects_etc_subdirectory(self):
        """: Any path under /etc/ must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/etc/ssl/private/domain.key", "file_path")

    def test_rejects_proc_self_environ(self):
        """: /proc/self/environ (credential leak vector) must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/proc/self/environ", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_rejects_sys_path(self):
        """: /sys paths must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/sys/kernel/debug", "file_path")

    def test_rejects_dev_path(self):
        """: /dev paths must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/dev/sda", "file_path")

    def test_rejects_root_home(self):
        """: /root home directory must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/root/.ssh/id_rsa", "file_path")

    def test_rejects_var_log(self):
        """: /var/log paths must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/var/log/auth.log", "file_path")

    def test_rejects_macos_private_etc(self):
        """: macOS /private/etc (real target of /etc symlink) must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/private/etc/passwd", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_rejects_macos_private_var(self):
        """: macOS /private/var must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/private/var/log/system.log", "file_path")

    def test_rejects_redundant_separators_to_etc(self):
        """: normpath should collapse //etc//passwd to /etc/passwd and reject it."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/etc//passwd", "file_path")

    def test_param_name_appears_in_error(self):
        """: The param_name must appear in the error message."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/etc/passwd", "private_key_file_path")
        assert "private_key_file_path" in str(exc_info.value)

    # ------------------------------------------------------------------
    # Path traversal rejection
    # ------------------------------------------------------------------

    def test_rejects_dot_dot_traversal(self):
        """: Path traversal with .. must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("images/../../../etc/passwd", "file_path")
        assert "traversal" in str(exc_info.value).lower()

    def test_rejects_url_encoded_traversal_lowercase(self):
        """: URL-encoded %2e%2e traversal must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("%2e%2e%2fetc%2fpasswd", "file_path")
        assert "traversal" in str(exc_info.value).lower()

    def test_rejects_url_encoded_traversal_uppercase(self):
        """: URL-encoded %2E%2E traversal must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("%2E%2E/etc/passwd", "file_path")
        assert "traversal" in str(exc_info.value).lower()

    def test_rejects_traversal_in_middle_of_path(self):
        """: Traversal embedded in a path must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path("/tmp/uploads/../../../etc/shadow", "file_path")

    # ------------------------------------------------------------------
    # Valid paths — must NOT be rejected
    # ------------------------------------------------------------------

    def test_allows_tmp_path(self):
        """/tmp paths must be accepted.

        The returned path is the realpath-resolved form; on macOS /tmp is a
        symlink to /private/tmp so the result may differ from the input.
        """
        path = "/tmp/logo.png"
        result = validate_file_path(path, "file_path")
        assert result == os.path.realpath(path)

    def test_rejects_home_directory_path(self):
        """: Home directory paths outside the allow-list must be rejected.

        With the allow-list fix, arbitrary absolute paths (even user-owned ones
        like ~/.aws/credentials or ~/certs/domain.key) are blocked unless the
        operator explicitly adds the directory to OKTA_MCP_ALLOWED_KEY_DIRS.
        """
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("/Users/aniket/certs/domain.key", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_allows_relative_path_inside_tmp(self, monkeypatch):
        """A relative path whose CWD-resolved real path falls inside /tmp must pass.

        The returned value is the realpath-resolved absolute path so callers
        always open the validated location regardless of CWD changes.
        """
        # Use /tmp directly — on macOS this resolves to /private/tmp which is
        # in the default allow-list.  tempfile.gettempdir() returns the
        # per-user temp folder (/var/folders/...) which is NOT /tmp.
        monkeypatch.chdir("/tmp")
        result = validate_file_path("logo.png", "file_path")
        assert result == os.path.realpath(os.path.abspath("logo.png"))

    def test_rejects_relative_path_outside_allowed(self, monkeypatch, tmp_path):
        """A relative path that resolves outside the allow-list must be rejected."""
        monkeypatch.chdir(tmp_path)  # tmp_path is under /private/var/... on macOS
        # Only rejected when the resolved path is not under /tmp or /var/tmp.
        import tempfile
        real_tmp = os.path.realpath(tempfile.gettempdir())
        real_resolved = os.path.realpath(os.path.abspath("secrets.env"))
        if real_resolved.startswith(real_tmp + os.sep) or real_resolved == real_tmp:
            pytest.skip("CWD resolves inside /tmp — skipping outside-allowed test")
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("secrets.env", "file_path")
        assert "permitted" in str(exc_info.value).lower()

    def test_returns_resolved_path(self):
        """validate_file_path must return the realpath-resolved absolute path.

        The function returns ``os.path.realpath(path)`` so callers can open
        the exact same path that was security-checked, eliminating the TOCTOU
        window.  On macOS /tmp is a symlink to /private/tmp, so the resolved
        path differs from the input.
        """
        path = "/tmp/my-favicon.gif"
        assert validate_file_path(path, "file_path") == os.path.realpath(path)

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    def test_rejects_empty_path(self):
        """Empty string must be rejected."""
        with pytest.raises(InvalidFilePathError) as exc_info:
            validate_file_path("", "file_path")
        assert "empty" in str(exc_info.value).lower()

    def test_rejects_non_string_path(self):
        """Non-string values must be rejected."""
        with pytest.raises(InvalidFilePathError):
            validate_file_path(123, "file_path")
