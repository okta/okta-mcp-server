# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""
Input validation utilities for Okta MCP Server.

This module provides validation functions to prevent path traversal and SSRF attacks
by ensuring user-supplied IDs do not contain malicious characters that could manipulate
URL paths when passed to the Okta SDK client.
"""

import re

from loguru import logger


class InvalidOktaIdError(ValueError):
    """Exception raised when an Okta ID contains invalid characters."""

    pass


# Characters that are not allowed in Okta IDs to prevent path traversal
# This includes path separators, URL-reserved characters, and traversal sequences
FORBIDDEN_PATTERNS = [
    "/",  # Path separator
    "\\",  # Windows path separator
    "..",  # Path traversal
    "?",  # Query string delimiter
    "#",  # Fragment delimiter
    "%2f",  # URL-encoded forward slash
    "%2F",  # URL-encoded forward slash (uppercase)
    "%5c",  # URL-encoded backslash
    "%5C",  # URL-encoded backslash (uppercase)
    "%2e%2e",  # URL-encoded ..
    "%2E%2E",  # URL-encoded .. (uppercase)
]

# Regex pattern for valid Okta IDs
# Okta IDs are typically alphanumeric strings, sometimes with hyphens or underscores
# They may also be email addresses (for user lookups)
VALID_OKTA_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-@.+]+$")


def validate_okta_id(id_value: str, id_type: str = "ID") -> str:
    """
    Validate that an Okta ID does not contain path traversal or injection characters.

    This function prevents SSRF attacks where malicious IDs like '../groups/00g123'
    could be used to target unintended Okta APIs.

    Args:
        id_value: The ID value to validate (user_id, group_id, policy_id, rule_id, etc.)
        id_type: A descriptive name for the ID type (used in error messages)

    Returns:
        The validated ID value (unchanged if valid)

    Raises:
        InvalidOktaIdError: If the ID contains forbidden characters or patterns
    """
    if not id_value:
        raise InvalidOktaIdError(f"{id_type} cannot be empty")

    if not isinstance(id_value, str):
        raise InvalidOktaIdError(f"{id_type} must be a string")

    # Check for forbidden patterns (case-insensitive for URL-encoded variants)
    id_lower = id_value.lower()
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.lower() in id_lower:
            logger.warning(f"Rejected {id_type} containing forbidden pattern '{pattern}': {id_value}")
            raise InvalidOktaIdError(
                f"Invalid {id_type}: contains forbidden character or pattern '{pattern}'. "
                f"IDs must not contain path traversal sequences or URL-reserved characters."
            )

    # Validate against allowed character pattern
    if not VALID_OKTA_ID_PATTERN.match(id_value):
        logger.warning(f"Rejected {id_type} with invalid characters: {id_value}")
        raise InvalidOktaIdError(
            f"Invalid {id_type}: contains invalid characters. "
            f"IDs must contain only alphanumeric characters, hyphens, underscores, "
            f"at signs, dots, and plus signs."
        )

    return id_value
