# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
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

import functools
import inspect
import os
import re
from typing import Any, Callable

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
#
# IMPORTANT: The forbidden patterns check MUST run BEFORE the regex validation.
# The regex allows dots (for email addresses like user@example.com), but ".."
# is caught by the forbidden patterns list. This ordering ensures path traversal
# sequences like ".." are rejected even though single dots are allowed.
VALID_OKTA_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-@.+]+$")

# Maximum length of ID to log (to prevent log injection attacks)
MAX_LOG_ID_LENGTH = 100


def _sanitize_for_log(value: str) -> str:
    """Sanitize a value for safe logging by truncating and escaping."""
    if len(value) > MAX_LOG_ID_LENGTH:
        return f"{value[:MAX_LOG_ID_LENGTH]}... (truncated)"
    return value


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

    # IMPORTANT: Check forbidden patterns FIRST before regex validation.
    # The regex allows dots (for emails), but we must reject ".." sequences.
    id_lower = id_value.lower()
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.lower() in id_lower:
            logger.warning(
                f"Rejected {id_type} containing forbidden pattern '{pattern}': "
                f"{_sanitize_for_log(id_value)}"
            )
            raise InvalidOktaIdError(
                f"Invalid {id_type}: contains forbidden character or pattern '{pattern}'. "
                f"IDs must not contain path traversal sequences or URL-reserved characters."
            )

    # Validate against allowed character pattern
    if not VALID_OKTA_ID_PATTERN.match(id_value):
        logger.warning(f"Rejected {id_type} with invalid characters: {_sanitize_for_log(id_value)}")
        raise InvalidOktaIdError(
            f"Invalid {id_type}: contains invalid characters. "
            f"IDs must contain only alphanumeric characters, hyphens, underscores, "
            f"at signs, dots, and plus signs."
        )

    return id_value


class InvalidFilePathError(ValueError):
    """Exception raised when a file path is invalid or potentially unsafe."""

    pass


# Path traversal sequences to reject in file paths
FILE_PATH_TRAVERSAL_PATTERNS = [
    "..",
    "%2e%2e",  # URL-encoded ..
    "%2E%2E",  # URL-encoded .. (uppercase)
]

# ---------------------------------------------------------------------------
# Allow-list for file paths
# ---------------------------------------------------------------------------
# Environment variable operators set to expand the safe-directory list.
# Value must be a colon-separated list of absolute directory paths (Unix) or
# semicolon-separated (Windows).  Example:
#   export OKTA_MCP_ALLOWED_KEY_DIRS="/tmp:/opt/certs"
ALLOWED_KEY_DIRS_ENV = "OKTA_MCP_ALLOWED_KEY_DIRS"

# Built-in defaults: only /tmp and /var/tmp are permitted unless the operator
# explicitly extends the list via the environment variable.
_DEFAULT_ALLOWED_KEY_DIRS: tuple = ("/tmp", "/var/tmp")


def _get_raw_allowed_key_dirs() -> tuple:
    """
    Return normalized (non-symlink-resolved) allowed directory prefixes.

    Uses ``os.path.normpath`` + ``os.path.abspath`` — **no** ``realpath`` call —
    so that no filesystem access occurs on the allowed-dir values themselves
    beyond reading the current process's working directory.  This is the set
    used in the first (filesystem-free) validation phase.

    Priority:
      1. OKTA_MCP_ALLOWED_KEY_DIRS environment variable (if set and non-empty).
      2. Built-in defaults: /tmp and /var/tmp.
    """
    env_val = os.environ.get(ALLOWED_KEY_DIRS_ENV, "").strip()
    if env_val:
        sep = ";" if os.name == "nt" else ":"
        dirs = [d.strip() for d in env_val.split(sep) if d.strip()]
    else:
        dirs = list(_DEFAULT_ALLOWED_KEY_DIRS)
    return tuple(os.path.normpath(os.path.abspath(d)) for d in dirs)


def _get_allowed_key_dirs() -> tuple:
    """
    Return the set of real (symlink-resolved) absolute directory prefixes
    inside which file reads are permitted.

    Uses ``os.path.realpath`` to follow symlinks on the *trusted* allowed-dir
    values (e.g. /tmp → /private/tmp on macOS).  This is the set used in the
    second (symlink-escape) validation phase.

    Priority:
      1. OKTA_MCP_ALLOWED_KEY_DIRS environment variable (if set and non-empty).
      2. Built-in defaults: /tmp and /var/tmp.
    """
    env_val = os.environ.get(ALLOWED_KEY_DIRS_ENV, "").strip()
    if env_val:
        sep = ";" if os.name == "nt" else ":"
        dirs = [d.strip() for d in env_val.split(sep) if d.strip()]
    else:
        dirs = list(_DEFAULT_ALLOWED_KEY_DIRS)
    return tuple(os.path.realpath(d) for d in dirs)


def validate_file_path(file_path: str, param_name: str = "file_path") -> str:
    """
    Validate that a file path is safe to open.

    Uses a **two-phase** allow-list approach so that the filesystem is never
    accessed on an untrusted path before that path has been validated:

    Phase 1 — filesystem-free string check (fail-fast, no I/O on user path):
      Normalise the path using only ``os.path.normpath`` + ``os.path.abspath``
      (pure string operations; no symlink resolution) and verify it falls
      inside the raw (non-realpath) allowed directories.  This rejects obvious
      out-of-bounds absolute paths (e.g. ``/etc/passwd``) **immediately**,
      without performing any filesystem operation on the user-supplied value.

    Phase 2 — symlink-escape check (filesystem I/O, allowed-range paths only):
      Resolve the path to its real on-disk location via ``os.path.realpath``
      (follows symlinks) and verify the result is still inside the
      realpath-resolved allowed directories.  Because this step is only reached
      when Phase 1 has already confirmed the path is lexically within the
      allow-list, filesystem access is scoped to paths that are already in the
      vicinity of permitted directories.

    By default only ``/tmp`` and ``/var/tmp`` are permitted; operators extend
    this via the ``OKTA_MCP_ALLOWED_KEY_DIRS`` environment variable.

    Steps performed:
      1. Basic type / emptiness checks.
      2. Reject path traversal sequences lexically (``..``, URL-encoded forms).
      3. **Phase 1**: normalize with ``normpath``+``abspath``; reject if outside
         the raw allowed-dir list (no filesystem access on user path).
      4. **Phase 2**: resolve with ``realpath``; reject if outside the
         realpath-resolved allowed-dir list (catches symlink escapes).
         The resolved path is **not** included in the error message to prevent
         information disclosure.

    Args:
        file_path: The path to validate.
        param_name: Descriptive name used in error messages.

    Returns:
        The symlink-resolved absolute path (``os.path.realpath``) of the
        validated file.  Callers **must** use this returned path for all
        subsequent I/O (``isfile``, ``open``, etc.) instead of the original
        user-supplied value to ensure the path that is opened is identical
        to the path that was validated, preventing TOCTOU attacks.

    Raises:
        InvalidFilePathError: If the path contains traversal sequences
            or resolves outside the permitted directory allow-list.
    """
    if not file_path:
        raise InvalidFilePathError(f"{param_name} cannot be empty")

    if not isinstance(file_path, str):
        raise InvalidFilePathError(f"{param_name} must be a string")

    # ------------------------------------------------------------------ #
    # Step 1: Reject traversal sequences at the lexical level (no I/O).   #
    # Catches patterns like "images/../../etc/passwd" before normalization. #
    # ------------------------------------------------------------------ #
    path_lower = file_path.lower()
    for pattern in FILE_PATH_TRAVERSAL_PATTERNS:
        if pattern in path_lower:
            logger.warning(
                f"Rejected {param_name} containing path traversal pattern '{pattern}': "
                f"{_sanitize_for_log(file_path)}"
            )
            raise InvalidFilePathError(
                f"Invalid {param_name}: path traversal sequences are not allowed."
            )

    # ------------------------------------------------------------------ #
    # Phase 1: string-only normalization — ZERO filesystem access on the  #
    # user-supplied path.  Rejects obvious out-of-bounds paths             #
    # (e.g. /etc/passwd, /Users/…/secret.key) immediately.                #
    #                                                                      #
    # The allowed-dir set is the union of:                                 #
    #   • raw_allowed_dirs  (normpath+abspath of configured dirs)          #
    #   • real_allowed_dirs (realpath of configured dirs)                  #
    # Both are derived from *trusted* configured values — calling realpath #
    # on them is safe.  Including both handles OS-level symlinks in the    #
    # allowed-dir list itself (e.g. /tmp → /private/tmp on macOS): a       #
    # relative "logo.png" with CWD=/private/tmp normalises to             #
    # /private/tmp/logo.png, which only matches the realpath form.         #
    # An absolute /tmp/logo.png normalises to /tmp/logo.png, which only   #
    # matches the raw form.  Checking both means both work correctly       #
    # without ever calling realpath on the user-supplied value.            #
    # ------------------------------------------------------------------ #
    normalized_path = os.path.normpath(os.path.abspath(file_path))
    raw_allowed_dirs = _get_raw_allowed_key_dirs()
    real_allowed_dirs = _get_allowed_key_dirs()
    # Deduplicate while preserving order (raw first, then real).
    _phase1_dirs = tuple(dict.fromkeys((*raw_allowed_dirs, *real_allowed_dirs)))
    if not any(
        normalized_path == d or normalized_path.startswith(d + os.sep)
        for d in _phase1_dirs
    ):
        # Use raw dirs in the display message (shows the logical/configured paths).
        allowed_display = os.pathsep.join(raw_allowed_dirs) if raw_allowed_dirs else "(none configured)"
        logger.warning(
            f"Rejected {param_name}: normalized path is outside permitted directories "
            f"({allowed_display}): {_sanitize_for_log(file_path)!r}"
        )
        raise InvalidFilePathError(
            f"Invalid {param_name}: the path is outside the permitted directories "
            f"({allowed_display}). "
            f"Place the file inside a permitted directory or configure allowed "
            f"directories via the {ALLOWED_KEY_DIRS_ENV} environment variable."
        )

    # ------------------------------------------------------------------ #
    # Phase 2: realpath-based symlink-escape check.                        #
    # Only reached for paths that passed Phase 1, so filesystem access is  #
    # scoped to paths already confirmed to be near the allow-list.         #
    # The resolved realpath is intentionally excluded from the error        #
    # message to prevent information disclosure of symlink targets.         #
    # ------------------------------------------------------------------ #
    real_path = os.path.realpath(os.path.abspath(file_path))
    real_allowed_dirs = _get_allowed_key_dirs()
    if not any(
        real_path == real_dir or real_path.startswith(real_dir + os.sep)
        for real_dir in real_allowed_dirs
    ):
        allowed_display = os.pathsep.join(real_allowed_dirs) if real_allowed_dirs else "(none configured)"
        logger.warning(
            f"Rejected {param_name}: resolved path is outside permitted directories "
            f"({allowed_display}): {_sanitize_for_log(file_path)!r}"
        )
        raise InvalidFilePathError(
            f"Invalid {param_name}: the path resolves outside the permitted directories "
            f"({allowed_display}). Symlink escapes are not permitted. "
            f"Place the file inside a permitted directory or configure allowed "
            f"directories via the {ALLOWED_KEY_DIRS_ENV} environment variable."
        )

    # Return the symlink-resolved absolute path so callers always open the
    # exact path that was security-checked, eliminating the TOCTOU window
    # between validation and the subsequent open() call.
    return real_path


def validate_ids(*id_params: str, error_return_type: str = "list"):
    """
    Decorator that validates specified ID parameters before function execution.

    This decorator extracts the named parameters from the function call and validates
    each one using validate_okta_id(). If any validation fails, it returns an error
    response in the specified format without executing the wrapped function.

    Args:
        *id_params: Names of function parameters to validate (e.g., "user_id", "group_id")
        error_return_type: Format of error response - "list" or "dict"

    Usage:
        @validate_ids("user_id")
        async def get_user(user_id: str, ctx: Context = None) -> list:
            ...

        @validate_ids("group_id", "user_id")
        async def add_user_to_group(group_id: str, user_id: str, ctx: Context = None) -> list:
            ...

        @validate_ids("policy_id", error_return_type="dict")
        async def get_policy(ctx: Context, policy_id: str) -> dict:
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            # Get function signature to map positional args to parameter names
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Validate each specified ID parameter
            for param_name in id_params:
                if param_name in bound_args.arguments:
                    id_value = bound_args.arguments[param_name]
                    if id_value is not None:  # Skip None values (optional params)
                        try:
                            validate_okta_id(id_value, param_name)
                        except InvalidOktaIdError as e:
                            logger.error(f"Invalid {param_name}: {e}")
                            if error_return_type == "dict":
                                return {"error": str(e)}
                            else:  # default to list
                                return [f"Error: {e}"]

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            # Get function signature to map positional args to parameter names
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Validate each specified ID parameter
            for param_name in id_params:
                if param_name in bound_args.arguments:
                    id_value = bound_args.arguments[param_name]
                    if id_value is not None:
                        try:
                            validate_okta_id(id_value, param_name)
                        except InvalidOktaIdError as e:
                            logger.error(f"Invalid {param_name}: {e}")
                            if error_return_type == "dict":
                                return {"error": str(e)}
                            else:
                                return [f"Error: {e}"]

            return func(*args, **kwargs)

        # Return appropriate wrapper based on whether function is async
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
