# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import datetime
import re
from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.exceptions.exceptions import ForbiddenException, UnauthorizedException
from okta.models.device_assurance import DeviceAssurance

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_DEVICE_ASSURANCE_POLICY
from okta_mcp_server.utils.validation import validate_ids

# Semantic version pattern: X.Y, X.Y.Z, or X.Y.Z.W (each component a non-negative integer)
_SEMVER_PATTERN = re.compile(r"^\d+\.\d+(\.\d+(\.\d+)?)?$")

# Matches two-component versions (X.Y) that need normalising to X.Y.0
_TWO_COMPONENT_VERSION = re.compile(r"^\d+\.\d+$")

# Matches single-component versions (X) — valid for Android major-only OS versions
_SINGLE_COMPONENT_VERSION = re.compile(r"^\d+$")

# Security-relevant attributes that can be configured per platform.
# If an attribute is expected for a platform but absent from the API response,
# it means the organisation has NOT configured that check — not that it passed.
# Note: These reflect API constraints after testing — not all listed attributes may be
# accepted by the API for their respective platforms.
_PLATFORM_SECURITY_ATTRIBUTES: Dict[str, List[str]] = {
    "MACOS": ["osVersion", "diskEncryptionType", "screenLockType", "secureHardwarePresent"],
    "WINDOWS": ["osVersion", "diskEncryptionType", "screenLockType", "secureHardwarePresent"],
    "IOS": ["osVersion", "jailbreak", "screenLockType"],
    "ANDROID": ["osVersion", "jailbreak", "screenLockType"],
    "CHROMEOS": ["osVersion"],
}

# Maps each attribute to the ONLY platforms that support it.
# Any other platform combination must be rejected before hitting the API.
_PLATFORM_ONLY_ATTRIBUTES: Dict[str, List[str]] = {
    "diskEncryptionType": ["MACOS", "WINDOWS"],
    "secureHardwarePresent": ["MACOS", "WINDOWS"],
    "jailbreak": ["ANDROID", "IOS"],
    "screenLockType": ["ANDROID", "IOS", "MACOS", "WINDOWS"],
}


def _build_scope_error(operation: str, status: int = 403) -> Dict[str, str]:
    """Return a user-friendly error dict when the API rejects a request due to missing scope.

    Args:
        operation: Human-readable verb describing what was attempted
                   (e.g. ``"list"``, ``"create"``, ``"delete"``).  Used to pick
                   the appropriate scope hint.
        status:    HTTP status code returned by Okta (typically 401 or 403).
    """
    if operation in ("create", "replace", "delete"):
        scope_hint = "okta.deviceAssurance.manage"
    else:
        scope_hint = "okta.deviceAssurance.read"
    return {
        "error": (
            f"The Okta API call was blocked by permissions (HTTP {status}). "
            f"Missing required OAuth scope for Device Assurance Policies: '{scope_hint}'. "
            f"First, check your MCP configuration (mcp.json) and ensure your OKTA_SCOPES includes '{scope_hint}'. "
            f"Then grant the scope to your Okta OIDC app and re-authenticate before retrying."
        )
    }


def _get_configured_scopes(manager: Any) -> Optional[set[str]]:
    """Extract the configured OAuth scopes from the auth manager.

    This is intentionally based on the *configured* scopes (OKTA_SCOPES / manager.scopes),
    not the cached access token, to avoid coupling tool behavior to local keychain state
    and to keep unit tests deterministic.

    Returns:
        - set[str] if scopes could be read
        - None if the manager does not expose scopes (e.g., test doubles)
    """
    scopes_str = getattr(manager, "scopes", None)
    if not scopes_str or not isinstance(scopes_str, str):
        return None
    return set(scopes_str.split())


def _missing_required_scope(required_scope: str, manager: Any) -> bool:
    """Return True when the configured scope set is known and missing the required scope."""
    configured = _get_configured_scopes(manager)
    return configured is not None and required_scope not in configured


def _validate_os_version(policy_data: Dict[str, Any]) -> Optional[str]:
    """Validate and normalise osVersion.minimum format if present.

    Accepts X.Y, X.Y.Z, and X.Y.Z.W formats. Two-component versions (X.Y)
    are automatically normalised to X.Y.0 in-place before being sent to the API.

    Android exception: single-component major versions (e.g. "12") are accepted
    and passed through as-is — the Okta API expects the raw major version for Android
    and rejects normalised forms like "12.0.0".

    Returns an error message string if validation fails, None if valid.
    """
    os_version = policy_data.get("osVersion") or policy_data.get("os_version")
    if not os_version:
        return None

    minimum = os_version.get("minimum")
    if not minimum:
        return None

    platform = (policy_data.get("platform") or "").upper()

    # Android accepts single-component major versions (e.g. "12").
    # The Okta API for Android expects the major version as-is (e.g. "12"), not "12.0.0".
    if platform == "ANDROID" and _SINGLE_COMPONENT_VERSION.match(minimum):
        logger.debug(f"Android OS version '{minimum}' accepted as-is (major version)")
        return None

    if not _SEMVER_PATTERN.match(minimum):
        return (
            f"Invalid OS version format: '{minimum}'. "
            f"Version must be in X.Y, X.Y.Z, or X.Y.Z.W format "
            f"(e.g., '14.2', '14.2.1', '14.2.1.0'). "
            f"For Android, a major version only (e.g. '12') is also accepted."
        )

    # Normalise X.Y → X.Y.0 so the Okta API always receives a full three-component version.
    if _TWO_COMPONENT_VERSION.match(minimum):
        normalized = f"{minimum}.0"
        logger.debug(f"Normalised OS version '{minimum}' → '{normalized}'")
        os_version["minimum"] = normalized

    return None


def _validate_platform_attributes(policy_data: Dict[str, Any]) -> Optional[str]:
    """Validate that the requested attributes are supported by the given platform.

    Returns an error message string if incompatible attributes are found, None if valid.
    """
    platform = (policy_data.get("platform") or "").upper()
    if not platform:
        return None

    errors = []
    for attr, supported_platforms in _PLATFORM_ONLY_ATTRIBUTES.items():
        if policy_data.get(attr) is not None:
            if platform not in supported_platforms:
                errors.append(
                    f"'{attr}' is not supported for {platform} — "
                    f"only available on: {', '.join(supported_platforms)}."
                )
            elif attr == "jailbreak" and policy_data.get(attr) is True:
                errors.append(
                    "The 'jailbreak' attribute currently only accepts the value false. "
                    "Set jailbreak to false or omit the field entirely."
                )

    if errors:
        return (
            f"Invalid policy configuration for platform {platform}: "
            + " ".join(errors)
            + " Remove the unsupported attribute(s) and try again."
        )
    return None


def _enrich_policy_with_attribute_status(policy_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Add explicit security attribute status to a policy response.

    For each security-relevant attribute on the policy's platform, marks it as
    'configured' or 'not_configured'. This prevents ambiguity between
    "the attribute was checked and found compliant" vs "the attribute was
    never configured in this policy".
    """
    platform = policy_dict.get("platform")
    if not platform:
        return policy_dict

    expected_attrs = _PLATFORM_SECURITY_ATTRIBUTES.get(platform, [])
    attribute_status: Dict[str, str] = {}

    for attr in expected_attrs:
        value = policy_dict.get(attr)
        if value is not None:
            attribute_status[attr] = "configured"
        else:
            attribute_status[attr] = "not_configured"

    policy_dict["securityAttributeStatus"] = attribute_status
    return policy_dict


def _compute_policy_diff(
    before: Dict[str, Any], after: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Compute a structured diff between two policy states.

    Returns a list of change dicts with attribute name, before/after values,
    and a description of the security implication.
    """
    # Metadata keys to skip when comparing
    skip_keys = {
        "id", "createdBy", "createdDate", "lastUpdate", "lastUpdatedBy",
        "_links", "links", "securityAttributeStatus",
    }

    changes: List[Dict[str, Any]] = []
    all_keys = set(before.keys()) | set(after.keys())

    for key in sorted(all_keys - skip_keys):
        before_val = before.get(key)
        after_val = after.get(key)

        if before_val != after_val:
            changes.append({
                "attribute": key,
                "before": before_val,
                "after": after_val,
                "implication": _get_implication(key, before_val, after_val),
            })

    return changes


def _get_implication(attr: str, before: Any, after: Any) -> str:
    """Return a human-readable security implication for a policy change."""
    if attr == "osVersion":
        return (
            "Changes the minimum OS version requirement. Devices running "
            "older versions will fail this assurance check."
        )
    if attr == "jailbreak":
        if after:
            return "Jailbroken/rooted devices will now be blocked."
        return "Jailbroken/rooted devices will no longer be blocked by this policy."
    if attr == "diskEncryptionType":
        return (
            "Changes disk encryption requirements. Devices not meeting "
            "the new encryption standard will fail this assurance check."
        )
    if attr == "screenLockType":
        return (
            "Changes screen lock requirements. Devices without the required "
            "screen lock type will fail this assurance check."
        )
    if attr == "secureHardwarePresent":
        if after:
            return "Devices must now have secure hardware (e.g., TPM) to pass this check."
        return "Secure hardware is no longer required by this policy."
    if attr == "name":
        return "Policy display name updated."
    if attr == "platform":
        return (
            "Target platform changed. This affects which devices "
            "are evaluated against this policy."
        )
    return f"The '{attr}' setting has been modified."


@mcp.tool()
async def list_device_assurance_policies(ctx: Context) -> Dict[str, Any]:
    """List all Device Assurance Policies in the Okta organization.

    Use this to audit which device assurance policies exist, compare OS
    version requirements across policies, find policies that do or do not
    block jailbroken/rooted devices, or identify policies whose platform
    requirements may be outdated.

    IMPORTANT — always call fresh: Never reuse results from a previous call
    to resolve a policy name to an ID. Always call this tool again to get
    an up-to-date list, as policies may have been created or deleted since
    the last call. The response includes a ``retrieved_at`` timestamp — if
    the user references a policy by name that does not appear in a previous
    list, you MUST call this tool again before concluding that the policy
    does not exist.

    IMPORTANT — intermittent empty response: If this tool returns an empty
    list but the user expects policies to exist, call it again — the API
    occasionally returns an empty response on the first call after server
    start. A retry will return the correct data.

    Returns:
        Dict containing:
            - policies (List[Dict]): List of device assurance policy objects.
            - retrieved_at (str): ISO-8601 UTC timestamp of when this list
              was fetched. Use this to detect stale data.
            - note (str): Reminder that the list may become stale and must
              be re-fetched before resolving a policy name to an ID.
            - warning (str): Present if the API returned an unexpected empty
              response; the caller should retry.
            - error (str): Error message if the operation fails.

    Scope/permission errors:
        If the Okta API returns HTTP 401/403 (commonly due to missing OAuth scopes),
        this tool returns ``{"error": "..."}``.
        In that case, present the error message verbatim and STOP — do not retry
        and do not attempt follow-up actions until scopes are fixed.
    """
    logger.info("Listing device assurance policies")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Scope precheck: if we can determine the token lacks the required scope,
    # return the error immediately and do nothing else.
    if _missing_required_scope("okta.deviceAssurance.read", manager):
        return _build_scope_error("list", 403)

    try:
        okta_client = await get_okta_client(manager)
        policies, resp, err = await okta_client.list_device_assurance_policies()

        if err:
            logger.error(f"Error listing device assurance policies: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("list", err.status)
            return {"error": str(err)}

        # The SDK occasionally returns None on the first call after server start
        # (auth initialisation race). Distinguish None (transient — advise retry)
        # from an empty list (genuinely no policies configured).
        # A 4xx status with an empty body is also surfaced here — treat it as a
        # permission/scope error rather than a transient issue.
        if policies is None:
            if resp is not None and hasattr(resp, "status_code") and resp.status_code in (401, 403):
                logger.error(
                    f"list_device_assurance_policies returned HTTP {resp.status_code} "
                    "with empty body — likely a missing scope."
                )
                return _build_scope_error("list", resp.status_code)
            logger.warning(
                "SDK returned None for list_device_assurance_policies — "
                "likely a transient auth initialisation issue."
            )
            return {
                "policies": [],
                "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "warning": (
                    "The API returned an unexpected empty response. "
                    "If you expect policies to exist, please call this tool again."
                ),
                "note": (
                    "This list was retrieved at the time shown in retrieved_at. "
                    "Always call list_device_assurance_policies again before resolving "
                    "a policy name to an ID — the list may have changed since it was last fetched."
                ),
            }

        policy_list = list(policies)

        if not policy_list:
            logger.info("No device assurance policies found")
            return {
                "policies": [],
                "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "note": (
                    "This list was retrieved at the time shown in retrieved_at. "
                    "Always call list_device_assurance_policies again before resolving "
                    "a policy name to an ID — the list may have changed since it was last fetched."
                ),
            }

        logger.info(f"Successfully retrieved {len(policy_list)} device assurance policy(ies)")
        return {
            "policies": [
                _enrich_policy_with_attribute_status(policy.to_dict())
                for policy in policy_list
            ],
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "note": (
                "This list was retrieved at the time shown in retrieved_at. "
                "Always call list_device_assurance_policies again before resolving "
                "a policy name to an ID — the list may have changed since it was last fetched."
            ),
        }

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied listing device assurance policies: {e}")
        return _build_scope_error("list", e.status)
    except Exception as e:
        logger.error(f"Exception listing device assurance policies: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
async def get_device_assurance_policy(
    ctx: Context, device_assurance_id: str
) -> Optional[Dict[str, Any]]:
    """Retrieve a specific Device Assurance Policy by ID.

    Use this to inspect the full configuration of a policy — platform type
    (ANDROID, IOS, MACOS, WINDOWS, CHROMEOS), minimum OS version, disk
    encryption requirements, biometric lock settings, jailbreak/root
    detection, and any other compliance checks configured in the policy.

    IMPORTANT — name-to-ID resolution: This tool requires a policy ID, not a
    name. If the user refers to a policy by name, you MUST call
    list_device_assurance_policies() first to get a FRESH, current list before
    resolving the name to an ID. NEVER resolve a policy name using results
    already present in the conversation — those results may be stale. Even if
    you called list_device_assurance_policies moments ago, call it again: a
    policy may have been created in the Okta UI between that call and now.
    Only after receiving the fresh list may you map the name to an ID and call
    this tool.

    Parameters:
        device_assurance_id (str, required): The ID of the device assurance policy.

    Returns:
        Dict containing the full policy details, or an error dict.

    Scope/permission errors:
        If the Okta API returns HTTP 401/403 (commonly due to missing OAuth scopes),
        this tool returns ``{"error": "..."}``.
        In that case, present the error message verbatim and STOP — do not retry
        and do not attempt follow-up actions until scopes are fixed.
    """
    logger.info(f"Getting device assurance policy {device_assurance_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    if _missing_required_scope("okta.deviceAssurance.read", manager):
        return _build_scope_error("get", 403)

    try:
        okta_client = await get_okta_client(manager)
        policy, _, err = await okta_client.get_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Error getting device assurance policy {device_assurance_id}: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("get", err.status)
            return {"error": str(err)}

        if not policy:
            return None
        return _enrich_policy_with_attribute_status(policy.to_dict())

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied getting device assurance policy {device_assurance_id}: {e}")
        return _build_scope_error("get", e.status)
    except Exception as e:
        logger.error(f"Exception getting device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def create_device_assurance_policy(
    ctx: Context, policy_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Create a new Device Assurance Policy.

    Platform-specific attribute support:
        - ANDROID: name, platform, osVersion, jailbreak (false only), screenLockType
        - IOS: name, platform, osVersion, jailbreak (false only), screenLockType
        - MACOS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - WINDOWS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - CHROMEOS: name, platform, osVersion

    Parameters:
        policy_data (dict, required): The device assurance policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): Target platform.
                One of: ANDROID, IOS, MACOS, WINDOWS, CHROMEOS.
            - osVersion (dict, optional): Minimum OS version requirements.
                Format: {\"minimum\": \"X.Y.Z\"} where X.Y.Z is semantic version.
                For ANDROID, use major version only: {\"minimum\": \"12\"}
            - diskEncryptionType (dict, optional): Required disk encryption (MACOS, WINDOWS only).
                Format: {\"type\": \"ALL_INTERNAL_VOLUMES\"}
            - secureHardwarePresent (bool, optional): Require secure hardware (MACOS, WINDOWS only).
            - screenLockType (dict, optional): Required screen lock type (ANDROID, IOS, MACOS, WINDOWS).
                Format: {\"include\": [\"BIOMETRIC\"]} or {\"include\": [\"PASSCODE\", \"BIOMETRIC\"]}
                Note: For ANDROID, [\"PASSCODE\"] alone is not valid — must include BIOMETRIC.
            - jailbreak (bool, optional): Block jailbroken/rooted devices (IOS, ANDROID only).
                Note: Currently only accepts false value.

    Returns:
        Dict containing the created policy details, or an error dict.

    Scope/permission errors:
        If the Okta API returns HTTP 401/403 (commonly due to missing OAuth scopes),
        this tool returns ``{"error": "..."}``.
        In that case, present the error message verbatim and STOP — do not retry
        and do not attempt follow-up actions until scopes are fixed.
    """
    logger.info("Creating new device assurance policy")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    if _missing_required_scope("okta.deviceAssurance.manage", manager):
        return _build_scope_error("create", 403)

    try:
        version_error = _validate_os_version(policy_data)
        if version_error:
            return {"error": version_error}

        platform_error = _validate_platform_attributes(policy_data)
        if platform_error:
            return {"error": platform_error}

        okta_client = await get_okta_client(manager)
        policy_model = DeviceAssurance.from_dict(policy_data)
        policy, _, err = await okta_client.create_device_assurance_policy(policy_model)

        if err:
            logger.error(f"Error creating device assurance policy: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("create", err.status)
            return {"error": str(err)}

        logger.info(f"Successfully created device assurance policy {policy.id if policy else 'unknown'}")
        return policy.to_dict() if policy else None

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied creating device assurance policy: {e}")
        return _build_scope_error("create", e.status)
    except Exception as e:
        logger.error(f"Exception creating device assurance policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
async def replace_device_assurance_policy(
    ctx: Context, device_assurance_id: str, policy_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Replace (fully update) an existing Device Assurance Policy.

    Use this to update minimum OS version requirements, change platform
    compliance settings, or standardise policy configurations across your
    organisation.

    Platform-specific attribute support:
        - ANDROID: name, platform, osVersion, jailbreak (false only), screenLockType
        - IOS: name, platform, osVersion, jailbreak (false only), screenLockType
        - MACOS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - WINDOWS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - CHROMEOS: name, platform, osVersion

    The response includes a "before" and "after" state comparison plus a
    list of changes with security implications so the user can review what
    changed before the update takes effect.

    Parameters:
        device_assurance_id (str, required): The ID of the policy to update.
        policy_data (dict, required): The complete updated policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): Target platform.
                One of: ANDROID, IOS, MACOS, WINDOWS, CHROMEOS.
            - osVersion (dict, optional): Minimum OS version requirements.
                Format: {\"minimum\": \"X.Y.Z\"} where X.Y.Z is semantic version.
                For ANDROID, use major version only: {\"minimum\": \"12\"}
            - diskEncryptionType (dict, optional): Required disk encryption (MACOS, WINDOWS only).
                Format: {\"type\": \"ALL_INTERNAL_VOLUMES\"}
            - secureHardwarePresent (bool, optional): Require secure hardware (MACOS, WINDOWS only).
            - screenLockType (dict, optional): Required screen lock type (ANDROID, IOS, MACOS, WINDOWS).
                Format: {\"include\": [\"BIOMETRIC\"]} or {\"include\": [\"PASSCODE\", \"BIOMETRIC\"]}
                Note: For ANDROID, [\"PASSCODE\"] alone is not valid — must include BIOMETRIC.
            - jailbreak (bool, optional): Block jailbroken/rooted devices (IOS, ANDROID only).
                Note: Currently only accepts false value.

    Returns:
        Dict containing:
            - before (Dict): Policy state before the update (with securityAttributeStatus).
            - after (Dict): Policy state after the update (with securityAttributeStatus).
            - changes (List[Dict]): List of changed attributes, each with
              attribute name, before/after values, and security implication.
            - error (str): Error message if the operation fails.

    Scope/permission errors:
        If the Okta API returns HTTP 401/403 (commonly due to missing OAuth scopes),
        this tool returns ``{"error": "..."}``.
        In that case, present the error message verbatim and STOP — do not retry
        and do not attempt follow-up actions until scopes are fixed.
    """
    logger.info(f"Replacing device assurance policy {device_assurance_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    if _missing_required_scope("okta.deviceAssurance.manage", manager):
        return _build_scope_error("replace", 403)

    try:
        version_error = _validate_os_version(policy_data)
        if version_error:
            return {"error": version_error}

        platform_error = _validate_platform_attributes(policy_data)
        if platform_error:
            return {"error": platform_error}

        okta_client = await get_okta_client(manager)

        # Fetch current state for before/after comparison
        current_policy, _, fetch_err = await okta_client.get_device_assurance_policy(
            device_assurance_id
        )
        if fetch_err:
            logger.error(
                f"Error fetching current device assurance policy {device_assurance_id}: {fetch_err}"
            )
            if hasattr(fetch_err, "status") and fetch_err.status in (401, 403):
                return _build_scope_error("replace", fetch_err.status)
            return {"error": str(fetch_err)}

        before_state = _enrich_policy_with_attribute_status(
            current_policy.to_dict()
        ) if current_policy else {}

        policy_model = DeviceAssurance.from_dict(policy_data)
        policy, _, err = await okta_client.replace_device_assurance_policy(
            device_assurance_id, policy_model
        )

        if err:
            logger.error(f"Error replacing device assurance policy {device_assurance_id}: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("replace", err.status)
            return {"error": str(err)}

        if not policy:
            return None

        after_state = _enrich_policy_with_attribute_status(policy.to_dict())
        changes = _compute_policy_diff(before_state, after_state)

        logger.info(f"Successfully replaced device assurance policy {device_assurance_id}")
        return {
            "before": before_state,
            "after": after_state,
            "changes": changes,
        }

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied replacing device assurance policy {device_assurance_id}: {e}")
        return _build_scope_error("replace", e.status)
    except Exception as e:
        logger.error(f"Exception replacing device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_ids("device_assurance_id", error_return_type="dict")
async def delete_device_assurance_policy(
    ctx: Context, device_assurance_id: str
) -> Dict[str, Any]:
    """Delete a Device Assurance Policy from the Okta organization.

    Confirmation is handled server-side via MCP elicitation — call this tool
    directly without prompting the user for manual confirmation first.
    Note: A policy that is currently assigned to an authentication policy
    cannot be deleted.

    Parameters:
        device_assurance_id (str, required): The ID of the device assurance policy to delete.

    Returns:
        Dict with success status or cancellation message.

    Scope/permission errors:
        If the Okta API returns HTTP 401/403 (commonly due to missing OAuth scopes),
        this tool returns ``{"error": "..."}``.
        In that case, present the error message verbatim and STOP — do not retry
        and do not attempt follow-up actions until scopes are fixed.
    """
    logger.warning(f"Deletion requested for device assurance policy {device_assurance_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    # Scope precheck must happen before elicitation so we don't prompt for
    # confirmation when the operation cannot succeed.
    if _missing_required_scope("okta.deviceAssurance.manage", manager):
        return _build_scope_error("delete", 403)

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_DEVICE_ASSURANCE_POLICY.format(policy_id=device_assurance_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Device assurance policy deletion cancelled for {device_assurance_id}")
        return {"message": "Device assurance policy deletion cancelled by user."}

    try:
        okta_client = await get_okta_client(manager)
        result = await okta_client.delete_device_assurance_policy(device_assurance_id)
        err = result[-1]

        if err:
            logger.error(f"Error deleting device assurance policy {device_assurance_id}: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("delete", err.status)
            return {"error": str(err)}

        logger.info(f"Device assurance policy {device_assurance_id} deleted successfully")
        return {
            "success": True,
            "message": f"Device assurance policy {device_assurance_id} deleted successfully",
        }

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied deleting device assurance policy {device_assurance_id}: {e}")
        return _build_scope_error("delete", e.status)
    except Exception as e:
        logger.error(f"Exception deleting device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}
