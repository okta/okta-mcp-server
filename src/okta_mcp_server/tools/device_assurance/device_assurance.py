# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import datetime
from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context
from okta.exceptions.exceptions import ForbiddenException, UnauthorizedException
from okta.models.device_assurance import DeviceAssurance
from pydantic import BaseModel, ConfigDict, model_validator

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_DEVICE_ASSURANCE_POLICY
from okta_mcp_server.utils.validation import validate_ids, validate_os_version_params


# ---------------------------------------------------------------------------
# Input types for create/replace tools
#
# Pydantic BaseModel with extra='forbid' so FastMCP will reject any field that
# is not in the schema.  ``osVersion`` is intentionally absent: the OS version
# is always supplied via the top-level ``user_stated_os_version`` parameter so
# it is validated verbatim before being injected into the API payload.
# The model_validator fires BEFORE the tool body runs, giving a clear error
# message when the LLM tries to put osVersion inside policy_data.
# ---------------------------------------------------------------------------

class _ScreenLockTypeInput(BaseModel):
    model_config = ConfigDict(extra="allow")
    include: Optional[List[str]] = None


class _DiskEncryptionTypeInput(BaseModel):
    model_config = ConfigDict(extra="allow")
    type: Optional[str] = None


_OS_VERSION_IN_POLICY_DATA_ERROR = (
    "osVersion must NOT be included in policy_data. "
    "Pass the OS version as a separate parameter: user_stated_os_version. "
    "Set user_stated_os_version to the EXACT characters the user typed — "
    "do NOT normalize or append '.0'. "
    "Then retry this call with osVersion removed from policy_data."
)


class PolicyDataInput(BaseModel):
    """Accepted fields for create/replace. ``osVersion`` is intentionally excluded —
    always pass the OS version via the ``user_stated_os_version`` parameter."""
    model_config = ConfigDict(extra="forbid")

    name: Optional[str] = None
    platform: Optional[str] = None
    diskEncryptionType: Optional[_DiskEncryptionTypeInput] = None
    secureHardwarePresent: Optional[bool] = None
    screenLockType: Optional[_ScreenLockTypeInput] = None
    jailbreak: Optional[bool] = None

    @model_validator(mode="before")
    @classmethod
    def reject_os_version(cls, data: Any) -> Any:
        """Intercept osVersion before Pydantic validates anything else.

        This runs BEFORE the tool body, so the LLM sees a clear error
        immediately rather than a silent strip or an API failure.
        """
        if isinstance(data, dict) and "osVersion" in data:
            raise ValueError(_OS_VERSION_IN_POLICY_DATA_ERROR)
        return data

    def as_api_dict(self) -> Dict[str, Any]:
        """Return a plain dict of set (non-None) fields, ready for the Okta API."""
        return {k: v for k, v in self.model_dump().items() if v is not None}



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


def _enrich_policy_with_attribute_status(
    policy_dict: Dict[str, Any],
    unverifiable_attrs: Optional[set[str]] = None,
) -> Dict[str, Any]:
    """Add explicit security attribute status to a policy response.

    For each security-relevant attribute on the policy's platform, marks it as
    ``'configured'``, ``'not_configured'``, or ``'unverifiable'``. This prevents
    ambiguity between:
    - "the attribute was checked and found compliant"
    - "the attribute was never configured in this policy"
    - "the attribute could not be verified due to a partial API failure" (AC4)

    AC1: The policy ``status`` field (ACTIVE/INACTIVE) is always surfaced.
    If absent from the API response, it is set to ``"UNKNOWN"`` so the LLM
    can detect the gap rather than silently omitting it.

    AC4: If ``unverifiable_attrs`` is provided, attributes in that set are marked
    ``'unverifiable'`` rather than ``'not_configured'``, and a ``partial_failure``
    section is added to the response listing them explicitly.
    """
    platform = policy_dict.get("platform")
    if not platform:
        return policy_dict

    expected_attrs = _PLATFORM_SECURITY_ATTRIBUTES.get(platform, [])
    attribute_status: Dict[str, str] = {}
    unverifiable_set = unverifiable_attrs or set()

    for attr in expected_attrs:
        if attr in unverifiable_set:
            attribute_status[attr] = "unverifiable"
        elif policy_dict.get(attr) is not None:
            attribute_status[attr] = "configured"
        else:
            attribute_status[attr] = "not_configured"

    # AC4: Explicitly surface the list of unverifiable attributes so the LLM
    # never misrepresents them as 'not configured'.
    unverifiable_list = [a for a in expected_attrs if a in unverifiable_set]
    if unverifiable_list:
        policy_dict["partial_failure"] = {
            "unverifiable_attributes": unverifiable_list,
            "message": (
                "The following security attributes could not be verified due to "
                f"a partial API failure: {', '.join(unverifiable_list)}. "
                "Their status is unknown — do not treat them as 'not configured'."
            ),
        }

    # AC1: Always surface the policy activation status (ACTIVE / INACTIVE).
    # If the SDK model omits it, set an explicit sentinel so the LLM can detect the gap.
    if "status" not in policy_dict:
        policy_dict["status"] = "UNKNOWN"

    policy_dict["securityAttributeStatus"] = attribute_status
    return policy_dict


def _detect_unverifiable_attributes(policy_dict: Dict[str, Any], resp: Any) -> set[str]:
    """Detect which security attributes could not be verified due to a partial API response.

    A partial API failure is indicated when the HTTP response carries a 207
    (Multi-Status) status code. In that case, security attributes that are absent
    from the policy dict are considered *unverifiable* — they may be configured but
    the API could not confirm their current values.

    Returns:
        A set of attribute names that are unverifiable. Empty set when no partial
        failure is detected.
    """
    if resp is None:
        return set()

    status_code = getattr(resp, "status_code", None) or getattr(resp, "status", None)
    if status_code != 207:
        return set()

    platform = policy_dict.get("platform", "")
    expected_attrs = _PLATFORM_SECURITY_ATTRIBUTES.get(platform, [])
    # In a partial (207) response, any absent expected attribute is unverifiable.
    return {attr for attr in expected_attrs if policy_dict.get(attr) is None}


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
@validate_os_version_params("version_threshold")
async def list_device_assurance_policies(
    ctx: Context, version_threshold: Optional[str] = None
) -> Dict[str, Any]:
    """List all Device Assurance Policies in the Okta organization.

    Use this to audit which device assurance policies exist, compare OS
    version requirements across policies, find policies that do or do not
    block jailbroken/rooted devices, or identify policies whose platform
    requirements may be outdated.

    *** MANDATORY — OS VERSION THRESHOLD QUERIES ***
        Any time the user's request mentions a version number for filtering or
        comparison (e.g. "older than 14.2", "below 14.2.1", "at least 13.x"):

        1. You MUST pass that exact user-supplied string as ``version_threshold``.
           WRONG: list_device_assurance_policies()                         ← bypasses validation
           RIGHT: list_device_assurance_policies(version_threshold="<user value>") ← always pass through
           NEVER call this tool with no arguments and then filter the result
           yourself — that completely bypasses format validation.

        2. If the version is rejected (e.g. because the patch component is
           missing), relay the error word-for-word. STOP and ask the user:
           "What is the exact full version in X.Y.Z format?" Do NOT guess
           or complete the version yourself. Do NOT proceed until the user
           explicitly confirms the full X.Y.Z version.

        3. NEVER guess or infer what the user "probably" meant — always ask.

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
              Each policy includes a ``status`` field (``ACTIVE``, ``INACTIVE``,
              or ``UNKNOWN`` if the API did not return it). You MUST present this
              field when listing or comparing policies so the user sees the current
              activation state.
            - version_threshold (str, optional): Echo of the validated threshold
              when one was supplied. Use this value for any subsequent filtering
              or comparison in your response.
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
        enriched_policies = []
        for policy in policy_list:
            policy_dict = policy.to_dict()
            unverifiable = _detect_unverifiable_attributes(policy_dict, resp)
            enriched_policies.append(_enrich_policy_with_attribute_status(policy_dict, unverifiable))
        result: Dict[str, Any] = {
            "policies": enriched_policies,
            "retrieved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "note": (
                "This list was retrieved at the time shown in retrieved_at. "
                "Always call list_device_assurance_policies again before resolving "
                "a policy name to an ID — the list may have changed since it was last fetched."
            ),
        }
        if version_threshold is not None:
            result["version_threshold"] = version_threshold
        return result

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
        policy, resp, err = await okta_client.get_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Error getting device assurance policy {device_assurance_id}: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("get", err.status)
            return {"error": str(err)}

        if not policy:
            return None
        policy_dict = policy.to_dict()
        unverifiable = _detect_unverifiable_attributes(policy_dict, resp)
        return _enrich_policy_with_attribute_status(policy_dict, unverifiable)

    except (ForbiddenException, UnauthorizedException) as e:
        logger.error(f"Access denied getting device assurance policy {device_assurance_id}: {e}")
        return _build_scope_error("get", e.status)
    except Exception as e:
        logger.error(f"Exception getting device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}


@mcp.tool()
@validate_os_version_params("user_stated_os_version")
async def create_device_assurance_policy(
    ctx: Context, policy_data: PolicyDataInput, user_stated_os_version: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """Create a new Device Assurance Policy.

    *** MANDATORY — OS VERSION ***
        If the policy requires a minimum OS version:
        a. Do NOT put osVersion inside policy_data — the tool constructs it
           from user_stated_os_version after validation.
        b. Set user_stated_os_version to the EXACT characters the user typed,
           verbatim. NEVER invent or complete the version. "12.1" and
           "12.1.0" are NOT the same — never append a patch number yourself.
        c. If user_stated_os_version is rejected, relay the error and ask:
           "What is the exact full version in X.Y.Z format?"

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
            - osVersion: Do NOT include — use user_stated_os_version instead.
            - diskEncryptionType (dict, optional): Required disk encryption (MACOS, WINDOWS only).
                Format: {\"type\": \"ALL_INTERNAL_VOLUMES\"}
            - secureHardwarePresent (bool, optional): Require secure hardware (MACOS, WINDOWS only).
            - screenLockType (dict, optional): Required screen lock type (ANDROID, IOS, MACOS, WINDOWS).
                Format: {\"include\": [\"BIOMETRIC\"]} or {\"include\": [\"PASSCODE\", \"BIOMETRIC\"]}
                Note: For ANDROID, [\"PASSCODE\"] alone is not valid — must include BIOMETRIC.
            - jailbreak (bool, optional): Block jailbroken/rooted devices (IOS, ANDROID only).
                Note: Currently only accepts false value.
        user_stated_os_version (str, optional): The EXACT OS version string the user
            typed, character-for-character. Required when setting a minimum OS version.
            For ANDROID a single major version (e.g. "12") is accepted.
            For all other platforms X.Y.Z is required — X.Y alone will be rejected.

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
        # AC2: Intercept osVersion when the function is called directly (e.g. in tests)
        # without going through Pydantic/FastMCP.  In production FastMCP calls, the
        # PolicyDataInput model_validator fires first and the function is never reached
        # if osVersion is present.
        raw = policy_data if isinstance(policy_data, dict) else policy_data.as_api_dict()
        if raw.get("osVersion") and user_stated_os_version is None:
            return {"error": _OS_VERSION_IN_POLICY_DATA_ERROR}

        # Inject the verbatim-validated version into the API payload.
        if user_stated_os_version:
            raw = {**raw, "osVersion": {"minimum": user_stated_os_version}}

        platform_error = _validate_platform_attributes(raw)
        if platform_error:
            return {"error": platform_error}

        okta_client = await get_okta_client(manager)
        policy_model = DeviceAssurance.from_dict(raw)
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
@validate_os_version_params("user_stated_os_version")
async def replace_device_assurance_policy(
    ctx: Context, device_assurance_id: str, policy_data: PolicyDataInput,
    user_stated_os_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Replace (fully update) an existing Device Assurance Policy.

    *** MANDATORY RESPONSE FORMAT — YOU MUST FOLLOW THIS EVERY TIME ***
        This tool ALWAYS returns ``"before"``, ``"after"``, and ``"changes"``
        fields. After every successful call you MUST:
        1. Present a formatted before/after comparison table to the user.
        2. For every entry in ``"changes"``, show the attribute name,
           old value, new value, and the ``"implication"`` string.
        3. NEVER reply with just "Done" or a one-line summary.
           The user must see the full comparison — always.
        4. OS VERSION — always use ``user_stated_os_version`` parameter:
           a. Do NOT put osVersion in policy_data — the tool derives it from
              user_stated_os_version after validation.
           b. Set user_stated_os_version to the EXACT characters the user
              typed, verbatim. NEVER invent or complete the version. "X.Y" and
              "X.Y.0" are NOT the same — never append a patch number yourself.
           c. If user_stated_os_version is rejected, relay the error — STOP and ask:
              "What is the exact full version in X.Y.Z format?"
           d. Do NOT call this tool until the user explicitly states the full
              X.Y.Z version.

    Use this to update minimum OS version requirements, change platform
    compliance settings, or standardise policy configurations across your
    organisation.

    Platform-specific attribute support:
        - ANDROID: name, platform, osVersion, jailbreak (false only), screenLockType
        - IOS: name, platform, osVersion, jailbreak (false only), screenLockType
        - MACOS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - WINDOWS: name, platform, osVersion, diskEncryptionType, screenLockType, secureHardwarePresent
        - CHROMEOS: name, platform, osVersion

    The response ALWAYS includes ``"before"`` and ``"after"`` state comparisons
    plus a ``"changes"`` list with security implications for each modified attribute.
    You MUST present this as a formatted confirmation summary to the user, showing
    exactly what changed and its security implication. Never simply say "Done" —
    always display the before/after comparison table.

    Parameters:
        device_assurance_id (str, required): The ID of the policy to update.
        policy_data (dict, required): The complete updated policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): Target platform.
                One of: ANDROID, IOS, MACOS, WINDOWS, CHROMEOS.
            - osVersion: Do NOT include — use user_stated_os_version instead.
            - diskEncryptionType (dict, optional): Required disk encryption (MACOS, WINDOWS only).
                Format: {\"type\": \"ALL_INTERNAL_VOLUMES\"}
            - secureHardwarePresent (bool, optional): Require secure hardware (MACOS, WINDOWS only).
            - screenLockType (dict, optional): Required screen lock type (ANDROID, IOS, MACOS, WINDOWS).
                Format: {\"include\": [\"BIOMETRIC\"]} or {\"include\": [\"PASSCODE\", \"BIOMETRIC\"]}
                Note: For ANDROID, [\"PASSCODE\"] alone is not valid — must include BIOMETRIC.
            - jailbreak (bool, optional): Block jailbroken/rooted devices (IOS, ANDROID only).
                Note: Currently only accepts false value.
        user_stated_os_version (str, optional): The EXACT OS version string the user
            typed, character-for-character. Required when changing the minimum OS version.
            For ANDROID a single major version (e.g. "12") is accepted.
            For all other platforms X.Y.Z is required — X.Y alone will be rejected.

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
        # AC2: same guard as create — intercept osVersion in direct-call paths.
        raw = policy_data if isinstance(policy_data, dict) else policy_data.as_api_dict()
        if raw.get("osVersion") and user_stated_os_version is None:
            return {"error": _OS_VERSION_IN_POLICY_DATA_ERROR}

        # Inject the verbatim-validated version into the API payload.
        if user_stated_os_version:
            raw = {**raw, "osVersion": {"minimum": user_stated_os_version}}

        platform_error = _validate_platform_attributes(raw)
        if platform_error:
            return {"error": platform_error}

        okta_client = await get_okta_client(manager)

        # Fetch current state for before/after comparison
        current_policy, fetch_resp, fetch_err = await okta_client.get_device_assurance_policy(
            device_assurance_id
        )
        if fetch_err:
            logger.error(
                f"Error fetching current device assurance policy {device_assurance_id}: {fetch_err}"
            )
            if hasattr(fetch_err, "status") and fetch_err.status in (401, 403):
                return _build_scope_error("replace", fetch_err.status)
            return {"error": str(fetch_err)}

        before_dict = current_policy.to_dict() if current_policy else {}
        before_unverifiable = (
            _detect_unverifiable_attributes(before_dict, fetch_resp) if current_policy else set()
        )
        before_state = (
            _enrich_policy_with_attribute_status(before_dict, before_unverifiable)
            if current_policy else {}
        )

        policy_model = DeviceAssurance.from_dict(raw)
        policy, replace_resp, err = await okta_client.replace_device_assurance_policy(
            device_assurance_id, policy_model
        )

        if err:
            logger.error(f"Error replacing device assurance policy {device_assurance_id}: {err}")
            if hasattr(err, "status") and err.status in (401, 403):
                return _build_scope_error("replace", err.status)
            return {"error": str(err)}

        if not policy:
            return None

        after_dict = policy.to_dict()
        after_unverifiable = _detect_unverifiable_attributes(after_dict, replace_resp)
        after_state = _enrich_policy_with_attribute_status(after_dict, after_unverifiable)
        changes = _compute_policy_diff(before_state, after_state)

        logger.info(f"Successfully replaced device assurance policy {device_assurance_id}")
        return {
            "before": before_state,
            "after": after_state,
            "changes": changes,
            "_display_required": (
                "MANDATORY: Present 'before' and 'after' as a comparison table. "
                "For every entry in 'changes', show: attribute name, before value, "
                "after value, and implication. "
                "Do NOT respond with 'Done' or a brief summary."
            ),
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

    The user will be asked for confirmation before the deletion proceeds.
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
