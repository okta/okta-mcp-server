# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, List, Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta.models.device_assurance import DeviceAssurance

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DELETE_DEVICE_ASSURANCE_POLICY
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
async def list_device_assurance_policies(ctx: Context) -> Dict[str, Any]:
    """List all Device Assurance Policies in the Okta organization.

    Use this to audit which device assurance policies exist, compare OS
    version requirements across policies, find policies that do or do not
    block jailbroken/rooted devices, or identify policies whose platform
    requirements may be outdated.

    Returns:
        Dict containing:
            - policies (List[Dict]): List of device assurance policy objects.
            - error (str): Error message if the operation fails.
    """
    logger.info("Listing device assurance policies")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        policies, _, err = await okta_client.list_device_assurance_policies()

        if err:
            logger.error(f"Error listing device assurance policies: {err}")
            return {"error": str(err)}

        if not policies:
            logger.info("No device assurance policies found")
            return {"policies": []}

        logger.info(f"Successfully retrieved {len(policies)} device assurance policy(ies)")
        return {"policies": [policy.to_dict() for policy in policies]}

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

    Parameters:
        device_assurance_id (str, required): The ID of the device assurance policy.

    Returns:
        Dict containing the full policy details, or an error dict.
    """
    logger.info(f"Getting device assurance policy {device_assurance_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        policy, _, err = await okta_client.get_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Error getting device assurance policy {device_assurance_id}: {err}")
            return {"error": str(err)}

        return policy.to_dict() if policy else None

    except Exception as e:
        logger.error(f"Exception getting device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def create_device_assurance_policy(
    ctx: Context, policy_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Create a new Device Assurance Policy.

    Parameters:
        policy_data (dict, required): The device assurance policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): Target platform.
                One of: ANDROID, IOS, MACOS, WINDOWS, CHROMEOS.
            - osVersion (dict, optional): Minimum OS version requirements.
                Example: {\"minimum\": \"14.0.0\"}
            - diskEncryptionType (dict, optional): Required disk encryption types.
            - secureHardwarePresent (bool, optional): Require secure hardware (e.g. TPM).
            - screenLockType (dict, optional): Required screen lock types.
            - jailbreak (bool, optional): Block jailbroken/rooted devices.
            - thirdPartySignalProviders (dict, optional): Third-party signal providers config.

    Returns:
        Dict containing the created policy details, or an error dict.
    """
    logger.info("Creating new device assurance policy")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        policy_model = DeviceAssurance.from_dict(policy_data)
        policy, _, err = await okta_client.create_device_assurance_policy(policy_model)

        if err:
            logger.error(f"Error creating device assurance policy: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully created device assurance policy {policy.id if policy else 'unknown'}")
        return policy.to_dict() if policy else None

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

    Parameters:
        device_assurance_id (str, required): The ID of the policy to update.
        policy_data (dict, required): The complete updated policy configuration.
            - name (str, required): The policy name.
            - platform (str, required): Target platform.
                One of: ANDROID, IOS, MACOS, WINDOWS, CHROMEOS.
            - osVersion (dict, optional): Minimum OS version requirements.
                Example: {\"minimum\": \"14.2.1\"}
            - diskEncryptionType (dict, optional): Required disk encryption types.
            - secureHardwarePresent (bool, optional): Require secure hardware.
            - screenLockType (dict, optional): Required screen lock types.
            - jailbreak (bool, optional): Block jailbroken/rooted devices.
            - thirdPartySignalProviders (dict, optional): Third-party signal providers config.

    Returns:
        Dict containing the updated policy details, or an error dict.
    """
    logger.info(f"Replacing device assurance policy {device_assurance_id}")
    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        policy_model = DeviceAssurance.from_dict(policy_data)
        policy, _, err = await okta_client.replace_device_assurance_policy(
            device_assurance_id, policy_model
        )

        if err:
            logger.error(f"Error replacing device assurance policy {device_assurance_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully replaced device assurance policy {device_assurance_id}")
        return policy.to_dict() if policy else None

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
    """
    logger.warning(f"Deletion requested for device assurance policy {device_assurance_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_DEVICE_ASSURANCE_POLICY.format(policy_id=device_assurance_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Device assurance policy deletion cancelled for {device_assurance_id}")
        return {"message": "Device assurance policy deletion cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        _, _, err = await okta_client.delete_device_assurance_policy(device_assurance_id)

        if err:
            logger.error(f"Error deleting device assurance policy {device_assurance_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Device assurance policy {device_assurance_id} deleted successfully")
        return {
            "success": True,
            "message": f"Device assurance policy {device_assurance_id} deleted successfully",
        }

    except Exception as e:
        logger.error(f"Exception deleting device assurance policy {device_assurance_id}: {e}")
        return {"error": str(e)}
