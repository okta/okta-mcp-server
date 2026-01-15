# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client


@mcp.tool()
async def list_policies(
    ctx: Context,
    type: str,
    status: Optional[str] = None,
    q: Optional[str] = None,
    limit: Optional[int] = 20,
    after: Optional[str] = None,
) -> Dict[str, Any]:
    """List all the policies from the Okta organization.

    Parameters:
        type (str, required): Specifies the type of policy to return. Available policy types are:
            OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, IDP_DISCOVERY, ACCESS_POLICY,
            PROFILE_ENROLLMENT, POST_AUTH_SESSION, ENTITY_RISK
        status (str, optional): Refines the query by the status of the policy - ACTIVE or INACTIVE.
        q (str, optional): A query string to search policies by name.
        limit (int, optional): Number of results to return (min 20, max 100).
        after (str, optional): Specifies the pagination cursor for the next page of policies.

    Returns:
        Dict containing:
            - policies (List[Dict]): List of policy dictionaries, each containing policy details
            - error (str): Error message if the operation fails
    """
    logger.info("Listing policies from Okta organization")
    logger.debug(f"Type: '{type}', Status: '{status}', Q: '{q}', limit: {limit}")

    # Validate limit parameter range
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        params = {"type": type, "limit": limit}
        if status:
            params["status"] = status
        if q:
            params["q"] = q
        if after:
            params["after"] = after

        logger.debug("Calling Okta API to list policies")
        policies, _, err = await okta_client.list_policies(**params)

        if err:
            logger.error(f"Error listing policies: {err}")
            return {"error": str(err)}

        if not policies:
            logger.info("No policies found")
            return {"policies": []}

        logger.info(f"Successfully retrieved {len(policies)} policies")
        return {
            "policies": [policy.as_dict() for policy in policies],
        }

    except Exception as e:
        logger.error(f"Exception listing policies: {e}")
        return {"error": str(e)}


@mcp.tool()
async def get_policy(ctx: Context, policy_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific policy by ID.

    Parameters:
        policy_id (str, required): The ID of the policy to retrieve.

    Returns:
        Dict containing the policy details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.get_policy(policy_id)

        if err:
            logger.error(f"Error getting policy {policy_id}: {err}")
            return {"error": str(err)}

        return policy.as_dict() if policy else None

    except Exception as e:
        logger.error(f"Exception getting policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def create_policy(ctx: Context, policy_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Create a new policy.

    Parameters:
        policy_data (dict, required): The policy configuration containing:
            - type (str, required): Policy type (OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY, PROFILE_ENROLLMENT,
            POST_AUTH_SESSION, ENTITY_RISK, DEVICE_SIGNAL_COLLECTION)
            - name (str, required): Policy name
            - description (str, optional): Policy description
            - status (str, optional): ACTIVE or INACTIVE (default: ACTIVE)
            - priority (int, optional): Priority of the policy
            - conditions (dict, optional): Policy conditions
            - settings (dict, optional): Policy-specific settings

    Returns:
        Dict containing the created policy details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.create_policy(policy_data)

        if err:
            logger.error(f"Error creating policy: {err}")
            return {"error": str(err)}

        return policy.as_dict() if policy else None

    except Exception as e:
        logger.error(f"Exception creating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def update_policy(ctx: Context, policy_id: str, policy_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update an existing policy.

    Parameters:
        policy_id (str, required): The ID of the policy to update.
        policy_data (dict, required): The updated policy configuration.

    Returns:
        Dict containing the updated policy details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        policy, _, err = await okta_client.update_policy(policy_id, policy_data)

        if err:
            logger.error(f"Error updating policy {policy_id}: {err}")
            return {"error": str(err)}

        return policy.as_dict() if policy else None

    except Exception as e:
        logger.error(f"Exception updating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def delete_policy(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """Delete a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to delete.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.delete_policy(policy_id)

        if err:
            logger.error(f"Error deleting policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} deleted successfully"}

    except Exception as e:
        logger.error(f"Exception deleting policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def activate_policy(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """Activate a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to activate.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.activate_policy(policy_id)

        if err:
            logger.error(f"Error activating policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} activated successfully"}

    except Exception as e:
        logger.error(f"Exception activating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def deactivate_policy(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """Deactivate a policy.

    Parameters:
        policy_id (str, required): The ID of the policy to deactivate.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.deactivate_policy(policy_id)

        if err:
            logger.error(f"Error deactivating policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} deactivated successfully"}

    except Exception as e:
        logger.error(f"Exception deactivating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def list_policy_rules(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """List all rules for a specific policy.

    Parameters:
        policy_id (str, required): The ID of the policy.

    Returns:
        Dict containing:
            - rules (List[Dict]): List of policy rule dictionaries
            - has_next (bool): Whether there are more results
            - next_page_token (Optional[str]): Token for next page
            - error (str): Error message if the operation fails
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        rules, resp, err = await okta_client.list_policy_rules(policy_id)

        if err:
            logger.error(f"Error listing policy rules: {err}")
            return {"error": str(err)}

        if not rules:
            logger.info("No policy rules found")
            return {"rules": []}

        return {
            "rules": [rule.as_dict() for rule in rules],
            "has_next": resp.has_next() if resp else False,
            "next_page_token": resp.get_next_page_token() if resp and resp.has_next() else None,
        }

    except Exception as e:
        logger.error(f"Exception listing policy rules: {e}")
        return {"error": str(e)}


@mcp.tool()
async def get_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule.

    Returns:
        Dict containing the policy rule details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.get_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error getting policy rule: {err}")
            return {"error": str(err)}

        return rule.as_dict() if rule else None

    except Exception as e:
        logger.error(f"Exception getting policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
async def create_policy_rule(ctx: Context, policy_id: str, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Create a new rule for a policy.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_data (dict, required): The rule configuration containing:
            - name (str, required): Rule name
            - priority (int, optional): Priority of the rule
            - status (str, optional): ACTIVE or INACTIVE
            - conditions (dict, optional): Rule conditions
            - actions (dict, optional): Rule actions

    Returns:
        Dict containing the created rule details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.create_policy_rule(policy_id, rule_data)

        if err:
            logger.error(f"Error creating policy rule: {err}")
            return {"error": str(err)}

        return rule.as_dict() if rule else None

    except Exception as e:
        logger.error(f"Exception creating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
async def update_policy_rule(
    ctx: Context, policy_id: str, rule_id: str, rule_data: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Update an existing policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to update.
        rule_data (dict, required): The updated rule configuration.

    Returns:
        Dict containing the updated rule details.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        rule, _, err = await okta_client.update_policy_rule(policy_id, rule_id, rule_data)

        if err:
            logger.error(f"Error updating policy rule: {err}")
            return {"error": str(err)}

        return rule.as_dict() if rule else None

    except Exception as e:
        logger.error(f"Exception updating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
async def delete_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Dict[str, Any]:
    """Delete a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to delete.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.delete_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error deleting policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} deleted successfully"}

    except Exception as e:
        logger.error(f"Exception deleting policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
async def activate_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Dict[str, Any]:
    """Activate a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to activate.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.activate_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error activating policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} activated successfully"}

    except Exception as e:
        logger.error(f"Exception activating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
async def deactivate_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Dict[str, Any]:
    """Deactivate a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to deactivate.

    Returns:
        Dict with success status.
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        _, err = await okta_client.deactivate_policy_rule(policy_id, rule_id)

        if err:
            logger.error(f"Error deactivating policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} deactivated successfully"}

    except Exception as e:
        logger.error(f"Exception deactivating policy rule: {e}")
        return {"error": str(e)}
