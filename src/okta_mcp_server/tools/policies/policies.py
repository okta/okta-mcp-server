# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Any, Dict, Optional

from loguru import logger
from mcp.server.fastmcp import Context

import okta.models as okta_models
from okta.models.policy_rule import PolicyRule

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeactivateConfirmation, DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, extract_after_cursor, paginate_all_results
from okta_mcp_server.utils.messages import (
    DEACTIVATE_POLICY,
    DEACTIVATE_POLICY_RULE,
    DELETE_POLICY,
    DELETE_POLICY_RULE,
)
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response, none_body_error
from okta_mcp_server.utils.validation import validate_ids


# Mapping from Okta policy rule type → typed SDK model class.
# The base PolicyRule model silently drops type-specific fields like `actions` and
# `conditions`, causing 400 API errors ("Expecting an action but none were found").
# Each typed subclass preserves those fields.
_POLICY_RULE_MODEL_MAP: Dict[str, Any] = {
    "SIGN_ON": okta_models.OktaSignOnPolicyRule,
    "PASSWORD": okta_models.PasswordPolicyRule,
    "ACCESS_POLICY": okta_models.AccessPolicyRule,
    "PROFILE_ENROLLMENT": okta_models.ProfileEnrollmentPolicyRule,
    "MFA_ENROLL": okta_models.AuthenticatorEnrollmentPolicyRule,
    "IDP_DISCOVERY": okta_models.IdpDiscoveryPolicyRule,
    "DEVICE_SIGNAL_COLLECTION": okta_models.DeviceSignalCollectionPolicyRule,
    "ENTITY_RISK": okta_models.EntityRiskPolicyRule,
    "POST_AUTH_SESSION": okta_models.PostAuthSessionPolicyRule,
}


def _build_policy_rule_model(rule_data: Dict[str, Any]) -> Any:
    """Convert a plain dict to the appropriate typed Okta SDK PolicyRule model.

    The base PolicyRule model lacks type-specific fields such as `actions` and
    `conditions`. Without this mapping those fields are silently dropped, causing
    Okta API 400 errors like "Expecting an action but none were found".
    """
    rule_type = str(rule_data.get("type", "")).upper()
    model_cls = _POLICY_RULE_MODEL_MAP.get(rule_type, PolicyRule)
    logger.debug(f"Using model class '{model_cls.__name__}' for rule type '{rule_type}'")
    return model_cls.from_dict(rule_data)


@mcp.tool()
@require_scopes("okta.policies.read")
@json_response
async def list_policies(
    ctx: Context,
    type: str,
    status: Optional[str] = None,
    q: Optional[str] = None,
    limit: Optional[int] = None,
    after: Optional[str] = None,
    fetch_all: bool = False,
) -> Dict[str, Any]:
    """List all the policies from the Okta organization with pagination support.

    Parameters:
        type (str, required): Specifies the type of policy to return. Available policy types are:
            OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, IDP_DISCOVERY, ACCESS_POLICY,
            PROFILE_ENROLLMENT, POST_AUTH_SESSION, ENTITY_RISK
        status (str, optional): Refines the query by the status of the policy - ACTIVE or INACTIVE.
        q (str, optional): A query string to search policies by name.
        limit (int, optional): Number of results to return per page (min 20, max 100). Default: 20.
        after (str, optional): Pagination cursor for the next page of policies.
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
            - items (List[Dict]): List of policy dictionaries
            - total_fetched (int): Number of policies returned
            - has_more (bool): Whether more results are available
            - next_cursor (str | None): Cursor for the next page
            - fetch_all_used (bool): Whether fetch_all was used
            - pagination_info (Dict): Detailed pagination metadata (when fetch_all=True)
            - error (str): Error message if the operation fails
    """
    logger.info("Listing policies from Okta organization")
    logger.debug(f"Type: '{type}', Status: '{status}', Q: '{q}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}")

    if limit is None:
        limit = 20

    # Validate limit parameter range
    if limit < 20:
        logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
        limit = 20
    elif limit > 100:
        logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
        limit = 100

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        effective_limit = 100 if fetch_all else limit
        params = build_query_params(q=q, after=after, limit=effective_limit)
        if "limit" in params:
            params["limit"] = str(params["limit"])
        params["type"] = type
        if status:
            params["status"] = status

        logger.debug("Calling Okta API to list policies")
        policies, response, err = await okta_client.list_policies(**params)

        if err:
            logger.error(f"Error listing policies: {err}")
            return {"error": str(err)}

        if not policies:
            logger.info("No policies found")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(policies)} policies")

            async def _next_page(cursor):
                p = {k: v for k, v in params.items() if k != "after"}
                p["after"] = cursor
                return await okta_client.list_policies(**p)

            async def _on_page(pages, total):
                logger.info(f"[list_policies] Page {pages} fetched — {total} policies so far")

            all_policies, pagination_info = await paginate_all_results(
                response, policies, next_page_fn=_next_page, on_page=_on_page
            )
            logger.info(f"Successfully retrieved {len(all_policies)} policies across {pagination_info['pages_fetched']} pages")
            return create_paginated_response(all_policies, response, fetch_all_used=True, pagination_info=pagination_info)

        logger.info(f"Successfully retrieved {len(policies)} policies")
        return create_paginated_response(policies, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception listing policies: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.read")
@validate_ids("policy_id", error_return_type="dict")
@json_response
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

        if policy is None:
            return none_body_error(
                "get_policy",
                f"retrieving policy {policy_id!r}",
                "Verify the ID with list_policies(type=...).",
            )

        return policy

    except Exception as e:
        logger.error(f"Exception getting policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@json_response
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

        if policy is None:
            return none_body_error(
                "create_policy",
                f"creating policy {policy_data.get('name', 'N/A')!r}",
                "Use list_policies(type=...) to confirm and retrieve the new policy.",
            )

        return policy

    except Exception as e:
        logger.error(f"Exception creating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", error_return_type="dict")
@json_response
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
        policy, _, err = await okta_client.replace_policy(policy_id, policy_data)

        if err:
            logger.error(f"Error updating policy {policy_id}: {err}")
            return {"error": str(err)}

        if policy is None:
            return none_body_error(
                "update_policy",
                f"updating policy {policy_id!r}",
                "Re-fetch with get_policy() to confirm the current state.",
            )

        return policy

    except Exception as e:
        logger.error(f"Exception updating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", error_return_type="dict")
@json_response
async def delete_policy(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """Delete a policy.

    The user will be asked for confirmation before the deletion proceeds.

    Parameters:
        policy_id (str, required): The ID of the policy to delete.

    Returns:
        Dict with success status.
    """
    logger.warning(f"Deletion requested for policy {policy_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_POLICY.format(policy_id=policy_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Policy deletion cancelled for {policy_id}")
        return {"message": "Policy deletion cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        result = await okta_client.delete_policy(policy_id)
        err = result[-1]

        if err:
            logger.error(f"Error deleting policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} deleted successfully"}

    except Exception as e:
        logger.error(f"Exception deleting policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", error_return_type="dict")
@json_response
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
        result = await okta_client.activate_policy(policy_id)
        err = result[-1]

        if err:
            logger.error(f"Error activating policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} activated successfully"}

    except Exception as e:
        logger.error(f"Exception activating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", error_return_type="dict")
@json_response
async def deactivate_policy(ctx: Context, policy_id: str) -> Dict[str, Any]:
    """Deactivate a policy.

    The user will be asked for confirmation before the deactivation proceeds.

    Parameters:
        policy_id (str, required): The ID of the policy to deactivate.

    Returns:
        Dict with success status.
    """
    logger.info(f"Deactivation requested for policy {policy_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DEACTIVATE_POLICY.format(policy_id=policy_id),
        schema=DeactivateConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Policy deactivation cancelled for {policy_id}")
        return {"message": "Policy deactivation cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        result = await okta_client.deactivate_policy(policy_id)
        err = result[-1]

        if err:
            logger.error(f"Error deactivating policy {policy_id}: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Policy {policy_id} deactivated successfully"}

    except Exception as e:
        logger.error(f"Exception deactivating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.read")
@validate_ids("policy_id", error_return_type="dict")
@json_response
async def list_policy_rules(
    ctx: Context,
    policy_id: str,
    after: Optional[str] = None,
    fetch_all: bool = False,
) -> Dict[str, Any]:
    """List all rules for a specific policy with pagination support.

    Parameters:
        policy_id (str, required): The ID of the policy.
        after (str, optional): Pagination cursor for the next page of rules.
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
            - items (List[Dict]): List of policy rule dictionaries
            - total_fetched (int): Number of rules returned
            - has_more (bool): Whether more results are available
            - next_cursor (str | None): Cursor for the next page
            - fetch_all_used (bool): Whether fetch_all was used
            - pagination_info (Dict): Detailed pagination metadata (when fetch_all=True)
            - error (str): Error message if the operation fails
    """
    manager = ctx.request_context.lifespan_context.okta_auth_manager
    okta_client = await get_okta_client(manager)

    try:
        params = {}
        if after:
            params["after"] = after

        rules, resp, err = await okta_client.list_policy_rules(policy_id, **params)

        if err:
            logger.error(f"Error listing policy rules: {err}")
            return {"error": str(err)}

        if not rules:
            logger.info("No policy rules found")
            return create_paginated_response([], resp, fetch_all_used=fetch_all)

        _has_more = (hasattr(resp, "has_next") and resp.has_next()) or bool(extract_after_cursor(resp))
        if fetch_all and resp and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(rules)} policy rules")

            async def _next_page(cursor):
                return await okta_client.list_policy_rules(policy_id, after=cursor)

            async def _on_page(pages, total):
                logger.info(f"[list_policy_rules] Page {pages} fetched — {total} rules so far")

            all_rules, pagination_info = await paginate_all_results(
                resp, rules, next_page_fn=_next_page, on_page=_on_page
            )
            logger.info(f"Successfully retrieved {len(all_rules)} rules across {pagination_info['pages_fetched']} pages")
            return create_paginated_response(all_rules, resp, fetch_all_used=True, pagination_info=pagination_info)

        logger.info(f"Successfully retrieved {len(rules)} policy rules")
        return create_paginated_response(rules, resp, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception listing policy rules: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.read")
@validate_ids("policy_id", "rule_id", error_return_type="dict")
@json_response
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

        if rule is None:
            return none_body_error(
                "get_policy_rule",
                f"retrieving rule {rule_id!r} for policy {policy_id!r}",
                "Verify the IDs with list_policy_rules(policy_id=...).",
            )

        return rule

    except Exception as e:
        logger.error(f"Exception getting policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", error_return_type="dict")
@json_response
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
        policy_rule = _build_policy_rule_model(rule_data)
        rule, _, err = await okta_client.create_policy_rule(policy_id, policy_rule)

        if err:
            logger.error(f"Error creating policy rule: {err}")
            return {"error": str(err)}

        if rule is None:
            return none_body_error(
                "create_policy_rule",
                f"creating rule {rule_data.get('name', 'N/A')!r} for policy {policy_id!r}",
                "Use list_policy_rules(policy_id=...) to confirm and retrieve the new rule.",
            )

        return rule

    except Exception as e:
        logger.error(f"Exception creating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", "rule_id", error_return_type="dict")
@json_response
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
        policy_rule = _build_policy_rule_model(rule_data)
        rule, _, err = await okta_client.replace_policy_rule(policy_id, rule_id, policy_rule)

        if err:
            logger.error(f"Error updating policy rule: {err}")
            return {"error": str(err)}

        if rule is None:
            return none_body_error(
                "update_policy_rule",
                f"updating rule {rule_id!r} for policy {policy_id!r}",
                "Re-fetch with get_policy_rule() to confirm the current state.",
            )

        return rule

    except Exception as e:
        logger.error(f"Exception updating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", "rule_id", error_return_type="dict")
@json_response
async def delete_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Dict[str, Any]:
    """Delete a policy rule.

    The user will be asked for confirmation before the deletion proceeds.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to delete.

    Returns:
        Dict with success status.
    """
    logger.warning(f"Deletion requested for policy rule {rule_id} in policy {policy_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_POLICY_RULE.format(rule_id=rule_id, policy_id=policy_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Policy rule deletion cancelled for {rule_id}")
        return {"message": "Policy rule deletion cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        result = await okta_client.delete_policy_rule(policy_id, rule_id)
        err = result[-1]

        if err:
            logger.error(f"Error deleting policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} deleted successfully"}

    except Exception as e:
        logger.error(f"Exception deleting policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", "rule_id", error_return_type="dict")
@json_response
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
        result = await okta_client.activate_policy_rule(policy_id, rule_id)
        err = result[-1]

        if err:
            logger.error(f"Error activating policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} activated successfully"}

    except Exception as e:
        logger.error(f"Exception activating policy rule: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes("okta.policies.manage")
@validate_ids("policy_id", "rule_id", error_return_type="dict")
@json_response
async def deactivate_policy_rule(ctx: Context, policy_id: str, rule_id: str) -> Dict[str, Any]:
    """Deactivate a policy rule.

    Parameters:
        policy_id (str, required): The ID of the policy.
        rule_id (str, required): The ID of the rule to deactivate.

    Returns:
        Dict with success status.
    """
    logger.info(f"Deactivation requested for policy rule {rule_id} in policy {policy_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DEACTIVATE_POLICY_RULE.format(rule_id=rule_id, policy_id=policy_id),
        schema=DeactivateConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Policy rule deactivation cancelled for {rule_id}")
        return {"message": "Policy rule deactivation cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        okta_client = await get_okta_client(manager)
        result = await okta_client.deactivate_policy_rule(policy_id, rule_id)
        err = result[-1]

        if err:
            logger.error(f"Error deactivating policy rule: {err}")
            return {"error": str(err)}

        return {"success": True, "message": f"Rule {rule_id} deactivated successfully"}

    except Exception as e:
        logger.error(f"Exception deactivating policy rule: {e}")
        return {"error": str(e)}
