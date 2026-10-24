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
from okta_mcp_server.utils.elicitation import DeactivateConfirmation, DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import (
    DEACTIVATE_GROUP_RULE,
    DELETE_GROUP_RULE,
    DELETE_GROUP_RULE_REMOVE_USERS,
)
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response, none_body_error
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.groups.read")
@json_response
async def list_group_rules(
    ctx: Context,
    search: str = "",
    expand: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all group rules from the Okta organization with pagination support.

    This tool retrieves group rules from the Okta organization. Group rules
    automatically assign users to groups based on defined conditions.

    Parameters:
        search (str, optional): Only return rules whose name contains this keyword.
        expand (str, optional): "groupIdToGroupNameMap" to include the names of the groups referenced by each rule.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of rules to return per page (min 20, max 100).

    Returns:
        Dict containing:
        - items: List of group rule objects
        - total_fetched: Number of rules returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing group rules from Okta organization")
    logger.debug(f"Search: '{search}', Expand: '{expand}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}")

    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit = 20
        elif limit > 100:
            logger.warning(f"Limit {limit} exceeds maximum (100), setting to 100")
            limit = 100

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(search=search, after=after, limit=limit, expand=expand)

        logger.debug("Calling Okta API to list group rules")
        rules, response, err = await client.list_group_rules(**query_params)

        if err:
            logger.error(f"Okta API error while listing group rules: {err}")
            return {"error": f"Error: {err}"}

        if not rules:
            logger.info("No group rules found")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(rules)} group rules")

            async def _next_page(cursor):
                p = {k: v for k, v in query_params.items() if k != "after"}
                p["after"] = cursor
                return await client.list_group_rules(**p)

            all_rules, pagination_info = await paginate_all_results(response, rules, next_page_fn=_next_page)

            logger.info(
                f"Successfully retrieved {len(all_rules)} group rules across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(all_rules, response, fetch_all_used=True, pagination_info=pagination_info)
        else:
            logger.info(f"Successfully retrieved {len(rules)} group rules")
            return create_paginated_response(rules, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing group rules: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.read")
@validate_ids("rule_id", error_return_type="dict")
@json_response
async def get_group_rule(rule_id: str, ctx: Context = None, expand: Optional[str] = None) -> dict:
    """Get a group rule by ID from the Okta organization.

    This tool retrieves a specific group rule by its ID.

    Parameters:
        rule_id (str, required): The ID of the group rule to retrieve.
        expand (str, optional): "groupIdToGroupNameMap" to include the names of the groups referenced by the rule.

    Returns:
        Dict containing the group rule details.
    """
    logger.info(f"Getting group rule with ID: {rule_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get group rule {rule_id}")

        query_params = build_query_params(expand=expand)
        rule, _, err = await client.get_group_rule(rule_id, **query_params)

        if err:
            logger.error(f"Okta API error while getting group rule {rule_id}: {err}")
            return {"error": f"Error: {err}"}

        if rule is None:
            return none_body_error(
                "get_group_rule",
                f"retrieving group rule {rule_id!r}",
                "Verify the ID with list_group_rules().",
            )

        logger.info(f"Successfully retrieved group rule: {rule_id}")
        return rule
    except Exception as e:
        logger.error(f"Exception while getting group rule {rule_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.manage")
@json_response
async def create_group_rule(rule_data: Dict[str, Any], ctx: Context = None, activate: bool = True) -> dict:
    """Create a new group rule in the Okta organization.

    This tool creates a new group rule that automatically assigns users to groups
    based on defined conditions.

    Parameters:
        rule_data (dict, required): The group rule configuration containing:
            - type (str, required): Must be "group_rule"
            - name (str, required): Name of the group rule (max 50 characters)
            - conditions (dict, required):
                - expression (dict, required):
                    - type (str): "urn:okta:expression:1.0"
                    - value (str): Okta Expression Language condition evaluated against the user
                      (e.g. "user.department==\"Engineering\"")
                - people (dict, optional): Users and groups excluded from the rule
                    - users (dict): {"exclude": [user IDs]}
                    - groups (dict): {"exclude": [group IDs]}
            - actions (dict, required):
                - assignUserToGroups (dict): {"groupIds": [group IDs to assign matching users to]}
            New rules are always created INACTIVE; use the activate flag to activate it.
        activate (bool, optional): Activate the rule after creation. Defaults to True.

    Example rule_data:
        {
            "type": "group_rule",
            "name": "Engineering department",
            "conditions": {
                "expression": {"type": "urn:okta:expression:1.0", "value": "user.department==\\"Engineering\\""}
            },
            "actions": {"assignUserToGroups": {"groupIds": ["00g1a2b3c4D5E6F7G8H9"]}}
        }

    Returns:
        Dict containing the created group rule details.
    """
    logger.info("Creating new group rule in Okta organization")
    logger.debug(f"Rule data keys: {list(rule_data.keys())}, name: {rule_data.get('name', 'N/A')}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug("Calling Okta API to create group rule")

        rule, _, err = await client.create_group_rule(rule_data)

        if err:
            logger.error(f"Okta API error while creating group rule: {err}")
            return {"error": f"Error: {err}"}

        if rule is None:
            return none_body_error(
                "create_group_rule",
                f"creating group rule {rule_data.get('name', 'N/A')!r}",
                "Use list_group_rules(search=...) to confirm and retrieve the new rule.",
            )

        logger.info(f"Successfully created group rule: {rule.id}")

        if activate:
            logger.info(f"Activating newly created group rule: {rule.id}")
            activate_err = (await client.activate_group_rule(rule.id))[-1]
            if activate_err:
                logger.warning(f"Rule created but activation failed: {activate_err}")
                return {
                    "rule": rule,
                    "warning": f"Rule created but activation failed: {activate_err}",
                }

        return rule
    except Exception as e:
        logger.error(f"Exception while creating group rule: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.manage")
@validate_ids("rule_id", error_return_type="dict")
@json_response
async def update_group_rule(rule_id: str, rule_data: Dict[str, Any], ctx: Context = None) -> dict:
    """Update an existing group rule in the Okta organization.

    This tool replaces the configuration of a group rule by its ID.
    The entire rule body is replaced (PUT semantics).

    Only INACTIVE rules can be updated. Deactivate the rule with deactivate_group_rule first,
    then reactivate it with activate_group_rule after updating.

    Parameters:
        rule_id (str, required): The ID of the group rule to update.
        rule_data (dict, required): The full group rule configuration, in the same shape as
            create_group_rule (type, name, conditions, actions).

    Returns:
        Dict containing the updated group rule details.
    """
    logger.info(f"Updating group rule with ID: {rule_id}")
    logger.debug(f"Updated fields: {list(rule_data.keys())}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to update group rule {rule_id}")

        rule, _, err = await client.replace_group_rule(rule_id, rule_data)

        if err:
            logger.error(f"Okta API error while updating group rule {rule_id}: {err}")
            return {"error": f"Error: {err}"}

        if rule is None:
            return none_body_error(
                "update_group_rule",
                f"updating group rule {rule_id!r}",
                "Use get_group_rule() to confirm the current state of the rule.",
            )

        logger.info(f"Successfully updated group rule: {rule_id}")
        return rule
    except Exception as e:
        logger.error(f"Exception while updating group rule {rule_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.manage")
@validate_ids("rule_id", error_return_type="dict")
@json_response
async def delete_group_rule(rule_id: str, ctx: Context = None, remove_users: bool = False) -> dict:
    """Delete a group rule by ID from the Okta organization.

    This tool deletes a group rule by its ID. The rule must be inactive (deactivated)
    before it can be deleted. The user will be asked for confirmation.

    By default, users the rule already assigned stay in the target groups.

    Parameters:
        rule_id (str, required): The ID of the group rule to delete.
        remove_users (bool, optional): If True, also remove the users this rule assigned
            from the target groups. Defaults to False.

    Returns:
        Dict with success status or error.
    """
    logger.warning(f"Deletion requested for group rule {rule_id} (remove_users={remove_users})")

    message = DELETE_GROUP_RULE_REMOVE_USERS if remove_users else DELETE_GROUP_RULE
    outcome = await elicit_or_fallback(
        ctx,
        message=message.format(rule_id=rule_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Group rule deletion cancelled for {rule_id}")
        return {"message": "Group rule deletion cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete group rule {rule_id}")

        if remove_users:
            result = await client.delete_group_rule(rule_id, remove_users=True)
        else:
            result = await client.delete_group_rule(rule_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deleting group rule {rule_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully deleted group rule: {rule_id}")
        return {"success": True, "message": f"Group rule {rule_id} deleted successfully"}
    except Exception as e:
        logger.error(f"Exception while deleting group rule {rule_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.manage")
@validate_ids("rule_id", error_return_type="dict")
@json_response
async def activate_group_rule(rule_id: str, ctx: Context = None) -> dict:
    """Activate a group rule in the Okta organization.

    This tool activates a previously deactivated group rule, making it
    take effect for automatic group assignment.

    Parameters:
        rule_id (str, required): The ID of the group rule to activate.

    Returns:
        Dict with success status.
    """
    logger.info(f"Activating group rule: {rule_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to activate group rule {rule_id}")

        result = await client.activate_group_rule(rule_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while activating group rule {rule_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully activated group rule: {rule_id}")
        return {"success": True, "message": f"Group rule {rule_id} activated successfully"}
    except Exception as e:
        logger.error(f"Exception while activating group rule {rule_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.groups.manage")
@validate_ids("rule_id", error_return_type="dict")
@json_response
async def deactivate_group_rule(rule_id: str, ctx: Context = None) -> dict:
    """Deactivate a group rule in the Okta organization.

    This tool deactivates an active group rule, stopping automatic group
    assignment for that rule. The user will be asked for confirmation.

    Parameters:
        rule_id (str, required): The ID of the group rule to deactivate.

    Returns:
        Dict with success status.
    """
    logger.info(f"Deactivation requested for group rule {rule_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DEACTIVATE_GROUP_RULE.format(rule_id=rule_id),
        schema=DeactivateConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"Group rule deactivation cancelled for {rule_id}")
        return {"message": "Group rule deactivation cancelled by user."}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate group rule {rule_id}")

        result = await client.deactivate_group_rule(rule_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deactivating group rule {rule_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully deactivated group rule: {rule_id}")
        return {"success": True, "message": f"Group rule {rule_id} deactivated successfully"}
    except Exception as e:
        logger.error(f"Exception while deactivating group rule {rule_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}
