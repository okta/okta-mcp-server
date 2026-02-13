# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, paginate_all_results
from okta_mcp_server.utils.validation import InvalidOktaIdError, validate_okta_id


@mcp.tool()
async def list_groups(
    ctx: Context,
    search: str = "",
    filter: Optional[str] = None,
    q: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all the groups from the Okta organization with pagination support.
    If search, filter, or q is specified, it will list only those groups that satisfy the condition.

    Parameters:
        search (str, optional): The value of the search string when searching for some specific set of groups.
        filter (str, optional): A filter string to filter groups by Okta profile attributes.
        q (str, optional): A query string to search groups by Okta profile attributes.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of groups to return per page (min 20, max 100).
        The search, filter, and q are performed on group profile attributes.

    Examples:
        For pagination:
        - First call: list_groups(search="profile.name sw \"Engineering\"")
        - Next page: list_groups(search="profile.name sw \"Engineering\"", after="cursor_value")
        - All pages: list_groups(search="profile.name sw \"Engineering\"", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of group objects
        - total_fetched: Number of groups returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing groups from Okta organization")
    logger.debug(
        f"Search: '{search}', Filter: '{filter}', Q: '{q}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}"
    )

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
        client = await get_okta_client(manager)
        query_params = build_query_params(search=search, filter=filter, q=q, after=after, limit=limit)

        logger.debug("Calling Okta API to list groups")
        groups, response, err = await client.list_groups(query_params)

        if err:
            logger.error(f"Okta API error while listing groups: {err}")
            return {"error": f"Error: {err}"}

        if not groups:
            logger.info("No groups found")
            return create_paginated_response([], response, fetch_all)

        if fetch_all and response and hasattr(response, "has_next") and response.has_next():
            logger.info(f"fetch_all=True, auto-paginating from initial {len(groups)} groups")
            all_groups, pagination_info = await paginate_all_results(response, groups)

            logger.info(
                f"Successfully retrieved {len(all_groups)} groups across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_groups, response, fetch_all_used=True, pagination_info=pagination_info
            )
        else:
            logger.info(f"Successfully retrieved {len(groups)} groups")
            return create_paginated_response(groups, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing groups: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
async def get_group(group_id: str, ctx: Context = None) -> list:
    """Get a group by ID from the Okta organization

    This tool retrieves a group by its ID from the Okta organization.

    Parameters:
        group_id (str, required): The ID of the group to retrieve.

    Returns:
        List containing the group details.
    """
    logger.info(f"Getting group with ID: {group_id}")

    try:
        validate_okta_id(group_id, "group_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid group_id: {e}")
        return {"error": f"Error: {e}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get group {group_id}")

        group, _, err = await client.get_group(group_id)

        if err:
            logger.error(f"Okta API error while getting group {group_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully retrieved group: {group_id}")
        return [group]
    except Exception as e:
        logger.error(f"Exception while getting group {group_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def create_group(profile: dict, ctx: Context = None) -> list:
    """Create a group in the Okta organization.

    This tool creates a new group in the Okta organization with the provided profile.

    Parameters:
        profile (dict, required): The profile of the group to create.

    Returns:
        List containing the created group details.
    """
    logger.info("Creating new group in Okta organization")
    logger.debug(f"Group profile: name={profile.get('name', 'N/A')}, description={profile.get('description', 'N/A')}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # Wrap the profile in a dict with 'profile' key as required by Okta SDK
        logger.debug("Calling Okta API to create group")

        group, _, err = await client.create_group({"profile": profile})

        if err:
            logger.error(f"Okta API error while creating group: {err}")
            return {"error": f"Error: {err}"}

        logger.info(
            f"Successfully created group: {group.id} ({group.profile.name if hasattr(group, 'profile') else 'N/A'})"
        )
        return [group]
    except Exception as e:
        logger.error(f"Exception while creating group: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
def delete_group(group_id: str, ctx: Context = None) -> list:
    """Delete a group by ID from the Okta organization.

    This tool deletes a group by its ID from the Okta organization, but requires confirmation. Wait for the
    user to confirm the deletion before proceeding.

    IMPORTANT: After calling this function, you MUST STOP and wait for the human user to type 'DELETE'
    as confirmation. DO NOT automatically call confirm_delete_group afterward.

    Parameters:
        group_id (str, required): The ID of the group to delete.

    Returns:
        List containing the result of the deletion operation or a confirmation request.
    """
    logger.warning(f"Deletion requested for group {group_id}, awaiting confirmation")

    # Step 1: First prompt - this is handled by the parameter request

    # Step 2: Ask for confirmation
    return [
        {
            "confirmation_required": True,
            "message": f"To confirm deletion of group {group_id}, please type 'DELETE'",
            "group_id": group_id,
        }
    ]


@mcp.tool()
async def confirm_delete_group(group_id: str, confirmation: str, ctx: Context = None) -> list:
    """Confirm and execute group deletion after receiving confirmation.

    This function MUST ONLY be called after the human user has explicitly typed 'DELETE' as confirmation.
    NEVER call this function automatically after delete_group.

    Parameters:
        group_id (str, required): The ID of the group to delete.
        confirmation (str, required): Must be 'DELETE' to confirm deletion.

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Processing deletion confirmation for group {group_id}")

    try:
        validate_okta_id(group_id, "group_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid group_id: {e}")
        return [{"error": f"Error: {e}"}]

    # Step 3: Check confirmation and delete if correct
    if confirmation != "DELETE":
        logger.warning(f"Group deletion cancelled for {group_id} - incorrect confirmation")
        return [{"error": "Deletion cancelled. Confirmation 'DELETE' was not provided correctly."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete group {group_id}")

        _, err = await client.delete_group(group_id)

        if err:
            logger.error(f"Okta API error while deleting group {group_id}: {err}")
            return [{"error": f"Error: {err}"}]

        logger.info(f"Successfully deleted group: {group_id}")
        return [{"message": f"Group {group_id} deleted successfully"}]
    except Exception as e:
        logger.error(f"Exception while deleting group {group_id}: {type(e).__name__}: {e}")
        return [{"error": f"Exception: {e}"}]


@mcp.tool()
async def update_group(group_id: str, profile: dict, ctx: Context = None) -> list:
    """Update a group by ID in the Okta organization.

    This tool updates a group by its ID with the provided profile.

    Parameters:
        group_id (str, required): The ID of the group to update.
        profile (dict, required): The new profile for the group.

    Returns:
        List containing the updated group details.
    """
    logger.info(f"Updating group with ID: {group_id}")
    logger.debug(f"Updated fields: {list(profile.keys())}")

    try:
        validate_okta_id(group_id, "group_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid group_id: {e}")
        return {"error": f"Error: {e}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # Wrap the profile in a dict with 'profile' key as required by Okta SDK
        logger.debug(f"Calling Okta API to update group {group_id}")

        group, _, err = await client.update_group(group_id, {"profile": profile})

        if err:
            logger.error(f"Okta API error while updating group {group_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully updated group: {group_id}")
        return [group]
    except Exception as e:
        logger.error(f"Exception while updating group {group_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def list_group_users(
    group_id: str,
    ctx: Context = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all users in a group by ID from the Okta organization with pagination support.

    This tool retrieves all users in a group by its ID from the Okta organization.

    Parameters:
        group_id (str, required): The ID of the group to retrieve users from.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of users to return per page (min 20, max 100).

    Examples:
        For pagination:
        - First call: list_group_users("group_id")
        - Next page: list_group_users("group_id", after="cursor_value")
        - All pages: list_group_users("group_id", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of user objects in the group
        - total_fetched: Number of users returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Listing users in group: {group_id}")
    logger.debug(f"fetch_all: {fetch_all}, after: '{after}', limit: {limit}")

    try:
        validate_okta_id(group_id, "group_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid group_id: {e}")
        return {"error": f"Error: {e}"}

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
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to list users in group {group_id}")

        query_params = build_query_params(after=after, limit=limit)
        users, response, err = await client.list_group_users(group_id, query_params)

        if err:
            logger.error(f"Okta API error while listing group users for {group_id}: {err}")
            return {"error": f"Error: {err}"}

        if not users:
            logger.info(f"No users found in group {group_id}")
            return create_paginated_response([], response, fetch_all)

        if fetch_all and response and hasattr(response, "has_next") and response.has_next():
            logger.info(f"fetch_all=True, auto-paginating from initial {len(users)} users in group {group_id}")
            all_users, pagination_info = await paginate_all_results(response, users)

            pages_fetched = pagination_info["pages_fetched"]
            logger.info(
                f"Successfully retrieved {len(all_users)} users from group {group_id} across {pages_fetched} pages"
            )
            return create_paginated_response(all_users, response, fetch_all_used=True, pagination_info=pagination_info)
        else:
            logger.info(f"Successfully retrieved {len(users)} users from group {group_id}")
            return create_paginated_response(users, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing users in group {group_id}: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
async def list_group_apps(group_id: str, ctx: Context = None) -> list:
    """List all applications in a group by ID from the Okta organization.

    This tool retrieves all applications in a group by its ID from the Okta organization.

    Parameters:
        group_id (str, required): The ID of the group to retrieve applications from.

    Returns:
        List containing the applications in the group.
    """
    logger.info(f"Listing applications assigned to group: {group_id}")

    try:
        validate_okta_id(group_id, "group_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid group_id: {e}")
        return {"error": f"Error: {e}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to list applications for group {group_id}")

        apps, _, err = await client.list_assigned_applications_for_group(group_id)

        if err:
            logger.error(f"Okta API error while listing applications for group {group_id}: {err}")
            return {"error": f"Error: {err}"}

        app_count = len(apps) if apps else 0
        logger.info(f"Successfully retrieved {app_count} applications for group {group_id}")

        return [app for app in apps]
    except Exception as e:
        logger.error(f"Exception while listing applications for group {group_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def add_user_to_group(group_id: str, user_id: str, ctx: Context = None) -> list:
    """Add a user to a group by ID in the Okta organization.

    This tool adds a user to a group by its ID in the Okta organization.

    Parameters:
        group_id (str, required): The ID of the group to add the user to.
        user_id (str, required): The ID of the user to add to the group.

    Returns:
        List containing the result of the addition operation.
    """
    logger.info(f"Adding user {user_id} to group {group_id}")

    try:
        validate_okta_id(group_id, "group_id")
        validate_okta_id(user_id, "user_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid ID: {e}")
        return {"error": f"Error: {e}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to add user {user_id} to group {group_id}")

        _, err = await client.add_user_to_group(group_id, user_id)

        if err:
            logger.error(f"Okta API error while adding user {user_id} to group {group_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully added user {user_id} to group {group_id}")
        return [{"message": "User added to group successfully"}]
    except Exception as e:
        logger.error(f"Exception while adding user {user_id} to group {group_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def remove_user_from_group(group_id: str, user_id: str, ctx: Context = None) -> list:
    """Remove a user from a group by ID in the Okta organization.

    This tool removes a user from a group by its ID in the Okta organization.

    Parameters:
        group_id (str, required): The ID of the group to remove the user from.
        user_id (str, required): The ID of the user to remove from the group.

    Returns:
        List containing the result of the removal operation.
    """
    logger.info(f"Removing user {user_id} from group {group_id}")

    try:
        validate_okta_id(group_id, "group_id")
        validate_okta_id(user_id, "user_id")
    except InvalidOktaIdError as e:
        logger.error(f"Invalid ID: {e}")
        return {"error": f"Error: {e}"}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to remove user {user_id} from group {group_id}")

        _, err = await client.remove_user_from_group(group_id, user_id)

        if err:
            logger.error(f"Okta API error while removing user {user_id} from group {group_id}: {err}")
            return {"error": f"Error: {err}"}

        logger.info(f"Successfully removed user {user_id} from group {group_id}")
        return [{"message": "User removed from group successfully"}]
    except Exception as e:
        logger.error(f"Exception while removing user {user_id} from group {group_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]
