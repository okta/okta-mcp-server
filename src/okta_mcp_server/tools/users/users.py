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
from okta_mcp_server.utils.elicitation import DeactivateConfirmation, DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DEACTIVATE_USER, DELETE_USER
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, paginate_all_results
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
async def list_users(
    ctx: Context,
    search: str = "",
    filter: Optional[str] = None,
    q: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all the users from the Okta organization with pagination support.
    If search, filter, or q is specified, it will list only those users that satisfy the condition.
    Use after and limit for pagination.
    Use fetch_all=True to automatically fetch all pages of results.
    By default, it will only fetch users whose status is not "DEPROVISIONED".

    Parameters:
        search (str, optional): The value of the search string when searching for some specific set of users.
        filter (str, optional): A filter string to filter users by Okta profile attributes.
        q (str, optional): A query string to search users by Okta profile attributes.
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of users to return per page (min 20, max 100).
        The search, filter, and q are performed on user profile attributes.

    Examples:
        To search users whose organization is Okta use search=profile.organization eq "Okta"
        To search users updated after 06/01/2013 but with a status of LOCKED_OUT or RECOVERY use
        search=lastUpdated gt "2013-06-01T00:00:00.000Z" and (status eq "LOCKED_OUT" or status eq "RECOVERY")

        For pagination:
        - First call: list_users(search="profile.department eq \"Engineering\"")
        - Next page: list_users(search="profile.department eq \"Engineering\"", after="cursor_value")
        - All pages: list_users(search="profile.department eq \"Engineering\"", fetch_all=True)

    Returns:
        Dict containing:
        - items: List of (user.profile, user.id) tuples
        - total_fetched: Number of users returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing users from Okta organization")
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

        logger.debug("Calling Okta API to list users")
        users, response, err = await client.list_users(query_params)

        if err:
            logger.error(f"Okta API error while listing users: {err}")
            return {"error": f"Error: {err}"}

        if not users:
            logger.info("No users found")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        # Convert users to the expected format
        user_items = [(user.profile, user.id) for user in users]

        if fetch_all and response and hasattr(response, "has_next") and response.has_next():
            logger.info(f"fetch_all=True, auto-paginating from initial {len(users)} users")
            all_users, pagination_info = await paginate_all_results(response, users)
            all_user_items = [(user.profile, user.id) for user in all_users]

            logger.info(
                f"Successfully retrieved {len(all_user_items)} users across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_user_items, response, fetch_all_used=True, pagination_info=pagination_info
            )
        else:
            logger.info(f"Successfully retrieved {len(user_items)} users")
            return create_paginated_response(user_items, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while listing users: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
async def get_user_profile_attributes(ctx: Context = None) -> list:
    """List all user profile attributes supported by your Okta org.
    This is helpful in case you need to check if the user profile attribute is valid.
    The prompt can contain non existent search terms, in which case we should seek clarification from the user
    by listing most similar profile attributes.

    Returns:
        A list of user profile attributes.
    """
    logger.info("Fetching user profile attributes")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug("Fetching first user to extract profile attributes")

        users, _, err = await client.list_users({"limit": 1})

        if err:
            logger.error(f"Okta API error while fetching profile attributes: {err}")
            return {"error": f"Error: {err}"}

        if len(users) > 0:
            attributes = vars(users[0].profile)
            logger.info(f"Successfully retrieved {len(attributes)} profile attributes")
            logger.debug(f"Profile attributes: {list(attributes.keys())}")
            return attributes

        logger.warning("No users found in the organization")
        return users  # no user has been created yet
    except Exception as e:
        logger.error(f"Exception while fetching profile attributes: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@validate_ids("user_id")
async def get_user(user_id: str, ctx: Context = None) -> list:
    """Get a user by ID from the Okta organization

    This tool retrieves a user by their ID from the Okta organization.

    Parameters:
        user_id (str, required): The ID of the user to retrieve.

    Returns:
        List containing the user details.
    """
    logger.info(f"Getting user with ID: {user_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get user {user_id}")

        user = await client.get_user(user_id)

        logger.info(f"Successfully retrieved user: {user.profile.email if hasattr(user, 'profile') else user_id}")
        return [user]
    except Exception as e:
        logger.error(f"Exception while getting user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def create_user(profile: dict, ctx: Context = None) -> list:
    """Create a user in the Okta organization.

    This tool creates a new user in the Okta organization with the provided profile.

    Parameters:
        profile (dict, required): The profile of the user to create.

    Returns:
        List containing the created user details.
    """
    logger.info("Creating new user in Okta organization")
    logger.debug(f"User profile: email={profile.get('email', 'N/A')}, login={profile.get('login', 'N/A')}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # Wrap the profile in a dict with 'profile' key as required by Okta SDK
        user_data = {"profile": profile}
        logger.debug("Calling Okta API to create user")

        user, _, err = await client.create_user(user_data)

        if err:
            logger.error(f"Okta API error while creating user: {err}")
            return [f"Error: {err}"]

        logger.info(
            f"Successfully created user: {user.id} ({user.profile.email if hasattr(user, 'profile') else 'N/A'})"
        )
        return [user]
    except Exception as e:
        logger.error(f"Exception while creating user: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@validate_ids("user_id")
async def update_user(user_id: str, profile: dict, ctx: Context = None) -> list:
    """Update a user in the Okta organization.

    This tool updates an existing user in the Okta organization with the provided profile.

    Parameters:
        user_id (str, required): The ID of the user to update.
        profile (dict, required): The updated profile of the user.

    Returns:
        List containing the updated user details.
    """
    logger.info(f"Updating user with ID: {user_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        user_data = {"profile": profile}
        logger.debug(f"Calling Okta API to update user {user_id}")

        user, _, err = await client.update_user(user_id, user_data)

        if err:
            logger.error(f"Okta API error while updating user {user_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully updated user: {user_id}")
        return [user]
    except Exception as e:
        logger.error(f"Exception while updating user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@validate_ids("user_id")
async def deactivate_user(user_id: str, ctx: Context = None) -> list:
    """Deactivates a user from the Okta organization.

    This tool deactivates a user from the Okta organization by their ID.
    The user will be asked for confirmation before the deactivation proceeds.
    Deactivating the user is a prerequisite for deleting the user.

    Parameters:
        user_id (str, required): The ID of the user to deactivate.

    Returns:
        List containing the result of the deactivation operation.
    """
    logger.info(f"Deactivation requested for user: {user_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DEACTIVATE_USER.format(user_id=user_id),
        schema=DeactivateConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"User deactivation cancelled for {user_id}")
        return [{"message": "User deactivation cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate user {user_id}")

        _, err = await client.deactivate_user(user_id)

        if err:
            logger.error(f"Okta API error while deactivating user {user_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deactivated user: {user_id}")
        return [f"User {user_id} deactivated successfully."]
    except Exception as e:
        logger.error(f"Exception while deactivating user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
@validate_ids("user_id")
async def delete_deactivated_user(user_id: str, ctx: Context = None) -> list:
    """Delete a user from the Okta organization who has already been deactivated or deprovisioned.

    This tool permanently deletes a deactivated/deprovisioned user. The user will be
    asked for confirmation before the deletion proceeds.

    Parameters:
        user_id (str, required): The ID of the deactivated or deprovisioned user to delete.

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Deletion requested for deactivated user: {user_id}")

    outcome = await elicit_or_fallback(
        ctx,
        message=DELETE_USER.format(user_id=user_id),
        schema=DeleteConfirmation,
        auto_confirm_on_fallback=True,
    )

    if not outcome.confirmed:
        logger.info(f"User deletion cancelled for {user_id}")
        return [{"message": "User deletion cancelled by user."}]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete user {user_id}")

        _, err = await client.deactivate_or_delete_user(user_id)

        if err:
            logger.error(f"Okta API error while deleting user {user_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deleted user: {user_id}")
        return [f"User {user_id} deleted successfully."]
    except Exception as e:
        logger.error(f"Exception while deleting user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]
