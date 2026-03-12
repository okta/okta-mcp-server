# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import csv
import os
from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta.models.create_user_request import CreateUserRequest
from okta.models.update_user_request import UpdateUserRequest

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.elicitation import DeactivateConfirmation, DeleteConfirmation, elicit_or_fallback
from okta_mcp_server.utils.messages import DEACTIVATE_USER, DELETE_USER
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, extract_after_cursor, paginate_all_results
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
            NOTE: fetch_all is capped at 200 pages (40,000 users at 200/page).
            If the org has more users than the cap, the result will be partial. Always check
            pagination_info.stopped_early in the response — if True, the count is incomplete
            and you MUST tell the user "at least N users were found; the result may be incomplete".
            Never report a partial fetch_all count as the exact total.
            WARNING: For orgs with more than ~5,000 users, fetch_all=True returns a very large
            response that may be slow or exceed response limits. For bulk exports or auditing,
            use export_users_csv() instead — it writes directly to disk and avoids size limits.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of users to return per page (min 20, max 200).
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
    limit_clamped = None
    if limit is not None:
        if limit < 20:
            logger.warning(f"Limit {limit} is below minimum (20), setting to 20")
            limit_clamped = f"limit {limit} is below minimum (20); clamped to 20"
            limit = 20
        elif limit > 200:
            logger.warning(f"Limit {limit} exceeds maximum (200), setting to 200")
            limit_clamped = f"limit {limit} exceeds maximum (200); clamped to 200"
            limit = 200

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        # When fetch_all=True, force limit=200 on every page to minimise API
        # round-trips regardless of what the caller passed in as `limit`.
        effective_limit = 200 if fetch_all else limit
        query_params = build_query_params(search=search, filter=filter, q=q, after=after, limit=effective_limit)

        logger.debug("Calling Okta API to list users")
        users, response, err = await client.list_users(**query_params)

        if err:
            logger.error(f"Okta API error while listing users: {err}")
            return {"error": f"Error: {err}"}

        if not users:
            logger.info("No users found")
            result = create_paginated_response([], response, fetch_all_used=fetch_all)
            if limit_clamped:
                result["warning"] = limit_clamped
            return result

        # Convert users to the expected format
        user_items = [(user.profile, user.id) for user in users]

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(users)} users")

            async def _next_page(cursor):
                # Always use max page size during fetch_all to minimise API
                # round-trips, regardless of the caller-supplied limit.
                p = {k: v for k, v in query_params.items() if k not in ["after", "limit"]}
                p["after"] = cursor
                p["limit"] = 200
                return await client.list_users(**p)

            async def _on_page(pages, total):
                logger.info(f"[list_users] Page {pages} fetched — {total} users total so far")
                if pages % 5 == 0:
                    await ctx.info(f"Fetching users... {total} fetched so far ({pages} pages)")

            all_users, pagination_info = await paginate_all_results(
                response, users, next_page_fn=_next_page, on_page=_on_page, max_pages=200
            )
            all_user_items = [(user.profile, user.id) for user in all_users]

            logger.info(
                f"Successfully retrieved {len(all_user_items)} users across {pagination_info['pages_fetched']} pages"
            )
            result = create_paginated_response(
                all_user_items, response, fetch_all_used=True, pagination_info=pagination_info
            )
            if limit_clamped:
                result["warning"] = limit_clamped
            # When a manual `after` cursor was supplied AND fetch_all=True, total_fetched
            # only counts users from that cursor onwards — not the full org total.
            # Surface this so the LLM can communicate it accurately to the user.
            if after:
                result["pagination_note"] = (
                    "fetch_all resumed from the provided 'after' cursor. "
                    f"'total_fetched' ({result['total_fetched']}) counts only the users fetched "
                    "from that cursor onwards, not the total org count."
                )
            if pagination_info.get("stopped_early"):
                result["warning"] = (
                    f"fetch_all stopped early after {pagination_info['pages_fetched']} pages "
                    f"({result['total_fetched']} users). The org has more users. "
                    f"Reason: {pagination_info.get('stop_reason')}. "
                    "Use export_users_csv() for a complete export of large orgs."
                )
            return result
        else:
            logger.info(f"Successfully retrieved {len(user_items)} users")
            result = create_paginated_response(user_items, response, fetch_all_used=fetch_all)
            if limit_clamped:
                result["warning"] = limit_clamped
            return result

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

        users, _, err = await client.list_users(limit=1)

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

        user, _, err = await client.get_user(user_id)

        if err:
            logger.error(f"Okta API error while getting user {user_id}: {err}")
            return [f"Error: {err}"]

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
        # Wrap the profile in a CreateUserRequest model as required by Okta SDK v3
        user_data = CreateUserRequest.from_dict({"profile": profile})
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
        # Wrap the profile in an UpdateUserRequest model as required by Okta SDK v3
        user_data = UpdateUserRequest.from_dict({"profile": profile})
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

        result = await client.deactivate_user(user_id)
        err = result[-1]

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

        result = await client.delete_user(user_id)
        err = result[-1]

        if err:
            logger.error(f"Okta API error while deleting user {user_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deleted user: {user_id}")
        return [f"User {user_id} deleted successfully."]
    except Exception as e:
        logger.error(f"Exception while deleting user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def export_users_csv(
    ctx: Context,
    output_path: str = "/tmp/okta_users_export.csv",
    search: str = "",
    filter: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    """Fetch all users from the Okta organization and save them to a CSV file on disk.

    Uses the same pagination logic as list_users (fetch_all=True) but writes results
    directly to a CSV file instead of returning them, avoiding response size limits.

    Parameters:
        output_path (str): Absolute path where the CSV file will be written.
            Defaults to /tmp/okta_users_export.csv.
        search (str, optional): Search expression for filtering users.
        filter (str, optional): Filter string for users.
        q (str, optional): Query string for users.

    Returns:
        Dict containing:
        - output_path: Path to the written CSV file
        - total_users: Total number of users written
        - pages_fetched: Number of pages fetched
        - stopped_early: Whether pagination hit the page cap
        - stop_reason: Reason pagination stopped (if stopped_early)
    """
    logger.info(f"export_users_csv: starting export to {output_path}")

    CSV_FIELDS = [
        "id", "status", "login", "email", "firstName", "lastName",
        "displayName", "mobilePhone", "primaryPhone", "department",
        "title", "organization", "userType", "employeeNumber",
        "costCenter", "division", "manager",
    ]

    # SDK v3 UserProfile stores attributes in snake_case (first_name, not firstName).
    # Map CSV column names (camelCase) → SDK attribute names (snake_case).
    _PROFILE_ATTR = {
        "firstName": "first_name",
        "lastName": "last_name",
        "displayName": "display_name",
        "mobilePhone": "mobile_phone",
        "primaryPhone": "primary_phone",
        "userType": "user_type",
        "employeeNumber": "employee_number",
        "costCenter": "cost_center",
        # Already snake_case in SDK v3:
        "login": "login",
        "email": "email",
        "department": "department",
        "title": "title",
        "organization": "organization",
        "division": "division",
        "manager": "manager",
    }

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(search=search, filter=filter, q=q, limit=200)

        logger.debug("Calling Okta API — first page")
        users, response, err = await client.list_users(**query_params)

        if err:
            logger.error(f"Okta API error: {err}")
            return {"error": str(err)}

        if not users:
            logger.info("No users found")
            return {"output_path": output_path, "total_users": 0, "pages_fetched": 1}

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))

        all_users = list(users)
        pagination_info = {"pages_fetched": 1, "total_items": len(all_users), "stopped_early": False, "stop_reason": None}

        if _has_more:
            async def _next_page(cursor):
                p = {k: v for k, v in query_params.items() if k != "after"}
                p["after"] = cursor
                return await client.list_users(**p)

            async def _on_page(pages, total):
                logger.info(f"[export_users_csv] Page {pages} fetched — {total} users so far")
                if pages % 5 == 0:
                    await ctx.info(f"Exporting users... {total} written so far ({pages} pages)")

            all_users, pagination_info = await paginate_all_results(
                response, users, next_page_fn=_next_page, on_page=_on_page
            )

        # Write CSV
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for user in all_users:
                profile = user.profile

                def pget(csv_col, _profile=profile):
                    # Try all known attribute name variants for the given CSV column name.
                    # Okta SDK v3 (Pydantic v2) stores fields in snake_case internally
                    # (e.g. first_name, last_name), but some builds expose camelCase.
                    # Try: mapped snake_case → original camelCase → dict lookup (for
                    # dynamic/custom profiles) → empty string as last resort.
                    sdk_attr = _PROFILE_ATTR.get(csv_col, csv_col)

                    # 1. Pydantic snake_case attribute (SDK v3 primary)
                    val = getattr(_profile, sdk_attr, None)
                    if val is not None and val != "":
                        return val

                    # 2. CamelCase attribute (SDK v3 fallback / some builds)
                    if sdk_attr != csv_col:
                        val = getattr(_profile, csv_col, None)
                        if val is not None and val != "":
                            return val

                    # 3. Dict-style access for dynamic/custom profile attributes
                    if hasattr(_profile, "__dict__"):
                        val = _profile.__dict__.get(sdk_attr) or _profile.__dict__.get(csv_col)
                        if val is not None and val != "":
                            return val

                    # 4. model_fields / model_dump for Pydantic v2 models
                    if hasattr(_profile, "model_dump"):
                        try:
                            dumped = _profile.model_dump(by_alias=True)
                            val = dumped.get(csv_col) or dumped.get(sdk_attr)
                            if val is not None and val != "":
                                return val
                        except Exception:
                            pass

                    return ""

                writer.writerow({
                    "id": getattr(user, "id", ""),
                    "status": getattr(user, "status", ""),
                    "login": pget("login"),
                    "email": pget("email"),
                    "firstName": pget("firstName"),
                    "lastName": pget("lastName"),
                    "displayName": pget("displayName"),
                    "mobilePhone": pget("mobilePhone"),
                    "primaryPhone": pget("primaryPhone"),
                    "department": pget("department"),
                    "title": pget("title"),
                    "organization": pget("organization"),
                    "userType": pget("userType"),
                    "employeeNumber": pget("employeeNumber"),
                    "costCenter": pget("costCenter"),
                    "division": pget("division"),
                    "manager": pget("manager"),
                })

        total = len(all_users)
        logger.info(f"export_users_csv: wrote {total} users to {output_path}")
        await ctx.info(f"Export complete! {total} users written to {output_path}")

        # Count users with missing firstName/lastName so the LLM can surface a note.
        missing_names = sum(
            1 for u in all_users
            if not (getattr(u.profile, "first_name", None) or getattr(u.profile, "firstName", None))
            or not (getattr(u.profile, "last_name", None) or getattr(u.profile, "lastName", None))
        )

        result = {
            "output_path": output_path,
            "total_users": total,
            "pages_fetched": pagination_info["pages_fetched"],
            "stopped_early": pagination_info["stopped_early"],
            "stop_reason": pagination_info.get("stop_reason"),
        }
        if missing_names > 0:
            result["note"] = (
                f"{missing_names} of {total} users have empty firstName or lastName in the CSV. "
                "This means those users were created in Okta without a first/last name — "
                "the data is not missing from the export, it is simply not set in Okta for those accounts."
            )
        return result

    except Exception as e:
        logger.error(f"Exception in export_users_csv: {type(e).__name__}: {e}")
        return {"error": str(e)}
