# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.users.read", error_return_type="list")
@validate_ids("user_id")
async def list_user_groups(user_id: str, ctx: Context = None) -> list:
    """List all groups that a user is a member of.

    This tool retrieves all groups of which the specified user is a member.
    To list all groups in your org, use list_groups() from the Groups tools instead.

    Parameters:
        user_id (str, required): The ID, login, or login shortname of the user.

    Returns:
        List of group objects the user belongs to.
    """
    logger.info(f"Listing groups for user: {user_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to list groups for user {user_id}")

        groups, _, err = await client.list_user_groups(user_id)

        if err:
            logger.error(f"Okta API error while listing groups for user {user_id}: {err}")
            return [f"Error: {err}"]

        if not groups:
            logger.info(f"No groups found for user {user_id}")
            return []

        logger.info(f"Successfully retrieved {len(groups)} groups for user {user_id}")
        return groups

    except Exception as e:
        logger.error(f"Exception while listing groups for user {user_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]
