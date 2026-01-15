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
async def list_applications(
    ctx: Context,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    filter: Optional[str] = None,
    expand: Optional[str] = None,
    include_non_deleted: Optional[bool] = None,
) -> list:
    """List all applications from the Okta organization.

    Parameters:
        q (str, optional): Searches for applications by label, property, or link
        after (str, optional): Specifies the pagination cursor for the next page of results
        limit (int, optional): Specifies the number of results per page (min 20, max 100)
        filter (str, optional): Filters applications by status, user.id, group.id, or credentials.signing.kid
        expand (str, optional): Expands the app user object to include the user's profile or expand the app group
        object to include the group's profile
        include_non_deleted (bool, optional): Include non-deleted applications in the results

    Returns:
        List containing the applications from the Okta organization.
    """
    logger.info("Listing applications from Okta organization")
    logger.debug(f"Query parameters: q='{q}', filter='{filter}', limit={limit}")

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
        query_params = {}

        if q:
            query_params["q"] = q
        if after:
            query_params["after"] = after
        if limit:
            query_params["limit"] = limit
        if filter:
            query_params["filter"] = filter
        if expand:
            query_params["expand"] = expand
        if include_non_deleted is not None:
            query_params["includeNonDeleted"] = include_non_deleted

        logger.debug("Calling Okta API to list applications")
        apps, _, err = await client.list_applications(query_params)

        if err:
            logger.error(f"Okta API error while listing applications: {err}")
            return [f"Error: {err}"]

        if not apps:
            logger.info("No applications found")
            return []

        logger.info(f"Successfully retrieved {len(apps)} applications")
        return [app for app in apps]
    except Exception as e:
        logger.error(f"Exception while listing applications: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def get_application(ctx: Context, app_id: str, expand: Optional[str] = None) -> Any:
    """Get an application by ID from the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to retrieve
        expand (str, optional): Expands the app user object to include the user's profile or expand the
        app group object

    Returns:
        Dictionary containing the application details or error information.
    """
    logger.info(f"Getting application with ID: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        query_params = {}
        if expand:
            query_params["expand"] = expand

        app, _, err = await client.get_application(app_id, query_params)

        if err:
            logger.error(f"Okta API error while getting application {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved application: {app_id}")
        return app
    except Exception as e:
        logger.error(f"Exception while getting application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def create_application(ctx: Context, app_config: Dict[str, Any], activate: bool = True) -> Any:
    """Create a new application in the Okta organization.

    Parameters:
        app_config (dict, required): The application configuration including name, label, signOnMode, settings, etc.
        activate (bool, optional): Execute activation lifecycle operation after creation. Defaults to True.

    Returns:
        Dictionary containing the created application details or error information.
    """
    logger.info("Creating new application in Okta organization")
    logger.debug(f"Application label: {app_config.get('label', 'N/A')}, name: {app_config.get('name', 'N/A')}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        query_params = {"activate": activate}

        logger.debug("Calling Okta API to create application")
        app, _, err = await client.create_application(app_config, query_params)

        if err:
            logger.error(f"Okta API error while creating application: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully created application")
        return app
    except Exception as e:
        logger.error(f"Exception while creating application: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def update_application(ctx: Context, app_id: str, app_config: Dict[str, Any]) -> Any:
    """Update an application by ID in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to update
        app_config (dict, required): The updated application configuration

    Returns:
        Dictionary containing the updated application details or error information.
    """
    logger.info(f"Updating application with ID: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        logger.debug(f"Calling Okta API to update application {app_id}")
        app, _, err = await client.update_application(app_id, app_config)

        if err:
            logger.error(f"Okta API error while updating application {app_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully updated application: {app_id}")
        return app
    except Exception as e:
        logger.error(f"Exception while updating application {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def delete_application(ctx: Context, app_id: str) -> list:
    """Delete an application by ID from the Okta organization.

    This tool deletes an application by its ID from the Okta organization, but requires confirmation.

    IMPORTANT: After calling this function, you MUST STOP and wait for the human user to type 'DELETE'
    as confirmation. DO NOT automatically call confirm_delete_application afterward.

    Parameters:
        app_id (str, required): The ID of the application to delete

    Returns:
        List containing the result of the deletion operation or a confirmation request.
    """
    logger.warning(f"Deletion requested for application {app_id}, awaiting confirmation")

    return [
        {
            "confirmation_required": True,
            "message": f"To confirm deletion of application {app_id}, please type 'DELETE'",
            "app_id": app_id,
        }
    ]


@mcp.tool()
async def confirm_delete_application(ctx: Context, app_id: str, confirmation: str) -> list:
    """Confirm and execute application deletion after receiving confirmation.

    This function MUST ONLY be called after the human user has explicitly typed 'DELETE' as confirmation.
    NEVER call this function automatically after delete_application.

    Parameters:
        app_id (str, required): The ID of the application to delete
        confirmation (str, required): Must be 'DELETE' to confirm deletion

    Returns:
        List containing the result of the deletion operation.
    """
    logger.info(f"Processing deletion confirmation for application {app_id}")

    if confirmation != "DELETE":
        logger.warning(f"Application deletion cancelled for {app_id} - incorrect confirmation")
        return ["Error: Deletion cancelled. Confirmation 'DELETE' was not provided correctly."]

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to delete application {app_id}")

        _, err = await client.delete_application(app_id)

        if err:
            logger.error(f"Okta API error while deleting application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deleted application: {app_id}")
        return [f"Application {app_id} deleted successfully"]
    except Exception as e:
        logger.error(f"Exception while deleting application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def activate_application(ctx: Context, app_id: str) -> list:
    """Activate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to activate

    Returns:
        List containing the result of the activation operation.
    """
    logger.info(f"Activating application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to activate application {app_id}")

        _, err = await client.activate_application(app_id)

        if err:
            logger.error(f"Okta API error while activating application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully activated application: {app_id}")
        return [f"Application {app_id} activated successfully"]
    except Exception as e:
        logger.error(f"Exception while activating application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]


@mcp.tool()
async def deactivate_application(ctx: Context, app_id: str) -> list:
    """Deactivate an application in the Okta organization.

    Parameters:
        app_id (str, required): The ID of the application to deactivate

    Returns:
        List containing the result of the deactivation operation.
    """
    logger.info(f"Deactivating application: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to deactivate application {app_id}")

        _, err = await client.deactivate_application(app_id)

        if err:
            logger.error(f"Okta API error while deactivating application {app_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully deactivated application: {app_id}")
        return [f"Application {app_id} deactivated successfully"]
    except Exception as e:
        logger.error(f"Exception while deactivating application {app_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]
