from typing import Any, Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client


@mcp.tool()
async def list_profile_mappings(
    ctx: Context,
    source_id: Optional[str] = None,
    target_id: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> Any:
    """List profile mappings in the Okta organization.

    Parameters:
        source_id (str, optional): Filter by source ID (app or user type ID)
        target_id (str, optional): Filter by target ID (app or user type ID)
        after (str, optional): Pagination cursor for the next page of results
        limit (int, optional): Maximum number of mappings to return

    Returns:
        List of profile mappings.
    """
    logger.info("Listing profile mappings")
    logger.debug(f"Query parameters: source_id={source_id}, target_id={target_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        query_params = {}
        if source_id:
            query_params["sourceId"] = source_id
        if target_id:
            query_params["targetId"] = target_id
        if after:
            query_params["after"] = after
        if limit:
            query_params["limit"] = limit

        mappings, _, err = await client.list_profile_mappings(query_params)

        if err:
            logger.error(f"Okta API error while listing profile mappings: {err}")
            return {"error": str(err)}

        if not mappings:
            logger.info("No profile mappings found")
            return []

        logger.info(f"Successfully retrieved {len(mappings)} profile mappings")
        return [m for m in mappings]
    except Exception as e:
        logger.error(f"Exception while listing profile mappings: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
async def get_profile_mapping(ctx: Context, mapping_id: str) -> Any:
    """Get a profile mapping by ID.

    Parameters:
        mapping_id (str, required): The ID of the profile mapping to retrieve

    Returns:
        Dictionary containing the profile mapping details including property mappings and expressions.
    """
    logger.info(f"Getting profile mapping: {mapping_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)

        mapping, _, err = await client.get_profile_mapping(mapping_id)

        if err:
            logger.error(f"Okta API error while getting profile mapping {mapping_id}: {err}")
            return {"error": str(err)}

        logger.info(f"Successfully retrieved profile mapping: {mapping_id}")
        return mapping
    except Exception as e:
        logger.error(f"Exception while getting profile mapping {mapping_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
