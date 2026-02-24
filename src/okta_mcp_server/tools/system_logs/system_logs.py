# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import asyncio
from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)


async def paginate_system_logs(
    client, initial_response, initial_logs, initial_params, limit, max_pages=50, delay=0.1
):
    """Special pagination handler for System Logs API.

    The System Logs API has unique behavior where response.has_next() may return False
    even when more results exist (especially with since/until filters). This function
    handles pagination more robustly by:
    1. Checking if we received a full page (count == limit)
    2. Extracting the cursor from response metadata
    3. Manually making subsequent API calls until no more data

    Args:
        client: Okta client instance
        initial_response: First API response object
        initial_logs: First page of log entries
        initial_params: Query parameters dict used for initial request
        limit: Page size limit
        max_pages: Maximum pages to fetch (safety limit)
        delay: Delay between requests in seconds

    Returns:
        Tuple of (all_logs, pagination_info dict)
    """
    all_logs = list(initial_logs) if initial_logs else []
    pages_fetched = 1
    response = initial_response

    pagination_info = {
        "pages_fetched": 1,
        "total_items": len(all_logs),
        "stopped_early": False,
        "stop_reason": None,
    }

    # Continue paginating while we have a cursor or got a full page
    while pages_fetched < max_pages:
        # Try to extract cursor from response
        cursor = extract_after_cursor(response)

        # Determine if there might be more data
        got_full_page = limit and len(initial_logs if pages_fetched == 1 else []) == limit
        has_cursor = cursor is not None
        sdk_says_has_more = response and hasattr(response, "has_next") and response.has_next()

        # If no indicators of more data, stop
        if not (has_cursor or got_full_page or sdk_says_has_more):
            logger.debug("No more pagination indicators, stopping")
            break

        # If we don't have a cursor but got a full page, log warning and stop
        # (we can't continue without a cursor)
        if not has_cursor:
            if got_full_page:
                logger.warning(
                    f"Got full page of {limit} results but no cursor available. "
                    "Cannot continue pagination. Consider using smaller time ranges."
                )
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = "No cursor available despite full page"
            break

        # Add delay between requests
        if delay > 0:
            await asyncio.sleep(delay)

        # Build params for next page
        next_params = dict(initial_params)
        next_params["after"] = cursor

        try:
            logger.debug(f"Fetching page {pages_fetched + 1} with cursor: {cursor[:20]}...")
            next_logs, next_response, next_err = await client.get_logs(next_params)

            if next_err:
                logger.warning(f"Error fetching page {pages_fetched + 1}: {next_err}")
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = f"API error: {next_err}"
                break

            if not next_logs or len(next_logs) == 0:
                logger.debug("No more logs returned, stopping pagination")
                break

            all_logs.extend(next_logs)
            pages_fetched += 1
            response = next_response
            logger.info(f"Fetched page {pages_fetched}, total logs: {len(all_logs)}")

        except Exception as e:
            logger.error(f"Exception during pagination on page {pages_fetched + 1}: {e}")
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = f"Exception: {e}"
            break

    if pages_fetched >= max_pages:
        pagination_info["stopped_early"] = True
        pagination_info["stop_reason"] = f"Reached maximum page limit ({max_pages})"
        logger.warning(f"Stopped pagination at {max_pages} pages limit")

    pagination_info["pages_fetched"] = pages_fetched
    pagination_info["total_items"] = len(all_logs)

    return all_logs, pagination_info


@mcp.tool()
async def get_logs(
    ctx: Context = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    filter: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    """Retrieve system logs from the Okta organization with pagination support.

    This tool retrieves system logs from the Okta organization.

    Parameters:
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of log entries to return per page (min 20, max 100).
        since (str, optional): Filter logs since this timestamp (ISO 8601 format).
        until (str, optional): Filter logs until this timestamp (ISO 8601 format).
        filter (str, optional): Filter expression for log events.
        q (str, optional): Query string to search log events.

    Examples:
        For pagination:
        - First call: get_logs()
        - Next page: get_logs(after="cursor_value")
        - All pages: get_logs(fetch_all=True)
        - Time range: get_logs(since="2024-01-01T00:00:00.000Z", until="2024-01-02T00:00:00.000Z")

    Returns:
        Dict containing:
        - items: List of log entry objects
        - total_fetched: Number of log entries returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Retrieving system logs from Okta organization")
    logger.debug(f"fetch_all: {fetch_all}, after: '{after}', limit: {limit}, since: '{since}', until: '{until}'")

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
        logger.debug("Calling Okta API to retrieve system logs")

        query_params = build_query_params(after=after, limit=limit, since=since, until=until, filter=filter, q=q)

        logs, response, err = await client.get_logs(query_params)

        if err:
            logger.error(f"Okta API error while retrieving system logs: {err}")
            return {"error": f"Error: {err}"}

        if not logs:
            logger.info("No system logs found")
            return create_paginated_response([], response, fetch_all)

        log_count = len(logs)
        logger.debug(f"Retrieved {log_count} system log entries in first page")

        if log_count > 0:
            logger.debug(f"First log entry timestamp: {logs[0].published if hasattr(logs[0], 'published') else 'N/A'}")
            logger.debug(f"Log types found: {set(log.eventType for log in logs[:10] if hasattr(log, 'eventType'))}")

        # Handle fetch_all with special System Logs pagination
        if fetch_all:
            logger.info(f"fetch_all=True, auto-paginating from initial {log_count} log entries")
            # Use custom pagination handler that works around SDK limitations with System Logs
            all_logs, pagination_info = await paginate_system_logs(
                client, response, logs, query_params, limit or 100  # Default to 100 if limit not specified
            )

            logger.info(
                f"Successfully retrieved {len(all_logs)} log entries across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(all_logs, response, fetch_all_used=True, pagination_info=pagination_info)
        else:
            logger.info(f"Successfully retrieved {log_count} system log entries")
            return create_paginated_response(logs, response, fetch_all_used=fetch_all)

    except Exception as e:
        logger.error(f"Exception while retrieving system logs: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}
