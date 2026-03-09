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
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response, extract_after_cursor, paginate_all_results

# Workaround for SDK v3.1.0 bug: when Behavior Detection is enabled the Okta API returns
# `userBehaviors` as List[dict], but LogSecurityContext expects List[StrictStr], which
# causes a ValidationError that crashes every get_logs call on sign-on/DENY events.
# Fix: relax the annotation to Optional[List[Any]] and force a Pydantic schema rebuild.
try:
    import typing as _typing
    from okta.models.log_security_context import LogSecurityContext as _LogSecurityContext

    _patched_type = _typing.Optional[_typing.List[_typing.Any]]
    _LogSecurityContext.__annotations__["user_behaviors"] = _patched_type
    if "user_behaviors" in _LogSecurityContext.model_fields:
        _LogSecurityContext.model_fields["user_behaviors"].annotation = _patched_type
    _LogSecurityContext.model_rebuild(force=True)
    logger.debug("Applied userBehaviors type workaround for LogSecurityContext (SDK v3.1.0 bug)")
except Exception as _patch_err:
    logger.warning(f"Could not apply userBehaviors workaround: {_patch_err}")


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
            Use outcome.result to filter by event outcome. Valid values are:
            - "SUCCESS"   – successful operations (e.g. logins, password changes)
            - "FAILURE"   – failed operations (e.g. wrong password, locked account)
            - "DENY"      – access blocked by a sign-on policy rule (use this for policy-blocked logins)
            - "ALLOW"     – access explicitly allowed by a sign-on policy rule
            - "CHALLENGE" – MFA or step-up challenge triggered
            - "UNKNOWN"   – outcome could not be determined
            IMPORTANT: To find login failures AND policy-blocked sign-ons, query BOTH:
              filter='outcome.result eq "FAILURE"' and filter='outcome.result eq "DENY"'
            Example: filter='outcome.result eq "DENY"' for sign-on policy denials
            Example: filter='outcome.result eq "FAILURE"' for authentication failures (wrong password etc.)
        q (str, optional): Query string to search log events.

    Examples:
        For pagination:
        - First call: get_logs()
        - Next page: get_logs(after="cursor_value")
        - All pages: get_logs(fetch_all=True)
        - Time range: get_logs(since="2024-01-01T00:00:00.000Z", until="2024-01-02T00:00:00.000Z")
        - Policy-blocked logins: get_logs(filter='outcome.result eq "DENY"')
        - Authentication failures: get_logs(filter='outcome.result eq "FAILURE"')

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

        logs, response, err = await client.list_log_events(**query_params)

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

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {log_count} log entries")

            async def _next_page(cursor):
                p = dict(query_params)
                p["after"] = cursor
                return await client.list_log_events(**p)

            async def _on_page(pages, total):
                await ctx.info(f"Fetching logs... {total} fetched so far ({pages} pages)")

            all_logs, pagination_info = await paginate_all_results(
                response, logs, next_page_fn=_next_page, on_page=_on_page
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
