# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Dedicated tool for investigating login failures.

Eliminates the two-call FAILURE/DENY problem by querying both outcomes in a
single tool invocation and returning a unified, categorised response.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    extract_after_cursor,
    paginate_all_results,
)

# Login-related eventTypes we care about for categorisation
_LOGIN_EVENT_TYPES = {
    "user.session.start",
    "user.authentication.auth_via_mfa",
    "user.authentication.sso",
    "user.authentication.auth_via_IDP",
    "user.authentication.auth_via_social",
    "user.authentication.auth_via_radius",
    "policy.evaluate_sign_on",
    "app.generic.unauth_app_access_attempt",
}


def _get_event_type(evt) -> str:
    """Extract eventType from an SDK object or dict."""
    if isinstance(evt, dict):
        return evt.get("event_type") or evt.get("eventType") or ""
    # SDK objects use snake_case attributes
    return getattr(evt, "event_type", None) or getattr(evt, "eventType", "") or ""


def _categorise_events(events: list) -> dict:
    """Split events into login-related and other buckets.

    Works with both raw SDK objects and dicts.
    """
    login_events = []
    other_events = []
    for evt in events:
        if _get_event_type(evt) in _LOGIN_EVENT_TYPES:
            login_events.append(evt)
        else:
            other_events.append(evt)
    return {"login_events": login_events, "other_events": other_events}


async def _fetch_logs_for_outcome(
    client,
    outcome: str,
    *,
    since: str,
    until: str,
    q: Optional[str] = None,
    user_id: Optional[str] = None,
    ctx: Optional[Context] = None,
    max_pages: int = 50,
) -> tuple[list[dict], dict]:
    """Fetch all log pages for a single outcome value. Returns (events, pagination_info)."""

    filter_expr = f'outcome.result eq "{outcome}"'
    if user_id:
        filter_expr += f' and actor.id eq "{user_id}"'

    query_params = build_query_params(
        limit=100,
        since=since,
        until=until,
        filter=filter_expr,
        q=q,
    )

    logs, response, err = await client.list_log_events(**query_params)

    if err:
        logger.error(f"Okta API error for outcome={outcome}: {err}")
        return [], {"error": str(err), "pages_fetched": 0, "stopped_early": False}

    if not logs:
        return [], {"pages_fetched": 1, "stopped_early": False, "total_fetched": 0}

    _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(
        extract_after_cursor(response)
    )

    if _has_more:
        async def _next_page(cursor):
            p = dict(query_params)
            p["after"] = cursor
            return await client.list_log_events(**p)

        label = outcome
        async def _on_page(pages, total):
            if pages % 5 == 0 and ctx:
                await ctx.info(f"Fetching {label} logs... {total} fetched so far ({pages} pages)")

        all_logs, pagination_info = await paginate_all_results(
            response, logs, max_pages=max_pages, next_page_fn=_next_page, on_page=_on_page
        )
    else:
        all_logs = logs
        pagination_info = {"pages_fetched": 1, "stopped_early": False, "total_fetched": len(logs)}

    return all_logs, pagination_info


@mcp.tool()
async def get_login_failures(
    ctx: Context = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    user_id: Optional[str] = None,
    q: Optional[str] = None,
) -> dict:
    """Investigate why a user failed to log in. Returns BOTH authentication failures AND policy-blocked sign-ins in one call.

    USE THIS TOOL (not get_logs) whenever the user asks about:
    - failed logins, login failures, sign-in problems
    - why a user can't log in / couldn't sign in
    - authentication errors, access denied
    - blocked logins, denied access
    - login issues, sign-in issues

    This tool automatically queries BOTH outcome types:
    - FAILURE: wrong password, invalid MFA, locked account, expired credentials
    - DENY: access blocked by sign-on policy (IP restriction, device trust, geo-fencing)

    A single get_logs call only returns ONE of these. This tool returns BOTH.

    Parameters:
        since (str, optional): Start of time window (ISO 8601). Defaults to 24 hours ago.
        until (str, optional): End of time window (ISO 8601). Defaults to now.
        user_id (str, optional): Okta user ID to scope the search. If provided, only
            events for this user are returned. Use list_users to find the user ID first.
        q (str, optional): Free-text search across log fields (e.g. a user's email).

    Returns:
        Dict containing:
        - failures: Events with outcome.result = FAILURE (wrong password, MFA errors, etc.)
            - login_events: Authentication/login-specific failure events
            - other_events: Other FAILURE events (token errors, DNS checks, etc.)
            - total: Total FAILURE event count
            - pagination: Pagination metadata
        - denials: Events with outcome.result = DENY (policy-blocked sign-ins)
            - login_events: Sign-on policy denial events
            - other_events: Other DENY events
            - total: Total DENY event count
            - pagination: Pagination metadata
        - summary: Human-readable summary with counts
        - time_window: The since/until range used
    """
    logger.info("Investigating login failures (FAILURE + DENY)")

    # Default time window: last 24 hours
    now = datetime.now(timezone.utc)
    if not since:
        since = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    if not until:
        until = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    logger.debug(f"Time window: {since} → {until}, user_id={user_id}, q={q}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
    except Exception as e:
        logger.error(f"Failed to get Okta client: {e}")
        return {"error": f"Failed to connect to Okta: {e}"}

    # Fetch FAILURE and DENY in parallel
    try:
        import asyncio

        failure_task = _fetch_logs_for_outcome(
            client, "FAILURE", since=since, until=until, q=q, user_id=user_id, ctx=ctx
        )
        deny_task = _fetch_logs_for_outcome(
            client, "DENY", since=since, until=until, q=q, user_id=user_id, ctx=ctx
        )

        (failure_events, failure_pagination), (deny_events, deny_pagination) = await asyncio.gather(
            failure_task, deny_task
        )
    except Exception as e:
        logger.error(f"Error fetching login failure logs: {e}")
        return {"error": f"Error fetching logs: {e}"}

    # Categorise into login-related vs other
    failure_categorised = _categorise_events(failure_events)
    deny_categorised = _categorise_events(deny_events)

    failure_login_count = len(failure_categorised["login_events"])
    deny_login_count = len(deny_categorised["login_events"])
    failure_other_count = len(failure_categorised["other_events"])
    deny_other_count = len(deny_categorised["other_events"])

    # Build summary
    summary_parts = []
    if failure_login_count > 0:
        summary_parts.append(
            f"{failure_login_count} authentication failure(s) (wrong password, MFA error, locked account, etc.)"
        )
    if deny_login_count > 0:
        summary_parts.append(
            f"{deny_login_count} policy denial(s) (blocked by sign-on policy rule)"
        )
    if failure_other_count > 0:
        summary_parts.append(
            f"{failure_other_count} other FAILURE event(s) (token errors, DNS checks, etc.)"
        )
    if deny_other_count > 0:
        summary_parts.append(f"{deny_other_count} other DENY event(s)")

    if not summary_parts:
        summary = "No login failures or policy denials found in this time window."
    else:
        summary = "Found: " + "; ".join(summary_parts) + "."

    # Check for stopped_early in either query
    warnings = []
    if failure_pagination.get("stopped_early"):
        warnings.append(
            "FAILURE query hit the page limit — results may be incomplete. "
            "Narrow the time window for complete results."
        )
    if deny_pagination.get("stopped_early"):
        warnings.append(
            "DENY query hit the page limit — results may be incomplete. "
            "Narrow the time window for complete results."
        )

    result = {
        "failures": {
            "login_events": failure_categorised["login_events"],
            "other_events": failure_categorised["other_events"],
            "total": len(failure_events),
            "pagination": failure_pagination,
        },
        "denials": {
            "login_events": deny_categorised["login_events"],
            "other_events": deny_categorised["other_events"],
            "total": len(deny_events),
            "pagination": deny_pagination,
        },
        "summary": summary,
        "time_window": {"since": since, "until": until},
    }

    if warnings:
        result["warnings"] = warnings

    if user_id:
        result["scoped_to_user"] = user_id

    logger.info(
        f"Login failure investigation complete: "
        f"{len(failure_events)} FAILURE + {len(deny_events)} DENY events "
        f"({failure_login_count} + {deny_login_count} login-related)"
    )

    return result
