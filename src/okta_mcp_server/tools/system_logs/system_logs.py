# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import re
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

    IMPORTANT — context isolation:
        Each call is INDEPENDENT. Do NOT carry forward q, search, or filter values from
        a previous query unless the user explicitly asks to apply the same filter again.
        Example: if the user previously asked about user X and now asks "show me ALL failed
        logins", do NOT add q=<user_X_email> to the new call — that would silently scope
        results to user X only.

    IMPORTANT — fetch_all usage:
        By default (fetch_all=False) only the first page is returned (up to 100 entries).
        RULE: For ANY query about "all", "complete", "total", "how many", "list all",
        "show all", "every", or any query that does not explicitly ask for just the
        latest/most recent event, you MUST use fetch_all=True. Without it the result
        is INCOMPLETE and counts will be WRONG.
        ALWAYS pair fetch_all=True with a time window: since="...", until="..."
        Example: get_logs(fetch_all=True, filter='outcome.result eq "FAILURE"', since="2026-03-11T00:00:00.000Z", until="2026-03-12T00:00:00.000Z")
        If the user does not specify a time range, default to the last 24 hours.
        fetch_all is capped at 50 pages (5,000 entries). If stopped_early=True, tell the user
        to narrow their time window or add a more specific filter.

    CRITICAL — login failure investigation:
        FAILURE and DENY are TWO SEPARATE outcome values. A single call is NEVER sufficient.
        - FAILURE: authentication failures (wrong password, locked account, MFA not completed)
        - DENY: access blocked by a sign-on policy rule (IP/device/policy violation)
        You MUST ALWAYS make TWO separate calls when investigating login failures:
          1. get_logs(filter='outcome.result eq "FAILURE"', fetch_all=True, ...)
          2. get_logs(filter='outcome.result eq "DENY"', fetch_all=True, ...)
        Making only ONE call is a BUG — you will silently miss an entire category of failures.
        This applies to ALL prompts about: failed logins, sign-in issues, login problems,
        why a user can't log in, authentication errors, access denied, denied sign-ins,
        denied access, blocked logins, sign-in failures, access issues, etc.

    CRITICAL — MFA challenge queries:
        When the user asks about MFA challenges, MFA prompts, step-up auth, or authentication
        challenges, ALWAYS use filter='outcome.result eq "CHALLENGE"'.
        Do NOT use eventType filters or outcome.result eq "SUCCESS" for MFA challenges.
        Using SUCCESS or eventType is WRONG for challenges — it will return incorrect results.

    CRITICAL — invalid outcome value:
        If the user asks for an unrecognised outcome type (e.g. "INVALID_OUTCOME", "BLOCKED"):
        You MUST still call this tool with filter='outcome.result eq "<VALUE>"' and let the
        server return the error. Do NOT decide yourself that the value is invalid and skip
        the call or say "no events found". The server will return an error dict — you MUST
        read that error dict and relay the message to the user, explaining which values are
        valid. Never silently say "no events found" when the tool returns an error dict.

    Parameters:
        fetch_all (bool, optional): If True, automatically fetch all pages of results. Default: False.
            USE fetch_all=True whenever the user asks for all/complete/total results.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of log entries to return per page (min 20, max 100).
        since (str, optional): Filter logs since this timestamp (ISO 8601 format).
        until (str, optional): Filter logs until this timestamp (ISO 8601 format).
        filter (str, optional): Filter expression for log events.
            Use outcome.result to filter by event outcome. The ONLY valid values are:
            - "SUCCESS"   – successful operations (e.g. logins, password changes)
            - "FAILURE"   – failed operations (e.g. wrong password, locked account)
            - "DENY"      – access blocked by a sign-on policy rule (policy-blocked logins)
            - "ALLOW"     – access explicitly allowed by a sign-on policy rule
            - "CHALLENGE" – MFA or step-up challenge triggered.
                            ALWAYS use filter='outcome.result eq "CHALLENGE"' for MFA challenges.
                            Do NOT use eventType filters or user.authentication fields for this.
                            Using outcome.result eq "SUCCESS" or eventType is WRONG for challenges.
            - "UNKNOWN"   – outcome could not be determined
            Any other value (e.g. "INVALID_OUTCOME", "BLOCKED", "DENIED") is NOT valid and
            will return an error. If the user asks for an unrecognised outcome type, you MUST
            still call this tool with filter='outcome.result eq "<VALUE>"' and let the server
            return the error. Do NOT decide yourself that the value is invalid and skip the call.
        q (str, optional): Query string to search log events.

    Examples:
        For pagination:
        - First call: get_logs()
        - Next page: get_logs(after="cursor_value")
        - All pages: get_logs(fetch_all=True)
        - Time range: get_logs(since="2024-01-01T00:00:00.000Z", until="2024-01-02T00:00:00.000Z")
        - Policy-blocked logins: get_logs(filter='outcome.result eq "DENY"', fetch_all=True)
        - Authentication failures: get_logs(filter='outcome.result eq "FAILURE"', fetch_all=True)
        - MFA challenges: get_logs(filter='outcome.result eq "CHALLENGE"', fetch_all=True)
        - Complete login failure investigation (ALWAYS do both):
            get_logs(filter='outcome.result eq "FAILURE"', since=..., until=..., fetch_all=True)
            get_logs(filter='outcome.result eq "DENY"', since=..., until=..., fetch_all=True)

    Returns:
        Dict containing:
        - items: List of log entry objects
        - total_fetched: Number of log entries returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
            NOTE: fetch_all is capped at 50 pages (5,000 entries). If stopped_early=True,
            advise the user to narrow their time window or use a more specific filter.
        - error: If present, relay this error message directly to the user. Do NOT treat
            an error response as "no results found" — always read and report the error text.
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

    # Validate outcome.result value if present in filter
    _VALID_OUTCOME_RESULTS = {"SUCCESS", "FAILURE", "DENY", "ALLOW", "CHALLENGE", "UNKNOWN"}
    if filter:
        outcome_match = re.search(r'outcome\.result\s+eq\s+["\']([^"\']+)["\']', filter, re.IGNORECASE)
        if outcome_match:
            outcome_value = outcome_match.group(1).upper()
            if outcome_value not in _VALID_OUTCOME_RESULTS:
                logger.warning(f"Invalid outcome.result value in filter: '{outcome_match.group(1)}'")
                return {
                    "error": (
                        f"Invalid outcome.result value: '{outcome_match.group(1)}'. "
                        f"Valid values are: {', '.join(sorted(_VALID_OUTCOME_RESULTS))}. "
                        "Note: DENY is for policy-blocked logins, FAILURE is for authentication "
                        "failures (wrong password, locked account). For MFA challenges use CHALLENGE."
                    )
                }

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    def _check_scope_error(err_or_exc) -> Optional[str]:
        """Return a user-friendly scope error message if this is a 403/insufficient_scope error, else None."""
        err_str = str(err_or_exc)
        err_status = (
            getattr(err_or_exc, "status", None)
            or getattr(err_or_exc, "status_code", None)
            or getattr(err_or_exc, "errorCode", None)
        )
        is_403 = (
            err_status in (403, "403")
            or "403" in err_str
            or "insufficient_scope" in err_str.lower()
            or "access_denied" in err_str.lower()
            or "okta.logs.read" in err_str.lower()
            or "E0000005" in err_str  # Okta "Invalid session" error code
            or "E0000006" in err_str  # Okta "You do not have permission" error code
        )
        if is_403:
            return (
                "Authorization error (HTTP 403): the OAuth client does not have the "
                "'okta.logs.read' scope. Please ensure this scope is granted to your "
                "OAuth application and that the current session was authenticated with it. "
                f"Okta error details: {err_or_exc}"
            )
        return None

    def _add_failure_deny_reminder(result: dict) -> None:
        """Mutate result in-place: add a reminder when only FAILURE or only DENY was queried."""
        filter_upper = (filter or "").upper()
        if "FAILURE" in filter_upper and "DENY" not in filter_upper:
            result["reminder"] = (
                "FAILURE results fetched. You MUST NOW make a second separate call: "
                "get_logs(filter='outcome.result eq \"DENY\"', fetch_all=True, since=..., until=...) "
                "— policy-blocked sign-ins are a completely separate outcome and will NOT appear "
                "in FAILURE results. Skipping this call is a bug."
            )
        elif "DENY" in filter_upper and "FAILURE" not in filter_upper:
            result["reminder"] = (
                "DENY results fetched. You MUST NOW make a second separate call: "
                "get_logs(filter='outcome.result eq \"FAILURE\"', fetch_all=True, since=..., until=...) "
                "— authentication failures are a completely separate outcome and will NOT appear "
                "in DENY results. Skipping this call is a bug."
            )

    try:
        client = await get_okta_client(manager)
        logger.debug("Calling Okta API to retrieve system logs")

        query_params = build_query_params(after=after, limit=limit, since=since, until=until, filter=filter, q=q)

        logs, response, err = await client.list_log_events(**query_params)

        if err:
            logger.error(f"Okta API error while retrieving system logs: {err}")
            scope_msg = _check_scope_error(err)
            if not scope_msg and response and getattr(response, "status_code", None) in (401, 403):
                scope_msg = (
                    f"Authorization error (HTTP {response.status_code}): the OAuth client does not "
                    "have the 'okta.logs.read' scope. Please ensure this scope is granted to your "
                    "OAuth application and that the current session was authenticated with it. "
                    f"Okta error details: {err}"
                )
            if scope_msg:
                return {"error": scope_msg}
            return {"error": f"Error: {err}"}

        if not logs:
            logger.info("No system logs found")
            if response and getattr(response, "status_code", None) in (401, 403):
                return {
                    "error": (
                        f"Authorization error (HTTP {response.status_code}): the OAuth client does not "
                        "have the 'okta.logs.read' scope. Please ensure this scope is granted to your "
                        "OAuth application and that the current session was authenticated with it."
                    )
                }
            result = create_paginated_response([], response, fetch_all)
            _add_failure_deny_reminder(result)
            return result

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
                if pages % 5 == 0:
                    await ctx.info(f"Fetching logs... {total} fetched so far ({pages} pages)")

            all_logs, pagination_info = await paginate_all_results(
                response, logs, max_pages=50, next_page_fn=_next_page, on_page=_on_page
            )

            logger.info(
                f"Successfully retrieved {len(all_logs)} log entries across {pagination_info['pages_fetched']} pages"
            )
            result = create_paginated_response(all_logs, response, fetch_all_used=True, pagination_info=pagination_info)
            _add_failure_deny_reminder(result)
            return result
        else:
            logger.info(f"Successfully retrieved {log_count} system log entries")
            result = create_paginated_response(logs, response, fetch_all_used=fetch_all)
            _add_failure_deny_reminder(result)
            return result

    except Exception as e:
        logger.error(f"Exception while retrieving system logs: {type(e).__name__}: {e}")
        scope_msg = _check_scope_error(e)
        if scope_msg:
            return {"error": scope_msg}
        return {"error": f"Exception: {e}"}
