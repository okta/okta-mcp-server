# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Read-only Okta Identity Governance (Access Requests) tools.

These endpoints live under ``/governance/api/v2`` and have no typed SDK
surface, so they go through :func:`okta_raw_request`.
"""

import asyncio
from collections import Counter
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, quote, urlencode, urlparse

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import build_query_params, create_paginated_response
from okta_mcp_server.utils.raw_request import okta_raw_request
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.serialization import json_response, none_body_error
from okta_mcp_server.utils.validation import validate_ids

_REQUEST_CONDITIONS_SCOPE = "okta.accessRequests.condition.read"
_CATALOG_SCOPE = "okta.accessRequests.catalog.read"

#: Top-level catalog entries only (apps, not their child entitlements/bundles).
_CATALOG_TOP_LEVEL_FILTER = "not(parent pr)"

_GOVERNANCE_MAX_LIMIT = 200

#: Safety limits for fetch_all, mirroring paginate_all_results defaults.
_GOVERNANCE_MAX_PAGES = 500
_GOVERNANCE_PAGE_DELAY_SECONDS = 0.1


def _governance_url(path: str, params: Dict[str, Any]) -> str:
    # quote (not quote_plus) so filter expressions like "not(parent pr)"
    # encode the space as %20 rather than "+".
    query_string = urlencode(params, quote_via=quote)
    return path + (f"?{query_string}" if query_string else "")


def _parse_governance_page(body: Any) -> tuple:
    """Split a Governance list response into ``(items, next_cursor)``.

    Governance v2 list responses are an envelope — ``{"data": [...],
    "_links": {"next": {"href": "...?after=<cursor>"}}}`` — rather than a bare
    array with a ``Link`` header like ``/api/v1``. The cursor is the ``after``
    query parameter of ``_links.next.href``; only the cursor is used, never the
    href itself, so a next link can't redirect requests to another host or
    path. A bare array is accepted as a single, final page.
    """
    if body is None:
        return [], None
    if isinstance(body, list):
        return body, None
    items = body.get("data") or []
    next_link = (body.get("_links") or {}).get("next")
    href = next_link.get("href") if isinstance(next_link, dict) else None
    if not href:
        return items, None
    cursor = parse_qs(urlparse(href).query).get("after", [None])[0]
    return items, cursor


async def _list_governance(
    ctx: Context, client, path: str, query_params: Dict[str, Any], scope: str, fetch_all: bool
) -> dict:
    """Fetch one page (or every page, with ``fetch_all``) of a Governance list endpoint."""
    _, body, err = await okta_raw_request(client, "GET", _governance_url(path, query_params), scopes=[scope])
    if err:
        logger.error(f"Okta API error while listing {path}: {err}")
        return {"error": str(err)}

    items, cursor = _parse_governance_page(body)

    if not fetch_all:
        result = create_paginated_response(items, None, fetch_all_used=False)
        # Governance responses carry the cursor in the body, not a Link header,
        # so has_more/next_cursor can't come from the transport response.
        result["has_more"] = cursor is not None
        result["next_cursor"] = cursor
        return result

    all_items = list(items)
    # Dedup by id so a cursor that doesn't advance can't duplicate entries or loop.
    seen_ids = {i["id"] for i in items if isinstance(i, dict) and i.get("id")}
    pages_fetched = 1
    pagination_info: Dict[str, Any] = {"stopped_early": False, "stop_reason": None}

    while cursor and pages_fetched < _GOVERNANCE_MAX_PAGES:
        await asyncio.sleep(_GOVERNANCE_PAGE_DELAY_SECONDS)
        next_params = dict(query_params)
        next_params["after"] = cursor
        _, page_body, page_err = await okta_raw_request(
            client, "GET", _governance_url(path, next_params), scopes=[scope]
        )
        if page_err:
            logger.warning(f"Error fetching {path} page {pages_fetched + 1}: {page_err}")
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = f"API error: {page_err}"
            break

        page, next_cursor = _parse_governance_page(page_body)
        if not page:
            cursor = None
            break

        fresh = [i for i in page if not (isinstance(i, dict) and i.get("id") in seen_ids)]
        if not fresh:
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = "Pagination cursor did not advance"
            break
        seen_ids.update(i["id"] for i in fresh if isinstance(i, dict) and i.get("id"))

        all_items.extend(fresh)
        pages_fetched += 1
        try:
            await ctx.info(f"Fetching {path}... {len(all_items)} fetched so far ({pages_fetched} pages)")
        except Exception:
            pass

        cursor = next_cursor

    if cursor and pages_fetched >= _GOVERNANCE_MAX_PAGES:
        pagination_info["stopped_early"] = True
        pagination_info["stop_reason"] = f"Reached maximum page limit ({_GOVERNANCE_MAX_PAGES})"
        logger.warning(f"Stopped {path} pagination at {_GOVERNANCE_MAX_PAGES} pages limit")

    pagination_info["pages_fetched"] = pages_fetched
    pagination_info["total_items"] = len(all_items)
    result = create_paginated_response(all_items, None, fetch_all_used=True, pagination_info=pagination_info)
    if pagination_info["stopped_early"] and cursor:
        # Partial result — surface the resume point instead of implying
        # the walk completed.
        result["has_more"] = True
        result["next_cursor"] = cursor
    return result


def _clamp_limit(limit: Optional[int]) -> Optional[int]:
    if limit is not None and limit > _GOVERNANCE_MAX_LIMIT:
        logger.warning(f"Limit {limit} exceeds maximum ({_GOVERNANCE_MAX_LIMIT}), setting to {_GOVERNANCE_MAX_LIMIT}")
        return _GOVERNANCE_MAX_LIMIT
    return limit


# ---------------------------------------------------------------------------
# Access request conditions
# ---------------------------------------------------------------------------


@mcp.tool()
@require_scopes(_REQUEST_CONDITIONS_SCOPE)
@validate_ids("app_id", error_return_type="dict")
@json_response
async def list_app_request_conditions(
    ctx: Context,
    app_id: str,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    fetch_all: bool = False,
) -> dict:
    """List the access request conditions configured for an app (Okta Identity Governance).

    Use this when:
    - A user can't see an app under "Request apps" on their End-User Dashboard.
    - A user can see an app but the request goes to the wrong approvers, or
      offers the wrong access level or duration.
    - You need to know who is allowed to request an app at all.

    An app is requestable only through its ACTIVE conditions. A user sees the
    app under "Request apps" only if at least one ACTIVE condition's
    ``requesterSettings`` covers them (``EVERYONE``, or ``GROUPS`` containing
    one of their groups; check with list_user_groups). INACTIVE conditions are
    switched off. INVALID conditions usually reference something that no
    longer exists (e.g. a deleted group or approval sequence) and are not
    applied until fixed in the Admin Console. No conditions at all means the
    app is not requestable.

    Parameters:
        app_id (str, required): The Okta app ID (e.g. from list_applications).
        after (str, optional): Pagination cursor from a previous ``next_cursor``.
        limit (int, optional): Maximum conditions per page (max 200).
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
        - items: Request condition objects (``id``, ``name``, ``status``,
          ``priority``, ``requesterSettings``, ``approvalSequenceId``,
          ``accessScopeSettings``, ``accessDurationSettings``, ...)
        - status_summary: Count of the returned conditions by ``status``
          (e.g. ``{"ACTIVE": 1, "INVALID": 1}``)
        - total_fetched, has_more, next_cursor, fetch_all_used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Listing access request conditions for app: {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(after=after, limit=_clamp_limit(limit))
        result = await _list_governance(
            ctx,
            client,
            f"/governance/api/v2/resources/{app_id}/request-conditions",
            query_params,
            _REQUEST_CONDITIONS_SCOPE,
            fetch_all,
        )
        if "error" in result:
            return result

        result["status_summary"] = dict(
            Counter(c.get("status", "UNKNOWN") if isinstance(c, dict) else "UNKNOWN" for c in result["items"])
        )
        logger.info(f"Successfully retrieved {result['total_fetched']} request conditions for app {app_id}")
        return result
    except Exception as e:
        logger.error(f"Exception while listing request conditions for app {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


@mcp.tool()
@require_scopes(_REQUEST_CONDITIONS_SCOPE)
@validate_ids("app_id", "condition_id", error_return_type="dict")
@json_response
async def get_app_request_condition(ctx: Context, app_id: str, condition_id: str) -> dict:
    """Get one access request condition for an app (Okta Identity Governance).

    Use this after list_app_request_conditions to inspect a single condition in
    full — for example, to see exactly which groups it lets request the app,
    which approval sequence it uses, or why its status is INVALID.

    Parameters:
        app_id (str, required): The Okta app ID.
        condition_id (str, required): The request condition ID (from list_app_request_conditions).

    Returns:
        Dict with the request condition, or error information.
    """
    logger.info(f"Getting access request condition {condition_id} for app {app_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        _, condition, err = await okta_raw_request(
            client,
            "GET",
            f"/governance/api/v2/resources/{app_id}/request-conditions/{condition_id}",
            scopes=[_REQUEST_CONDITIONS_SCOPE],
        )
        if err:
            logger.error(f"Okta API error while getting request condition {condition_id}: {err}")
            return {"error": str(err)}

        if condition is None:
            return none_body_error(
                "get_app_request_condition",
                f"retrieving request condition {condition_id!r} for app {app_id!r}",
                "Verify the IDs with list_app_request_conditions().",
            )

        logger.info(f"Successfully retrieved request condition {condition_id}")
        return condition
    except Exception as e:
        logger.error(f"Exception while getting request condition {condition_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Access request catalog
# ---------------------------------------------------------------------------


@mcp.tool()
@require_scopes(_CATALOG_SCOPE)
@json_response
async def list_catalog_entries(
    ctx: Context,
    app_name: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    fetch_all: bool = False,
) -> dict:
    """List the apps in the Access Requests catalog (what end users browse under "Request apps").

    Use this when:
    - A user asks which apps they (or anyone) can request.
    - A user can't see an app under "Request apps": if the app is missing
      here, it isn't in the catalog at all; if it's present, check its
      conditions with list_app_request_conditions.

    Not to be confused with list_catalog_apps, which browses the Okta
    Integration Network (OIN) catalog of installable app integrations.

    Only top-level entries are returned (filter ``not(parent pr)``), not the
    entitlements or bundles nested under an app.

    Parameters:
        app_name (str, optional): Search entries by app name (sent as ``match``).
        after (str, optional): Pagination cursor from a previous ``next_cursor``.
        limit (int, optional): Maximum entries per page (max 200).
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
        - items: Catalog entry objects (``id``, ``label``, ``description``,
          ``requestable``, ``_links``, ...)
        - total_fetched, has_more, next_cursor, fetch_all_used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info(f"Listing access request catalog entries (app_name='{app_name}', fetch_all={fetch_all})")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        query_params = build_query_params(
            filter=_CATALOG_TOP_LEVEL_FILTER, after=after, limit=_clamp_limit(limit), match=app_name
        )
        result = await _list_governance(
            ctx, client, "/governance/api/v2/catalogs/default/entries", query_params, _CATALOG_SCOPE, fetch_all
        )
        if "error" not in result:
            logger.info(f"Successfully retrieved {result['total_fetched']} catalog entries")
        return result
    except Exception as e:
        logger.error(f"Exception while listing catalog entries: {type(e).__name__}: {e}")
        return {"error": str(e)}
