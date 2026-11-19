# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Group Push Mapping tools for the Okta MCP Server.

Group Push lets an Okta source group be "pushed" to a downstream provisioning
application (the app must have the ``GROUP_PUSH`` feature enabled). The push
mappings are stored *per application* at
``/api/v1/apps/{appId}/group-push/mappings`` — there is no reverse index that,
given a source group, returns the apps it is pushed to.

This module exposes:

- :func:`list_group_push_mappings` — list the push mappings for a single app
  (the direct wrapper over the Okta API).
- :func:`find_apps_pushing_group` — answer "is this source group pushed to any
  app, and which?" by scanning ``GROUP_PUSH``-enabled apps and collecting the
  mappings whose ``sourceGroupId`` matches the group.

Both tools fall back to a raw API fetch (plain dicts) when the bundled SDK
cannot deserialize an object, so schema drift never yields an empty/partial list.
"""

from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import create_paginated_response, extract_after_cursor, paginate_all_results
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.sdk_fallback import fetch_all_raw, fetch_raw_page, is_deserialization_error
from okta_mcp_server.utils.validation import validate_ids

# Valid GroupPushMappingStatus enum values (okta.models.group_push_mapping_status).
_VALID_STATUSES = {"ACTIVE", "ERROR", "INACTIVE"}

# Mapping-list limit bounds per the Okta API (1 ≤ limit ≤ 1000).
_MAPPINGS_MIN_LIMIT = 1
_MAPPINGS_MAX_LIMIT = 1000

# Notice attached to results that came from the raw fallback path.
_RAW_NOTICE = (
    "Results were retrieved via a raw API fallback because the Okta SDK could not "
    "deserialize one or more objects (schema drift). The list is complete and accurate."
)


def _normalize_status(status: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Return ``(normalized_status, error)``.

    ``normalized_status`` is the upper-cased status (or ``None`` if not supplied);
    ``error`` is a user-facing message when the value is invalid.
    """
    if status is None or status == "":
        return None, None
    normalized = str(status).strip().upper()
    if normalized not in _VALID_STATUSES:
        return None, (
            f"Invalid status '{status}'. Valid values are: {', '.join(sorted(_VALID_STATUSES))}."
        )
    return normalized, None


def _raw_mapping_params(
    limit: int,
    after: Optional[str] = None,
    source_group_id: Optional[str] = None,
    status: Optional[str] = None,
    last_updated: Optional[str] = None,
) -> dict:
    """Build the camelCase query-parameter dict for the raw mappings endpoint."""
    params: dict = {"limit": limit}
    if after:
        params["after"] = after
    if source_group_id:
        params["sourceGroupId"] = source_group_id
    if status:
        params["status"] = status
    if last_updated:
        params["lastUpdated"] = last_updated
    return params


async def _list_mappings_raw(
    client,
    app_id: str,
    after: Optional[str],
    limit: int,
    source_group_id: Optional[str],
    status: Optional[str],
    last_updated: Optional[str],
    fetch_all: bool,
) -> dict:
    """Raw-fetch fallback for :func:`list_group_push_mappings`."""
    logger.info(f"Using raw API fallback to list group push mappings for app {app_id}")
    path = f"/api/v1/apps/{app_id}/group-push/mappings"
    effective_limit = _MAPPINGS_MAX_LIMIT if fetch_all else limit
    params = _raw_mapping_params(effective_limit, after, source_group_id, status, last_updated)

    mappings, response, err = await fetch_raw_page(client, path, params)
    if err:
        logger.error(f"Raw fallback failed while listing group push mappings for app {app_id}: {err}")
        return {"error": str(err)}

    if not mappings:
        result = create_paginated_response([], response, fetch_all_used=fetch_all)
        result["raw_fallback"] = True
        return result

    _has_more = bool(extract_after_cursor(response))
    if fetch_all and response and _has_more:
        async def _next_page(cursor):
            p = _raw_mapping_params(effective_limit, cursor, source_group_id, status, last_updated)
            return await fetch_raw_page(client, path, p)

        all_mappings, pagination_info = await paginate_all_results(
            response, mappings, next_page_fn=_next_page
        )
        result = create_paginated_response(
            all_mappings, response, fetch_all_used=True, pagination_info=pagination_info
        )
        result["raw_fallback"] = True
        result["notice"] = _RAW_NOTICE
        return result

    result = create_paginated_response(mappings, response, fetch_all_used=fetch_all)
    result["raw_fallback"] = True
    result["notice"] = _RAW_NOTICE
    return result


@mcp.tool()
@require_scopes("okta.apps.read", error_return_type="dict")
@validate_ids("app_id", "source_group_id", error_return_type="dict")
async def list_group_push_mappings(
    app_id: str,
    ctx: Context = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    source_group_id: Optional[str] = None,
    status: Optional[str] = None,
    last_updated: Optional[str] = None,
    fetch_all: bool = False,
) -> dict:
    """List Group Push mappings configured on an application.

    Group Push mappings are keyed by APPLICATION, not by group. Each mapping links
    an Okta source group (``sourceGroupId``) to a target group in the downstream
    app (``targetGroupId``). To find which apps a *source group* is pushed to, use
    ``find_apps_pushing_group`` instead.

    Parameters:
        app_id (str, required): The ID of the application (must have the GROUP_PUSH feature).
        after (str, optional): Pagination cursor for the next page.
        limit (int, optional): Max mappings per page (1-1000). Default: 20.
        source_group_id (str, optional): Filter mappings by source Okta group ID.
        status (str, optional): Filter by mapping status: ACTIVE, ERROR, or INACTIVE.
        last_updated (str, optional): Return mappings updated on/after this UTC
            timestamp (format: YYYY-MM-DDTHH:mm:ssZ).
        fetch_all (bool, optional): If True, automatically fetch all pages. Default: False.

    Returns:
        Dict containing:
            - items (List): List of group push mapping objects. Each has sourceGroupId,
              targetGroupId, status, lastPush, and errorSummary (if the last push failed).
            - total_fetched (int): Number of mappings returned.
            - has_more (bool): Whether more results are available.
            - next_cursor (str | None): Cursor for the next page.
            - fetch_all_used (bool): Whether fetch_all was used.
            - raw_fallback (bool): Present and True when the SDK could not deserialize
              one or more mappings and a raw fetch was used. The list is still complete.
            - error: If present, relay it to the user; do not treat it as "no mappings".
    """
    logger.info(f"Listing group push mappings for app: {app_id}")
    logger.debug(
        f"after: '{after}', limit: {limit}, source_group_id: '{source_group_id}', "
        f"status: '{status}', last_updated: '{last_updated}', fetch_all: {fetch_all}"
    )

    if limit is None:
        limit = 20
    if limit < _MAPPINGS_MIN_LIMIT:
        logger.warning(f"Limit {limit} is below minimum ({_MAPPINGS_MIN_LIMIT}), setting to {_MAPPINGS_MIN_LIMIT}")
        limit = _MAPPINGS_MIN_LIMIT
    elif limit > _MAPPINGS_MAX_LIMIT:
        logger.warning(f"Limit {limit} exceeds maximum ({_MAPPINGS_MAX_LIMIT}), setting to {_MAPPINGS_MAX_LIMIT}")
        limit = _MAPPINGS_MAX_LIMIT

    normalized_status, status_err = _normalize_status(status)
    if status_err:
        return {"error": status_err}

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        effective_limit = _MAPPINGS_MAX_LIMIT if fetch_all else limit

        # Convert the status string to the SDK enum for the typed call path.
        status_enum = None
        if normalized_status is not None:
            from okta.models.group_push_mapping_status import GroupPushMappingStatus

            status_enum = GroupPushMappingStatus(normalized_status)

        sdk_kwargs = {"after": after, "limit": effective_limit}
        if source_group_id:
            sdk_kwargs["source_group_id"] = source_group_id
        if status_enum is not None:
            sdk_kwargs["status"] = status_enum
        if last_updated:
            sdk_kwargs["last_updated"] = last_updated

        try:
            mappings, response, err = await client.list_group_push_mappings(app_id, **sdk_kwargs)
        except Exception as sdk_exc:
            if is_deserialization_error(sdk_exc):
                logger.warning(
                    f"SDK could not deserialize group push mappings for app {app_id} "
                    f"({type(sdk_exc).__name__}: {sdk_exc}); falling back to raw API fetch"
                )
                return await _list_mappings_raw(
                    client, app_id, after, limit, source_group_id, normalized_status, last_updated, fetch_all
                )
            raise

        if err:
            logger.error(f"Okta API error while listing group push mappings for app {app_id}: {err}")
            return {"error": str(err)}

        if not mappings:
            logger.info(f"No group push mappings found for app {app_id}")
            return create_paginated_response([], response, fetch_all_used=fetch_all)

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(mappings)} mappings for app {app_id}")

            async def _next_page(cursor):
                p = dict(sdk_kwargs)
                p["after"] = cursor
                try:
                    return await client.list_group_push_mappings(app_id, **p)
                except Exception as page_exc:
                    if is_deserialization_error(page_exc):
                        logger.warning(
                            f"SDK could not deserialize a later page of mappings for app {app_id} "
                            f"({type(page_exc).__name__}: {page_exc}); fetching this page via raw API"
                        )
                        raw_p = _raw_mapping_params(
                            effective_limit, cursor, source_group_id, normalized_status, last_updated
                        )
                        return await fetch_raw_page(
                            client, f"/api/v1/apps/{app_id}/group-push/mappings", raw_p
                        )
                    raise

            all_mappings, pagination_info = await paginate_all_results(
                response, mappings, next_page_fn=_next_page
            )
            logger.info(
                f"Successfully retrieved {len(all_mappings)} mappings for app {app_id} "
                f"across {pagination_info['pages_fetched']} pages"
            )
            return create_paginated_response(
                all_mappings, response, fetch_all_used=True, pagination_info=pagination_info
            )

        logger.info(f"Successfully retrieved {len(mappings)} group push mappings for app {app_id}")
        return create_paginated_response(mappings, response, fetch_all_used=fetch_all)
    except Exception as e:
        logger.error(f"Exception while listing group push mappings for app {app_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}


def _mapping_value(mapping, key: str):
    """Read a field from a mapping that may be an SDK model or a raw dict."""
    if isinstance(mapping, dict):
        return mapping.get(key)
    return getattr(mapping, key, None)


def _normalized_text(value) -> Optional[str]:
    """Return stripped text, or None for null, non-string, or blank values."""
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _app_display_label(app: dict, app_id: str) -> str:
    """Choose a null-safe display label from nullable app metadata."""
    for key in ("label", "name", "description"):
        value = _normalized_text(app.get(key))
        if value:
            return value
    return app_id


@mcp.tool()
@require_scopes("okta.apps.read", error_return_type="dict")
@validate_ids("group_id", error_return_type="dict")
async def find_apps_pushing_group(
    group_id: str,
    ctx: Context = None,
    status: Optional[str] = None,
    max_app_pages: int = 25,
    max_apps_checked: int = 500,
) -> dict:
    """Find which applications a source Okta group is pushed to via Group Push.

    Okta provides no reverse index from a source group to the apps it is pushed
    to, so this tool scans every application that has the ``GROUP_PUSH`` feature
    enabled and collects the push mappings whose ``sourceGroupId`` equals
    ``group_id``. This directly answers "is this group being pushed to any app?".

    Note: Only apps whose ``features`` list includes ``GROUP_PUSH`` are checked,
    since only those can have push mappings. On very large orgs the scan is bounded
    by ``max_app_pages`` and ``max_apps_checked``; check ``scan_complete`` in the
    result to confirm the whole org was covered.

    Parameters:
        group_id (str, required): The source Okta group ID to look for.
        status (str, optional): Only return mappings with this status: ACTIVE, ERROR, or INACTIVE.
        max_app_pages (int, optional): Max pages (200 apps/page) of applications to scan. Default: 25.
        max_apps_checked (int, optional): Max number of GROUP_PUSH-enabled apps to query. Default: 500.

    Returns:
        Dict containing:
            - group_id (str): The source group that was searched for.
            - is_pushed_to_any_app (bool): True if at least one matching mapping was found.
            - matches (List): One entry per app with a matching mapping, each containing
              app_id, app_label, and the list of mapping objects (sourceGroupId == group_id).
            - apps_scanned (int): Total applications inspected.
            - push_enabled_apps_checked (int): Apps with GROUP_PUSH that were queried for mappings.
            - scan_complete (bool): False if a page/app cap or a non-404 error truncated the scan.
            - skipped_apps (List[dict]): Present when some push apps could not be read because
              their mappings endpoint returned 404 (typically stale app instances). These do
              not make the scan inconclusive.
            - notes (List[str]): Any warnings (e.g. truncation, per-app errors).
            - error: If present, relay it to the user.
    """
    logger.info(f"Finding apps that push source group: {group_id}")

    normalized_status, status_err = _normalize_status(status)
    if status_err:
        return {"error": status_err}

    if max_app_pages < 1:
        max_app_pages = 1
    if max_apps_checked < 1:
        max_apps_checked = 1

    manager = ctx.request_context.lifespan_context.okta_auth_manager
    notes: list[str] = []
    scan_complete = True

    try:
        client = await get_okta_client(manager)

        # Step 1: list all applications as raw dicts (robust against schema drift)
        # and keep only those with the GROUP_PUSH feature enabled.
        apps, _, apps_err, apps_pinfo = await fetch_all_raw(
            client, "/api/v1/apps", {"limit": 200}, max_pages=max_app_pages
        )
        if apps_err:
            logger.error(f"Error while listing applications: {apps_err}")
            return {"error": str(apps_err)}

        apps = apps or []
        if apps_pinfo and apps_pinfo.get("stopped_early"):
            scan_complete = False
            notes.append(
                f"Application scan stopped early: {apps_pinfo.get('stop_reason')}. "
                "Increase max_app_pages to cover the whole org."
            )

        push_apps = [a for a in apps if "GROUP_PUSH" in (a.get("features") or [])]
        logger.info(
            f"Scanned {len(apps)} apps; {len(push_apps)} have GROUP_PUSH enabled"
        )

        if len(push_apps) > max_apps_checked:
            scan_complete = False
            notes.append(
                f"{len(push_apps)} GROUP_PUSH apps found but only the first {max_apps_checked} "
                "were checked. Increase max_apps_checked to cover them all."
            )
            push_apps = push_apps[:max_apps_checked]

        # Step 2: for each push-enabled app, fetch the mappings filtered to this
        # source group, and double-check the sourceGroupId client-side.
        matches: list[dict] = []
        skipped_apps: list[dict] = []
        for app in push_apps:
            app_id = app.get("id")
            if not app_id:
                continue
            app_label = _app_display_label(app, app_id)

            params = _raw_mapping_params(
                _MAPPINGS_MAX_LIMIT, source_group_id=group_id, status=normalized_status
            )
            path = f"/api/v1/apps/{app_id}/group-push/mappings"
            mappings, resp, err, _ = await fetch_all_raw(client, path, params, max_pages=10)
            if err:
                status = getattr(resp, "status", None) or getattr(resp, "status_code", None)
                # A 404 means this (often stale) app instance has no group-push
                # mappings endpoint/records — it is not a gap in coverage, so it
                # does not make the overall scan inconclusive.
                if status == 404 or "404" in str(err):
                    skipped_apps.append(
                        {"app_id": app_id, "app_label": app_label, "reason": "not found (404)"}
                    )
                else:
                    scan_complete = False
                    notes.append(f"Could not read mappings for app {app_id} ({app_label}): {err}")
                continue

            app_matches = [
                m for m in (mappings or []) if _mapping_value(m, "sourceGroupId") == group_id
            ]
            if app_matches:
                matches.append(
                    {"app_id": app_id, "app_label": app_label, "mappings": app_matches}
                )

        result = {
            "group_id": group_id,
            "is_pushed_to_any_app": len(matches) > 0,
            "matches": matches,
            "apps_scanned": len(apps),
            "push_enabled_apps_checked": len(push_apps),
            "scan_complete": scan_complete,
        }
        if skipped_apps:
            result["skipped_apps"] = skipped_apps
        if notes:
            result["notes"] = notes
        logger.info(
            f"Group {group_id} push search complete: matched {len(matches)} app(s), "
            f"scan_complete={scan_complete}"
        )
        return result
    except Exception as e:
        logger.error(f"Exception while finding apps pushing group {group_id}: {type(e).__name__}: {e}")
        return {"error": str(e)}
