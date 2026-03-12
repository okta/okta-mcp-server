# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import asyncio
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from loguru import logger


def extract_after_cursor(response) -> Optional[str]:
    """Extract the 'after' cursor from the next page URL in Okta API response.

    Supports both Okta SDK v2 (OktaAPIResponse with has_next/_next) and
    v3 (ApiResponse with headers containing a Link header).

    Args:
        response: OktaAPIResponse (v2) or ApiResponse (v3) object

    Returns:
        str: The 'after' cursor value, or None if no next page
    """
    import re

    # --- Okta SDK v3: ApiResponse with Link header ---
    if response and hasattr(response, "headers") and response.headers:
        link_header = ""
        try:
            link_header = response.headers.get("Link", "") or response.headers.get("link", "")
        except Exception:
            for key in response.headers:
                if key.lower() == "link":
                    link_header = response.headers[key]
                    break

        if link_header and 'rel="next"' in link_header:
            match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
            if match:
                next_url = match.group(1)
                try:
                    parsed = urlparse(next_url)
                    qp = parse_qs(parsed.query)
                    cursor = qp.get("after", [None])[0]
                    if cursor:
                        return cursor
                except Exception as e:
                    logger.warning(f"Failed to parse Link header cursor: {e}")

    # --- Okta SDK v2: OktaAPIResponse with has_next()/_next ---
    if not response or not hasattr(response, "has_next") or not response.has_next():
        return None

    try:
        # response._next contains URL like: "/api/v1/users?after=00u1abc123def456"
        if hasattr(response, "_next") and response._next:
            parsed = urlparse(response._next)
            qp = parse_qs(parsed.query)
            return qp.get("after", [None])[0]
    except Exception as e:
        logger.warning(f"Failed to extract after cursor: {e}")

    return None


async def paginate_all_results(
    initial_response,
    initial_items: List,
    max_pages: int = 500,
    delay_between_requests: float = 0.1,
    next_page_fn=None,
    on_page=None,
) -> Tuple[List, Dict[str, Any]]:
    """Auto-paginate through all pages of results.

    Supports both Okta SDK v2 (OktaAPIResponse with has_next/next()) and SDK v3
    (ApiResponse with Link header cursor).  For SDK v3, a ``next_page_fn`` callable
    must be supplied; it will be called as ``next_page_fn(after_cursor)`` and must
    return a ``(items, response, err)`` tuple matching the SDK v3 convention.

    Args:
        initial_response: The first OktaAPIResponse (v2) or ApiResponse (v3) object
        initial_items: The first page of items
        max_pages: Maximum number of pages to fetch (safety limit)
        delay_between_requests: Delay in seconds between requests
        next_page_fn: Async callable for SDK v3 pagination:
            ``async (after: str) -> (items, response, err)``
        on_page: Optional async callable invoked after each page is fetched.
            Signature: ``async (pages_fetched: int, total_items: int) -> None``
            Use this to emit progress notifications to the caller.

    Returns:
        Tuple of (all_items, pagination_info)
    """
    all_items = list(initial_items) if initial_items else []
    pages_fetched = 1
    response = initial_response

    pagination_info = {"pages_fetched": 1, "total_items": len(all_items), "stopped_early": False, "stop_reason": None}

    if not response:
        return all_items, pagination_info

    # --- SDK v2: response.has_next() / response.next() ---
    if hasattr(response, "has_next"):
        try:
            while response.has_next() and pages_fetched < max_pages:
                if delay_between_requests > 0:
                    await asyncio.sleep(delay_between_requests)

                try:
                    next_items, next_err = await response.next()

                    if next_err:
                        logger.warning(f"Error fetching page {pages_fetched + 1}: {next_err}")
                        pagination_info["stopped_early"] = True
                        pagination_info["stop_reason"] = f"API error: {next_err}"
                        break

                    if next_items:
                        all_items.extend(next_items)
                        pages_fetched += 1
                        logger.debug(f"Fetched page {pages_fetched}, total items: {len(all_items)}")
                        if on_page:
                            try:
                                await on_page(pages_fetched, len(all_items))
                            except Exception:
                                pass
                    else:
                        break

                except Exception as e:
                    logger.error(f"Exception during pagination on page {pages_fetched + 1}: {e}")
                    pagination_info["stopped_early"] = True
                    pagination_info["stop_reason"] = f"Exception: {e}"
                    break

            if pages_fetched >= max_pages and response.has_next():
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = f"Reached maximum page limit ({max_pages})"
                logger.warning(f"Stopped pagination at {max_pages} pages limit")

        except Exception as e:
            logger.error(f"Unexpected error during pagination: {e}")
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = f"Unexpected error: {e}"

    # --- SDK v3: Link header cursor + caller-supplied next_page_fn ---
    elif next_page_fn is not None:
        cursor = extract_after_cursor(response)
        try:
            while cursor and pages_fetched < max_pages:
                if delay_between_requests > 0:
                    await asyncio.sleep(delay_between_requests)

                try:
                    next_items, next_response, next_err = await next_page_fn(cursor)

                    if next_err:
                        logger.warning(f"Error fetching page {pages_fetched + 1}: {next_err}")
                        pagination_info["stopped_early"] = True
                        pagination_info["stop_reason"] = f"API error: {next_err}"
                        break

                    if next_items:
                        all_items.extend(next_items)
                        pages_fetched += 1
                        logger.debug(f"Fetched page {pages_fetched}, total items: {len(all_items)}")
                        if on_page:
                            try:
                                await on_page(pages_fetched, len(all_items))
                            except Exception:
                                pass
                    else:
                        break

                    response = next_response
                    cursor = extract_after_cursor(next_response) if next_response else None

                except Exception as e:
                    logger.error(f"Exception during pagination on page {pages_fetched + 1}: {e}")
                    pagination_info["stopped_early"] = True
                    pagination_info["stop_reason"] = f"Exception: {e}"
                    break

            if cursor and pages_fetched >= max_pages:
                pagination_info["stopped_early"] = True
                pagination_info["stop_reason"] = f"Reached maximum page limit ({max_pages})"
                logger.warning(f"Stopped pagination at {max_pages} pages limit")

        except Exception as e:
            logger.error(f"Unexpected error during SDK v3 pagination: {e}")
            pagination_info["stopped_early"] = True
            pagination_info["stop_reason"] = f"Unexpected error: {e}"

    pagination_info["pages_fetched"] = pages_fetched
    pagination_info["total_items"] = len(all_items)

    return all_items, pagination_info


def create_paginated_response(
    items: List, response, fetch_all_used: bool = False, pagination_info: Optional[Dict] = None
) -> Dict[str, Any]:
    """Create a standardized paginated response format.

    Args:
        items: List of items to return
        response: OktaAPIResponse object
        fetch_all_used: Whether fetch_all was used
        pagination_info: Additional pagination metadata

    Returns:
        Dict with standardized pagination response format
    """
    result = {
        "items": items,
        "total_fetched": len(items),
        "has_more": False,
        "next_cursor": None,
        "fetch_all_used": fetch_all_used,
    }

    # Add pagination info if not fetch_all
    if not fetch_all_used and response:
        next_cursor = extract_after_cursor(response)
        has_more_v2 = response.has_next() if hasattr(response, "has_next") else False
        result["has_more"] = has_more_v2 or bool(next_cursor)
        result["next_cursor"] = next_cursor

    # Add detailed pagination info if available
    if pagination_info:
        result["pagination_info"] = pagination_info

    return result


def build_query_params(
    search: str = "",
    filter: Optional[str] = None,
    q: Optional[str] = None,
    after: Optional[str] = None,
    limit: Optional[int] = None,
    **kwargs,
) -> Dict[str, Any]:
    """Build query parameters dict for Okta API calls.

    Args:
        search: Search string
        filter: Filter string
        q: Query string
        after: Pagination cursor
        limit: Page size limit
        **kwargs: Additional query parameters

    Returns:
        Dict of query parameters with non-empty values
    """
    query_params = {}

    if search:
        query_params["search"] = search
    if filter:
        query_params["filter"] = filter
    if q:
        query_params["q"] = q
    if after:
        query_params["after"] = after
    if limit:
        query_params["limit"] = limit

    # Add any additional parameters
    for key, value in kwargs.items():
        if value is not None and value != "":
            query_params[key] = value

    return query_params
