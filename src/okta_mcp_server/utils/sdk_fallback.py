# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Raw-fetch fallback helpers for the Okta SDK.

The bundled Okta SDK (OpenAPI-generated) deserializes list responses into strict
Pydantic models. When a single object in a collection has drifted from the
bundled OpenAPI schema (e.g. an unknown enum or an unexpected nested shape),
Pydantic raises a ``ValidationError`` that aborts deserialization of the *whole*
collection — so the caller gets nothing instead of an "all but the bad item"
list.

These helpers let tools detect that failure mode and fall back to a raw API
fetch that returns plain ``dict`` objects, bypassing strict model validation so
the caller still receives a complete, accurate list.
"""

import json
from typing import Any, Optional
from urllib.parse import quote, urlencode

from loguru import logger
from pydantic import ValidationError

from okta_mcp_server.utils.pagination import paginate_all_results


def is_deserialization_error(exc: Exception) -> bool:
    """Return True if ``exc`` looks like an SDK model deserialization failure.

    Only schema/validation failures should trigger a raw fallback — genuine
    transport, auth, or rate-limit errors must surface to the caller unchanged.
    """
    if isinstance(exc, ValidationError):
        return True
    # Some SDK/pydantic internals re-wrap the error; match defensively on text.
    text = f"{type(exc).__name__}: {exc}".lower()
    return "validationerror" in text or "validation error" in text


async def fetch_raw_page(
    client, path: str, query_params: Optional[dict] = None
) -> tuple[Optional[list], Any, Optional[Exception]]:
    """Fetch a single collection page as raw dicts, bypassing SDK models.

    Args:
        client: An initialized Okta SDK client.
        path: API path beginning with ``/`` (e.g. ``/api/v1/groups/{id}/apps``).
        query_params: Optional query parameters; ``None``/empty values are dropped.

    Returns:
        A ``(items, response, err)`` tuple mirroring the SDK convention. ``items``
        is a list of plain dicts (a lone object is wrapped in a single-item list).
    """
    executor = client.get_request_executor()
    url = f"{client.get_base_url()}{path}"

    if query_params:
        cleaned = {k: v for k, v in query_params.items() if v not in (None, "")}
        if cleaned:
            # safe="" + quote ensures cursor characters such as '=', '+', '/'
            # survive correctly in the query string.
            url = f"{url}?{urlencode(cleaned, safe='', quote_via=quote)}"

    request, error = await executor.create_request("GET", url, {}, {})
    if error:
        return None, None, error

    # No response_type is passed to execute(), so the executor returns the raw
    # JSON body without attempting strict Pydantic model validation.
    response, response_body, error = await executor.execute(request)
    if error:
        return None, response, error

    try:
        data = json.loads(response_body) if response_body else []
    except (ValueError, TypeError) as parse_err:
        return None, response, parse_err

    if not isinstance(data, list):
        data = [data]
    return data, response, None


async def fetch_all_raw(
    client,
    path: str,
    query_params: Optional[dict] = None,
    max_pages: int = 50,
    on_page=None,
) -> tuple[Optional[list], Any, Optional[Exception], Optional[dict]]:
    """Fetch every page of a collection as raw dicts via cursor pagination.

    Reuses the shared :func:`paginate_all_results` cursor loop, so it transparently
    follows the ``Link: rel="next"`` header.

    Returns:
        A ``(items, response, err, pagination_info)`` tuple. On error, ``items``
        and ``pagination_info`` are ``None`` and ``err`` is populated.
    """
    first_items, response, err = await fetch_raw_page(client, path, query_params)
    if err:
        return None, response, err, None

    async def _next_page(cursor):
        params = dict(query_params or {})
        params["after"] = cursor
        return await fetch_raw_page(client, path, params)

    all_items, pagination_info = await paginate_all_results(
        response,
        first_items or [],
        max_pages=max_pages,
        next_page_fn=_next_page,
        on_page=on_page,
    )
    logger.debug(f"fetch_all_raw retrieved {len(all_items)} items from {path}")
    return all_items, response, None, pagination_info
