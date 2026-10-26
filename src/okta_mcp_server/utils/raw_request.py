# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Raw request helper for Okta endpoints the typed SDK can't serve.

Some endpoints (the OIN catalog, the Governance ``/governance/api/v2`` API)
have no typed SDK method, or the typed method mangles the request body. Tools
for those endpoints go through the SDK's request executor directly via
:func:`okta_raw_request`, which keeps the SDK's auth headers, retries and
org-URL handling.

The request executor returns HTTP errors as values instead of raising
``ForbiddenException`` / ``UnauthorizedException``, so ``@require_scopes``
never sees them. :func:`okta_raw_request` closes that gap: a 401/403 comes
back as a :class:`ScopeDeniedError` whose ``str()`` is the same canonical
message ``require_scopes`` produces, so a tool's usual
``return {"error": str(err)}`` matches ``build_scope_error(scopes)``.
"""

import json
from typing import Any, Dict, Optional, Sequence

from okta_mcp_server.utils.scope_guard import scope_error_message

#: HTTP statuses that mean the token lacks a scope (or the app lacks the grant).
_SCOPE_DENIED_STATUSES = (401, 403)


class ScopeDeniedError(Exception):
    """A 401/403 from a raw request, carrying the canonical scope-error message.

    Attributes:
        scopes: The scope(s) the calling tool requires.
        status: The HTTP status Okta returned.
        cause:  The original SDK error (``OktaAPIError`` / ``HTTPError``).
    """

    def __init__(self, scopes: Sequence[str], status: int, cause: Any):
        self.scopes = list(scopes)
        self.status = status
        self.cause = cause
        super().__init__(scope_error_message(self.scopes))


async def okta_raw_request(
    client,
    method: str,
    url: str,
    *,
    scopes: Sequence[str],
    body: Optional[Dict[str, Any]] = None,
    keep_empty_params: bool = False,
) -> tuple:
    """Issue a raw request through the Okta SDK request executor.

    Args:
        client: An ``OktaClient`` from ``get_okta_client``.
        method: HTTP method.
        url: Path relative to the org (e.g. ``/api/v1/catalog/apps``); the
            executor prefixes the org URL.
        scopes: The scope(s) the calling tool requires, used for the error
            message when Okta answers 401/403.
        body: Optional JSON body.
        keep_empty_params: Pass True to forward the body verbatim — by default
            the SDK's create_request prunes empty-string/list/dict values from
            the body (``clear_empty_params``).

    Returns:
        Tuple of ``(response, parsed_body, error)`` — the transport response,
        the JSON-decoded body (``None`` when the body is empty), and the error
        (``None`` on success). ``response`` and ``parsed_body`` are ``None``
        whenever ``error`` is set. A 401/403 error is a :class:`ScopeDeniedError`.
    """
    executor = client.get_request_executor()
    request, err = await executor.create_request(
        method=method, url=url, body=body or {}, headers={}, oauth=False, keep_empty_params=keep_empty_params
    )
    if err:
        return None, None, err
    response, response_body, err = await executor.execute(request)
    if err:
        status = getattr(err, "status", None)
        if status in _SCOPE_DENIED_STATUSES:
            return None, None, ScopeDeniedError(scopes, status, err)
        return None, None, err
    return response, json.loads(response_body) if response_body else None, None
