# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Centralized OAuth 2.0 scope guard utilities for the Okta MCP Server.

This module provides the canonical scope-enforcement layer that is shared by every tool.
It has three responsibilities:

1.  **Error messaging** — ``build_scope_error`` produces a single, consistent
    user-facing error dict/list whenever a required scope is absent.

2.  **Runtime decorator** — ``require_scopes(*scopes)`` is a tool-level decorator
    that performs two checks:
        a. *Pre-call*: reads ``manager.scopes`` (sourced from ``OKTA_SCOPES``) and
           short-circuits before any API request if a scope is missing.
        b. *Exception*: catches ``ForbiddenException`` / ``UnauthorizedException``
           returned by the Okta SDK for stale tokens or misconfigured apps.

3.  **Startup pruning** — ``prune_tools_by_scope(server, manager)`` is called once
    inside the MCP lifespan after authentication completes.  It removes tools from
    the FastMCP tool registry for which the token lacks the required scope, so the
    LLM never sees tools it cannot call.
"""

import functools
import inspect
from typing import Any, Optional

from loguru import logger
from okta.exceptions.exceptions import ForbiddenException, UnauthorizedException

# ---------------------------------------------------------------------------
# Module-level pruning state — populated once at startup by prune_tools_by_scope
# ---------------------------------------------------------------------------

#: Maps tool_name → required_scope for every tool disabled at startup
_DISABLED_TOOLS: dict[str, str] = {}
#: The set of scopes that were present in the token at startup
_CONFIGURED_SCOPES: set[str] = set()


def get_disabled_tools() -> dict[str, str]:
    """Return a copy of the tools disabled at startup and the scope each needs."""
    return dict(_DISABLED_TOOLS)


def get_startup_scopes() -> set[str]:
    """Return the set of OAuth scopes that were present in the token at startup."""
    return set(_CONFIGURED_SCOPES)

# ---------------------------------------------------------------------------
# Canonical error message
# ---------------------------------------------------------------------------

_SCOPE_ERROR_TEMPLATE = (
    "Your token is missing required scope(s). "
    "Please add the following scope(s) to your MCP configuration and application: {scopes}. "
    "Update OKTA_SCOPES in your MCP client configuration (e.g. mcp.json / settings.json), "
    "grant the scope(s) to your Okta application, then re-authenticate."
)


def _scope_error_message(scopes: list[str]) -> str:
    """Return the canonical scope-error string for the given missing scopes."""
    return _SCOPE_ERROR_TEMPLATE.format(scopes=", ".join(sorted(scopes)))


def build_scope_error(scopes: list[str], return_type: str = "dict") -> Any:
    """Build a user-friendly scope-error response.

    Args:
        scopes:       List of missing OAuth 2.0 scope strings.
        return_type:  ``"dict"`` (default) or ``"list"``, to match the tool's
                      own error-return convention.

    Returns:
        ``{"error": "<message>"}`` or ``[{"error": "<message>"}]``.
    """
    msg = _scope_error_message(scopes)
    if return_type == "list":
        return [{"error": msg}]
    return {"error": msg}


# ---------------------------------------------------------------------------
# Scope introspection helpers
# ---------------------------------------------------------------------------

def get_configured_scopes(manager: Any) -> Optional[set[str]]:
    """Extract the configured OAuth scopes from the auth manager as a set.

    Reads ``manager.scopes`` — the space-separated string built from the
    ``OKTA_SCOPES`` environment variable — rather than the cached keychain
    token.  This keeps the check deterministic and decoupled from keychain
    state.

    Returns:
        A ``set[str]`` of scope tokens, or ``None`` if the manager does not
        expose a ``scopes`` attribute (e.g. in test doubles).
    """
    scopes_str = getattr(manager, "scopes", None)
    if not scopes_str or not isinstance(scopes_str, str):
        return None
    return set(scopes_str.split())


def _extract_manager(fn: Any, args: tuple, kwargs: dict) -> Any:
    """Find the OktaAuthManager in a tool call's bound arguments.

    Looks for a parameter whose value has a ``request_context`` attribute
    (i.e. an MCP ``Context`` object), then navigates to the auth manager.
    Returns ``None`` if the context cannot be found or is not yet populated
    (e.g. the lifespan hasn't completed).
    """
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        for val in bound.arguments.values():
            rc = getattr(val, "request_context", None)
            if rc is not None:
                return rc.lifespan_context.okta_auth_manager
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Runtime decorator
# ---------------------------------------------------------------------------

def require_scopes(*required_scopes: str, error_return_type: str = "dict"):
    """Decorator that enforces required OAuth 2.0 scopes before a tool runs.

    Place this decorator directly below ``@mcp.tool()`` (and above any
    ``@validate_ids`` decorator).  It performs:

    1. **Pre-call check** — compares ``manager.scopes`` against the required
       scope(s).  If any are missing, returns ``build_scope_error(...)``
       immediately without touching the Okta API.

    2. **Exception catch** — wraps the tool body in a try/except for
       ``ForbiddenException`` and ``UnauthorizedException`` so that stale
       tokens or app misconfiguration produce the same canonical error message
       rather than a raw SDK exception.

    Args:
        *required_scopes:   One or more scope strings (e.g. ``"okta.users.read"``).
        error_return_type:  ``"dict"`` (default) or ``"list"`` — must match the
                            tool's own error-return convention.

    Example::

        @mcp.tool()
        @require_scopes("okta.users.read")
        async def list_users(ctx: Context, ...) -> dict: ...

        @mcp.tool()
        @require_scopes("okta.users.manage", error_return_type="list")
        async def create_user(profile: dict, ctx: Context = None) -> list: ...

    Scope/permission errors:
        If the token is missing the required scope(s), this decorator returns
        ``{"error": "..."}`` (or ``[{"error": "..."}]`` for list tools).
        Present the error message verbatim and STOP — do not retry until the
        scopes are fixed.
    """
    def decorator(fn: Any) -> Any:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs) -> Any:
            # --- Pre-call scope check -----------------------------------------
            manager = _extract_manager(fn, args, kwargs)
            if manager is not None:
                configured = get_configured_scopes(manager)
                if configured is not None:
                    missing = [s for s in required_scopes if s not in configured]
                    if missing:
                        logger.warning(
                            f"Tool '{fn.__name__}' blocked — missing scope(s): {missing}. "
                            f"Configured scopes: {sorted(configured)}"
                        )
                        return build_scope_error(missing, error_return_type)

            # --- Execute tool body with exception guard -----------------------
            try:
                return await fn(*args, **kwargs)
            except (ForbiddenException, UnauthorizedException) as exc:
                status = getattr(exc, "status", 403)
                logger.error(
                    f"Tool '{fn.__name__}' received HTTP {status} from Okta API — "
                    f"likely missing scope(s): {list(required_scopes)}"
                )
                return build_scope_error(list(required_scopes), error_return_type)

        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Startup pruning
# ---------------------------------------------------------------------------

def prune_tools_by_scope(server: Any, manager: Any) -> None:
    """Remove tools from the FastMCP registry that lack their required scope.

    Called once inside the MCP lifespan immediately after authentication
    completes.  Tools removed here will not appear in ``tools/list``, so the
    LLM never attempts to call a tool it cannot execute.

    The mapping of tool → required scope is loaded lazily from
    ``okta_mcp_server.utils.scope_registry.TOOL_SCOPE_REGISTRY`` to avoid
    circular imports at module load time.

    Args:
        server:   The ``FastMCP`` instance (passed into the lifespan function).
        manager:  The authenticated ``OktaAuthManager`` instance.
    """
    from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY  # lazy import

    configured = get_configured_scopes(manager)
    if configured is None:
        logger.warning(
            "prune_tools_by_scope: could not read configured scopes — "
            "all tools will remain registered."
        )
        return

    # Persist startup state so get_scope_status tool can surface it to the LLM.
    # Reset both dicts first so repeated calls (e.g. in tests) don't accumulate
    # stale state from a previous invocation.
    global _DISABLED_TOOLS, _CONFIGURED_SCOPES
    _DISABLED_TOOLS = {}
    _CONFIGURED_SCOPES = set(configured)

    # NOTE: FastMCP does not expose a public API for removing tools from the
    # registry at runtime.  We use the private ``_tool_manager`` attribute here
    # as the only available mechanism.  If FastMCP adds a public ``remove_tool``
    # API in a future release this should be updated.
    # Tracked in: https://github.com/jlowin/fastmcp (watch for public API)
    registered_names = {t.name for t in server._tool_manager.list_tools()}
    disabled: list[str] = []
    enabled: list[str] = []

    for tool_name, required_scope in TOOL_SCOPE_REGISTRY.items():
        if tool_name not in registered_names:
            continue  # tool not loaded (shouldn't happen, but be safe)
        if required_scope not in configured:
            try:
                server._tool_manager.remove_tool(tool_name)
                disabled.append(tool_name)
                _DISABLED_TOOLS[tool_name] = required_scope
                logger.info(
                    f"[scope-guard] Disabled tool '{tool_name}' — "
                    f"missing scope '{required_scope}'"
                )
            except Exception as exc:
                logger.warning(
                    f"[scope-guard] Failed to remove tool '{tool_name}': {exc}"
                )
        else:
            enabled.append(tool_name)

    total = len(enabled) + len(disabled)
    logger.info(
        f"[scope-guard] Startup complete: {len(enabled)}/{total} tools enabled "
        f"based on OKTA_SCOPES. "
        f"{len(disabled)} tool(s) disabled: {sorted(disabled) if disabled else 'none'}."
    )
