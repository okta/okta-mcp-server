# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Centralized OAuth 2.0 scope guard utilities for the Okta Open Source MCP Server.

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
#: List of "*.manage configured without its *.read sibling" gaps detected at
#: startup. Each entry is
#: ``{"manage_scope": ..., "missing_read_scope": ..., "disabled_tools": [...]}``.
#: Populated by ``prune_tools_by_scope`` — see the detection pass at the end
#: of that function for why this is *not* the same thing as a `.manage` →
#: `.read` hierarchy (there isn't one; see README "Scope-Based Tool Loading").
_MANAGE_WITHOUT_READ_GAPS: list[dict[str, Any]] = []


def get_disabled_tools() -> dict[str, str]:
    """Return a copy of the tools disabled at startup and the scope each needs."""
    return dict(_DISABLED_TOOLS)


def get_startup_scopes() -> set[str]:
    """Return the set of OAuth scopes that were present in the token at startup."""
    return set(_CONFIGURED_SCOPES)


def get_manage_without_read_gaps() -> list[dict[str, Any]]:
    """Return the `.manage`-without-`.read` gaps detected at startup.

    Each returned entry describes a scope actually present in ``OKTA_SCOPES``
    that ends in ``.manage`` whose sibling ``.read`` scope (same
    ``okta.<resource>.`` prefix) is *absent*, where that absence actually
    disabled at least one tool. Entries have the shape::

        {
            "manage_scope": "okta.users.manage",
            "missing_read_scope": "okta.users.read",
            "disabled_tools": ["get_user", "get_user_profile_attributes", "list_users"],
        }

    This does not indicate a bug — see the README's "Scope-Based Tool
    Loading" section: this server deliberately requires every scope to be
    listed explicitly and does not infer `.read` from `.manage`. It exists so
    callers (e.g. the ``get_scope_status`` tool) can proactively surface the
    situation to an LLM/operator instead of leaving it to be discovered only
    via a missing-tool error.
    """
    return [dict(gap) for gap in _MANAGE_WITHOUT_READ_GAPS]


def build_manage_without_read_status() -> dict[str, Any]:
    """Build the additive status fragment for `.manage`-without-`.read` gaps.

    Shaped to match the key-naming convention already used by the
    ``get_scope_status`` MCP tool (see its ``by_scope`` entries, keyed on
    ``missing_scope`` / ``disabled_tools``): each entry here mirrors that
    with ``manage_scope`` / ``missing_read_scope`` / ``disabled_tools``.

    Returns a single additive key, ``manage_without_read_gaps``, so a caller
    can merge this straight into an existing status dict without disturbing
    any existing keys, e.g.::

        status = {...}  # existing get_scope_status() response
        status.update(build_manage_without_read_status())

    When nothing is wrong, ``manage_without_read_gaps`` is an empty list —
    that is the clean/absent case.
    """
    return {"manage_without_read_gaps": get_manage_without_read_gaps()}

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
    # Reset all three first so repeated calls (e.g. in tests) don't accumulate
    # stale state from a previous invocation.
    global _DISABLED_TOOLS, _CONFIGURED_SCOPES, _MANAGE_WITHOUT_READ_GAPS
    _DISABLED_TOOLS = {}
    _CONFIGURED_SCOPES = set(configured)
    _MANAGE_WITHOUT_READ_GAPS = []

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

    # ------------------------------------------------------------------
    # Detection pass: *.manage configured without its *.read sibling.
    #
    # This does NOT change what was pruned above — the exact-match
    # enforcement is intentional (see README "Scope-Based Tool Loading"):
    # OKTA_SCOPES is meant to be an explicit, auditable declaration, and a
    # `.manage` → `.read` hierarchy would make that declaration lossy. What
    # was silent before is the *consequence*: an operator who configures only
    # `okta.<resource>.manage` — reasonably expecting read+write, since the
    # Okta API itself grants read access via `.manage` — gets the matching
    # `.read` tools removed from tools/list with no signal as to why. This
    # loop makes that loudly visible via logger.warning.
    #
    # The sibling relationship is derived generically from the scope string
    # (swap the trailing "manage" component for "read") — no resource names
    # are hardcoded, so this holds for every current and future scope in
    # TOOL_SCOPE_REGISTRY, including resources (like "logs") that have no
    # `.manage` counterpart at all: those scopes never end in ".manage", so
    # they never enter this loop in the first place.
    # ------------------------------------------------------------------
    for scope in sorted(configured):
        prefix, sep, suffix = scope.rpartition(".")
        if suffix != "manage" or not sep:
            continue  # not a "*.manage" scope (covers e.g. "okta.logs.read")

        sibling_read = f"{prefix}.read"
        if sibling_read in configured:
            continue  # both declared explicitly — normal, nothing to warn about

        tools_needing_sibling = sorted(
            disabled_tool
            for disabled_tool, required_scope in _DISABLED_TOOLS.items()
            if required_scope == sibling_read
        )
        if not tools_needing_sibling:
            # Nothing in TOOL_SCOPE_REGISTRY actually required the sibling
            # `.read` scope (or it wasn't disabled for some other reason) —
            # there is no real consequence here, so stay quiet.
            continue

        _MANAGE_WITHOUT_READ_GAPS.append(
            {
                "manage_scope": scope,
                "missing_read_scope": sibling_read,
                "disabled_tools": tools_needing_sibling,
            }
        )
        logger.warning(
            f"[scope-guard] Configured scope '{scope}' does NOT implicitly enable "
            f"'{sibling_read}' for this server — '.manage' does not imply '.read' "
            f"here, even though Okta's own API does grant read access via "
            f"'.manage'. The following tool(s) remain disabled because "
            f"'{sibling_read}' is missing from OKTA_SCOPES: "
            f"{tools_needing_sibling}. "
            f"Remediation: add '{sibling_read}' to OKTA_SCOPES — this server "
            f"requires each scope to be listed explicitly; '.manage' does not "
            f"imply '.read'."
        )
