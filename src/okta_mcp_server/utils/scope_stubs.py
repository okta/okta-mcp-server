# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Scope-info stub tools for the Okta Open Source MCP Server.

For each OAuth scope that is absent from ``OKTA_SCOPES``, this module registers
exactly one lightweight stub tool. The stub appears in ``tools/list`` so the LLM
can discover that the capability exists but requires an additional scope.

Design rationale
----------------
- Real tools are pruned by ``prune_tools_by_scope`` when their scope is missing.
- Without stubs, the LLM has no signal that the capability exists at all and says
  "I cannot do that" with no actionable guidance.
- One stub *per scope group* (at most one per scope in TOOL_SCOPE_REGISTRY) keeps the tool list short while
  giving the LLM enough information to explain exactly what is missing and how to
  fix it.
- Stubs are registered only for *missing* scopes — servers with all scopes loaded
  register zero stubs.

``SCOPE_STUB_REGISTRY``
-----------------------
Maps stub tool name → required scope. Populated at module import time and exported
for use by tests.
"""

import os
import re
from typing import Any, Iterable

from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY
from okta_mcp_server.utils.serialization import json_response

#: Maps stub_tool_name → required_scope; populated during _register_stubs().
SCOPE_STUB_REGISTRY: dict[str, str] = {}


def _scope_to_stub_name(scope: str) -> str:
    """Convert a scope string to a valid snake_case tool name.

    Every dot-separated part after the leading ``okta`` is kept, so four-part
    scopes such as ``okta.accessRequests.condition.read`` and
    ``okta.accessRequests.condition.manage`` get distinct names. Three-part
    scopes keep the names they have always had.

    Examples::

        'okta.brands.read'                    → 'brands_read_scope_info'
        'okta.deviceAssurance.read'           → 'device_assurance_read_scope_info'
        'okta.emailDomains.manage'            → 'email_domains_manage_scope_info'
        'okta.accessRequests.condition.read'  → 'access_requests_condition_read_scope_info'
    """
    parts = scope.split(".")[1:]
    snake_parts = [re.sub(r"(?<!^)(?=[A-Z])", "_", part).lower() for part in parts]
    return "_".join(snake_parts) + "_scope_info"


def _stub_names_by_scope(scopes: Iterable[str]) -> dict[str, str]:
    """Map each scope to its stub tool name, failing loudly on a collision.

    Snake-casing can in principle fold two different scopes onto one name
    (e.g. ``okta.fooBar.read`` and ``okta.foo.bar.read``). Two stubs with one
    name would make FastMCP silently keep only one, so a collision raises.
    """
    names: dict[str, str] = {}
    owners: dict[str, str] = {}
    for scope in sorted(set(scopes)):
        name = _scope_to_stub_name(scope)
        if name in owners:
            raise ValueError(
                f"Scope stub name collision: '{owners[name]}' and '{scope}' both map to '{name}'"
            )
        owners[name] = scope
        names[scope] = name
    return names


def _build_stub_description(scope: str, tools: list[str]) -> str:
    tools_str = ", ".join(sorted(tools))
    return (
        f"[SCOPE REQUIRED] The following Okta tools are currently disabled because "
        f"the '{scope}' OAuth scope is missing from OKTA_SCOPES:\n"
        f"{tools_str}\n\n"
        f"Call this tool to get step-by-step instructions for enabling these tools."
    )


def _make_stub_fn(scope: str, tools: list[str]) -> Any:
    """Return an async stub function that returns scope-fix instructions."""
    async def stub() -> dict:
        return {
            "missing_scope": scope,
            "disabled_tools": sorted(tools),
            "instructions": (
                f"To enable these tools, add '{scope}' to OKTA_SCOPES:\n"
                "1. Open your MCP configuration file (e.g. mcp.json or settings.json).\n"
                f"2. Add '{scope}' to the OKTA_SCOPES environment variable "
                "(space-separated).\n"
                "3. Grant the same scope to your Okta API Services application\n"
                "   (Admin Console → Applications → your app → Okta API Scopes).\n"
                "4. Save the file and restart the MCP server."
            ),
        }

    return stub


def _register_stubs() -> None:
    """Register one scope-info stub tool for each scope absent from OKTA_SCOPES.

    Called once at module import time (after real tool modules are imported).
    Reads ``OKTA_SCOPES`` from the environment — the same source used by
    ``prune_tools_by_scope`` — to decide which stubs to add.
    """
    from okta_mcp_server.server import mcp  # lazy — server.py is already loaded by main()

    from loguru import logger

    okta_scopes_env = os.environ.get("OKTA_SCOPES", "")
    configured: set[str] = set(okta_scopes_env.split()) if okta_scopes_env else set()

    # Group tool names by the scope they require
    by_scope: dict[str, list[str]] = {}
    for tool_name, required_scope in TOOL_SCOPE_REGISTRY.items():
        by_scope.setdefault(required_scope, []).append(tool_name)

    # Checked across every registry scope, not only the missing ones, so a
    # collision fails regardless of which scopes this server is configured with.
    stub_names = _stub_names_by_scope(by_scope)

    registered = 0
    for scope in sorted(by_scope.keys()):
        if scope in configured:
            continue  # real tools for this scope are active — no stub needed

        tools = by_scope[scope]
        stub_name = stub_names[scope]
        SCOPE_STUB_REGISTRY[stub_name] = scope

        # Wrap in the same json_response boundary every statically-defined
        # @mcp.tool() function gets, so this dynamically-registered tool
        # cannot leak a plain-text exception if its body ever raises.
        stub_fn = json_response(_make_stub_fn(scope, tools))
        stub_fn.__name__ = stub_name
        stub_fn.__doc__ = _build_stub_description(scope, tools)

        mcp.tool()(stub_fn)
        registered += 1
        logger.debug(f"[scope-stubs] Registered stub '{stub_name}' for missing scope '{scope}'")

    if registered:
        logger.info(
            f"[scope-stubs] Registered {registered} scope-info stub(s) for missing scopes: "
            f"{sorted(SCOPE_STUB_REGISTRY.values())}"
        )


_register_stubs()
