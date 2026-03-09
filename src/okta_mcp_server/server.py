# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import importlib
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from loguru import logger
from mcp.server.fastmcp import Context, FastMCP

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager

# ---------------------------------------------------------------------------
# Toolset registry — maps a short name to its importable module and tool count.
# ---------------------------------------------------------------------------
TOOLSET_REGISTRY: dict[str, dict] = {
    "users": {
        "description": "User lifecycle, profile management, and status operations",
        "module": "okta_mcp_server.tools.users.users",
        "tool_count": 7,
    },
    "groups": {
        "description": "Group CRUD, membership management, and app assignments",
        "module": "okta_mcp_server.tools.groups.groups",
        "tool_count": 10,
    },
    "applications": {
        "description": "Application lifecycle, user assignment, and group assignment",
        "module": "okta_mcp_server.tools.applications.applications",
        "tool_count": 8,
    },
    "policies": {
        "description": "Policy and policy rule management across all policy types",
        "module": "okta_mcp_server.tools.policies.policies",
        "tool_count": 14,
    },
    "device_assurance": {
        "description": "Device assurance policy management",
        "module": "okta_mcp_server.tools.device_assurance.device_assurance",
        "tool_count": 5,
    },
    "system_logs": {
        "description": "System log retrieval and audit trail access",
        "module": "okta_mcp_server.tools.system_logs.system_logs",
        "tool_count": 1,
    },
    "brands": {
        "description": "Org-level branding configuration",
        "module": "okta_mcp_server.tools.customization.brands.brands",
        "tool_count": 6,
    },
    "custom_domains": {
        "description": "Custom domain management and certificate handling",
        "module": "okta_mcp_server.tools.customization.custom_domains.custom_domains",
        "tool_count": 7,
    },
    "themes": {
        "description": "Theme assets — logo, favicon, background, colours",
        "module": "okta_mcp_server.tools.customization.themes.themes",
        "tool_count": 9,
    },
    "custom_pages": {
        "description": "Sign-in page and error page customisation",
        "module": "okta_mcp_server.tools.customization.custom_pages.custom_pages",
        "tool_count": 19,
    },
    "custom_templates": {
        "description": "Email template customisation and previews",
        "module": "okta_mcp_server.tools.customization.custom_templates.custom_templates",
        "tool_count": 14,
    },
    "email_domains": {
        "description": "Email domain configuration and verification",
        "module": "okta_mcp_server.tools.customization.email_domains.email_domains",
        "tool_count": 6,
    },
}

# Tracks which toolsets have already been imported this session.
_loaded_toolsets: set[str] = set()

LOG_FILE = os.environ.get("OKTA_LOG_FILE")


@dataclass
class OktaAppContext:
    okta_auth_manager: OktaAuthManager


@asynccontextmanager
async def okta_authorisation_flow(server: FastMCP) -> AsyncIterator[OktaAppContext]:
    """
    Manages the application lifecycle. It initializes the OktaManager on startup,
    performs authorization, and yields the context for use in tools.
    """
    logger.info("Starting Okta authorization flow")
    manager = OktaAuthManager()
    await manager.authenticate()
    logger.info("Okta authentication completed successfully")

    try:
        yield OktaAppContext(okta_auth_manager=manager)
    finally:
        logger.debug("Clearing Okta tokens")
        manager.clear_tokens()


mcp = FastMCP("Okta IDaaS MCP Server", lifespan=okta_authorisation_flow)


# ---------------------------------------------------------------------------
# Strategy 3 — Dynamic toolset discovery via meta-tools
#
# The LLM starts with ONLY these 3 tools.  It can discover what toolsets
# exist, load the one(s) it needs for the task, and confirm what is loaded.
# No toolset module is imported at startup — zero unused tools in context.
# ---------------------------------------------------------------------------

@mcp.tool()
def list_available_toolsets() -> dict:
    """
    List all available Okta toolsets that can be loaded on demand.

    Call this first when you need to perform Okta operations to discover
    which toolset provides the tools you need. Each toolset groups related
    Okta API capabilities. After choosing a toolset, call load_toolset()
    to make its tools available.

    Returns a dict with:
      - available: toolsets not yet loaded (name, description, tool_count)
      - loaded: toolsets already active in this session
    """
    available = []
    for name, meta in TOOLSET_REGISTRY.items():
        if name not in _loaded_toolsets:
            available.append({
                "name": name,
                "description": meta["description"],
                "tool_count": meta["tool_count"],
            })

    loaded = [
        {
            "name": name,
            "description": TOOLSET_REGISTRY[name]["description"],
            "tool_count": TOOLSET_REGISTRY[name]["tool_count"],
        }
        for name in _loaded_toolsets
    ]

    return {
        "available": available,
        "loaded": loaded,
        "total_available_tools": sum(m["tool_count"] for m in available),
    }


@mcp.tool()
async def load_toolset(toolset_name: str, ctx: Context) -> dict:
    """
    Load an Okta toolset by name to make its tools available for use.

    Call list_available_toolsets() first to see valid toolset names and
    what each one provides. Once loaded, the toolset's tools are immediately
    usable. A toolset only needs to be loaded once per session.

    Args:
        toolset_name: Name of the toolset to load (e.g. "users", "groups").
                      Use list_available_toolsets() to see valid names.

    Returns a dict confirming the load with the list of tools now available.
    """
    if toolset_name not in TOOLSET_REGISTRY:
        valid = sorted(TOOLSET_REGISTRY.keys())
        return {
            "success": False,
            "error": f"Unknown toolset '{toolset_name}'. Valid names: {valid}",
        }

    if toolset_name in _loaded_toolsets:
        return {
            "success": True,
            "message": f"Toolset '{toolset_name}' is already loaded.",
            "tool_count": TOOLSET_REGISTRY[toolset_name]["tool_count"],
        }

    try:
        entry = TOOLSET_REGISTRY[toolset_name]
        importlib.import_module(entry["module"])
        _loaded_toolsets.add(toolset_name)
        logger.info(f"[Strategy 3] Dynamically loaded toolset '{toolset_name}' ({entry['tool_count']} tools)")

        # Notify the MCP client that the tool list has changed so it re-fetches
        # the full list. The LLM will then see the newly registered tools
        # immediately and can use them in this same conversation turn.
        await ctx.session.send_tool_list_changed()

        return {
            "success": True,
            "message": (
                f"Toolset '{toolset_name}' loaded. "
                f"The tool list has been refreshed — you now have access to its "
                f"{entry['tool_count']} tools and can call them directly."
            ),
            "toolset": toolset_name,
            "tool_count": entry["tool_count"],
            "description": entry["description"],
        }

    except Exception as exc:
        logger.error(f"[Strategy 3] Failed to load toolset '{toolset_name}': {exc}")
        return {
            "success": False,
            "error": f"Failed to load toolset '{toolset_name}': {exc}",
        }


@mcp.tool()
def get_loaded_toolsets() -> dict:
    """
    Show which Okta toolsets are currently loaded and active in this session.

    Use this to check what tools are already available before calling
    load_toolset() again, or to confirm a load was successful.

    Returns a dict with loaded toolsets and total active tool count.
    """
    loaded = [
        {
            "name": name,
            "description": TOOLSET_REGISTRY[name]["description"],
            "tool_count": TOOLSET_REGISTRY[name]["tool_count"],
        }
        for name in _loaded_toolsets
    ]

    return {
        "loaded": loaded,
        "total_active_tools": sum(TOOLSET_REGISTRY[n]["tool_count"] for n in _loaded_toolsets),
        "session_starts_with": "3 meta-tools (list_available_toolsets, load_toolset, get_loaded_toolsets)",
    }


def main():
    """Run the Okta MCP server."""
    logger.remove()

    if LOG_FILE:
        logger.add(
            LOG_FILE,
            mode="w",
            level=os.environ.get("OKTA_LOG_LEVEL", "INFO"),
            retention="5 days",
            enqueue=True,
            serialize=True,
        )

    logger.add(
        sys.stderr, level=os.environ.get("OKTA_LOG_LEVEL", "INFO"), format="{time} {level} {message}", serialize=True
    )

    logger.info("Starting Okta MCP Server — Strategy 3: Dynamic toolset discovery")
    logger.info("LLM starts with 3 meta-tools; toolsets are loaded on demand")

    mcp.run()

