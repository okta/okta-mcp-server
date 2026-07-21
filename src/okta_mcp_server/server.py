# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from loguru import logger
from mcp.server.fastmcp import FastMCP

from okta_mcp_server.utils.auth.auth_manager import OktaAuthManager
from okta_mcp_server.utils.scope_guard import get_disabled_tools, get_startup_scopes, prune_tools_by_scope
from okta_mcp_server.utils.serialization import json_response

LOG_FILE = os.environ.get("OKTA_LOG_FILE")


@dataclass
class OktaAppContext:
    okta_auth_manager: OktaAuthManager


@asynccontextmanager
async def okta_authorisation_flow(server: FastMCP) -> AsyncIterator[OktaAppContext]:
    """
    Manages the application lifecycle. It initializes the OktaManager on startup,
    re-using a cached token from the OS keyring when one is still valid, and yields
    the context for use in tools.
    """
    logger.info("Starting Okta authorization flow")
    manager = OktaAuthManager()

    if manager.is_cached_token_valid():
        logger.info("Re-using cached Okta token from keyring; skipping interactive auth")
    else:
        if not await manager.is_valid_token():
            logger.error("Authentication failed: no token available after refresh and re-auth")
            sys.exit(1)
        logger.info("Okta authentication completed (refresh or new auth)")

    prune_tools_by_scope(server, manager)

    yield OktaAppContext(okta_auth_manager=manager)


mcp = FastMCP("Okta IDaaS MCP Server", lifespan=okta_authorisation_flow)


# ---------------------------------------------------------------------------
# Scope-status tool — always available, no scope requirement
# ---------------------------------------------------------------------------

@mcp.tool()
@json_response
async def get_scope_status() -> dict:
    """Report which Okta MCP tools are active and which are disabled due to missing OAuth scopes.

    Call this tool whenever:
    - A user asks you to perform an Okta operation but no matching tool is available.
    - You are unsure whether a capability is supported.
    - You want to explain why a specific action cannot be performed.

    Returns a dict with:
    - ``configured_scopes``: list of OAuth scopes present in the token at startup.
    - ``disabled_tools``: dict mapping each disabled tool name to the scope it requires.
    - ``instructions``: actionable steps the user must take to enable the missing tools.

    IMPORTANT: If the user asks you to perform an action and the required tool appears
    in ``disabled_tools``, do NOT attempt the operation. Instead, tell the user:
    "This tool is not available because the scope '<scope>' is missing from your token.
    Follow the instructions below to enable it and restart the MCP server."
    """
    disabled = get_disabled_tools()
    configured = sorted(get_startup_scopes())

    if not disabled:
        return {
            "configured_scopes": configured,
            "disabled_tools": {},
            "instructions": "All tools are active. No missing scopes.",
        }

    # Group disabled tools by the scope they need
    by_scope: dict[str, list[str]] = {}
    for tool_name, required_scope in sorted(disabled.items()):
        by_scope.setdefault(required_scope, []).append(tool_name)

    scope_summary = [
        {"missing_scope": scope, "disabled_tools": sorted(tools)}
        for scope, tools in sorted(by_scope.items())
    ]

    missing_scopes = sorted(by_scope.keys())

    instructions = (
        "The following OAuth 2.0 scopes are missing from your token. "
        "To enable the associated tools:\n"
        "1. Open your MCP client configuration file (e.g. mcp.json or settings.json).\n"
        "2. Find the OKTA_SCOPES environment variable for this server.\n"
        "3. Add the missing scope(s) listed above (space-separated).\n"
        "4. Grant the same scope(s) to your Okta API Services application "
        "(Admin Console → Applications → your app → Okta API Scopes).\n"
        "5. Save the file and restart the MCP server.\n\n"
        f"Missing scope(s): {', '.join(missing_scopes)}"
    )

    return {
        "configured_scopes": configured,
        "disabled_tools": disabled,
        "by_scope": scope_summary,
        "instructions": instructions,
    }


def main():
    """Run the Okta Open Source MCP Server."""
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

    logger.info("Starting Okta Open Source MCP Server")
    from okta_mcp_server.tools.applications import applications  # noqa: F401
    from okta_mcp_server.tools.customization.brands import brands  # noqa: F401
    from okta_mcp_server.tools.customization.custom_domains import custom_domains  # noqa: F401
    from okta_mcp_server.tools.customization.themes import themes  # noqa: F401
    from okta_mcp_server.tools.customization.custom_pages import custom_pages  # noqa: F401
    from okta_mcp_server.tools.customization.custom_templates import custom_templates  # noqa: F401
    from okta_mcp_server.tools.customization.email_domains import email_domains  # noqa: F401
    from okta_mcp_server.tools.device_assurance import device_assurance  # noqa: F401
    from okta_mcp_server.tools.groups import groups  # noqa: F401
    from okta_mcp_server.tools.mappings import mappings  # noqa: F401
    from okta_mcp_server.tools.policies import policies  # noqa: F401
    from okta_mcp_server.tools.system_logs import system_logs  # noqa: F401
    from okta_mcp_server.tools.system_logs import login_failures  # noqa: F401
    from okta_mcp_server.tools.users import users  # noqa: F401
    from okta_mcp_server.utils import scope_stubs  # noqa: F401

    mcp.run()
