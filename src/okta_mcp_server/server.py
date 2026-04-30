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

    if await manager.is_valid_token():
        logger.info("Re-using cached Okta token from keyring; skipping interactive auth")
    else:
        if not manager.has_token():
            logger.error("Authentication failed: no token available after refresh and re-auth")
            sys.exit(1)
        logger.info("Okta authentication completed (refresh or new auth)")

    yield OktaAppContext(okta_auth_manager=manager)


mcp = FastMCP("Okta IDaaS MCP Server", lifespan=okta_authorisation_flow)


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

    logger.info("Starting Okta MCP Server")
    from okta_mcp_server.tools.applications import applications  # noqa: F401
    from okta_mcp_server.tools.groups import groups  # noqa: F401
    from okta_mcp_server.tools.policies import policies  # noqa: F401
    from okta_mcp_server.tools.system_logs import system_logs  # noqa: F401
    from okta_mcp_server.tools.users import users  # noqa: F401

    mcp.run()
