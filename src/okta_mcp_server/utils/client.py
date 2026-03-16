# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from __future__ import annotations

import os

import keyring
from loguru import logger
from okta.client import Client as OktaClient

from okta_mcp_server.utils.auth.auth_manager import SERVICE_NAME, OktaAuthManager


async def get_okta_client(manager: OktaAuthManager | None) -> OktaClient:
    """Initialize and return an Okta client.

    In stdio mode (manager is not None): uses OktaAuthManager + keyring.
    In HTTP mode (manager is None): gets Okta token from MCP Bearer auth context.
    """
    logger.debug("Initializing Okta client")

    if manager is not None:
        # stdio mode — existing behavior
        api_token = keyring.get_password(SERVICE_NAME, "api_token")
        if not await manager.is_valid_token():
            logger.warning("Token is invalid or expired, re-authenticating")
            await manager.authenticate()
            api_token = keyring.get_password(SERVICE_NAME, "api_token")
        org_url = manager.org_url
    else:
        # HTTP mode — OAuthProxy passes through the upstream Okta access token.
        # The Bearer token in the request IS the Okta access token.
        from mcp.server.auth.middleware.auth_context import get_access_token

        access_token_info = get_access_token()
        if access_token_info is None:
            raise RuntimeError("No authenticated user in HTTP mode")

        api_token = access_token_info.token
        if not api_token:
            raise RuntimeError("No Okta access token in auth context")

        org_url = os.environ.get("OKTA_ORG_URL", "")

    config = {
        "orgUrl": org_url,
        "token": api_token,
        "authorizationMode": "Bearer",
        "userAgent": "okta-mcp-server/0.0.1",
    }
    logger.debug(f"Okta client configured for org: {org_url}")
    return OktaClient(config)
