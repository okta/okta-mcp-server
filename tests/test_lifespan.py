# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the server lifespan — token reuse and persistence across shutdowns."""

from __future__ import annotations

from contextlib import suppress
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from okta_mcp_server.server import OktaAppContext, okta_authorisation_flow


def _fake_manager(token_valid: bool = True):
    manager = MagicMock()
    manager.is_valid_token = AsyncMock(return_value=token_valid)
    manager.authenticate = AsyncMock()
    return manager


class TestLifespanStartupAuth:
    """Startup should reuse a cached/refreshable token instead of always re-authenticating."""

    @pytest.mark.asyncio
    async def test_reuses_token_without_device_prompt_when_valid(self):
        # A valid (or silently refreshable) token must NOT trigger another device
        # grant on startup — this is the reconnect-without-re-prompt regression.
        manager = _fake_manager(token_valid=True)
        with patch("okta_mcp_server.server.OktaAuthManager", return_value=manager), \
                patch("okta_mcp_server.server.prune_tools_by_scope") as prune:
            async with okta_authorisation_flow(MagicMock()) as ctx:
                assert isinstance(ctx, OktaAppContext)
                assert ctx.okta_auth_manager is manager

        manager.is_valid_token.assert_awaited_once()
        manager.authenticate.assert_not_awaited()
        prune.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticates_when_no_valid_token(self):
        manager = _fake_manager(token_valid=False)
        with patch("okta_mcp_server.server.OktaAuthManager", return_value=manager), \
                patch("okta_mcp_server.server.prune_tools_by_scope"):
            async with okta_authorisation_flow(MagicMock()):
                pass

        manager.is_valid_token.assert_awaited_once()
        manager.authenticate.assert_awaited_once()


class TestLifespanTokenPersistence:
    """The lifespan must not wipe stored tokens on shutdown (only explicit logout should)."""

    @pytest.mark.asyncio
    async def test_tokens_not_cleared_on_normal_exit(self):
        manager = _fake_manager(token_valid=True)
        with patch("okta_mcp_server.server.OktaAuthManager", return_value=manager), \
                patch("okta_mcp_server.server.prune_tools_by_scope"):
            async with okta_authorisation_flow(MagicMock()):
                pass

        manager.clear_tokens.assert_not_called()

    @pytest.mark.asyncio
    async def test_tokens_not_cleared_on_exception(self):
        manager = _fake_manager(token_valid=True)
        with patch("okta_mcp_server.server.OktaAuthManager", return_value=manager), \
                patch("okta_mcp_server.server.prune_tools_by_scope"):
            with suppress(RuntimeError):
                async with okta_authorisation_flow(MagicMock()):
                    raise RuntimeError("boom")

        manager.clear_tokens.assert_not_called()
