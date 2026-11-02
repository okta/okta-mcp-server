# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the package entrypoint (okta_mcp_server.main)."""

from __future__ import annotations

from unittest.mock import patch

import okta_mcp_server


def test_main_calls_server_main_once():
    with patch("okta_mcp_server.server.main") as mock_server_main:
        okta_mcp_server.main()
        mock_server_main.assert_called_once_with()


def test_main_does_not_crash_when_server_main_returns_none():
    """server.main() returns None once mcp.run() exits; the entrypoint must not raise.

    The previous asyncio.run(server.main()) wrapper raised
    'ValueError: a coroutine was expected, got None' in this case.
    """
    with patch("okta_mcp_server.server.main", return_value=None):
        okta_mcp_server.main()
