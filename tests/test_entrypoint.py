# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.


"""Tests for the ``okta-mcp-server`` console-script entry point."""

from __future__ import annotations

from unittest.mock import patch

import okta_mcp_server


class TestMainEntryPoint:
    def test_calls_synchronous_server_main_without_asyncio_run(self):
        """server.main() is a regular function that blocks in mcp.run(); it must not be passed to asyncio.run()."""
        with patch("okta_mcp_server.server.main", return_value=None) as server_main:
            okta_mcp_server.main()

        server_main.assert_called_once_with()

    def test_server_main_is_not_a_coroutine_function(self):
        import inspect

        from okta_mcp_server import server

        assert not inspect.iscoroutinefunction(server.main)
