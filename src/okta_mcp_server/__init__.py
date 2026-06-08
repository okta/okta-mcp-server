# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from . import server


def main():
    """Run the server"""
    # server.main() is synchronous and runs the MCP event loop itself via
    # mcp.run(), so it must be called directly. Wrapping it in asyncio.run()
    # crashed on startup with "a coroutine was expected, got None" whenever
    # mcp.run() returned (e.g. when launched without a stdio client attached).
    server.main()
