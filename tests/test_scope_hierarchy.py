# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the ``.manage``-without-``.read`` detection in ``scope_guard.py``.

Background
----------
``TOOL_SCOPE_REGISTRY`` maps each tool to a single, exact required scope, and
``prune_tools_by_scope`` enforces that with exact string membership -- there is
no ``.manage`` -> ``.read`` hierarchy, and that is intentional (see the README
section "Scope-Based Tool Loading"): ``OKTA_SCOPES`` is meant to be an
explicit, auditable declaration, and a hierarchy would make it lossy.

What *was* a real defect is that the consequence of that design was silent:
an operator who configures only ``okta.users.manage`` -- reasonably expecting
read+write, since Okta's own API grants read access via ``.manage`` -- got the
matching ``.read`` tools quietly dropped from ``tools/list`` with no signal
why. These tests cover the fix: a loud ``logger.warning`` at prune time, the
``get_manage_without_read_gaps()`` / ``build_manage_without_read_status()``
accessors that expose the same data to callers (and eventually
``get_scope_status``), and a doc-regression guard on ``README.md``.

Note on ``get_scope_status``
-----------------------------
The MCP tool ``get_scope_status`` itself is defined in ``server.py``, which is
out of scope for this change (another change concurrently owns that file).
So the tests below exercise ``build_manage_without_read_status()`` -- the
additive fragment designed to be merged into ``get_scope_status``'s response
(``status.update(build_manage_without_read_status())``) -- rather than the
tool function body, plus one lightweight sanity check that the existing tool
still works unmodified.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from loguru import logger

from okta_mcp_server.utils import scope_guard
from okta_mcp_server.utils.scope_registry import TOOL_SCOPE_REGISTRY

# ---------------------------------------------------------------------------
# Fakes -- minimal stand-ins for FastMCP's tool manager and OktaAuthManager.
# Mirrors the fixture style used in tests/test_server_lifespan.py (plain
# fakes/mocks, no fixtures shared via conftest.py since only this file needs
# them).
# ---------------------------------------------------------------------------


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolManager:
    """Minimal stand-in for FastMCP's private ``_tool_manager`` attribute."""

    def __init__(self, tool_names) -> None:
        self._tools = {name: _FakeTool(name) for name in tool_names}

    def list_tools(self):
        return list(self._tools.values())

    def remove_tool(self, name: str) -> None:
        del self._tools[name]


class _FakeServer:
    def __init__(self, tool_names) -> None:
        self._tool_manager = _FakeToolManager(tool_names)


class _FakeManager:
    """Minimal stand-in for OktaAuthManager -- only ``.scopes`` is read."""

    def __init__(self, scopes: str) -> None:
        self.scopes = scopes


def _all_registered_tool_names() -> list[str]:
    """Every tool name declared in the real TOOL_SCOPE_REGISTRY.

    Using the real registry (read-only import) rather than a hand-picked
    subset means the sibling-derivation logic under test is exercised
    against every scope actually in play, including ``okta.logs.read``
    (no ``.manage`` counterpart) alongside every ``.read``/``.manage`` pair.
    """
    return list(TOOL_SCOPE_REGISTRY.keys())


@pytest.fixture(autouse=True)
def _reset_scope_guard_module_state():
    """Belt-and-suspenders reset around the module globals ``prune_tools_by_scope``
    owns, so a failure partway through one test can't leak state into the next.
    ``prune_tools_by_scope`` already resets these at the top of every call
    (see its docstring), so this mainly guards tests that don't call it at all.
    """
    yield
    scope_guard._DISABLED_TOOLS = {}
    scope_guard._CONFIGURED_SCOPES = set()
    scope_guard._MANAGE_WITHOUT_READ_GAPS = []


@pytest.fixture
def loguru_sink():
    """Capture loguru log records emitted during a test.

    pytest's built-in ``caplog`` fixture only intercepts the stdlib
    ``logging`` module, and this codebase logs via ``loguru`` directly, so
    tests that need to assert on ``logger.warning(...)`` content add a
    temporary sink and remove it on teardown.
    """
    records: list = []
    sink_id = logger.add(lambda msg: records.append(msg.record), level="DEBUG")
    yield records
    logger.remove(sink_id)


def _warning_messages(records) -> list[str]:
    return [r["message"] for r in records if r["level"].name == "WARNING"]


# ---------------------------------------------------------------------------
# Detection pass in prune_tools_by_scope
# ---------------------------------------------------------------------------


class TestManageWithoutReadDetection:
    def test_manage_only_disables_read_tools_and_warns(self, loguru_sink):
        server = _FakeServer(_all_registered_tool_names())
        manager = _FakeManager("okta.users.manage")

        scope_guard.prune_tools_by_scope(server, manager)

        disabled = scope_guard.get_disabled_tools()
        for tool in ("list_users", "get_user", "get_user_profile_attributes"):
            assert disabled[tool] == "okta.users.read"
        # okta.users.manage *is* configured, so manage-scoped tools stay enabled.
        for tool in ("create_user", "update_user", "deactivate_user", "delete_deactivated_user"):
            assert tool not in disabled

        gaps = scope_guard.get_manage_without_read_gaps()
        assert len(gaps) == 1
        assert gaps[0]["manage_scope"] == "okta.users.manage"
        assert gaps[0]["missing_read_scope"] == "okta.users.read"
        assert gaps[0]["disabled_tools"] == [
            "get_user",
            "get_user_profile_attributes",
            "list_users",
        ]

        gap_warnings = [m for m in _warning_messages(loguru_sink) if "okta.users.read" in m]
        assert gap_warnings, "expected a logger.warning naming the missing sibling scope"
        message = gap_warnings[0]
        assert "okta.users.manage" in message
        for tool in ("list_users", "get_user", "get_user_profile_attributes"):
            assert tool in message

    def test_manage_and_read_both_configured_no_warning(self, loguru_sink):
        server = _FakeServer(_all_registered_tool_names())
        manager = _FakeManager("okta.users.manage okta.users.read")

        scope_guard.prune_tools_by_scope(server, manager)

        disabled = scope_guard.get_disabled_tools()
        assert "list_users" not in disabled
        assert "get_user" not in disabled
        assert "get_user_profile_attributes" not in disabled

        assert scope_guard.get_manage_without_read_gaps() == []
        assert not _warning_messages(loguru_sink)

    def test_read_only_configuration_no_warning(self, loguru_sink):
        """A plain read-only OKTA_SCOPES (no .manage at all) is a perfectly
        normal setup and must not warn."""
        server = _FakeServer(_all_registered_tool_names())
        manager = _FakeManager("okta.users.read")

        scope_guard.prune_tools_by_scope(server, manager)

        assert scope_guard.get_manage_without_read_gaps() == []
        assert not _warning_messages(loguru_sink)

    def test_logs_read_alone_has_no_manage_sibling_and_does_not_crash(self, loguru_sink):
        """okta.logs.read has no *.manage counterpart anywhere in
        TOOL_SCOPE_REGISTRY. The sibling derivation must not invent one, warn
        spuriously, or raise."""
        server = _FakeServer(_all_registered_tool_names())
        manager = _FakeManager("okta.logs.read")

        scope_guard.prune_tools_by_scope(server, manager)  # must not raise

        assert scope_guard.get_manage_without_read_gaps() == []
        assert not _warning_messages(loguru_sink)

    def test_repeated_calls_do_not_accumulate_stale_gaps(self):
        """Mirrors the existing reset-on-each-call contract documented for
        _DISABLED_TOOLS / _CONFIGURED_SCOPES: a second call must not leak
        gaps detected during a prior call."""
        server = _FakeServer(_all_registered_tool_names())
        scope_guard.prune_tools_by_scope(server, _FakeManager("okta.users.manage"))
        assert len(scope_guard.get_manage_without_read_gaps()) == 1

        server2 = _FakeServer(_all_registered_tool_names())
        scope_guard.prune_tools_by_scope(
            server2, _FakeManager("okta.users.manage okta.users.read")
        )
        assert scope_guard.get_manage_without_read_gaps() == []


# ---------------------------------------------------------------------------
# build_manage_without_read_status() -- the additive fragment meant to be
# merged into get_scope_status's response.
# ---------------------------------------------------------------------------


class TestBuildManageWithoutReadStatus:
    def test_shape_is_additive_only(self):
        result = scope_guard.build_manage_without_read_status()
        assert list(result.keys()) == ["manage_without_read_gaps"]

    def test_reports_condition_when_present(self):
        server = _FakeServer(_all_registered_tool_names())
        scope_guard.prune_tools_by_scope(server, _FakeManager("okta.users.manage"))

        status = scope_guard.build_manage_without_read_status()
        assert status["manage_without_read_gaps"]
        gap = status["manage_without_read_gaps"][0]
        assert gap["manage_scope"] == "okta.users.manage"
        assert gap["missing_read_scope"] == "okta.users.read"
        assert "list_users" in gap["disabled_tools"]

    def test_reports_cleanly_when_absent(self):
        server = _FakeServer(_all_registered_tool_names())
        scope_guard.prune_tools_by_scope(
            server, _FakeManager("okta.users.manage okta.users.read")
        )

        status = scope_guard.build_manage_without_read_status()
        assert status["manage_without_read_gaps"] == []


class TestGetScopeStatusToolStillWorks:
    """``get_scope_status`` lives in server.py (out of scope for this change --
    see module docstring above). This is a narrow sanity check that importing
    and calling it is unaffected by the new scope_guard state, and that its
    pre-existing keys are all still present -- it does NOT assert on
    ``manage_without_read_gaps`` since that key is not wired in yet."""

    @pytest.mark.asyncio
    async def test_existing_keys_present_after_a_manage_only_prune(self):
        from okta_mcp_server.server import get_scope_status

        server = _FakeServer(_all_registered_tool_names())
        scope_guard.prune_tools_by_scope(server, _FakeManager("okta.users.manage"))

        result = await get_scope_status()

        assert "configured_scopes" in result
        assert "disabled_tools" in result
        assert "instructions" in result
        assert result["disabled_tools"]["list_users"] == "okta.users.read"


# ---------------------------------------------------------------------------
# README doc-regression guard
# ---------------------------------------------------------------------------


def test_readme_no_longer_claims_manage_implies_read():
    """Cheap guard against the false claim this whole change exists to fix
    creeping back in: `.manage` was documented as implicitly enabling all
    `.read` operations, which the exact-match enforcement in
    prune_tools_by_scope has never actually done."""
    readme_path = Path(__file__).resolve().parent.parent / "README.md"
    text = readme_path.read_text(encoding="utf-8")
    assert "implicitly enables all read operations" not in text
