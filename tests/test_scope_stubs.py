# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for the scope-info stub tools registered by ``_register_stubs()``.

Fresh-review finding: ``_register_stubs()`` used to call
``mcp.tool()(stub_fn)`` directly on the raw closure from ``_make_stub_fn``,
never passing it through ``@json_response`` — the single boundary every
statically-defined ``@mcp.tool()`` function gets. These tests lock in the
fix (``json_response(_make_stub_fn(...))``) so a future edit cannot silently
drop the wrapping and reopen the plain-text-leak class this whole PR exists
to close.
"""

from __future__ import annotations

import asyncio

from okta_mcp_server.utils.scope_stubs import _make_stub_fn


def test_stub_success_returns_json_native_dict():
    stub_fn = _make_stub_fn("okta.brands.read", ["get_brand", "list_brands"])

    result = asyncio.run(stub_fn())

    assert result["missing_scope"] == "okta.brands.read"
    assert result["disabled_tools"] == ["get_brand", "list_brands"]
    assert "OKTA_SCOPES" in result["instructions"]


def test_json_response_wrapped_stub_preserves_wrapped_attr():
    """Unit-level sanity check on the composition itself: wrapping a stub
    closure in json_response must preserve functools.wraps' __wrapped__
    attribute. This does NOT exercise _register_stubs() end-to-end --
    see test_register_stubs_wraps_with_json_response below for that."""
    from okta_mcp_server.utils.serialization import json_response

    stub_fn = json_response(_make_stub_fn("okta.groups.manage", ["create_group"]))

    assert hasattr(stub_fn, "__wrapped__")


def test_stub_body_exception_returns_envelope_not_raise():
    """If a stub body ever raises (e.g. a future edit adds fallible logic),
    json_response must convert it into the standard failure envelope instead
    of letting it propagate as a plain-text MCP protocol error."""
    from okta_mcp_server.utils.serialization import json_response

    async def broken_stub() -> dict:
        raise RuntimeError("simulated failure inside a stub body")

    wrapped = json_response(broken_stub)
    result = asyncio.run(wrapped())

    assert result["ok"] is False
    assert result["error"]["type"] == "RuntimeError"


def test_register_stubs_wraps_with_json_response(monkeypatch):
    """End-to-end: run _register_stubs() against a fake mcp/registry and
    confirm the function object it registers is json_response-wrapped."""
    import okta_mcp_server.utils.scope_stubs as scope_stubs_module

    registered = {}

    class _FakeToolDecoratorFactory:
        def __call__(self):
            def _decorator(fn):
                registered["fn"] = fn
                return fn
            return _decorator

    class _FakeMcp:
        tool = _FakeToolDecoratorFactory()

    class _FakeServerModule:
        mcp = _FakeMcp()

    monkeypatch.setitem(
        __import__("sys").modules, "okta_mcp_server.server", _FakeServerModule()
    )
    monkeypatch.setattr(
        scope_stubs_module, "TOOL_SCOPE_REGISTRY", {"list_brands": "okta.brands.read"}
    )
    monkeypatch.setattr(scope_stubs_module, "SCOPE_STUB_REGISTRY", {})
    monkeypatch.delenv("OKTA_SCOPES", raising=False)

    scope_stubs_module._register_stubs()

    assert "fn" in registered
    assert hasattr(registered["fn"], "__wrapped__"), (
        "The function registered via mcp.tool()(...) must be the "
        "json_response-wrapped stub, not the raw closure."
    )
