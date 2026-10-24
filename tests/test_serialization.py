# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for :mod:`okta_mcp_server.utils.serialization`.

Coverage focuses on the boundary contracts that justified the rewrite:

* Pydantic v2 models, plain dicts, lists, tuples, sets, and nested mixes all
  round-trip through ``json.dumps``.
* ``Enum`` values are unwrapped to their ``.value``.
* ``datetime`` values are emitted as RFC 3339 strings.
* ``OktaAPIResponse`` (and v3 ``ApiResponse`` look-alikes) are dropped.
* Self-referential structures do not blow the stack.
* The decorator preserves ``__name__`` / ``__doc__`` and produces the failure
  envelope when :func:`to_jsonable` raises.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from enum import Enum

import pytest

import okta.models as okta_models
from okta.models.application_sign_on_mode import ApplicationSignOnMode

from okta_mcp_server.utils.serialization import (
    _failure_envelope,
    json_response,
    to_jsonable,
)


# ---------------------------------------------------------------------------
# to_jsonable: scalars and enums
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [None, True, False, 0, 1, -3, 1.5, "", "hello"])
def test_scalars_pass_through(value):
    assert to_jsonable(value) == value


def test_enum_unwrapped_to_value():
    class Color(Enum):
        RED = "red"
        BLUE = "blue"

    assert to_jsonable(Color.RED) == "red"
    assert to_jsonable([Color.RED, Color.BLUE]) == ["red", "blue"]


def test_str_enum_mixin_unwrapped_to_value():
    """``(str, Enum)`` mixins (e.g. Okta's ``ApplicationSignOnMode``) must be
    unwrapped to their raw ``.value`` instead of leaking through the scalar
    passthrough.  Historically the scalar branch ran first, which let the
    enum object survive: any non-``json`` consumer (f-string, ``logger.info``)
    then rendered the Python repr ``<Color.RED: 'red'>`` — the exact bug
    described in issue #14.
    """

    class Color(str, Enum):
        RED = "red"
        BLUE = "blue"

    result = to_jsonable(Color.RED)
    assert result == "red"
    # Critical: the returned value must NOT still be the enum instance,
    # otherwise ``str(result)`` would still emit ``<Color.RED: 'red'>``.
    assert type(result) is str
    assert not isinstance(result, Color)

    # Nested inside a container round-trips through ``json.dumps`` cleanly.
    payload = {"mode": Color.BLUE, "modes": [Color.RED, Color.BLUE]}
    assert to_jsonable(payload) == {"mode": "blue", "modes": ["red", "blue"]}
    assert json.dumps(to_jsonable(payload)) == '{"mode": "blue", "modes": ["red", "blue"]}'


def test_int_enum_mixin_unwrapped_to_value():
    """``(int, Enum)`` mixins are unwrapped for the same reason as ``(str, Enum)``."""

    class Priority(int, Enum):
        LOW = 1
        HIGH = 2

    result = to_jsonable(Priority.HIGH)
    assert result == 2
    assert type(result) is int
    assert not isinstance(result, Priority)


# ---------------------------------------------------------------------------
# to_jsonable: containers
# ---------------------------------------------------------------------------

def test_dict_keys_coerced_to_str():
    result = to_jsonable({1: "a", "k": 2})
    assert result == {"1": "a", "k": 2}


def test_tuple_becomes_list():
    assert to_jsonable((1, 2, 3)) == [1, 2, 3]


def test_set_becomes_list():
    result = to_jsonable({1, 2, 3})
    assert isinstance(result, list)
    assert sorted(result) == [1, 2, 3]


def test_nested_structure_round_trips():
    payload = {
        "items": [{"id": "u1", "tags": ("a", "b")}, {"id": "u2", "tags": set()}],
        "meta": {"count": 2},
    }
    normalized = to_jsonable(payload)
    json.dumps(normalized)  # must not raise
    assert normalized["items"][0]["tags"] == ["a", "b"]


# ---------------------------------------------------------------------------
# to_jsonable: Pydantic v2 (Okta SDK) models
# ---------------------------------------------------------------------------

def test_pydantic_v2_model_is_flattened():
    app = okta_models.Application.model_construct(
        label="hello", sign_on_mode=ApplicationSignOnMode.SAML_2_0
    )
    result = to_jsonable(app)

    assert isinstance(result, dict)
    assert result.get("label") == "hello"
    # The output must not contain a Python repr like "<Application object at 0x...>".
    assert not re.search(r"<.+ object at 0x[0-9a-f]+>", json.dumps(result))


def test_list_of_models_round_trips():
    apps = [
        okta_models.Application.model_construct(
            label="a", sign_on_mode=ApplicationSignOnMode.SAML_2_0
        ),
        okta_models.Application.model_construct(
            label="b", sign_on_mode=ApplicationSignOnMode.OPENID_CONNECT
        ),
    ]
    result = to_jsonable(apps)

    assert isinstance(result, list)
    assert {item["label"] for item in result} == {"a", "b"}
    json.dumps(result)


# ---------------------------------------------------------------------------
# to_jsonable: datetime (RFC 3339 via Pydantic mode="json")
# ---------------------------------------------------------------------------

def test_datetime_in_pydantic_model_serialized_rfc3339():
    from pydantic import BaseModel

    class Stamped(BaseModel):
        when: datetime

    model = Stamped(when=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    result = to_jsonable(model)

    assert result["when"] == "2024-01-02T03:04:05Z"


def test_custom_pages_serialize_emits_rfc3339_datetime():
    """PR #90 review round 4: ``custom_pages._serialize`` must set
    ``mode='json'`` so nested datetimes survive as RFC 3339 strings when the
    payload flows through the outer ``@json_response`` boundary.  Without
    ``mode='json'``, ``model_dump`` returns a raw ``datetime`` and
    ``to_jsonable`` would fall through to ``str(datetime)`` producing
    ``"2024-01-02 03:04:05+00:00"`` (space separator) instead of the
    ``"2024-01-02T03:04:05Z"`` required by RFC 3339.
    """
    from pydantic import BaseModel

    from okta_mcp_server.tools.customization.custom_pages.custom_pages import (
        _serialize,
    )

    class PageWithTimestamp(BaseModel):
        when: datetime

    model = PageWithTimestamp(when=datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    serialized = _serialize(model)
    # After the local _serialize, the outer boundary runs to_jsonable — but
    # since serialized is already a plain dict, we can assert directly.
    assert serialized["when"] == "2024-01-02T03:04:05Z", (
        "custom_pages._serialize dropped mode='json' — datetime is no longer RFC 3339."
    )


# ---------------------------------------------------------------------------
# to_jsonable: transport object suppression
# ---------------------------------------------------------------------------

def test_okta_api_response_is_dropped():
    class OktaAPIResponse:  # mimics okta.api_response.OktaAPIResponse shape
        headers = {"x-okta-request-id": "abc"}

        def has_next(self) -> bool:
            return False

    assert to_jsonable(OktaAPIResponse()) is None


def test_v3_apiresponse_is_dropped():
    class ApiResponse:  # mimics SDK v3 duck-typed shape
        headers = {"Link": "..."}

    assert to_jsonable(ApiResponse()) is None


def test_response_lookalike_without_headers_is_not_dropped():
    """Class-name suffix alone must not cause a drop — protect domain models."""

    class CustomApiResponse:
        def __init__(self):
            self.label = "ok"

    result = to_jsonable(CustomApiResponse())
    assert result == {"label": "ok"}


# ---------------------------------------------------------------------------
# to_jsonable: safety guards
# ---------------------------------------------------------------------------

def test_self_referential_dict_does_not_recurse_forever():
    payload: dict = {"name": "loop"}
    payload["self"] = payload

    result = to_jsonable(payload)

    assert result["name"] == "loop"
    assert result["self"] is None  # cycle short-circuit


def test_unknown_object_falls_back_to_str():
    class Opaque:
        __slots__ = ()  # no __dict__, no model_dump, no to_dict

        def __str__(self) -> str:
            return "opaque-token"

    assert to_jsonable(Opaque()) == "opaque-token"


def test_unconfigured_mock_is_short_circuited_to_str():
    """``MagicMock`` exposes every attribute, including ``model_dump`` /
    ``to_dict`` / ``__dict__``; left unguarded the serializer would either
    recurse on opaque child mocks or trip ``RuntimeError: dictionary changed
    size during iteration`` while iterating ``vars(mock)``.  The defensive
    ``unittest.mock`` check must intercept the object and emit ``str(mock)``.
    """
    from unittest.mock import MagicMock

    result = to_jsonable(MagicMock(name="opaque"))

    assert isinstance(result, str)
    assert "Mock" in result


def test_mock_with_configured_to_dict_is_flattened():
    """A Mock whose ``to_dict`` is explicitly configured to return a real dict
    must take the SDK-v2 branch *before* the mock short-circuit fires, so test
    fixtures that simulate the Okta SDK contract keep working.
    """
    from unittest.mock import MagicMock

    mock_model = MagicMock()
    mock_model.to_dict.return_value = {"id": "abc", "status": "ACTIVE"}

    result = to_jsonable(mock_model)

    assert result == {"id": "abc", "status": "ACTIVE"}


def test_non_dict_model_dump_result_is_rejected():
    """``model_dump`` returning a non-dict / non-list value (e.g. another
    opaque object) must not be trusted — the serializer should fall through
    to subsequent strategies rather than recursing on whatever was returned.
    """
    class WeirdModel:
        def model_dump(self, **_kwargs):
            return object()  # not a dict, not a list, not a scalar

        def to_dict(self):
            return {"fallback": True}

    assert to_jsonable(WeirdModel()) == {"fallback": True}


def test_idempotent_on_already_jsonable_tree():
    payload = {"a": 1, "b": [True, None, "x"], "c": {"d": 2.5}}
    assert to_jsonable(to_jsonable(payload)) == payload


# ---------------------------------------------------------------------------
# Failure envelope
# ---------------------------------------------------------------------------

def test_failure_envelope_shape_is_json_native():
    try:
        raise ValueError("kaboom")
    except ValueError as exc:
        envelope = _failure_envelope("my_tool", exc)

    # Must be json.dumps-able without raising.
    encoded = json.dumps(envelope)
    assert "kaboom" in encoded

    assert envelope["ok"] is False
    assert envelope["error"]["type"] == "ValueError"
    assert envelope["error"]["tool"] == "my_tool"
    assert envelope["status_code"] is None
    # Raw traceback is opt-in via OKTA_MCP_INCLUDE_RAW.  Default: raw is
    # present but empty so the envelope shape is stable across configurations.
    assert envelope["raw"] == {}
    assert "traceback_tail" not in envelope["raw"]
    # The envelope must NOT contain an opaque-object repr.
    assert not re.search(r"<.+ object at 0x[0-9a-f]+>", encoded)


def test_failure_envelope_includes_traceback_when_flag_set(monkeypatch):
    monkeypatch.setenv("OKTA_MCP_INCLUDE_RAW", "1")
    try:
        raise ValueError("exposed")
    except ValueError as exc:
        envelope = _failure_envelope("my_tool", exc)

    assert "traceback_tail" in envelope["raw"]
    # The tail should carry a snippet of the raising context.
    assert "ValueError" in envelope["raw"]["traceback_tail"]


@pytest.mark.parametrize("falsy", ["", "0", "false", "no", "off", "anything-else"])
def test_failure_envelope_omits_traceback_for_falsy_flag(monkeypatch, falsy):
    monkeypatch.setenv("OKTA_MCP_INCLUDE_RAW", falsy)
    try:
        raise ValueError("nope")
    except ValueError as exc:
        envelope = _failure_envelope("my_tool", exc)

    assert envelope["raw"] == {}


def test_failure_envelope_truncates_long_messages():
    try:
        raise RuntimeError("x" * 5000)
    except RuntimeError as exc:
        envelope = _failure_envelope("t", exc)

    assert len(envelope["error"]["message"]) <= 1024


# ---------------------------------------------------------------------------
# @json_response decorator
# ---------------------------------------------------------------------------

def test_decorator_preserves_metadata_async():
    @json_response
    async def my_tool() -> dict:
        """Docstring of my_tool."""
        return {"ok": True}

    assert my_tool.__name__ == "my_tool"
    assert my_tool.__doc__ == "Docstring of my_tool."


def test_decorator_serializes_async_result():
    @json_response
    async def echo_app():
        return okta_models.Application.model_construct(
            label="hi", sign_on_mode=ApplicationSignOnMode.SAML_2_0
        )

    result = asyncio.run(echo_app())

    assert isinstance(result, dict)
    assert result["label"] == "hi"
    json.dumps(result)


def test_decorator_returns_envelope_when_serializer_raises(monkeypatch):
    @json_response
    async def will_break():
        return object()  # plain object, no __dict__ avoidance needed

    # Force to_jsonable to raise by patching the underlying worker.
    from okta_mcp_server.utils import serialization as ser

    def _raise(*_args, **_kwargs):
        raise RuntimeError("induced failure")

    monkeypatch.setattr(ser, "to_jsonable", _raise)

    result = asyncio.run(will_break())

    assert result["ok"] is False
    assert result["error"]["type"] == "RuntimeError"
    assert result["error"]["tool"] == "will_break"
    json.dumps(result)


def test_decorator_returns_envelope_when_tool_body_raises():
    """PR #90 follow-up review: @json_response's try/except wraps the call to
    the tool itself, not only the to_jsonable(...) step. Any exception raised
    directly by the wrapped tool -- including one that would occur before the
    tool's own inner try/except, e.g. attribute access on a malformed ctx --
    is caught here and converted into the same failure envelope, rather than
    propagating to the MCP SDK's own isError=True exception handling. This
    test exercises that path directly (no monkeypatching of to_jsonable),
    to distinguish it from test_decorator_returns_envelope_when_serializer_raises
    above.
    """

    @json_response
    async def raises_before_any_return():
        # Simulates code that runs before a tool's own try/except, e.g.
        # `ctx.request_context.lifespan_context.okta_auth_manager` on a
        # malformed context.
        raise AttributeError("'NoneType' object has no attribute 'okta_auth_manager'")

    result = asyncio.run(raises_before_any_return())

    assert result["ok"] is False
    assert result["error"]["type"] == "AttributeError"
    assert result["error"]["tool"] == "raises_before_any_return"
    json.dumps(result)


def test_decorator_returns_envelope_when_sync_tool_body_raises():
    @json_response
    def raises_immediately():
        raise ValueError("bad input")

    result = raises_immediately()

    assert result["ok"] is False
    assert result["error"]["type"] == "ValueError"
    assert result["error"]["tool"] == "raises_immediately"
    json.dumps(result)


def test_decorator_supports_sync_functions():
    @json_response
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5
