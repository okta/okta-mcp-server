# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2026-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Tests for :mod:`okta_mcp_server.utils.tolerant_deserialization`.

The unparseable item used throughout is broken in a way **no** Layer-1 patch
touches: it omits ``label``, which is genuinely required on ``Application`` and
which we deliberately do not relax.  That keeps these tests honest — they cannot
pass by accident because ``okta_compat`` happened to widen the field.

Covered:

* A ``List[Application]`` page with one bad record returns the good records and
  reports the bad one, with its raw payload, instead of failing outright.
* ``OKTA_MCP_STRICT_DESERIALIZATION`` restores the SDK's hard-fail behavior.
* Single-object targets stay strict.
* ``json_response`` attaches the warnings to a dict result without clobbering a
  ``"warnings"`` key the tool set itself.
"""

from __future__ import annotations

import asyncio
import copy

import pytest
from pydantic import ValidationError

from okta_mcp_server.utils.okta_compat import apply_okta_model_compat
from okta_mcp_server.utils.serialization import json_response
from okta_mcp_server.utils.tolerant_deserialization import (
    STRICT_ENV_VAR,
    get_deserialization_warnings,
    install_tolerant_deserialization,
    reset_deserialization_warnings,
    strict_deserialization_enabled,
)
from tests.conftest import load_fixture

apply_okta_model_compat()
install_tolerant_deserialization()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_client():
    """Return an ``ApiClient`` without running its ``__init__``.

    ``__deserialize`` only reaches class-level attributes (``PRIMITIVE_TYPES``,
    ``NATIVE_TYPES_MAPPING``) plus its own sibling methods, so no configuration
    or network setup is needed.
    """
    from okta.api_client import ApiClient

    return ApiClient.__new__(ApiClient)


def _deserialize(client, data, klass):
    """Invoke the (patched) name-mangled ``ApiClient.__deserialize``."""
    return client._ApiClient__deserialize(data, klass)


def _three_apps_with_one_broken() -> list[dict]:
    """Three SAML apps where the middle one is structurally invalid.

    The break — a missing required ``label`` — is not something any ``okta_compat``
    patch relaxes, so a passing test really does prove per-item tolerance.
    """
    good_one = load_fixture("saml_app_signon_fully_populated.json")

    broken = copy.deepcopy(good_one)
    broken["id"] = "0oa000000000000000009"
    del broken["label"]

    good_two = copy.deepcopy(good_one)
    good_two["id"] = "0oa000000000000000004"
    good_two["label"] = "Example Second App"

    return [good_one, broken, good_two]


@pytest.fixture(autouse=True)
def _clean_warning_context(monkeypatch):
    """Guarantee tolerant mode and an empty warning list for every test."""
    monkeypatch.delenv(STRICT_ENV_VAR, raising=False)
    reset_deserialization_warnings()
    yield
    reset_deserialization_warnings()


# ---------------------------------------------------------------------------
# Sanity: the bad item really is bad, and Layer 1 does not fix it
# ---------------------------------------------------------------------------

def test_broken_item_is_not_repaired_by_layer_one():
    """The structural break must survive the model patches, or the tests are vacuous."""
    from okta.models.application import Application

    _, broken, _ = _three_apps_with_one_broken()

    with pytest.raises(ValidationError) as excinfo:
        Application.from_dict(broken)

    assert "label" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Tolerant path
# ---------------------------------------------------------------------------

def test_list_drops_only_the_bad_item_and_records_a_warning():
    items = _three_apps_with_one_broken()

    parsed = _deserialize(_api_client(), items, "List[Application]")

    assert len(parsed) == 2
    assert [app.id for app in parsed] == ["0oa000000000000000003", "0oa000000000000000004"]

    warnings = get_deserialization_warnings()
    assert len(warnings) == 1
    entry = warnings[0]
    assert entry["type"] == "deserialization_error"
    assert entry["model"] == "Application"
    assert "label" in entry["error"]
    # The operator gets the untouched raw payload of the dropped record.
    assert entry["raw_item"] == items[1]
    assert entry["raw_item"]["id"] == "0oa000000000000000009"


def test_fully_valid_list_produces_no_warnings():
    """CONTROL: the happy path is unchanged and stays warning-free."""
    items = [load_fixture("saml_app_signon_fully_populated.json")]

    parsed = _deserialize(_api_client(), items, "List[Application]")

    assert len(parsed) == 1
    assert get_deserialization_warnings() == []


def test_tolerance_generalizes_beyond_applications():
    """The seam is type-agnostic: policies benefit from the same per-item guard."""
    good = load_fixture("access_policy_scalar_embedded.json")
    broken = copy.deepcopy(good)
    del broken["name"]  # required on Policy, and not relaxed by okta_compat

    parsed = _deserialize(_api_client(), [good, broken], "List[Policy]")

    assert len(parsed) == 1
    warnings = get_deserialization_warnings()
    assert len(warnings) == 1
    assert warnings[0]["model"] == "Policy"


def test_warnings_are_isolated_per_context():
    """The contextvar must not leak results between requests."""
    items = _three_apps_with_one_broken()
    _deserialize(_api_client(), items, "List[Application]")
    assert len(get_deserialization_warnings()) == 1

    async def _other_request():
        reset_deserialization_warnings()
        return get_deserialization_warnings()

    assert asyncio.run(_other_request()) == []


# ---------------------------------------------------------------------------
# Scope: single objects stay strict
# ---------------------------------------------------------------------------

def test_single_object_target_is_not_made_tolerant():
    """Layer 2 covers list responses only; ``get_*`` endpoints keep failing loudly.

    Dropping a single object would turn a hard error into a silent ``None``.
    """
    _, broken, _ = _three_apps_with_one_broken()

    with pytest.raises(ValidationError):
        _deserialize(_api_client(), broken, "Application")

    assert get_deserialization_warnings() == []


# ---------------------------------------------------------------------------
# Strict mode
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes"])
def test_strict_flag_truthy_values(monkeypatch, value):
    monkeypatch.setenv(STRICT_ENV_VAR, value)
    assert strict_deserialization_enabled() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_strict_flag_falsy_values(monkeypatch, value):
    monkeypatch.setenv(STRICT_ENV_VAR, value)
    assert strict_deserialization_enabled() is False


def test_strict_mode_restores_hard_failure(monkeypatch):
    """With the flag set, the same list raises exactly as it did before Layer 2."""
    items = _three_apps_with_one_broken()
    monkeypatch.setenv(STRICT_ENV_VAR, "true")

    with pytest.raises(ValidationError) as excinfo:
        _deserialize(_api_client(), items, "List[Application]")

    assert "label" in str(excinfo.value)
    assert get_deserialization_warnings() == []


def test_strict_flag_is_read_at_call_time(monkeypatch):
    """Toggling the env var mid-process must take effect without a reimport."""
    items = _three_apps_with_one_broken()

    monkeypatch.setenv(STRICT_ENV_VAR, "true")
    with pytest.raises(ValidationError):
        _deserialize(_api_client(), items, "List[Application]")

    monkeypatch.delenv(STRICT_ENV_VAR)
    assert len(_deserialize(_api_client(), items, "List[Application]")) == 2


# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------

def test_install_is_idempotent():
    """A second install must not double-wrap the SDK method."""
    from okta.api_client import ApiClient

    before = ApiClient._ApiClient__deserialize
    assert install_tolerant_deserialization() is False
    assert ApiClient._ApiClient__deserialize is before


# ---------------------------------------------------------------------------
# json_response integration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_json_response_attaches_warnings_to_dict_result():
    @json_response
    async def fake_tool():
        items = _three_apps_with_one_broken()
        parsed = _deserialize(_api_client(), items, "List[Application]")
        return {"items": [app.id for app in parsed], "total_fetched": len(parsed)}

    result = await fake_tool()

    assert result["total_fetched"] == 2
    assert len(result["warnings"]) == 1
    assert result["warnings"][0]["model"] == "Application"
    assert result["warnings"][0]["raw_item"]["id"] == "0oa000000000000000009"


@pytest.mark.asyncio
async def test_json_response_does_not_clobber_existing_warnings_key():
    """A tool's own ``warnings`` list is preserved; ours are appended after it."""

    @json_response
    async def fake_tool():
        items = _three_apps_with_one_broken()
        _deserialize(_api_client(), items, "List[Application]")
        return {"items": [], "warnings": ["a warning the tool raised itself"]}

    result = await fake_tool()

    assert result["warnings"][0] == "a warning the tool raised itself"
    assert len(result["warnings"]) == 2
    assert result["warnings"][1]["model"] == "Application"


@pytest.mark.asyncio
async def test_json_response_leaves_non_list_warnings_key_alone():
    """A non-list ``warnings`` value is not mangled into something else."""

    @json_response
    async def fake_tool():
        items = _three_apps_with_one_broken()
        _deserialize(_api_client(), items, "List[Application]")
        return {"warnings": "a single string set by the tool"}

    result = await fake_tool()

    assert result["warnings"] == "a single string set by the tool"


@pytest.mark.asyncio
async def test_json_response_adds_nothing_when_there_are_no_warnings():
    @json_response
    async def fake_tool():
        return {"items": []}

    assert await fake_tool() == {"items": []}


@pytest.mark.asyncio
async def test_json_response_resets_warnings_between_calls():
    """Warnings from one tool call must never appear in the next."""

    @json_response
    async def noisy_tool():
        _deserialize(_api_client(), _three_apps_with_one_broken(), "List[Application]")
        return {"items": []}

    @json_response
    async def quiet_tool():
        return {"items": []}

    assert "warnings" in await noisy_tool()
    assert "warnings" not in await quiet_tool()


def test_json_response_sync_branch_attaches_warnings():
    """The sync wrapper must behave identically to the async one."""

    @json_response
    def fake_sync_tool():
        _deserialize(_api_client(), _three_apps_with_one_broken(), "List[Application]")
        return {"items": []}

    result = fake_sync_tool()

    assert len(result["warnings"]) == 1
    assert result["warnings"][0]["model"] == "Application"


@pytest.mark.asyncio
async def test_json_response_leaves_non_dict_results_untouched():
    """A list-shaped result has nowhere to carry warnings and is returned as-is."""

    @json_response
    async def fake_tool():
        _deserialize(_api_client(), _three_apps_with_one_broken(), "List[Application]")
        return ["a", "b"]

    assert await fake_tool() == ["a", "b"]
